// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package ldap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/go-secure-stdlib/tlsutil"
)

const (
	schemeLDAP    = "ldap"
	schemeLDAPTLS = "ldaps"
)

// make an ldap.Conn interface so we can mock it out in tests
type ldapConnector interface {
	Bind(username, password string) error
	UnauthenticatedBind(username string) error
	Close() error
	StartTLS(config *tls.Config) error
	SetTimeout(d time.Duration)
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	SearchWithPaging(searchRequest *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
}

// Client provides a client for making requests to a directory service.
type Client struct {
	conf *ClientConfig
	// make this an inteface so we can mock it out in tests
	conn ldapConnector
	// dialFunc is an optional test seam for exercising URL recovery without a
	// network listener. Production clients use dialOne.
	dialFunc func(context.Context, string) (*ldapConnection, error)
}

// ldapConnection identifies the directory server that owns conn. URL, host,
// TLS configuration, and conn are always created together so a connection can
// never inherit the identity of a different URL.
type ldapConnection struct {
	conn ldapConnector
	url  string
	host string
}

// boundIdentity is the identity currently bound on a connection.
type boundIdentity struct {
	dn          string
	anonymous   bool
	hasIdentity bool
}

// trackedConn owns all bind and search activity for one authentication
// generation. In particular, it records the identity used for the most recent
// successful bind and makes searches context-aware. A connection is never
// shared between generations.
type trackedConn struct {
	ldapConnector
	ctx context.Context

	closeOnce sync.Once
	closeErr  error

	mu       sync.RWMutex
	lastBind boundIdentity
}

func newTrackedConn(ctx context.Context, conn ldapConnector) *trackedConn {
	if ctx == nil {
		ctx = context.Background()
	}
	return &trackedConn{
		ldapConnector: conn,
		ctx:           ctx,
	}
}

func (c *trackedConn) recordBind(dn string, anonymous bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastBind = boundIdentity{
		dn:          dn,
		anonymous:   anonymous,
		hasIdentity: true,
	}
}

func (c *trackedConn) lastBinding() boundIdentity {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastBind
}

func (c *trackedConn) contextDone() <-chan struct{} {
	if c == nil || c.ctx == nil {
		return nil
	}
	return c.ctx.Done()
}

func (c *trackedConn) Bind(username, password string) error {
	err := runWithContext(c.ctx, c.Close, func() error {
		return c.ldapConnector.Bind(username, password)
	})
	if err == nil {
		c.recordBind(username, false)
	}
	return err
}

func (c *trackedConn) UnauthenticatedBind(username string) error {
	err := runWithContext(c.ctx, c.Close, func() error {
		return c.ldapConnector.UnauthenticatedBind(username)
	})
	if err == nil {
		c.recordBind(username, true)
	}
	return err
}

func (c *trackedConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if c.contextDone() == nil {
		return c.ldapConnector.Search(req)
	}
	return runSearchWithContext(c.ctx, c.Close, func() (*ldap.SearchResult, error) {
		return c.ldapConnector.Search(req)
	})
}

func (c *trackedConn) SearchWithPaging(req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
	if c.contextDone() == nil {
		return c.ldapConnector.SearchWithPaging(req, pagingSize)
	}
	return runSearchWithContext(c.ctx, c.Close, func() (*ldap.SearchResult, error) {
		return c.ldapConnector.SearchWithPaging(req, pagingSize)
	})
}

func (c *trackedConn) Close() error {
	c.closeOnce.Do(func() {
		if c.ldapConnector != nil {
			c.closeErr = c.ldapConnector.Close()
		}
	})
	return c.closeErr
}

// authAttempt is one recoverable authentication generation. URL selection,
// TLS, bind identity, group collection, and the final AuthResult all belong to
// this value. Retrying creates a new authAttempt, which starts with empty group
// and identity state.
type authAttempt struct {
	id        uint64
	url       string
	host      string
	conf      *ClientConfig
	dialFunc  func(context.Context, string) (*ldapConnection, error)
	conn      *trackedConn
	client    *Client
	connected bool

	userBindDN  string
	groupBindDN string
}

var authAttemptSequence atomic.Uint64

func newAuthAttempt(conf *ClientConfig, rawURL string, dialFunc func(context.Context, string) (*ldapConnection, error)) *authAttempt {
	host := rawURL
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		host = u.Host
	}
	return &authAttempt{
		id:       authAttemptSequence.Add(1),
		url:      rawURL,
		host:     host,
		conf:     conf,
		dialFunc: dialFunc,
	}
}

func (a *authAttempt) connect(ctx context.Context) error {
	if a == nil || a.conf == nil {
		return fmt.Errorf("ldap.(authAttempt).connect: missing configuration: %w", ErrInternal)
	}
	var conn *ldapConnection
	var err error
	if a.dialFunc != nil {
		conn, err = a.dialFunc(ctx, a.url)
	} else {
		conn, err = (&Client{conf: a.conf}).dialOne(ctx, a.url)
	}
	if err != nil {
		return err
	}
	if conn == nil || conn.conn == nil {
		return fmt.Errorf("ldap.(authAttempt).connect: empty connection after dialing: %w", ErrUnknown)
	}
	if conn.url != "" {
		a.url = conn.url
	}
	if conn.host != "" {
		a.host = conn.host
	}
	a.conn = newTrackedConn(ctx, conn.conn)
	a.client = &Client{
		conf: a.conf,
		conn: a.conn,
	}
	a.connected = true
	return nil
}

func (a *authAttempt) close() error {
	if a == nil || a.conn == nil {
		return nil
	}
	if a.conn.ctx != nil && a.conn.ctx.Err() != nil {
		// Cancellation must return promptly even if the directory server does
		// not acknowledge the LDAP unbind promptly.
		go func() { _ = a.conn.Close() }()
		return nil
	}
	return a.conn.Close()
}

func (a *authAttempt) result(userDN string, userAttrs map[string][]string, groups []string, warnings []Warning) *AuthResult {
	var groupCopy []string
	if groups != nil {
		groupCopy = make([]string, len(groups))
		copy(groupCopy, groups)
	}
	var warningCopy []Warning
	if warnings != nil {
		warningCopy = make([]Warning, len(warnings))
		copy(warningCopy, warnings)
	}
	return &AuthResult{
		Success:        true,
		Groups:         groupCopy,
		UserDN:         userDN,
		UserAttributes: userAttrs,
		Warnings:       warningCopy,
		Host:           a.host,
		URL:            a.url,
		BindDN:         a.userBindDN,
		GroupBindDN:    a.groupBindDN,
		Generation:     a.id,
	}
}

// Warning is a warning message
type Warning string

func fmtWarning(format string, a ...interface{}) Warning {
	return Warning(fmt.Sprintf(format, a...))
}

// NewClient will create a new client from the configuration.  The following
// defaults will be used if no config value is provided for them:
//   - URLs:			see constant DefaultURL
//   - UserAttr: 		see constant DefaultUserAttr
//   - GroupAttr: 		see constant DefaultGroupAttr
//   - GroupFilter: 	see constant DefaultGroupFilter
//   - TLSMinVersion: 	see constant DefaultTLSMinVersion
//   - TLSMaxVersion: 	see constant DefaultTLSMaxVersion
func NewClient(ctx context.Context, conf *ClientConfig) (*Client, error) {
	const op = "ldap.NewClient"
	if conf == nil {
		return nil, fmt.Errorf("%s: missing config: %w", op, ErrInvalidParameter)
	}
	clientConf, err := conf.clone()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if len(clientConf.URLs) == 0 {
		clientConf.URLs = []string{DefaultURL}
	}
	if clientConf.GroupAttr == "" {
		clientConf.GroupAttr = DefaultGroupAttr
	}
	if clientConf.GroupFilter == "" {
		clientConf.GroupFilter = DefaultGroupFilter
	}
	if clientConf.TLSMinVersion == "" {
		clientConf.TLSMinVersion = DefaultTLSMinVersion
	}
	if clientConf.TLSMaxVersion == "" {
		clientConf.TLSMaxVersion = DefaultTLSMaxVersion
	}
	if clientConf.UserAttr == "" {
		clientConf.UserAttr = DefaultUserAttr
	}
	if err := clientConf.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &Client{
		conf: clientConf,
	}, nil
}

// connect will connect to a directory server using the URLs from the config or
// the WithURLs option. A connection is always retired before a replacement is
// selected, so a failed reconnect can never leave the previous bind identity
// available to the next caller.
//
// Supports options: WithURLs
func (c *Client) connect(ctx context.Context, opt ...Option) error {
	if ctx == nil {
		ctx = context.Background()
	}
	c.closeConn()
	conn, err := c.dial(ctx, opt...)
	if err != nil {
		return err
	}
	c.conn = conn.conn
	return nil
}

// dial selects one URL and creates its connection without changing the
// connection currently owned by the Client. The URL, host, TLS configuration
// and connection are returned as one value.
func (c *Client) dial(ctx context.Context, opt ...Option) (*ldapConnection, error) {
	const op = "ldap.(Client).connect"
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil || c.conf == nil {
		return nil, fmt.Errorf("%s: missing configuration: %w", op, ErrInternal)
	}
	opts := getConfigOpts(opt...)
	if len(c.conf.URLs) == 0 && len(opts.withURLs) == 0 {
		return nil, fmt.Errorf("%s: missing both configuration and optional LDAP URLs: %w", op, ErrInvalidParameter)
	}
	urls := opts.withURLs
	if len(urls) == 0 {
		urls = c.conf.URLs
	}

	var retErr *multierror.Error
	for _, rawURL := range urls {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s: connection attempt canceled: %w", op, err)
		}
		conn, err := c.dialOne(ctx, rawURL)
		if err == nil {
			return conn, nil
		}
		retErr = multierror.Append(retErr, err)
	}
	if retErr == nil {
		retErr = multierror.Append(retErr, fmt.Errorf("%s: no LDAP URLs were attempted: %w", op, ErrInvalidParameter))
	}
	return nil, retErr
}

// dialOne creates a connection for exactly one URL. TLS identity is derived
// from that URL's host and the returned ldapConnection keeps the URL and host
// attached to the connection for reporting.
func (c *Client) dialOne(ctx context.Context, rawURL string) (*ldapConnection, error) {
	const op = "ldap.(Client).connect"
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil || c.conf == nil {
		return nil, fmt.Errorf("%s: missing configuration: %w", op, ErrInternal)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%s: connection attempt canceled for url %q: %w", op, rawURL, err)
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%s: error parsing url %q: %w", op, rawURL, err)
	}
	host := u.Hostname()
	if host == "" {
		host = u.Host
	}

	var conn *ldap.Conn
	var tlsConfig *tls.Config
	switch u.Scheme {
	case schemeLDAP:
		conn, err = ldap.DialURL(rawURL, ldap.DialWithDialer(&net.Dialer{Timeout: c.getTimeout()}))
		if err != nil {
			break
		}
		if conn == nil {
			err = fmt.Errorf("%s: empty connection after dialing: %w", op, ErrUnknown)
			break
		}
		conn.SetTimeout(c.getTimeout())
		if c.conf.StartTLS {
			tlsConfig, err = getTLSConfig(
				host,
				withInsecureTLS(c.conf.InsecureTLS),
				withTLSMinVersion(c.conf.TLSMinVersion),
				withTLSMaxVersion(c.conf.TLSMaxVersion),
				withCertificates(c.conf.Certificates...),
				withClientTLSCert(c.conf.ClientTLSCert),
				withClientTLSKey(c.conf.ClientTLSKey),
			)
			if err != nil {
				break
			}
			err = conn.StartTLS(tlsConfig)
		}
	case schemeLDAPTLS:
		tlsConfig, err = getTLSConfig(
			host,
			withInsecureTLS(c.conf.InsecureTLS),
			withTLSMinVersion(c.conf.TLSMinVersion),
			withTLSMaxVersion(c.conf.TLSMaxVersion),
			withCertificates(c.conf.Certificates...),
			withClientTLSCert(c.conf.ClientTLSCert),
			withClientTLSKey(c.conf.ClientTLSKey),
		)
		if err != nil {
			break
		}
		conn, err = ldap.DialURL(rawURL, ldap.DialWithTLSDialer(tlsConfig, &net.Dialer{Timeout: c.getTimeout()}))
	default:
		return nil, fmt.Errorf("%s: invalid LDAP scheme in url %q: %w", op, rawURL, ErrInvalidParameter)
	}

	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, fmt.Errorf("%s: error connecting to host %q: %w", op, rawURL, err)
	}
	if conn == nil {
		return nil, fmt.Errorf("%s: error connecting to host %q: empty connection after dialing: %w", op, rawURL, ErrUnknown)
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%s: connection attempt canceled for url %q: %w", op, rawURL, err)
	}
	conn.SetTimeout(c.getTimeout())
	return &ldapConnection{
		conn: conn,
		url:  rawURL,
		host: u.Host,
	}, nil
}

// closeConn closes and clears the Client-owned connection.
func (c *Client) closeConn() {
	if c == nil || c.conn == nil {
		return
	}
	conn := c.conn
	c.conn = nil
	_ = conn.Close()
}

func (c *Client) getTimeout() time.Duration {
	switch c.conf.RequestTimeout {
	case 0:
		return DefaultTimeout * time.Second
	default:
		return time.Duration(c.conf.RequestTimeout) * time.Second
	}
}

// AuthResult is the result from a user authentication request via Client.Authenticate(...)
type AuthResult struct {
	// Success represents whether or not the attempt was successful
	Success bool

	// Groups are the groups that were associated with the authenticated
	// user (optional, see WithGroups() option)
	Groups []string

	// UserDN of the authenticated user (optional see WithUserAttributes()
	// option along with IncludeUserAttributes and ExcludedUserAttributes config
	// fields).
	UserDN string

	// UserAttributes that are associated with the authenticated user (optional
	// see WithUserAttributes() option along with IncludeUserAttributes and
	// ExcludedUserAttributes config fields)
	UserAttributes map[string][]string

	// Warnings are warnings that happen during either authentication or when
	// attempting to find the groups associated with the authenticated user (see
	// the WithGroups option)
	Warnings []Warning

	// Host is the host (including port when one was specified in the URL) of
	// the directory server that produced this result.
	Host string

	// URL is the exact LDAP URL selected for this result.
	URL string

	// BindDN is the DN of the authenticated user's successful bind.
	BindDN string

	// GroupBindDN is the identity bound when the group query ran. It can differ
	// from BindDN when a service BindDN or an anonymous group search is used. An
	// empty value can mean an anonymous empty-DN bind or that no group query was
	// requested; URL, Host and Generation distinguish the attempts.
	GroupBindDN string

	// Generation identifies the immutable authentication attempt that produced
	// this result. A retry or failover always uses a new generation, so Groups,
	// BindDN, Host and UserDN cannot be stitched together from different
	// attempts.
	Generation uint64
}

type Attribute struct {
	// Name is the name of the LDAP attribute
	Name string
	// Vals are the LDAP attribute values
	Vals []string
}

// Authenticate the user using the client's configured directory service.  If
// the WithGroups option is specified, it will also return the user's groups
// from the directory.
//
// Supported options: WithUserAttributes, WithGroups, WithDialer, WithURLs,
// WithLowerUserAttributeKeys, WithEmptyAnonymousGroupSearch
func (c *Client) Authenticate(ctx context.Context, username, password string, opt ...Option) (*AuthResult, error) {
	const op = "ldap.(Client).Authenticate"
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil || c.conf == nil {
		return nil, fmt.Errorf("%s: missing configuration: %w", op, ErrInternal)
	}
	if username == "" {
		return nil, fmt.Errorf("%s: missing username: %w", op, ErrInvalidParameter)
	}
	if !c.conf.AllowEmptyPasswordBinds && password == "" {
		return nil, fmt.Errorf("%s: password cannot be of zero length if allow_empty_passwd_bind is not enabled: %w", op, ErrInvalidParameter)
	}

	opts := getConfigOpts(opt...)
	conf, err := c.conf.clone()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	urls := append([]string(nil), conf.URLs...)
	if len(opts.withURLs) > 0 {
		urls = append([]string(nil), opts.withURLs...)
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("%s: missing both configuration and optional LDAP URLs: %w", op, ErrInvalidParameter)
	}

	// Authenticate never reuses the Client-owned connection. Retire it so a
	// legacy direct connect cannot leave an old bind identity around.
	c.closeConn()

	var attemptErrs *multierror.Error
	var anyConnected bool
	for _, rawURL := range urls {
		if err := ctx.Err(); err != nil {
			if attemptErrs != nil && len(attemptErrs.Errors) > 0 {
				attemptErrs = multierror.Append(attemptErrs, fmt.Errorf("authentication canceled before url %q: %w", rawURL, err))
				return nil, fmt.Errorf("%s: authentication canceled after %d URL attempt(s): %w", op, len(attemptErrs.Errors), attemptErrs)
			}
			return nil, fmt.Errorf("%s: authentication canceled: %w", op, err)
		}

		attempt := newAuthAttempt(conf, rawURL, c.dialFunc)
		result, retryable, err := c.authenticateAttempt(ctx, attempt, opts, username, password)
		closeErr := attempt.close()
		if err == nil {
			return result, nil
		}
		anyConnected = anyConnected || attempt.connected
		attemptErrs = multierror.Append(attemptErrs, err)
		if closeErr != nil {
			attemptErrs = multierror.Append(attemptErrs, fmt.Errorf("%s: closing connection for generation %d failed: %w", op, attempt.id, closeErr))
		}
		if !retryable {
			if len(attemptErrs.Errors) == 1 {
				return nil, err
			}
			return nil, fmt.Errorf("%s: LDAP authentication failed: %w", op, attemptErrs)
		}
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("%s: authentication canceled: %w", op, ctxErr)
	}
	if !anyConnected {
		return nil, fmt.Errorf("%s: failed to connect: %w", op, attemptErrs)
	}
	return nil, fmt.Errorf("%s: LDAP URL recovery failed after %d attempt(s): %w", op, len(urls), attemptErrs)
}

// authenticateAttempt performs the complete authentication flow against one
// URL generation. A retryable failure means the caller may start a new
// generation for another URL; the failed generation's connection, bind identity
// and group state are never reused.
func (c *Client) authenticateAttempt(ctx context.Context, attempt *authAttempt, opts configOptions, username, password string) (*AuthResult, bool, error) {
	const op = "ldap.(Client).Authenticate"
	if err := attempt.connect(ctx); err != nil {
		return nil, true, err
	}
	if err := ctx.Err(); err != nil {
		return nil, false, fmt.Errorf("%s: authentication canceled before bind (host %q / generation %d): %w", op, attempt.host, attempt.id, err)
	}

	userBindDN, err := attempt.client.getUserBindDN(username)
	if err != nil {
		return nil, isRetryableLDAPError(err), fmt.Errorf("%s: discovery of user bind DN failed (host %q / generation %d): %w", op, attempt.host, attempt.id, err)
	}

	// Try to bind as the login user. This is where the actual authentication takes place.
	if len(password) > 0 {
		err = attempt.client.conn.Bind(userBindDN, password)
	} else {
		err = attempt.client.conn.UnauthenticatedBind(userBindDN)
	}
	if err != nil {
		return nil, isRetryableLDAPError(err), fmt.Errorf("%s: unable to bind user (host %q / generation %d / bind DN %q): %w", op, attempt.host, attempt.id, userBindDN, err)
	}
	attempt.userBindDN = userBindDN

	if !opts.withGroups && !attempt.conf.IncludeUserGroups &&
		!opts.withUserAttributes && !attempt.conf.IncludeUserAttributes {
		return attempt.result("", nil, nil, nil), false, nil
	}

	// We re-bind to the BindDN if it's defined because we assume the BindDN
	// should be the one to search, not the user authenticating.
	if attempt.conf.BindDN != "" && attempt.conf.BindPassword != "" {
		if err := attempt.client.conn.Bind(attempt.conf.BindDN, attempt.conf.BindPassword); err != nil {
			// unless the binddn was changed during this inflight authentication
			// flow, it should be very difficult to encounter this error
			return nil, isRetryableLDAPError(err), fmt.Errorf("%s: unable to re-bind with the configuration BindDN user (host %q / generation %d / bind DN %q): %w", op, attempt.host, attempt.id, attempt.conf.BindDN, err)
		}
	}

	userDN, err := attempt.client.getUserDN(userBindDN, username)
	if err != nil {
		return nil, isRetryableLDAPError(err), fmt.Errorf("%s: failed to get the DN for the authenticated user (host %q / generation %d / bind DN %q): %w", op, attempt.host, attempt.id, userBindDN, err)
	}

	var userAttrs map[string][]string
	includeUserAttributes := attempt.conf.IncludeUserAttributes || opts.withUserAttributes
	if includeUserAttributes {
		userAttrs = map[string][]string{}
		attrs, err := attempt.client.getUserAttributes(userDN)
		if err != nil {
			return nil, isRetryableLDAPError(err), fmt.Errorf("%s: failed to get user attributes (host %q / generation %d / bind DN %q): %w", op, attempt.host, attempt.id, userBindDN, err)
		}
		for _, a := range attrs {
			name := a.Name
			if attempt.conf.LowerUserAttributeKeys || opts.withLowerUserAttributeKeys {
				name = strings.ToLower(a.Name)
			}
			userAttrs[name] = a.Vals
		}
	}
	if !opts.withGroups && !attempt.conf.IncludeUserGroups {
		return attempt.result(userDN, userAttrs, nil, nil), false, nil
	}

	if attempt.conf.AnonymousGroupSearch {
		// Some LDAP servers will reject anonymous group searches if userDN is
		// included in the query.
		dn := userDN
		if attempt.conf.AllowEmptyAnonymousGroupSearch || opts.withEmptyAnonymousGroupSearch {
			dn = ""
		}

		if err := attempt.client.conn.UnauthenticatedBind(dn); err != nil {
			return nil, isRetryableLDAPError(err), fmt.Errorf("%s: group search anonymous bind failed (host %q / generation %d / user DN %q / bind DN %q): %w", op, attempt.host, attempt.id, userDN, dn, err)
		}
	}

	groupBinding := attempt.conn.lastBinding()
	if groupBinding.hasIdentity {
		attempt.groupBindDN = groupBinding.dn
	}

	ldapGroups, warnings, err := attempt.client.getGroups(userDN, username)
	if err != nil {
		return nil, isRetryableLDAPError(err), fmt.Errorf("%s: unable to get user groups (host %q / generation %d / user DN %q / bind DN %q / group bind DN %q): %w", op, attempt.host, attempt.id, userDN, userBindDN, attempt.groupBindDN, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, false, fmt.Errorf("%s: authentication canceled after group query (host %q / generation %d / user DN %q / bind DN %q / group bind DN %q): %w", op, attempt.host, attempt.id, userDN, userBindDN, attempt.groupBindDN, err)
	}

	if includeUserAttributes {
		return attempt.result(userDN, userAttrs, ldapGroups, warnings), false, nil
	}
	return attempt.result("", nil, ldapGroups, warnings), false, nil
}

// Close will close the client's connection to the directory service.
func (c *Client) Close(ctx context.Context) {
	c.closeConn()
}

func (c *Client) getUserAttributes(userDN string) ([]Attribute, error) {
	const op = "ldap.(Client).getUserAttributes"
	switch {
	case userDN == "":
		return nil, fmt.Errorf("%s: missing user dn: %w", op, ErrInvalidParameter)
	}

	result, err := c.conn.Search(&ldap.SearchRequest{
		BaseDN:       userDN,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: derefAliasMap[c.conf.DerefAliases],
		Filter:       "(objectClass=*)",
	})
	switch {
	case err != nil:
		return nil, fmt.Errorf("%s: LDAP search for user attributes failed (baseDN: %q / filter: %q): %w", op, userDN, "(objectClass=*)", err)
	case len(result.Entries) != 1:
		return nil, fmt.Errorf("%s: LDAP search for user attributes was 0 or not unique", op)
	}
	userEntry := result.Entries[0]
	attributes := make([]Attribute, 0, len(userEntry.Attributes))
	for _, a := range userEntry.Attributes {
		switch {
		// exclude the default openLDAP password attribute
		case strings.EqualFold(a.Name, DefaultOpenLDAPUserPasswordAttribute):
		// exclude the default AD password attribute
		case strings.EqualFold(a.Name, DefaultADUserPasswordAttribute):
		// filter out excluded attributes
		case strutil.StrListContainsCaseInsensitive(c.conf.ExcludedUserAttributes, a.Name):
		default:
			attributes = append(attributes, Attribute{
				Name: a.Name,
				Vals: a.Values,
			})
		}
	}
	return attributes, nil
}

// getGroups queries LDAP and returns a slice describing the set of groups the
// authenticated user is a member of.
//
// If c.conf.UseTokenGroups is true then the search is performed directly on the
// userDN. The values of those attributes are converted to string SIDs, and then
// looked up to get Entry objects. Otherwise, the search query is constructed
// according to c.conf..GroupFilter, and run in context of c.conf.GroupDN.
// Groups will be resolved from the query results by following the attribute
// defined in c.conf.GroupAttr.
//
// c.conf.GroupFilter is a go template and is compiled with the following context: [UserDN, Username]
//
//	UserDN - The DN of the authenticated user
//	Username - The Username of the authenticated user
//
// Example:
//
//	 c.conf.GroupFilter = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))"
//	 c.conf.GroupDN     = "OU=Groups,DC=myorg,DC=com"
//	 c.conf.GroupAttr   = "cn"
//
//	NOTE - If the config GroupFilter is empty, no query is performed and an
//	empty result slice is returned.
func (c *Client) getGroups(userDN string, username string) ([]string, []Warning, error) {
	const op = "ldap.(Client).getGroups"
	var warnings []Warning
	if userDN == "" {
		return nil, warnings, fmt.Errorf("%s: missing user dn: %w", op, ErrInvalidParameter)
	}
	if username == "" {
		return nil, warnings, fmt.Errorf("%s: missing username: %w", op, ErrInvalidParameter)
	}
	var entries []*ldap.Entry
	var err error
	if c.conf.UseTokenGroups {
		entries, warnings, err = c.tokenGroupsSearch(userDN)
	} else {
		entries, warnings, err = c.filterGroupsSearch(userDN, username)
	}
	if err != nil {
		return nil, warnings, fmt.Errorf("%s: %w", op, err)
	}

	// retrieve the groups in a string/bool map as a structure to avoid duplicates
	ldapMap := make(map[string]bool)

	for _, e := range entries {
		dn, err := ldap.ParseDN(e.DN)
		if err != nil || len(dn.RDNs) == 0 {
			continue
		}

		// Enumerate attributes of each result, parse out CN and add as group
		values := e.GetAttributeValues(c.conf.GroupAttr)
		if len(values) > 0 {
			for _, val := range values {
				groupCN := c.getCN(val)
				ldapMap[groupCN] = true
			}
		} else {
			// If groupattr didn't resolve, use self (enumerating group objects)
			groupCN := c.getCN(e.DN)
			ldapMap[groupCN] = true
		}
	}

	ldapGroups := make([]string, 0, len(ldapMap))
	for key := range ldapMap {
		ldapGroups = append(ldapGroups, key)
	}

	return ldapGroups, warnings, nil
}

func (c *Client) tokenGroupsSearch(userDN string) ([]*ldap.Entry, []Warning, error) {
	const op = "ldap.(Client).tokenGroupsSearch"
	var warnings []Warning
	if userDN == "" {
		return nil, warnings, fmt.Errorf("%s: missing user dn: %w", op, ErrInvalidParameter)
	}
	result, err := c.conn.Search(&ldap.SearchRequest{
		BaseDN:       userDN,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: derefAliasMap[c.conf.DerefAliases],
		Filter:       "(objectClass=*)",
		Attributes: []string{
			"tokenGroups",
		},
		SizeLimit: 1,
	})
	if err != nil {
		return nil, warnings, fmt.Errorf("%s: search failed (baseDN: %q / filter: %q): %w", op, userDN, "(objectClass=*)", err)
	}
	if len(result.Entries) == 0 {
		warnings = append(warnings, fmtWarning("%s: unable to read object for group attributes: userdn %s and groupattr %s", op, userDN, c.conf.GroupAttr))
		return make([]*ldap.Entry, 0), warnings, nil
	}

	userEntry := result.Entries[0]
	groupAttrValues := userEntry.GetRawAttributeValues("tokenGroups")
	groupEntries := make([]*ldap.Entry, 0, len(groupAttrValues))

	{
		// we're using worker pool to make looking up token groups more
		// performant.  token groups have to be looked up individually, so if a
		// user is a member of MANY groups it can be helpful to do these lookups
		// concurrently vs serially. This is based on benchmarks and a
		// subsequent implementation within vault's codebase for looking up token
		// groups. See: https://github.com/hashicorp/vault/pull/22659
		const maxWorkers = 10
		var wg sync.WaitGroup
		var lock sync.Mutex
		taskChan := make(chan string) // intentionally an unbuffered chan so we can iterate (range) over it before it's closed.
		for i := 0; i < maxWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for sidString := range taskChan {
					groupResult, err := c.conn.Search(&ldap.SearchRequest{
						BaseDN:       fmt.Sprintf("<SID=%s>", sidString),
						Scope:        ldap.ScopeBaseObject,
						DerefAliases: derefAliasMap[c.conf.DerefAliases],
						Filter:       "(objectClass=*)",
						Attributes: []string{
							"1.1", // RFC no attributes
						},
						SizeLimit: 1,
					})
					if err != nil {
						lock.Lock()
						warnings = append(warnings, fmtWarning("%s: unable to read the group sid (baseDN: %q / filter: %q): %s", op, fmt.Sprintf("<SID=%s>", sidString), "(objectClass=*)", sidString))
						lock.Unlock()
						continue
					}
					if len(groupResult.Entries) == 0 {
						lock.Lock()
						warnings = append(warnings, fmtWarning("%s: unable to find the group sid (baseDN: %q / filter: %q): %s", op, fmt.Sprintf("<SID=%s>", sidString), "(objectClass=*)", sidString))
						lock.Unlock()
						continue
					}
					lock.Lock()
					groupEntries = append(groupEntries, groupResult.Entries[0])
					lock.Unlock()
				}
			}()
		}
		for _, sidBytes := range groupAttrValues {
			sidString, err := sidBytesToString(sidBytes)
			if err != nil {
				lock.Lock()
				warnings = append(warnings, fmtWarning("%s: unable to read sid: %s", op, err.Error()))
				lock.Unlock()
				continue
			}
			taskChan <- sidString
		}
		// closing the taskChan will allow the workers to start iterating
		// (range) - this unblocks them
		close(taskChan)

		// wait for all the workers to finish up the token group lookups and
		// adding all the groups to the slice of group entries
		wg.Wait()
	}

	return groupEntries, warnings, nil
}

func (c *Client) filterGroupsSearch(userDN string, username string) ([]*ldap.Entry, []Warning, error) {
	const op = "ldap.(Client).filterGroupsSearch"
	var warnings []Warning
	if userDN == "" {
		return nil, warnings, fmt.Errorf("%s: missing user dn: %w", op, ErrInvalidParameter)
	}
	if username == "" {
		return nil, warnings, fmt.Errorf("%s: missing username: %w", op, ErrInvalidParameter)
	}
	if c.conf.GroupFilter == "" {
		return make([]*ldap.Entry, 0), warnings, nil
	}
	if c.conf.GroupDN == "" {
		return make([]*ldap.Entry, 0), warnings, nil
	}
	// Parse the configuration as a template.
	// Example template "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))"
	t, err := template.New("queryTemplate").Parse(c.conf.GroupFilter)
	if err != nil {
		return nil, warnings, fmt.Errorf("%s: LDAP search failed due to template compilation error: %w", op, err)
	}

	// Build context to pass to template - we will be exposing UserDn and Username.
	context := struct {
		UserDN   string
		Username string
	}{
		ldap.EscapeFilter(userDN),
		ldap.EscapeFilter(username),
	}

	var renderedQuery bytes.Buffer
	if err := t.Execute(&renderedQuery, context); err != nil {
		return nil, warnings, fmt.Errorf("%s: LDAP search failed due to template parsing error: %w", op, err)
	}

	var result *ldap.SearchResult
	req := ldap.SearchRequest{
		BaseDN:       c.conf.GroupDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: derefAliasMap[c.conf.DerefAliases],
		Filter:       renderedQuery.String(),
		Attributes: []string{
			c.conf.GroupAttr,
		},
		SizeLimit: math.MaxInt32,
	}
	switch {
	case c.conf.MaximumPageSize > 0:
		result, err = c.conn.SearchWithPaging(&req, uint32(c.conf.MaximumPageSize))
	default:
		result, err = c.conn.Search(&req)
	}
	if err != nil {
		switch {
		case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
			warnings = append(warnings, Warning(err.Error()))
			return []*ldap.Entry{}, warnings, nil
		default:
			return nil, warnings, fmt.Errorf("%s: LDAP search failed (baseDN: %q / filter: %q): %w", op, c.conf.GroupDN, renderedQuery.String(), err)
		}
	}

	return result.Entries, warnings, nil
}

func sidBytesToString(b []byte) (string, error) {
	const op = "ldap.sidBytesToString"
	if b == nil {
		return "", fmt.Errorf("%s: missing bytes: %w", op, ErrInvalidParameter)
	}
	reader := bytes.NewReader(b)

	var revision, subAuthorityCount uint8
	var identifierAuthorityParts [3]uint16

	if err := binary.Read(reader, binary.LittleEndian, &revision); err != nil {
		return "", fmt.Errorf("%s: SID %#v convert failed reading Revision: %w", op, b, err)
	}

	if err := binary.Read(reader, binary.LittleEndian, &subAuthorityCount); err != nil {
		return "", fmt.Errorf("%s: SID %#v convert failed reading SubAuthorityCount: %w", op, b, err)
	}

	if err := binary.Read(reader, binary.BigEndian, &identifierAuthorityParts); err != nil {
		return "", fmt.Errorf("%s: SID %#v convert failed reading IdentifierAuthority: %w", op, b, err)
	}
	identifierAuthority := (uint64(identifierAuthorityParts[0]) << 32) + (uint64(identifierAuthorityParts[1]) << 16) + uint64(identifierAuthorityParts[2])

	subAuthority := make([]uint32, subAuthorityCount)
	if err := binary.Read(reader, binary.LittleEndian, &subAuthority); err != nil {
		return "", fmt.Errorf("%s: SID %#v convert failed reading SubAuthority: %w", op, b, err)
	}

	result := fmt.Sprintf("S-%d-%d", revision, identifierAuthority)
	for _, subAuthorityPart := range subAuthority {
		result += fmt.Sprintf("-%d", subAuthorityPart)
	}

	return result, nil
}

// SIDBytes creates a SID from the provided revision and identifierAuthority
func SIDBytes(revision uint8, identifierAuthority uint16) ([]byte, error) {
	const op = "ldap.SidBytes"
	var identifierAuthorityParts [3]uint16
	identifierAuthorityParts[2] = identifierAuthority

	subAuthorityCount := uint8(0)
	var writer bytes.Buffer
	if err := binary.Write(&writer, binary.LittleEndian, uint8(revision)); err != nil {
		return nil, fmt.Errorf("%s: unable to write revision: %w", op, err)
	}
	if err := binary.Write(&writer, binary.LittleEndian, subAuthorityCount); err != nil {
		return nil, fmt.Errorf("%s: unable to write subauthority count: %w", op, err)
	}
	if err := binary.Write(&writer, binary.BigEndian, identifierAuthorityParts); err != nil {
		return nil, fmt.Errorf("%s: unable to write authority parts: %w", op, err)
	}
	return writer.Bytes(), nil
}

func (c *Client) getUserBindDN(username string) (string, error) {
	const op = "ldap.(Client).getUserBindDN"
	if username == "" {
		return "", fmt.Errorf("%s: missing username: %w", op, ErrInvalidParameter)
	}
	// this validation check and the logic right below it are dependent, so if
	// you update one of them, be sure to update the other one as well.
	if !c.conf.DiscoverDN && (c.conf.BindDN == "" || c.conf.BindPassword == "") && c.conf.UPNDomain == "" && c.conf.UserDN == "" {
		return "", fmt.Errorf("%s: cannot derive UserBindDN based on config (see combination of: discoverdn, binddn, bindpass, upndomain, userdn): %w", op, ErrInvalidParameter)
	}
	var bindDN string
	if c.conf.DiscoverDN || (c.conf.BindDN != "" && c.conf.BindPassword != "") {
		var err error
		if c.conf.BindPassword != "" {
			err = c.conn.Bind(c.conf.BindDN, c.conf.BindPassword)
		} else {
			err = c.conn.UnauthenticatedBind(c.conf.BindDN)
		}
		if err != nil {
			return "", fmt.Errorf("%s: bind (service) failed: %w", op, err)
		}

		filter, err := c.renderUserSearchFilter(username)
		if err != nil {
			return "", fmt.Errorf("%s: %w", op, err)
		}

		result, err := c.conn.Search(&ldap.SearchRequest{
			BaseDN:       c.conf.UserDN,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: derefAliasMap[c.conf.DerefAliases],
			Filter:       filter,
			SizeLimit:    math.MaxInt32,
		})
		if err != nil {
			return "", fmt.Errorf("%s: LDAP search for binddn failed using (baseDN: %q / filter: %q): %w", op, c.conf.UserDN, filter, err)
		}
		if len(result.Entries) != 1 {
			return "", fmt.Errorf("LDAP search for binddn 0 or not unique")
		}
		bindDN = result.Entries[0].DN
	} else {
		if c.conf.UPNDomain != "" {
			bindDN = fmt.Sprintf("%s@%s", escapeValue(username), c.conf.UPNDomain)
		} else {
			bindDN = fmt.Sprintf("%s=%s,%s", c.conf.UserAttr, escapeValue(username), c.conf.UserDN)
		}
	}
	return bindDN, nil
}

/*
 * Returns the DN of the object representing the authenticated user.
 */
func (c *Client) getUserDN(bindDN, username string) (string, error) {
	const op = "ldap.(Client).getUserDN"
	if bindDN == "" {
		return "", fmt.Errorf("%s: missing bind dn: %w", op, ErrInvalidParameter)
	}
	if username == "" {
		return "", fmt.Errorf("%s: missing username: %w", op, ErrInvalidParameter)
	}
	var userDN string
	if c.conf.UPNDomain != "" {
		// Find the distinguished name for the user if userPrincipalName used for login, or sAMAccountName if enabled.
		var filter string
		if c.conf.EnableSamaccountnameLogin {
			filter = fmt.Sprintf("(|(userPrincipalName=%s@%s)(sAMAccountName=%s))", escapeValue(username), c.conf.UPNDomain, escapeValue(username))
		} else {
			filter = fmt.Sprintf("(userPrincipalName=%s@%s)", escapeValue(username), c.conf.UPNDomain)
		}
		result, err := c.conn.Search(&ldap.SearchRequest{
			BaseDN:       c.conf.UserDN,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: derefAliasMap[c.conf.DerefAliases],
			Filter:       filter,
			SizeLimit:    math.MaxInt32,
		})
		if err != nil {
			return userDN, fmt.Errorf("%s: LDAP search failed for detecting user (baseDN: %q / filter: %q): %w", op, c.conf.UserDN, filter, err)
		}
		if len(result.Entries) != 1 {
			return "", fmt.Errorf("%s: LDAP search for user 0 or not unique", op)
		}
		userDN = result.Entries[0].DN
	} else {
		userDN = bindDN
	}
	return userDN, nil
}

/*
 * Parses a distinguished name and returns the CN portion.
 * Given a non-conforming string (such as an already-extracted CN),
 * it will be returned as-is.
 */
func (c *Client) getCN(dn string) string {
	parsedDN, err := ldap.ParseDN(dn)
	if err != nil || len(parsedDN.RDNs) == 0 {
		// It was already a CN, return as-is
		return dn
	}

	for _, rdn := range parsedDN.RDNs {
		for _, rdnAttr := range rdn.Attributes {
			if c.conf.DeprecatedVaultPre111GroupCNBehavior == nil || *c.conf.DeprecatedVaultPre111GroupCNBehavior {
				if rdnAttr.Type == "CN" {
					return rdnAttr.Value
				}
			} else {
				if strings.EqualFold(rdnAttr.Type, "CN") {
					return rdnAttr.Value
				}
			}
		}
	}
	// Default, return self
	return dn
}

func (c *Client) renderUserSearchFilter(username string) (string, error) {
	const (
		op = "ldap.(Client).renderUserSearchFilter"

		emptyUserFilter   = ""
		defaultUserFilter = "({{.UserAttr}}={{.Username}})"
		queryTemplate     = "queryTemplate"
	)
	if username == "" {
		return "", fmt.Errorf("%s: missing username: %w", op, ErrInvalidParameter)
	}

	var userFilter string
	// The UserFilter can be blank if not set, or running this version of the code
	// on an existing ldap configuration
	switch {
	case c.conf.UserFilter != emptyUserFilter:
		userFilter = c.conf.UserFilter
	default:
		userFilter = defaultUserFilter
	}

	// Parse the configuration as a template.
	// Example template "({{.UserAttr}}={{.Username}})"
	t, err := template.New(queryTemplate).Parse(userFilter)
	if err != nil {
		return "", fmt.Errorf("%s: search failed due to template compilation error: %w", op, err)
	}

	// Build context to pass to template - we will be exposing UserDn and Username.
	context := struct {
		UserAttr string
		Username string
	}{
		EscapeFilter(c.conf.UserAttr),
		EscapeFilter(username),
	}
	if c.conf.UPNDomain != "" {
		context.UserAttr = "userPrincipalName"
		// Intentionally, calling EscapeFilter(...) (vs EscapeValue) since the
		// username is being injected into a search filter.
		// As an untrusted string, the username must be escaped according to RFC
		// 4515, in order to prevent attackers from injecting characters that could modify the filter
		context.Username = fmt.Sprintf("%s@%s", EscapeFilter(username), c.conf.UPNDomain)
	}

	var renderedFilter bytes.Buffer
	if err := t.Execute(&renderedFilter, context); err != nil {
		return "", fmt.Errorf("%s: search failed due to template parsing error: %w", op, err)
	}

	return renderedFilter.String(), nil
}

// runWithContext runs a blocking LDAP operation in one goroutine and closes the
// attempt's connection if the caller cancels the operation. The buffered
// result channel lets the operation goroutine exit even if cancellation wins
// the select.
func runWithContext(ctx context.Context, cancel func() error, operation func() error) error {
	if operation == nil {
		return nil
	}
	if ctx == nil || ctx.Done() == nil {
		return operation()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	result := make(chan error, 1)
	go func() {
		result <- operation()
	}()

	select {
	case <-ctx.Done():
		if cancel != nil {
			go func() { _ = cancel() }()
		}
		return ctx.Err()
	case err := <-result:
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
}

// runSearchWithContext is runWithContext for searches, which return a value in
// addition to an error.
func runSearchWithContext(ctx context.Context, cancel func() error, operation func() (*ldap.SearchResult, error)) (*ldap.SearchResult, error) {
	if operation == nil {
		return nil, nil
	}
	if ctx == nil || ctx.Done() == nil {
		return operation()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	type searchResult struct {
		result *ldap.SearchResult
		err    error
	}
	results := make(chan searchResult, 1)
	go func() {
		result, err := operation()
		results <- searchResult{result: result, err: err}
	}()

	select {
	case <-ctx.Done():
		if cancel != nil {
			go func() { _ = cancel() }()
		}
		return nil, ctx.Err()
	case result := <-results:
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return result.result, result.err
	}
}

// isRetryableLDAPError classifies errors that can safely be retried on another
// directory URL. Credential and request-shape failures are deliberately not
// retryable, while transport failures, restarts and server-unavailable
// responses are.
func isRetryableLDAPError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		// A per-operation request timeout can be recovered on another URL. If
		// the caller's context expired instead, the URL loop observes ctx.Err()
		// before starting another attempt.
		return true
	}

	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		switch ldapErr.ResultCode {
		case ldap.ErrorNetwork,
			ldap.LDAPResultTimeLimitExceeded,
			ldap.LDAPResultBusy,
			ldap.LDAPResultUnavailable,
			ldap.LDAPResultServerDown,
			ldap.LDAPResultTimeout,
			ldap.LDAPResultConnectError,
			ldap.LDAPResultProtocolError:
			return true
		default:
			return false
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	errText := strings.ToLower(err.Error())
	for _, fragment := range []string{
		"connection reset",
		"connection refused",
		"broken pipe",
		"connection closed",
		"unexpected eof",
		"server closed",
		"connection timed out",
		"i/o timeout",
	} {
		if strings.Contains(errText, fragment) {
			return true
		}
	}
	return false
}

func getTLSConfig(host string, opt ...Option) (*tls.Config, error) {
	const op = "ldap.getTLSConfig"
	if host == "" {
		return nil, fmt.Errorf("%s: missing host: %w", op, ErrInvalidParameter)
	}
	opts := getConfigOpts(opt...)
	tlsConfig := &tls.Config{
		ServerName: host,
	}

	if opts.withTLSMinVersion != "" {
		tlsMinVersion, ok := tlsutil.TLSLookup[opts.withTLSMinVersion]
		if !ok {
			return nil, fmt.Errorf("%s: invalid 'tls_min_version' in config: %w", op, ErrInvalidParameter)
		}
		tlsConfig.MinVersion = tlsMinVersion
	}

	if opts.withTLSMaxVersion != "" {
		tlsMaxVersion, ok := tlsutil.TLSLookup[opts.withTLSMaxVersion]
		if !ok {
			return nil, fmt.Errorf("%s: invalid 'tls_max_version' in config: %w", op, ErrInvalidParameter)
		}
		tlsConfig.MaxVersion = tlsMaxVersion
	}

	if opts.withInsecureTLS {
		tlsConfig.InsecureSkipVerify = true
	}
	if opts.withCertificates != nil {
		caPool := x509.NewCertPool()
		for _, c := range opts.withCertificates {
			ok := caPool.AppendCertsFromPEM([]byte(c))
			if !ok {
				return nil, fmt.Errorf("%s: could not append CA certificate: %w", op, ErrUnknown)
			}
		}
		tlsConfig.RootCAs = caPool
	}
	if opts.withClientTLSCert != "" && opts.withClientTLSKey != "" {
		certificate, err := tls.X509KeyPair([]byte(opts.withClientTLSCert), []byte(opts.withClientTLSKey))
		if err != nil {
			return nil, fmt.Errorf("%s: failed to parse client X509 key pair: %w", op, err)
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, certificate)
	} else if opts.withClientTLSCert != "" || opts.withClientTLSKey != "" {
		return nil, fmt.Errorf("%s: both client_tls_cert and client_tls_key must be set in configuration: %w", op, ErrInvalidParameter)
	}
	return tlsConfig, nil
}

// escapeValue will properly escape the input string as an ldap value
// rfc4514 states the following must be escaped:
// - leading space or hash
// - trailing space
// - special characters '"', '+', ',', ';', '<', '>', '\\'
// - hex
func escapeValue(input string) string {
	const op = "ldap.EscapeValue"
	if input == "" {
		return ""
	}

	buf := bytes.Buffer{}

	escFn := func(c byte) {
		buf.WriteByte('\\')
		buf.WriteByte(c)
	}

	inputLen := len(input)
	for i := 0; i < inputLen; i++ {
		char := input[i]
		switch {
		case i == 0 && char == ' ' || char == '#':
			// leading space or hash.
			escFn(char)
			continue
		case i == inputLen-1 && char == ' ':
			// trailing space.
			escFn(char)
			continue
		case specialChar(char):
			// special characters '"', '+', ',', ';', '<', '>', '\\'
			escFn(char)
			continue
		case char < ' ' || char > '~':
			// anything that's not between the ascii space and tilde must be hex
			buf.WriteByte('\\')
			buf.WriteString(hex.EncodeToString([]byte{char}))
			continue
		default:
			// everything remaining, doesn't need to be escaped
			buf.WriteByte(char)
		}
	}
	return buf.String()
}

func specialChar(char byte) bool {
	switch char {
	case '"', '+', ',', ';', '<', '>', '\\':
		return true
	default:
		return false
	}
}

func EscapeFilter(filter string) string {
	return ldap.EscapeFilter(filter)
}
