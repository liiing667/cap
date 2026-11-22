// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type generationMockConn struct {
	mu sync.Mutex

	binds      []string
	anonBinds  []string
	closeCalls int
	closed     chan struct{}
	closeOnce  sync.Once
	searchFn   func(*ldap.SearchRequest) (*ldap.SearchResult, error)
}

func newGenerationMockConn() *generationMockConn {
	return &generationMockConn{closed: make(chan struct{})}
}

func (c *generationMockConn) Bind(username, password string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.binds = append(c.binds, username)
	return nil
}

func (c *generationMockConn) UnauthenticatedBind(username string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.anonBinds = append(c.anonBinds, username)
	return nil
}

func (c *generationMockConn) Close() error {
	c.mu.Lock()
	c.closeCalls++
	c.mu.Unlock()
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *generationMockConn) StartTLS(config *tls.Config) error { return nil }

func (c *generationMockConn) SetTimeout(d time.Duration) {}

func (c *generationMockConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if c.searchFn != nil {
		return c.searchFn(req)
	}
	return &ldap.SearchResult{}, nil
}

func (c *generationMockConn) SearchWithPaging(req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
	return c.Search(req)
}

func TestTrackedConnTracksCurrentBindIdentity(t *testing.T) {
	t.Parallel()
	conn := newGenerationMockConn()
	tracked := newTrackedConn(context.Background(), conn)

	require.NoError(t, tracked.Bind("cn=alice,ou=people,dc=example,dc=org", "password"))
	binding := tracked.lastBinding()
	assert.True(t, binding.hasIdentity)
	assert.False(t, binding.anonymous)
	assert.Equal(t, "cn=alice,ou=people,dc=example,dc=org", binding.dn)

	require.NoError(t, tracked.UnauthenticatedBind(""))
	binding = tracked.lastBinding()
	assert.True(t, binding.hasIdentity)
	assert.True(t, binding.anonymous)
	assert.Empty(t, binding.dn)

	require.NoError(t, tracked.Close())
	require.NoError(t, tracked.Close())
	conn.mu.Lock()
	defer conn.mu.Unlock()
	assert.Equal(t, 1, conn.closeCalls)
}

func TestNewClientFreezesMutableURLSelection(t *testing.T) {
	t.Parallel()
	urls := []string{"ldaps://first.example.com:636", "ldaps://second.example.com:636"}
	excluded := []string{"memberOf"}
	pre111 := true
	conf := &ClientConfig{
		URLs:                                 urls,
		ExcludedUserAttributes:               excluded,
		DeprecatedVaultPre111GroupCNBehavior: &pre111,
	}

	client, err := NewClient(context.Background(), conf)
	require.NoError(t, err)

	urls[0] = "ldaps://mutated.example.com:636"
	excluded[0] = "mutated"
	pre111 = false

	assert.Equal(t, []string{"ldaps://first.example.com:636", "ldaps://second.example.com:636"}, client.conf.URLs)
	assert.Equal(t, []string{"memberOf"}, client.conf.ExcludedUserAttributes)
	require.NotNil(t, client.conf.DeprecatedVaultPre111GroupCNBehavior)
	assert.True(t, *client.conf.DeprecatedVaultPre111GroupCNBehavior)
}

func TestTrackedConnSearchCancellationClosesConnection(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := newGenerationMockConn()
	started := make(chan struct{})
	conn.searchFn = func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		close(started)
		<-conn.closed
		return nil, net.ErrClosed
	}
	tracked := newTrackedConn(ctx, conn)

	searches := make(chan error, 1)
	go func() {
		_, err := tracked.Search(&ldap.SearchRequest{BaseDN: "dc=example,dc=org"})
		searches <- err
	}()

	<-started
	cancel()

	select {
	case err := <-searches:
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("tracked search did not return after cancellation")
	}
}

func TestAuthAttemptResultCopiesGenerationState(t *testing.T) {
	t.Parallel()
	attempt := &authAttempt{
		id:          42,
		url:         "ldaps://ldap.example.com:636",
		host:        "ldap.example.com:636",
		userBindDN:  "cn=alice,ou=people,dc=example,dc=org",
		groupBindDN: "cn=directory-service,ou=people,dc=example,dc=org",
	}
	groups := []string{"group-a"}
	warnings := []Warning{"group query warning"}
	userAttrs := map[string][]string{"mail": {"alice@example.com"}}

	result := attempt.result("cn=alice,ou=people,dc=example,dc=org", userAttrs, groups, warnings)
	groups[0] = "mutated"
	warnings[0] = "mutated"

	assert.Equal(t, []string{"group-a"}, result.Groups)
	assert.Equal(t, []Warning{"group query warning"}, result.Warnings)
	assert.Equal(t, "ldap.example.com:636", result.Host)
	assert.Equal(t, "ldaps://ldap.example.com:636", result.URL)
	assert.Equal(t, attempt.userBindDN, result.BindDN)
	assert.Equal(t, attempt.groupBindDN, result.GroupBindDN)
	assert.Equal(t, uint64(42), result.Generation)

	empty := attempt.result("", nil, []string{}, nil)
	require.NotNil(t, empty.Groups)
	assert.Empty(t, empty.Groups)
}

func TestIsRetryableLDAPError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "network", err: ldap.NewError(ldap.ErrorNetwork, errors.New("network unavailable")), want: true},
		{name: "unavailable", err: ldap.NewError(ldap.LDAPResultUnavailable, errors.New("server unavailable")), want: true},
		{name: "server down", err: ldap.NewError(ldap.LDAPResultServerDown, errors.New("server down")), want: true},
		{name: "busy", err: ldap.NewError(ldap.LDAPResultBusy, errors.New("busy")), want: true},
		{name: "invalid credentials", err: ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("bad password")), want: false},
		{name: "context canceled", err: context.Canceled, want: false},
		{name: "operation deadline", err: context.DeadlineExceeded, want: true},
		{name: "wrapped network", err: fmt.Errorf("search failed: %w", ldap.NewError(ldap.ErrorNetwork, io.EOF)), want: true},
		{name: "eof", err: io.EOF, want: true},
		{name: "plain failure", err: errors.New("invalid filter"), want: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, isRetryableLDAPError(tc.err))
		})
	}
}

func TestAuthenticateRetriesWithFreshGeneration(t *testing.T) {
	t.Parallel()
	const (
		userBase  = "ou=people,dc=example,dc=org"
		groupBase = "ou=groups,dc=example,dc=org"
		serviceDN = "cn=directory-service,ou=people,dc=example,dc=org"
		firstURL  = "ldaps://first.example.com:636"
		secondURL = "ldaps://second.example.com:636"
	)

	newSearchConn := func(userDN, groupDN string, groupErr error) *generationMockConn {
		conn := newGenerationMockConn()
		conn.searchFn = func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			switch req.BaseDN {
			case userBase:
				return &ldap.SearchResult{
					Entries: []*ldap.Entry{{DN: userDN}},
				}, nil
			case groupBase:
				if groupErr != nil {
					return nil, groupErr
				}
				return &ldap.SearchResult{
					Entries: []*ldap.Entry{{DN: groupDN}},
				}, nil
			default:
				return &ldap.SearchResult{}, nil
			}
		}
		return conn
	}

	first := newSearchConn(
		"cn=alice,ou=people,dc=first,dc=example",
		"cn=first-generation-group,ou=groups,dc=example,dc=org",
		fmt.Errorf("group lookup exceeded its request timeout: %w", context.DeadlineExceeded),
	)
	second := newSearchConn(
		"cn=alice,ou=people,dc=second,dc=example",
		"cn=second-generation-group,ou=groups,dc=example,dc=org",
		nil,
	)

	client, err := NewClient(context.Background(), &ClientConfig{
		URLs:         []string{firstURL, secondURL},
		DiscoverDN:   true,
		BindDN:       serviceDN,
		BindPassword: "password",
		UserDN:       userBase,
		GroupDN:      groupBase,
	})
	require.NoError(t, err)
	client.dialFunc = func(_ context.Context, rawURL string) (*ldapConnection, error) {
		switch rawURL {
		case firstURL:
			return &ldapConnection{conn: first, url: firstURL, host: "first.example.com:636"}, nil
		case secondURL:
			return &ldapConnection{conn: second, url: secondURL, host: "second.example.com:636"}, nil
		default:
			return nil, fmt.Errorf("unexpected URL %q", rawURL)
		}
	}

	result, err := client.Authenticate(context.Background(), "alice", "password", WithGroups())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	secondGroupDN := "cn=second-generation-group,ou=groups,dc=example,dc=org"
	assert.Equal(t, []string{secondGroupDN}, result.Groups)
	assert.NotContains(t, result.Groups, "cn=first-generation-group,ou=groups,dc=example,dc=org")
	assert.Equal(t, "second.example.com:636", result.Host)
	assert.Equal(t, secondURL, result.URL)
	assert.Equal(t, "cn=alice,ou=people,dc=second,dc=example", result.BindDN)
	assert.Equal(t, serviceDN, result.GroupBindDN)
	assert.NotZero(t, result.Generation)

	first.mu.Lock()
	assert.Equal(t, 1, first.closeCalls)
	assert.Contains(t, first.binds, "cn=alice,ou=people,dc=first,dc=example")
	first.mu.Unlock()

	second.mu.Lock()
	assert.Equal(t, 1, second.closeCalls)
	assert.Contains(t, second.binds, "cn=alice,ou=people,dc=second,dc=example")
	assert.NotContains(t, second.binds, "cn=alice,ou=people,dc=first,dc=example")
	second.mu.Unlock()
}

func TestAuthenticateGroupFailureReportsHostAndBindDN(t *testing.T) {
	t.Parallel()
	const (
		selectedURL = "ldaps://restarted.example.com:636"
		userBase    = "ou=people,dc=example,dc=org"
		groupBase   = "ou=groups,dc=example,dc=org"
		userDN      = "cn=alice,ou=people,dc=example,dc=org"
	)

	conn := newGenerationMockConn()
	conn.searchFn = func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		switch req.BaseDN {
		case userBase:
			return &ldap.SearchResult{Entries: []*ldap.Entry{{DN: userDN}}}, nil
		case groupBase:
			return nil, ldap.NewError(ldap.ErrorNetwork, errors.New("directory restarted during group query"))
		default:
			return &ldap.SearchResult{}, nil
		}
	}

	client, err := NewClient(context.Background(), &ClientConfig{
		URLs:       []string{selectedURL},
		DiscoverDN: true,
		UserDN:     userBase,
		GroupDN:    groupBase,
	})
	require.NoError(t, err)
	client.dialFunc = func(_ context.Context, rawURL string) (*ldapConnection, error) {
		return &ldapConnection{conn: conn, url: rawURL, host: "restarted.example.com:636"}, nil
	}

	result, err := client.Authenticate(context.Background(), "alice", "password", WithGroups())
	require.Error(t, err)
	assert.Nil(t, result)
	errText := err.Error()
	assert.Contains(t, errText, "unable to get user groups")
	assert.Contains(t, errText, "restarted.example.com:636")
	assert.Contains(t, errText, userDN)
	assert.Contains(t, errText, "directory restarted during group query")
}

func TestAuthenticateCancellationReportsCurrentBind(t *testing.T) {
	t.Parallel()
	const (
		selectedURL = "ldaps://directory.example.com:636"
		userBase    = "ou=people,dc=example,dc=org"
		groupBase   = "ou=groups,dc=example,dc=org"
		userDN      = "cn=alice,ou=people,dc=example,dc=org"
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	groupSearchStarted := make(chan struct{})
	conn := newGenerationMockConn()
	conn.searchFn = func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		switch req.BaseDN {
		case userBase:
			return &ldap.SearchResult{Entries: []*ldap.Entry{{DN: userDN}}}, nil
		case groupBase:
			close(groupSearchStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		default:
			return &ldap.SearchResult{}, nil
		}
	}

	client, err := NewClient(context.Background(), &ClientConfig{
		URLs:       []string{selectedURL},
		DiscoverDN: true,
		UserDN:     userBase,
		GroupDN:    groupBase,
	})
	require.NoError(t, err)
	client.dialFunc = func(_ context.Context, rawURL string) (*ldapConnection, error) {
		return &ldapConnection{conn: conn, url: rawURL, host: "directory.example.com:636"}, nil
	}

	type authOutcome struct {
		result *AuthResult
		err    error
	}
	outcome := make(chan authOutcome, 1)
	go func() {
		result, err := client.Authenticate(ctx, "alice", "password", WithGroups())
		outcome <- authOutcome{result: result, err: err}
	}()

	<-groupSearchStarted
	cancel()

	select {
	case got := <-outcome:
		require.Error(t, got.err)
		assert.Nil(t, got.result)
		assert.ErrorIs(t, got.err, context.Canceled)
		assert.Contains(t, got.err.Error(), "unable to get user groups")
		assert.Contains(t, got.err.Error(), "directory.example.com:636")
		assert.Contains(t, got.err.Error(), userDN)
	case <-time.After(2 * time.Second):
		t.Fatal("authenticate did not return after cancellation")
	}
}
