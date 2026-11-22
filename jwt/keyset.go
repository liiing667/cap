// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/go-cleanhttp"
	"golang.org/x/oauth2"
)

// defaultKeySetStaleWindow bounds how long a complete previous key set
// generation may be used after a refresh failure. The window is intentionally
// finite: a failed refresh must not make a revoked key valid forever.
const defaultKeySetStaleWindow = 5 * time.Minute

// KeySet represents a set of keys that can be used to verify the signatures of JWTs.
// A KeySet is expected to be backed by a set of local or remote keys.
type KeySet interface {
	// VerifySignature parses the given JWT, verifies its signature, and returns the claims in its payload.
	// The given JWT must be of the JWS compact serialization form.
	VerifySignature(ctx context.Context, token string) (claims map[string]interface{}, err error)
}

// ReportingKeySet is an optional interface implemented by key sets that can
// report the key set generation and source used for a verification attempt.
// Validator uses this interface when it is available.
type ReportingKeySet interface {
	VerifySignatureWithReport(ctx context.Context, token string) (claims map[string]interface{}, report KeySetReport, err error)
}

// KeySetRefresher is an optional interface implemented by key sets that can
// explicitly refresh their key material.
type KeySetRefresher interface {
	Refresh(ctx context.Context) error
}

// KeySetMetadata is an optional interface implemented by key sets that can
// identify their source and current generation.
type KeySetMetadata interface {
	KeySetSource() string
	KeySetGeneration() uint64
}

type keySetSourceProvider interface {
	KeySetSource() string
}

type keySetSourceNamer interface {
	Source() string
}

type keySetGenerationProvider interface {
	KeySetGeneration() uint64
}

type keySetGenerationNamer interface {
	Generation() uint64
}

// KeySetSource returns the source label for keySet. Custom key sets can
// implement KeySetMetadata or a Source() string method to provide a stable
// label. Otherwise the concrete type is used so a report still identifies the
// selected source.
func KeySetSource(keySet KeySet) string {
	if keySet == nil {
		return ""
	}
	if v, ok := keySet.(keySetSourceProvider); ok {
		return v.KeySetSource()
	}
	if v, ok := keySet.(keySetSourceNamer); ok {
		return v.Source()
	}
	return fmt.Sprintf("%T", keySet)
}

// KeySetGeneration returns the current generation published by keySet. Key
// sets that do not expose generations are treated as generation one.
func KeySetGeneration(keySet KeySet) uint64 {
	if keySet == nil {
		return 0
	}
	if v, ok := keySet.(keySetGenerationProvider); ok {
		return v.KeySetGeneration()
	}
	if v, ok := keySet.(keySetGenerationNamer); ok {
		return v.Generation()
	}
	return 1
}

// KeySetOption configures a remote key set.
type KeySetOption func(*jsonWebKeySet)

// WithKeySetRefreshInterval controls how long a successfully fetched key set
// remains fresh. A zero or negative interval refreshes before every
// verification, which lets a revocation take effect on the next use.
func WithKeySetRefreshInterval(interval time.Duration) KeySetOption {
	return func(ks *jsonWebKeySet) {
		ks.refreshInterval = interval
	}
}

// WithKeySetStaleWindow bounds how long the complete previous generation may
// be used while refreshes are failing. A negative window disables stale
// fallback and fails closed when a refresh is required.
func WithKeySetStaleWindow(window time.Duration) KeySetOption {
	return func(ks *jsonWebKeySet) {
		ks.staleWindow = window
	}
}

// WithKeySetOldKeyWindow is an alias for WithKeySetStaleWindow.
func WithKeySetOldKeyWindow(window time.Duration) KeySetOption {
	return WithKeySetStaleWindow(window)
}

// WithKeySetClock overrides the clock used for refresh and stale-window
// decisions. It is primarily useful in tests.
func WithKeySetClock(now func() time.Time) KeySetOption {
	return func(ks *jsonWebKeySet) {
		if now != nil {
			ks.now = now
		}
	}
}

// jsonWebKeySet verifies JWT signatures using keys obtained from a JWKS URL.
//
// Keys are published as complete, immutable generations. A successful refresh
// replaces the whole key set and increments the generation atomically. A
// failed refresh leaves the previous complete generation in place for a
// bounded stale window, or fails closed when that window has elapsed. A
// verification report is always built from one snapshot, so a token cannot be
// verified against one generation and reported against another.
type jsonWebKeySet struct {
	// remoteJWKS is retained for callers that construct a key set around an
	// existing oidc.KeySet. New key sets use the generation-aware fields below.
	remoteJWKS oidc.KeySet

	issuer  string
	jwksURL string
	source  string
	client  *http.Client

	mu          sync.RWMutex
	keys        []jose.JSONWebKey
	generation  uint64
	lastRefresh time.Time
	refreshErr  error

	refreshMu       sync.Mutex
	refreshInterval time.Duration
	staleWindow     time.Duration
	now             func() time.Time
}

// staticKeySet verifies JWT signatures using local public keys.
type staticKeySet struct {
	publicKeys []crypto.PublicKey
}

// NewOIDCDiscoveryKeySet returns a KeySet that verifies JWT signatures using keys from the
// JSON Web Key Set (JWKS) published in the discovery document at the given issuer URL.
// The client used to obtain the remote keys will verify server certificates using the root
// certificates provided by issuerCAPEM. If issuerCAPEM is not provided, system certificates
// are used.
func NewOIDCDiscoveryKeySet(ctx context.Context, issuer string, issuerCAPEM string) (KeySet, error) {
	return NewOIDCDiscoveryKeySetWithOptions(ctx, issuer, issuerCAPEM)
}

// NewOIDCDiscoveryKeySetWithOptions is NewOIDCDiscoveryKeySet with key set
// refresh and stale-window options.
func NewOIDCDiscoveryKeySetWithOptions(ctx context.Context, issuer string, issuerCAPEM string, opts ...KeySetOption) (KeySet, error) {
	if issuer == "" {
		return nil, errors.New("issuer must not be empty")
	}

	// Configure an http client with the given certificates
	caCtx, err := createCAContext(ctx, issuerCAPEM)
	if err != nil {
		return nil, err
	}
	if caCtx == nil {
		caCtx = context.Background()
	}
	client := httpClientFromContext(caCtx)

	// Create and send the http request for the OIDC discovery document
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(caCtx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body and status code
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	// Unmarshal the response body to obtain the issuer and JWKS URL
	var p struct {
		Issuer  string `json:"issuer"`
		JWKSURL string `json:"jwks_uri"`
	}
	if err := unmarshalResp(resp, body, &p); err != nil {
		return nil, fmt.Errorf("failed to decode OIDC discovery document: %w", err)
	}

	// Ensure that the returned issuer matches what was given by issuer
	if p.Issuer != issuer {
		return nil, fmt.Errorf("issuer did not match the returned issuer, expected %q got %q",
			issuer, p.Issuer)
	}
	if p.JWKSURL == "" {
		return nil, errors.New("OIDC discovery document is missing jwks_uri")
	}

	keySet := newJSONWebKeySet(p.JWKSURL, p.JWKSURL, p.Issuer, client, opts...)
	// Keep the wrapped remote key set for compatibility with callers that
	// inspect the concrete key set, but use the generation-aware cache above.
	keySet.remoteJWKS = oidc.NewRemoteKeySet(caCtx, p.JWKSURL)
	return keySet, nil
}

// NewJSONWebKeySet returns a KeySet that verifies JWT signatures using keys from the JSON Web
// Key Set (JWKS) at the given jwksURL. The client used to obtain the remote JWKS will verify
// server certificates using the root certificates provided by jwksCAPEM. If jwksCAPEM is not
// provided, system certificates are used.
func NewJSONWebKeySet(ctx context.Context, jwksURL string, jwksCAPEM string) (KeySet, error) {
	return NewJSONWebKeySetWithOptions(ctx, jwksURL, jwksCAPEM)
}

// NewJSONWebKeySetWithOptions is NewJSONWebKeySet with key set refresh and
// stale-window options.
func NewJSONWebKeySetWithOptions(ctx context.Context, jwksURL string, jwksCAPEM string, opts ...KeySetOption) (KeySet, error) {
	if jwksURL == "" {
		return nil, errors.New("jwksURL must not be empty")
	}

	caCtx, err := createCAContext(ctx, jwksCAPEM)
	if err != nil {
		return nil, err
	}

	keySet := newJSONWebKeySet(jwksURL, jwksURL, "", httpClientFromContext(caCtx), opts...)
	// Keep the wrapped remote key set for compatibility with callers that
	// inspect the concrete key set, but use the generation-aware cache above.
	keySet.remoteJWKS = oidc.NewRemoteKeySet(caCtx, jwksURL)
	return keySet, nil
}

func newJSONWebKeySet(jwksURL, source, issuer string, client *http.Client, opts ...KeySetOption) *jsonWebKeySet {
	if client == nil {
		client = http.DefaultClient
	}
	ks := &jsonWebKeySet{
		issuer:          issuer,
		jwksURL:         jwksURL,
		source:          source,
		client:          client,
		refreshInterval: 0,
		staleWindow:     defaultKeySetStaleWindow,
		now:             time.Now,
	}
	if ks.source == "" {
		ks.source = jwksURL
	}
	for _, opt := range opts {
		if opt != nil {
			opt(ks)
		}
	}
	return ks
}

// Source returns the JWKS URL or legacy source label for this key set.
func (ks *jsonWebKeySet) Source() string {
	if ks == nil {
		return ""
	}
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	if ks.source != "" {
		return ks.source
	}
	if ks.jwksURL != "" {
		return ks.jwksURL
	}
	if ks.remoteJWKS != nil {
		return fmt.Sprintf("%T", ks.remoteJWKS)
	}
	return "jsonWebKeySet"
}

// KeySetSource returns the source label for this key set.
func (ks *jsonWebKeySet) KeySetSource() string { return ks.Source() }

// Generation returns the currently published key set generation.
func (ks *jsonWebKeySet) Generation() uint64 {
	if ks == nil {
		return 0
	}
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	if ks.remoteJWKS != nil && ks.jwksURL == "" {
		if ks.generation == 0 {
			return 1
		}
	}
	return ks.generation
}

// KeySetGeneration returns the currently published key set generation.
func (ks *jsonWebKeySet) KeySetGeneration() uint64 { return ks.Generation() }

// Refresh fetches a complete new key set generation. The old generation
// remains visible until the new generation has been parsed successfully.
func (ks *jsonWebKeySet) Refresh(ctx context.Context) error {
	if ks == nil {
		return errors.New("key set is nil")
	}

	ks.refreshMu.Lock()
	defer ks.refreshMu.Unlock()

	keys, err := ks.fetchKeys(ctx)
	if err != nil {
		ks.mu.Lock()
		ks.refreshErr = err
		ks.mu.Unlock()
		return err
	}

	now := ks.clock()
	ks.mu.Lock()
	if sameJSONWebKeys(ks.keys, keys) {
		ks.lastRefresh = now
		ks.refreshErr = nil
		ks.mu.Unlock()
		return nil
	}
	ks.keys = keys
	ks.generation++
	ks.lastRefresh = now
	ks.refreshErr = nil
	ks.mu.Unlock()
	return nil
}

// VerifySignature parses the given JWT, verifies its signature using JWKS keys, and returns
// the claims in its payload. The given JWT must be of the JWS compact serialization form.
func (ks *jsonWebKeySet) VerifySignature(ctx context.Context, token string) (map[string]interface{}, error) {
	claims, _, err := ks.VerifySignatureWithReport(ctx, token)
	return claims, err
}

// VerifySignatureWithReport verifies the token and reports the key set source
// and generation used for the attempt.
func (ks *jsonWebKeySet) VerifySignatureWithReport(ctx context.Context, token string) (claims map[string]interface{}, report KeySetReport, err error) {
	defer func() {
		if err != nil {
			report.Err = err
		}
		report.syncAliases()
	}()
	if ks == nil {
		report.FailureStage = StageKeySetRefresh
		return nil, report, &KeySetError{
			Stage: StageKeySetRefresh,
			Err:   errors.New("key set is nil"),
		}
	}
	report.Issuer = ks.issuer
	if issuer := unverifiedIssuer(token); issuer != "" {
		report.Issuer = issuer
	}
	report.KeySetSource = ks.Source()
	if kid, alg := unverifiedHeader(token); kid != "" || alg != "" {
		report.Kid = kid
		report.Alg = alg
	}

	jws, err := jose.ParseSigned(token, joseSignatureAlgorithms())
	if err != nil {
		report.FailureStage = StageParseToken
		return nil, report, &KeySetError{
			Stage:  StageParseToken,
			Source: report.KeySetSource,
			Err:    err,
		}
	}
	if len(jws.Signatures) == 0 {
		report.FailureStage = StageSignature
		return nil, report, &KeySetError{
			Stage:  StageSignature,
			Source: report.KeySetSource,
			Err:    errors.New("token must be signed"),
		}
	}
	if len(jws.Signatures) > 1 {
		report.FailureStage = StageSignature
		return nil, report, &KeySetError{
			Stage:  StageSignature,
			Source: report.KeySetSource,
			Err:    errors.New("token with multiple signatures not supported"),
		}
	}

	if kid := jws.Signatures[0].Header.KeyID; kid != "" {
		report.Kid = kid
	}
	if alg := Alg(jws.Signatures[0].Header.Algorithm); alg != "" {
		report.Alg = alg
	}
	report.KeySetGeneration = ks.Generation()

	// Legacy path for a key set wrapping an existing oidc.KeySet. This path
	// preserves the old behavior for callers that construct jsonWebKeySet
	// directly.
	if ks.remoteJWKS != nil && ks.jwksURL == "" {
		payload, err := ks.remoteJWKS.VerifySignature(ctx, token)
		if err != nil {
			report.FailureStage = StageSignature
			return nil, report, &KeySetError{
				Stage:      StageSignature,
				Source:     report.KeySetSource,
				Generation: report.KeySetGeneration,
				Kid:        report.Kid,
				Err:        err,
			}
		}
		claims := map[string]interface{}{}
		if err := json.Unmarshal(payload, &claims); err != nil {
			report.FailureStage = StageClaims
			return nil, report, &KeySetError{
				Stage:      StageClaims,
				Source:     report.KeySetSource,
				Generation: report.KeySetGeneration,
				Kid:        report.Kid,
				Err:        err,
			}
		}
		if issuer, ok := claims["iss"].(string); ok {
			report.Issuer = issuer
			report.IssuerVerified = true
		}
		report.Verified = true
		return claims, report, nil
	}

	keys, generation, refreshErr, err := ks.keysForToken(ctx, report.Kid, report.Alg)
	report.KeySetGeneration = generation
	if err != nil {
		report.FailureStage = StageKeySetRefresh
		report.RefreshError = err.Error()
		return nil, report, &KeySetError{
			Stage:      StageKeySetRefresh,
			Source:     report.KeySetSource,
			Generation: generation,
			Kid:        report.Kid,
			Err:        err,
		}
	}
	if refreshErr != nil {
		report.RefreshError = refreshErr.Error()
	}

	var lastErr error
	var matched bool
	for _, key := range keys {
		if !keyMatchesSigning(key, report.Kid, report.Alg) {
			continue
		}
		matched = true
		payload, err := jws.Verify(key)
		if err != nil {
			lastErr = err
			continue
		}

		claims := map[string]interface{}{}
		if err := json.Unmarshal(payload, &claims); err != nil {
			report.FailureStage = StageClaims
			return nil, report, &KeySetError{
				Stage:      StageClaims,
				Source:     report.KeySetSource,
				Generation: generation,
				Kid:        report.Kid,
				Err:        err,
			}
		}
		if issuer, ok := claims["iss"].(string); ok {
			report.Issuer = issuer
			report.IssuerVerified = true
		}

		report.Verified = true
		report.FailureStage = ""
		return claims, report, nil
	}

	if lastErr == nil {
		if !matched {
			lastErr = fmt.Errorf("no key found for kid %q", report.Kid)
		} else {
			lastErr = errors.New("no known key successfully validated the token signature")
		}
	}
	stage := StageSignature
	if refreshErr != nil {
		stage = StageKeySetRefresh
		lastErr = fmt.Errorf("%v; key set refresh failed: %w", lastErr, refreshErr)
	}
	report.FailureStage = stage
	return nil, report, &KeySetError{
		Stage:      stage,
		Source:     report.KeySetSource,
		Generation: generation,
		Kid:        report.Kid,
		Err:        lastErr,
	}
}

// keysForToken returns one complete key set snapshot for a verification
// attempt. It refreshes when the configured interval has elapsed. On refresh
// failure it either returns the complete previous generation while the stale
// window permits it, or returns an error without publishing a partial set.
func (ks *jsonWebKeySet) keysForToken(ctx context.Context, kid string, alg Alg) ([]jose.JSONWebKey, uint64, error, error) {
	now := ks.clock()
	ks.mu.RLock()
	initialGeneration := ks.generation
	initialLastRefresh := ks.lastRefresh
	if ks.cacheFreshLocked(now) {
		keys := cloneJSONWebKeys(ks.keys)
		generation := ks.generation
		ks.mu.RUnlock()
		return keys, generation, nil, nil
	}
	ks.mu.RUnlock()

	// Only one goroutine may fetch or publish a generation at a time. Waiting
	// goroutines observe the generation published by the winner instead of
	// starting another refresh and moving the reported generation backwards.
	ks.refreshMu.Lock()
	defer ks.refreshMu.Unlock()

	now = ks.clock()
	ks.mu.RLock()
	if (ks.generation != initialGeneration || ks.lastRefresh.After(initialLastRefresh)) && len(ks.keys) > 0 {
		keys := cloneJSONWebKeys(ks.keys)
		generation := ks.generation
		refreshErr := ks.refreshErr
		ks.mu.RUnlock()
		return keys, generation, refreshErr, nil
	}
	oldKeys := cloneJSONWebKeys(ks.keys)
	oldGeneration := ks.generation
	oldLastRefresh := ks.lastRefresh
	ks.mu.RUnlock()

	newKeys, fetchErr := ks.fetchKeys(ctx)
	if fetchErr != nil {
		ks.mu.Lock()
		ks.refreshErr = fetchErr
		ks.mu.Unlock()

		if len(oldKeys) > 0 && ks.staleWindow >= 0 && (oldLastRefresh.IsZero() || now.Sub(oldLastRefresh) <= ks.staleWindow) {
			return oldKeys, oldGeneration, fetchErr, nil
		}
		return nil, oldGeneration, fetchErr, fetchErr
	}

	ks.mu.Lock()
	if sameJSONWebKeys(ks.keys, newKeys) {
		ks.lastRefresh = now
		ks.refreshErr = nil
		generation := ks.generation
		keys := cloneJSONWebKeys(ks.keys)
		ks.mu.Unlock()
		return keys, generation, nil, nil
	}
	ks.keys = newKeys
	ks.generation = oldGeneration + 1
	ks.lastRefresh = now
	ks.refreshErr = nil
	generation := ks.generation
	ks.mu.Unlock()

	return cloneJSONWebKeys(newKeys), generation, nil, nil
}

func (ks *jsonWebKeySet) cacheFreshLocked(now time.Time) bool {
	if len(ks.keys) == 0 {
		return false
	}
	if ks.refreshInterval <= 0 {
		return false
	}
	return now.Sub(ks.lastRefresh) < ks.refreshInterval
}

func (ks *jsonWebKeySet) clock() time.Time {
	if ks.now != nil {
		return ks.now()
	}
	return time.Now()
}

func (ks *jsonWebKeySet) fetchKeys(ctx context.Context) ([]jose.JSONWebKey, error) {
	if ks == nil {
		return nil, errors.New("key set is nil")
	}
	if ks.jwksURL == "" {
		return nil, errors.New("key set has no JWKS URL")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ks.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create JWKS request: %w", err)
	}
	req.Header.Set("Cache-Control", "no-cache")
	client := ks.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read JWKS response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS: %s: %s", resp.Status, truncateString(string(body), 512))
	}

	var set jose.JSONWebKeySet
	if err := unmarshalResp(resp, body, &set); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("JWKS contained no keys")
	}
	keys := make([]jose.JSONWebKey, 0, len(set.Keys))
	for _, key := range set.Keys {
		if key.Key == nil && len(key.Certificates) > 0 && key.Certificates[0] != nil {
			key.Key = key.Certificates[0].PublicKey
		}
		if key.Key != nil && (key.Use == "" || key.Use == "sig") {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contained no usable keys")
	}
	return keys, nil
}

func keyMatchesSigning(key jose.JSONWebKey, kid string, alg Alg) bool {
	if key.Use != "" && key.Use != "sig" {
		return false
	}
	if kid != "" && key.KeyID != kid {
		return false
	}
	if key.Algorithm != "" && alg != "" && key.Algorithm != string(alg) {
		return false
	}
	return true
}

func cloneJSONWebKeys(keys []jose.JSONWebKey) []jose.JSONWebKey {
	if len(keys) == 0 {
		return nil
	}
	out := make([]jose.JSONWebKey, len(keys))
	copy(out, keys)
	return out
}

func sameJSONWebKeys(a, b []jose.JSONWebKey) bool {
	return reflect.DeepEqual(a, b)
}

func truncateString(s string, max int) string {
	if max < 0 || len(s) <= max {
		return s
	}
	return s[:max]
}

// RefreshKeySet refreshes keySet when it implements KeySetRefresher.
func RefreshKeySet(ctx context.Context, keySet KeySet) error {
	refresher, ok := keySet.(KeySetRefresher)
	if !ok {
		return errors.New("key set does not support refresh")
	}
	return refresher.Refresh(ctx)
}

// NewStaticKeySet returns a KeySet that verifies JWT signatures using the given publicKeys.
func NewStaticKeySet(publicKeys []crypto.PublicKey) (KeySet, error) {
	if len(publicKeys) == 0 {
		return nil, errors.New("publicKeys must not be empty")
	}

	return &staticKeySet{
		publicKeys: publicKeys,
	}, nil
}

// Source returns the static key set source label.
func (ks *staticKeySet) Source() string { return "static" }

// KeySetSource returns the static key set source label.
func (ks *staticKeySet) KeySetSource() string { return "static" }

// Generation returns the static key set generation.
func (ks *staticKeySet) Generation() uint64 { return 1 }

// KeySetGeneration returns the static key set generation.
func (ks *staticKeySet) KeySetGeneration() uint64 { return 1 }

// VerifySignature parses the given JWT, verifies its signature using local public keys, and
// returns the claims in its payload. The given JWT must be of the JWS compact serialization form.
func (ks *staticKeySet) VerifySignature(ctx context.Context, token string) (map[string]interface{}, error) {
	claims, _, err := ks.VerifySignatureWithReport(ctx, token)
	return claims, err
}

// VerifySignatureWithReport verifies the token with the static key set and
// reports the generation and source used.
func (ks *staticKeySet) VerifySignatureWithReport(_ context.Context, token string) (claims map[string]interface{}, report KeySetReport, err error) {
	report = KeySetReport{
		KeySetSource:     ks.Source(),
		KeySetGeneration: ks.Generation(),
	}
	if issuer := unverifiedIssuer(token); issuer != "" {
		report.Issuer = issuer
	}
	if kid, alg := unverifiedHeader(token); kid != "" || alg != "" {
		report.Kid = kid
		report.Alg = alg
	}
	defer func() {
		if err != nil {
			report.Err = err
		}
		report.syncAliases()
	}()

	parsedJWT, err := jwt.ParseSigned(token, joseSignatureAlgorithms())
	if err != nil {
		report.FailureStage = StageParseToken
		return nil, report, &KeySetError{
			Stage:      StageParseToken,
			Source:     report.KeySetSource,
			Generation: report.KeySetGeneration,
			Err:        err,
		}
	}
	if len(parsedJWT.Headers) > 0 {
		if kid := parsedJWT.Headers[0].KeyID; kid != "" {
			report.Kid = kid
		}
		if alg := Alg(parsedJWT.Headers[0].Algorithm); alg != "" {
			report.Alg = alg
		}
	}

	var allClaims map[string]interface{}
	for _, key := range ks.publicKeys {
		claims := map[string]interface{}{}
		if err := parsedJWT.Claims(key, &claims); err == nil {
			allClaims = claims
			break
		}
	}
	if allClaims == nil {
		report.FailureStage = StageSignature
		return nil, report, &KeySetError{
			Stage:      StageSignature,
			Source:     report.KeySetSource,
			Generation: report.KeySetGeneration,
			Kid:        report.Kid,
			Err:        errors.New("no known key successfully validated the token signature"),
		}
	}

	if issuer, ok := allClaims["iss"].(string); ok {
		report.Issuer = issuer
		report.IssuerVerified = true
	}
	report.Verified = true
	return allClaims, report, nil
}

// ParsePublicKeyPEM is used to parse RSA and ECDSA public keys from PEMs. The given
// data must be of PEM-encoded x509 certificate or PKIX public key forms. It returns an
// *rsa.PublicKey or *ecdsa.PublicKey.
func ParsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		var rawKey interface{}
		var err error
		if rawKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				rawKey = cert.PublicKey
			} else {
				return nil, err
			}
		}

		if rsaPublicKey, ok := rawKey.(*rsa.PublicKey); ok {
			return rsaPublicKey, nil
		}
		if ecPublicKey, ok := rawKey.(*ecdsa.PublicKey); ok {
			return ecPublicKey, nil
		}
	}

	return nil, errors.New("data does not contain any valid RSA or ECDSA public keys")
}

// createCAContext returns a context with a custom TLS client that's configured with the root
// certificates from caPEM. If no certificates are configured, the original context is returned.
func createCAContext(ctx context.Context, caPEM string) (context.Context, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if caPEM == "" {
		return ctx, nil
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM([]byte(caPEM)); !ok {
		return nil, errors.New("could not parse CA PEM value successfully")
	}

	tr := cleanhttp.DefaultPooledTransport()
	tr.TLSClientConfig = &tls.Config{
		RootCAs: certPool,
	}
	tc := &http.Client{
		Transport: tr,
	}

	caCtx := context.WithValue(ctx, oauth2.HTTPClient, tc)

	return caCtx, nil
}

func httpClientFromContext(ctx context.Context) *http.Client {
	if ctx == nil {
		return http.DefaultClient
	}
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && c != nil {
		return c
	}
	return http.DefaultClient
}

// unmarshalResp JSON unmarshals the given body into the value pointed to by v.
// If it is unable to JSON unmarshal body into v, then it returns an appropriate
// error based on the Content-Type header of r.
func unmarshalResp(r *http.Response, body []byte, v interface{}) error {
	err := json.Unmarshal(body, &v)
	if err == nil {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct) // ParseMediaType normalizes media type to lower case.
	if parseErr == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}
