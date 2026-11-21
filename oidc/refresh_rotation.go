// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	// DefaultRefreshLeaseDuration bounds how long one process may own a
	// refresh attempt before a restarted process treats the attempt as
	// uncertain.
	DefaultRefreshLeaseDuration = 30 * time.Second

	// DefaultRefreshIdleTimeout is the default idle lifetime for a newly
	// created refresh session.
	DefaultRefreshIdleTimeout = 30 * time.Minute

	// DefaultRefreshAbsoluteTimeout is the default hard lifetime for a newly
	// created refresh session. Rotations never extend this deadline.
	DefaultRefreshAbsoluteTimeout = 24 * time.Hour

	// DefaultRefreshReplayGrace is the period in which a concurrent request
	// which still presents the previous refresh token receives a conflict
	// rather than revoking the whole session.
	DefaultRefreshReplayGrace = 30 * time.Second

	refreshStoreTimeout = 10 * time.Second
)

// RefreshSessionState is the durable state of one refresh-token family.
type RefreshSessionState string

const (
	// RefreshSessionReady permits an exchange using the current refresh token.
	RefreshSessionReady RefreshSessionState = "ready"

	// RefreshSessionRotating reserves the session for one in-flight exchange.
	RefreshSessionRotating RefreshSessionState = "rotating"

	// RefreshSessionUncertain means an exchange may have been committed by the
	// provider, but the result was not durably recorded. The previous refresh
	// token must never be retried from this state.
	RefreshSessionUncertain RefreshSessionState = "uncertain"

	// RefreshSessionRevoked permanently invalidates the refresh-token family.
	RefreshSessionRevoked RefreshSessionState = "revoked"
)

// RefreshTokenDigest is the SHA-256 digest of a raw refresh token. Stores
// should persist digests, never the raw refresh token.
type RefreshTokenDigest [sha256.Size]byte

// DigestRefreshToken returns the digest used to compare and persist refresh
// tokens without retaining their raw values.
func DigestRefreshToken(token RefreshToken) RefreshTokenDigest {
	return sha256.Sum256([]byte(token))
}

// String returns the lower-case hexadecimal encoding of the digest.
func (d RefreshTokenDigest) String() string {
	return hex.EncodeToString(d[:])
}

// IsZero reports whether the digest is unset.
func (d RefreshTokenDigest) IsZero() bool {
	var zero RefreshTokenDigest
	return subtle.ConstantTimeCompare(d[:], zero[:]) == 1
}

// Equal compares two digests in constant time.
func (d RefreshTokenDigest) Equal(other RefreshTokenDigest) bool {
	return subtle.ConstantTimeCompare(d[:], other[:]) == 1
}

// MarshalText implements encoding.TextMarshaler for durable stores.
func (d RefreshTokenDigest) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler for durable stores.
func (d *RefreshTokenDigest) UnmarshalText(text []byte) error {
	if d == nil {
		return fmt.Errorf("refresh token digest is nil: %w", ErrNilParameter)
	}
	if len(text) != hex.EncodedLen(sha256.Size) {
		return fmt.Errorf("refresh token digest must be %d hexadecimal characters: %w", hex.EncodedLen(sha256.Size), ErrInvalidParameter)
	}
	decoded, err := hex.DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("refresh token digest is invalid: %w", ErrInvalidParameter)
	}
	copy(d[:], decoded)
	return nil
}

// RefreshAttemptID identifies one reservation of a refresh session.
type RefreshAttemptID string

// RefreshSession is one durable refresh-token family. A successful rotation
// advances Generation exactly once and retains every spent token digest so a
// process restart cannot make an old token current again.
type RefreshSession struct {
	ID         string               `json:"id"`
	Generation uint64               `json:"generation"`
	Revision   uint64               `json:"revision"`
	State      RefreshSessionState  `json:"state"`
	Current    RefreshTokenDigest   `json:"current"`
	Spent      []RefreshTokenDigest `json:"spent,omitempty"`

	Attempt        RefreshAttemptID `json:"attempt,omitempty"`
	LeaseExpiresAt time.Time        `json:"lease_expires_at,omitempty"`

	CreatedAt         time.Time `json:"created_at"`
	IdleExpiresAt     time.Time `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time `json:"absolute_expires_at"`

	// PreviousValidUntil is set after a rotation. Concurrent requests which
	// still present the previous token receive a conflict during this period
	// instead of revoking a session won by the other request.
	PreviousValidUntil time.Time `json:"previous_valid_until,omitempty"`
}

// Clone returns a deep copy of the session.
func (s RefreshSession) Clone() RefreshSession {
	s.Spent = append([]RefreshTokenDigest(nil), s.Spent...)
	return s
}

// Validate checks the invariants which a durable store must preserve.
func (s RefreshSession) Validate(now time.Time) error {
	switch {
	case s.ID == "":
		return fmt.Errorf("refresh session id is empty: %w", ErrInvalidParameter)
	case s.Current.IsZero():
		return fmt.Errorf("refresh session current token digest is empty: %w", ErrInvalidParameter)
	case s.CreatedAt.IsZero():
		return fmt.Errorf("refresh session creation time is empty: %w", ErrInvalidParameter)
	case s.AbsoluteExpiresAt.IsZero() || !s.AbsoluteExpiresAt.After(s.CreatedAt):
		return fmt.Errorf("refresh session absolute expiry is invalid: %w", ErrInvalidParameter)
	case s.IdleExpiresAt.IsZero() || s.IdleExpiresAt.After(s.AbsoluteExpiresAt):
		return fmt.Errorf("refresh session idle expiry is invalid: %w", ErrInvalidParameter)
	}

	switch s.State {
	case RefreshSessionReady:
	case RefreshSessionRotating:
		if s.Attempt == "" {
			return fmt.Errorf("rotating refresh session has no attempt id: %w", ErrInvalidParameter)
		}
	case RefreshSessionUncertain, RefreshSessionRevoked:
	default:
		return fmt.Errorf("refresh session state %q is invalid: %w", s.State, ErrInvalidParameter)
	}

	if !now.IsZero() && !now.Before(s.AbsoluteExpiresAt) && s.State != RefreshSessionRevoked {
		return fmt.Errorf("refresh session is expired: %w", ErrRefreshExpired)
	}
	return nil
}

func (s RefreshSession) hasSpent(digest RefreshTokenDigest) bool {
	for _, spent := range s.Spent {
		if spent.Equal(digest) {
			return true
		}
	}
	return false
}

// NewRefreshSession creates a ready session for a refresh token. Idle lifetime
// starts at now and is capped by the absolute lifetime, which is immutable for
// the lifetime of the session.
func NewRefreshSession(id string, token RefreshToken, now time.Time, idleTimeout, absoluteTimeout time.Duration) (RefreshSession, error) {
	switch {
	case id == "":
		return RefreshSession{}, fmt.Errorf("refresh session id is empty: %w", ErrInvalidParameter)
	case token == "":
		return RefreshSession{}, ErrMissingRefreshToken
	case now.IsZero():
		return RefreshSession{}, fmt.Errorf("refresh session start time is empty: %w", ErrInvalidParameter)
	case idleTimeout <= 0:
		return RefreshSession{}, fmt.Errorf("refresh session idle timeout must be positive: %w", ErrInvalidParameter)
	case absoluteTimeout <= 0:
		return RefreshSession{}, fmt.Errorf("refresh session absolute timeout must be positive: %w", ErrInvalidParameter)
	}

	absoluteExpiresAt := now.Add(absoluteTimeout)
	idleExpiresAt := now.Add(idleTimeout)
	if idleExpiresAt.After(absoluteExpiresAt) {
		idleExpiresAt = absoluteExpiresAt
	}
	return RefreshSession{
		ID:                id,
		State:             RefreshSessionReady,
		Current:           DigestRefreshToken(token),
		CreatedAt:         now,
		IdleExpiresAt:     idleExpiresAt,
		AbsoluteExpiresAt: absoluteExpiresAt,
	}, nil
}

// RefreshStore persists refresh-session generations. Implementations must make
// Create and CompareAndSwap atomic and durable across process restarts.
type RefreshStore interface {
	// Create stores a new session. It must return an error when the ID already
	// exists.
	Create(ctx context.Context, session RefreshSession) error

	// Load returns a copy of the session.
	Load(ctx context.Context, id string) (RefreshSession, error)

	// CompareAndSwap atomically replaces expected with next only when the
	// stored record still matches expected.Revision and its generation,
	// state, attempt, and current digest. It must return ErrRefreshConflict
	// when they do not match.
	CompareAndSwap(ctx context.Context, expected, next RefreshSession) error
}

// RefreshSessionStore is an alias for RefreshStore.
type RefreshSessionStore = RefreshStore

// MemoryRefreshStore is a process-local RefreshStore. It is useful for tests
// and for applications which already persist sessions elsewhere. It does not
// survive a process restart.
type MemoryRefreshStore struct {
	mu       sync.RWMutex
	sessions map[string]RefreshSession
}

// NewMemoryRefreshStore creates an empty in-memory refresh store.
func NewMemoryRefreshStore() *MemoryRefreshStore {
	return &MemoryRefreshStore{sessions: make(map[string]RefreshSession)}
}

// Create implements RefreshStore.
func (s *MemoryRefreshStore) Create(ctx context.Context, session RefreshSession) error {
	if s == nil {
		return ErrNilParameter
	}
	if err := refreshContextError(ctx); err != nil {
		return err
	}
	if err := session.Validate(time.Time{}); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = make(map[string]RefreshSession)
	}
	if _, ok := s.sessions[session.ID]; ok {
		return fmt.Errorf("refresh session %q already exists: %w", session.ID, ErrRefreshConflict)
	}
	s.sessions[session.ID] = session.Clone()
	return nil
}

// Load implements RefreshStore.
func (s *MemoryRefreshStore) Load(ctx context.Context, id string) (RefreshSession, error) {
	if s == nil {
		return RefreshSession{}, ErrNilParameter
	}
	if err := refreshContextError(ctx); err != nil {
		return RefreshSession{}, err
	}
	if id == "" {
		return RefreshSession{}, fmt.Errorf("refresh session id is empty: %w", ErrInvalidParameter)
	}

	s.mu.RLock()
	session, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return RefreshSession{}, fmt.Errorf("refresh session %q: %w", id, ErrRefreshSessionNotFound)
	}
	return session.Clone(), nil
}

// CompareAndSwap implements RefreshStore.
func (s *MemoryRefreshStore) CompareAndSwap(ctx context.Context, expected, next RefreshSession) error {
	if s == nil {
		return ErrNilParameter
	}
	if err := refreshContextError(ctx); err != nil {
		return err
	}
	if expected.ID == "" || next.ID != expected.ID {
		return fmt.Errorf("refresh session identity does not match: %w", ErrRefreshConflict)
	}
	if next.Revision != expected.Revision+1 {
		return fmt.Errorf("refresh session revision must advance by one: %w", ErrInvalidParameter)
	}
	if err := next.Validate(time.Time{}); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.sessions[expected.ID]
	if !ok {
		return fmt.Errorf("refresh session %q: %w", expected.ID, ErrRefreshSessionNotFound)
	}
	if !sameRefreshSessionFence(current, expected) {
		return fmt.Errorf("refresh session %q: %w", expected.ID, ErrRefreshConflict)
	}
	s.sessions[next.ID] = next.Clone()
	return nil
}

func sameRefreshSessionFence(current, expected RefreshSession) bool {
	return current.ID == expected.ID &&
		current.Revision == expected.Revision &&
		current.Generation == expected.Generation &&
		current.State == expected.State &&
		current.Attempt == expected.Attempt &&
		current.Current.Equal(expected.Current)
}

func refreshContextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is nil: %w", ErrNilParameter)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// RefreshTokenExchanger exchanges one refresh token with an OIDC provider.
type RefreshTokenExchanger interface {
	ExchangeRefreshToken(ctx context.Context, token RefreshToken) (*oauth2.Token, error)
}

// RefreshTokenExchangerFunc adapts a function to RefreshTokenExchanger.
type RefreshTokenExchangerFunc func(ctx context.Context, token RefreshToken) (*oauth2.Token, error)

// ExchangeRefreshToken implements RefreshTokenExchanger.
func (f RefreshTokenExchangerFunc) ExchangeRefreshToken(ctx context.Context, token RefreshToken) (*oauth2.Token, error) {
	if f == nil {
		return nil, fmt.Errorf("refresh token exchanger is nil: %w", ErrNilParameter)
	}
	return f(ctx, token)
}

type refreshRotatorConfig struct {
	now             func() time.Time
	leaseDuration   time.Duration
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	replayGrace     time.Duration
}

func defaultRefreshRotatorConfig() refreshRotatorConfig {
	return refreshRotatorConfig{
		now:             time.Now,
		leaseDuration:   DefaultRefreshLeaseDuration,
		idleTimeout:     DefaultRefreshIdleTimeout,
		absoluteTimeout: DefaultRefreshAbsoluteTimeout,
		replayGrace:     DefaultRefreshReplayGrace,
	}
}

// RefreshRotatorOption configures a RefreshRotator.
type RefreshRotatorOption func(*refreshRotatorConfig)

// WithRefreshNow sets the clock used by a RefreshRotator.
func WithRefreshNow(now func() time.Time) RefreshRotatorOption {
	return func(c *refreshRotatorConfig) {
		if now != nil {
			c.now = now
		}
	}
}

// WithRefreshLeaseDuration sets how long an attempt may remain in progress
// before it is treated as uncertain.
func WithRefreshLeaseDuration(d time.Duration) RefreshRotatorOption {
	return func(c *refreshRotatorConfig) {
		c.leaseDuration = d
	}
}

// WithRefreshIdleTimeout sets the idle lifetime assigned to newly created
// sessions and extended by successful exchanges.
func WithRefreshIdleTimeout(d time.Duration) RefreshRotatorOption {
	return func(c *refreshRotatorConfig) {
		c.idleTimeout = d
	}
}

// WithRefreshAbsoluteTimeout sets the hard lifetime assigned to newly created
// sessions. It is never extended by a rotation.
func WithRefreshAbsoluteTimeout(d time.Duration) RefreshRotatorOption {
	return func(c *refreshRotatorConfig) {
		c.absoluteTimeout = d
	}
}

// WithRefreshReplayGrace sets how long a concurrent request may present the
// previous refresh token without revoking the session.
func WithRefreshReplayGrace(d time.Duration) RefreshRotatorOption {
	return func(c *refreshRotatorConfig) {
		c.replayGrace = d
	}
}

// RefreshResult is one successful, committed reset of a refresh session.
type RefreshResult struct {
	Session RefreshSession
	Token   *oauth2.Token
	Rotated bool
}

// Generation returns the committed refresh-token generation.
func (r RefreshResult) Generation() uint64 { return r.Session.Generation }

type refreshRotatorLock struct {
	mu   sync.Mutex
	refs int
}

// RefreshRotator serializes and fences refresh-token rotation. The store is
// the authority across processes and restarts; the local lock only avoids
// duplicate in-process exchanges.
type RefreshRotator struct {
	store           RefreshStore
	exchanger       RefreshTokenExchanger
	now             func() time.Time
	leaseDuration   time.Duration
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	replayGrace     time.Duration

	locksMu sync.Mutex
	locks   map[string]*refreshRotatorLock
}

// NewRefreshRotator creates a refresh rotator backed by store.
func NewRefreshRotator(store RefreshStore, exchanger RefreshTokenExchanger, opt ...RefreshRotatorOption) (*RefreshRotator, error) {
	if isNilRefreshValue(store) {
		return nil, fmt.Errorf("refresh store is nil: %w", ErrNilParameter)
	}
	if isNilRefreshValue(exchanger) {
		return nil, fmt.Errorf("refresh token exchanger is nil: %w", ErrNilParameter)
	}

	cfg := defaultRefreshRotatorConfig()
	for _, o := range opt {
		if o != nil {
			o(&cfg)
		}
	}
	switch {
	case cfg.leaseDuration <= 0:
		return nil, fmt.Errorf("refresh lease duration must be positive: %w", ErrInvalidParameter)
	case cfg.idleTimeout <= 0:
		return nil, fmt.Errorf("refresh idle timeout must be positive: %w", ErrInvalidParameter)
	case cfg.absoluteTimeout <= 0:
		return nil, fmt.Errorf("refresh absolute timeout must be positive: %w", ErrInvalidParameter)
	case cfg.replayGrace < 0:
		return nil, fmt.Errorf("refresh replay grace must not be negative: %w", ErrInvalidParameter)
	}

	return &RefreshRotator{
		store:           store,
		exchanger:       exchanger,
		now:             cfg.now,
		leaseDuration:   cfg.leaseDuration,
		idleTimeout:     cfg.idleTimeout,
		absoluteTimeout: cfg.absoluteTimeout,
		replayGrace:     cfg.replayGrace,
		locks:           make(map[string]*refreshRotatorLock),
	}, nil
}

func isNilRefreshValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// Create enrolls a refresh token as generation zero of a new session.
func (r *RefreshRotator) Create(ctx context.Context, id string, token RefreshToken) (RefreshSession, error) {
	const op = "RefreshRotator.Create"
	if r == nil {
		return RefreshSession{}, fmt.Errorf("%s: rotator is nil: %w", op, ErrNilParameter)
	}
	if err := refreshContextError(ctx); err != nil {
		return RefreshSession{}, fmt.Errorf("%s: %w", op, err)
	}
	unlock := r.lock(id)
	defer unlock()

	session, err := NewRefreshSession(id, token, r.now(), r.idleTimeout, r.absoluteTimeout)
	if err != nil {
		return RefreshSession{}, fmt.Errorf("%s: %w", op, err)
	}
	if err := r.store.Create(ctx, session); err != nil {
		return RefreshSession{}, fmt.Errorf("%s: %w", op, err)
	}
	return session, nil
}

// Rotate exchanges the current refresh token and commits at most one new
// generation. The new token is returned only after the store confirms the
// commit. If an exchange times out, the session becomes uncertain and the old
// token is never retried automatically.
func (r *RefreshRotator) Rotate(ctx context.Context, id string, presented RefreshToken) (RefreshResult, error) {
	const op = "RefreshRotator.Rotate"
	if r == nil {
		return RefreshResult{}, fmt.Errorf("%s: rotator is nil: %w", op, ErrNilParameter)
	}
	if err := refreshContextError(ctx); err != nil {
		return RefreshResult{}, fmt.Errorf("%s: %w", op, err)
	}
	if id == "" {
		return RefreshResult{}, fmt.Errorf("%s: refresh session id is empty: %w", op, ErrInvalidParameter)
	}
	if presented == "" {
		return RefreshResult{}, fmt.Errorf("%s: %w", op, ErrMissingRefreshToken)
	}

	unlock := r.lock(id)
	defer unlock()

	for range 3 {
		session, err := r.store.Load(ctx, id)
		if err != nil {
			return RefreshResult{}, fmt.Errorf("%s: unable to load refresh session: %w", op, err)
		}
		if err := session.Validate(time.Time{}); err != nil {
			return RefreshResult{}, fmt.Errorf("%s: loaded refresh session is invalid: %w", op, err)
		}
		now := r.now()

		switch session.State {
		case RefreshSessionRevoked:
			return RefreshResult{Session: session}, fmt.Errorf("%s: %w", op, ErrRefreshRevoked)
		case RefreshSessionUncertain:
			return RefreshResult{Session: session}, fmt.Errorf("%s: %w", op, ErrRefreshUncertain)
		case RefreshSessionRotating:
			if now.Before(session.LeaseExpiresAt) {
				return RefreshResult{Session: session}, fmt.Errorf("%s: %w", op, ErrRefreshInProgress)
			}
			uncertain, err := r.markUncertain(ctx, session)
			if err != nil && errors.Is(err, ErrRefreshConflict) {
				continue
			}
			if err != nil {
				return RefreshResult{Session: session}, fmt.Errorf("%s: %w: %w", op, ErrRefreshUncertain, err)
			}
			return RefreshResult{Session: uncertain}, fmt.Errorf("%s: expired lease: %w", op, ErrRefreshUncertain)
		case RefreshSessionReady:
		default:
			return RefreshResult{Session: session}, fmt.Errorf("%s: refresh session state %q is invalid: %w", op, session.State, ErrInvalidParameter)
		}

		if !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
			revoked, revokeErr := r.revoke(ctx, session)
			if revokeErr != nil && !errors.Is(revokeErr, ErrRefreshConflict) {
				return RefreshResult{Session: session}, fmt.Errorf("%s: %w: %w", op, ErrRefreshExpired, revokeErr)
			}
			if revokeErr != nil {
				continue
			}
			return RefreshResult{Session: revoked}, fmt.Errorf("%s: %w", op, ErrRefreshExpired)
		}

		digest := DigestRefreshToken(presented)
		if !digest.Equal(session.Current) {
			if !session.hasSpent(digest) {
				return RefreshResult{Session: session}, fmt.Errorf("%s: %w", op, ErrRefreshInvalid)
			}
			if r.replayGrace > 0 && !session.PreviousValidUntil.IsZero() && !now.After(session.PreviousValidUntil) {
				return RefreshResult{Session: session}, fmt.Errorf("%s: previous token is within the concurrent-request grace period: %w", op, ErrRefreshConflict)
			}
			revoked, revokeErr := r.revoke(ctx, session)
			if revokeErr != nil && !errors.Is(revokeErr, ErrRefreshConflict) {
				return RefreshResult{Session: session}, fmt.Errorf("%s: %w: %w", op, ErrRefreshReplay, revokeErr)
			}
			if revokeErr != nil {
				continue
			}
			return RefreshResult{Session: revoked}, fmt.Errorf("%s: %w", op, ErrRefreshReplay)
		}

		attempt, err := newRefreshAttemptID()
		if err != nil {
			return RefreshResult{Session: session}, fmt.Errorf("%s: %w", op, err)
		}
		rotating := session
		rotating.State = RefreshSessionRotating
		rotating.Attempt = attempt
		rotating.LeaseExpiresAt = now.Add(r.leaseDuration)
		rotating.PreviousValidUntil = time.Time{}
		reserved, err := r.transition(ctx, session, rotating)
		if err != nil {
			if errors.Is(err, ErrRefreshConflict) {
				continue
			}
			return RefreshResult{Session: session}, fmt.Errorf("%s: unable to reserve refresh session: %w", op, err)
		}
		return r.exchangeAndCommit(ctx, reserved, presented)
	}

	return RefreshResult{}, fmt.Errorf("%s: refresh session kept changing: %w", op, ErrRefreshConflict)
}

// RotateRefreshToken is an alias for Rotate.
func (r *RefreshRotator) RotateRefreshToken(ctx context.Context, id string, presented RefreshToken) (RefreshResult, error) {
	return r.Rotate(ctx, id, presented)
}

func (r *RefreshRotator) exchangeAndCommit(ctx context.Context, rotating RefreshSession, presented RefreshToken) (RefreshResult, error) {
	const op = "RefreshRotator.Rotate"
	token, err := r.exchanger.ExchangeRefreshToken(ctx, presented)
	if err != nil {
		return r.handleExchangeError(ctx, rotating, err)
	}
	if token == nil {
		return r.failUncertain(ctx, rotating, fmt.Errorf("refresh token exchanger returned a nil token: %w", ErrInvalidParameter))
	}
	if token.AccessToken == "" {
		return r.failUncertain(ctx, rotating, ErrMissingAccessToken)
	}

	now := r.now()
	if !now.Before(rotating.AbsoluteExpiresAt) {
		revoked, revokeErr := r.revoke(ctx, rotating)
		if revokeErr != nil && !errors.Is(revokeErr, ErrRefreshConflict) {
			return RefreshResult{Session: rotating}, fmt.Errorf("%s: %w: %w", op, ErrRefreshExpired, revokeErr)
		}
		if revokeErr != nil {
			return RefreshResult{Session: rotating}, fmt.Errorf("%s: another process changed the expired session: %w", op, ErrRefreshConflict)
		}
		return RefreshResult{Session: revoked}, fmt.Errorf("%s: %w", op, ErrRefreshExpired)
	}

	nextToken := token.RefreshToken
	if nextToken == "" {
		nextToken = string(presented)
	}
	nextDigest := DigestRefreshToken(RefreshToken(nextToken))
	rotated := subtle.ConstantTimeCompare(nextDigest[:], rotating.Current[:]) == 0
	if rotated && rotating.hasSpent(nextDigest) {
		return r.failUncertain(ctx, rotating, fmt.Errorf("provider returned a previously spent refresh token: %w", ErrRefreshInvalid))
	}

	ready := rotating
	ready.State = RefreshSessionReady
	ready.Attempt = ""
	ready.LeaseExpiresAt = time.Time{}
	ready.IdleExpiresAt = now.Add(r.idleTimeout)
	if ready.IdleExpiresAt.After(ready.AbsoluteExpiresAt) {
		ready.IdleExpiresAt = ready.AbsoluteExpiresAt
	}
	if rotated {
		if rotating.Generation == ^uint64(0) {
			return r.failUncertain(ctx, rotating, fmt.Errorf("refresh generation overflow: %w", ErrInvalidParameter))
		}
		ready.Generation = rotating.Generation + 1
		ready.Spent = append(ready.Spent, rotating.Current)
		ready.Current = nextDigest
		if r.replayGrace > 0 {
			ready.PreviousValidUntil = now.Add(r.replayGrace)
		} else {
			ready.PreviousValidUntil = time.Time{}
		}
	}

	committed, err := r.transition(ctx, rotating, ready)
	if err != nil {
		if errors.Is(err, ErrRefreshConflict) {
			return RefreshResult{Session: rotating}, fmt.Errorf("%s: another rotation committed first: %w", op, ErrRefreshConflict)
		}
		return r.failUncertain(ctx, rotating, err)
	}
	return RefreshResult{Session: committed, Token: token, Rotated: rotated}, nil
}

func (r *RefreshRotator) handleExchangeError(ctx context.Context, rotating RefreshSession, exchangeErr error) (RefreshResult, error) {
	const op = "RefreshRotator.Rotate"
	var retrieveErr *oauth2.RetrieveError
	if errors.As(exchangeErr, &retrieveErr) && retrieveErr.Response != nil &&
		retrieveErr.Response.StatusCode >= 400 && retrieveErr.Response.StatusCode < 500 &&
		retrieveErr.ErrorCode == "invalid_grant" {
		// invalid_grant is the only response which definitively tells us the
		// presented refresh token was rejected. Other 4xx responses can be
		// produced by proxies after the token endpoint processed the request,
		// so they remain ambiguous.
		revoked, err := r.revoke(ctx, rotating)
		if err != nil {
			return r.failUncertain(ctx, rotating, errors.Join(exchangeErr, err))
		}
		return RefreshResult{Session: revoked}, fmt.Errorf("%s: provider rejected the refresh grant: %w: %w", op, ErrRefreshRevoked, exchangeErr)
	}
	return r.failUncertain(ctx, rotating, exchangeErr)
}

func (r *RefreshRotator) failUncertain(ctx context.Context, rotating RefreshSession, cause error) (RefreshResult, error) {
	const op = "RefreshRotator.Rotate"
	session, err := r.markUncertain(ctx, rotating)
	if err != nil {
		return RefreshResult{Session: rotating}, fmt.Errorf("%s: %w: %w", op, ErrRefreshUncertain, errors.Join(cause, err))
	}
	return RefreshResult{Session: session}, fmt.Errorf("%s: %w: %w", op, ErrRefreshUncertain, cause)
}

func (r *RefreshRotator) markUncertain(ctx context.Context, session RefreshSession) (RefreshSession, error) {
	uncertain := session
	uncertain.State = RefreshSessionUncertain
	uncertain.Attempt = ""
	uncertain.LeaseExpiresAt = time.Time{}
	uncertain.PreviousValidUntil = time.Time{}
	return r.transition(ctx, session, uncertain)
}

func (r *RefreshRotator) revoke(ctx context.Context, session RefreshSession) (RefreshSession, error) {
	revoked := session
	revoked.State = RefreshSessionRevoked
	revoked.Attempt = ""
	revoked.LeaseExpiresAt = time.Time{}
	revoked.PreviousValidUntil = time.Time{}
	return r.transition(ctx, session, revoked)
}

func (r *RefreshRotator) transition(ctx context.Context, expected, next RefreshSession) (RefreshSession, error) {
	next = next.Clone()
	if expected.Revision == ^uint64(0) {
		return RefreshSession{}, fmt.Errorf("refresh session revision overflow: %w", ErrInvalidParameter)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	next.Revision = expected.Revision + 1
	timeout := r.leaseDuration
	if timeout < refreshStoreTimeout {
		timeout = refreshStoreTimeout
	}
	storeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	if err := r.store.CompareAndSwap(storeCtx, expected, next); err != nil {
		return RefreshSession{}, err
	}
	return next.Clone(), nil
}

func (r *RefreshRotator) lock(id string) func() {
	r.locksMu.Lock()
	if r.locks == nil {
		r.locks = make(map[string]*refreshRotatorLock)
	}
	l, ok := r.locks[id]
	if !ok {
		l = new(refreshRotatorLock)
		r.locks[id] = l
	}
	l.refs++
	r.locksMu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		r.locksMu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(r.locks, id)
		}
		r.locksMu.Unlock()
	}
}

func newRefreshAttemptID() (RefreshAttemptID, error) {
	var id [sha256.Size]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("unable to generate refresh attempt id: %w", err)
	}
	return RefreshAttemptID(hex.EncodeToString(id[:])), nil
}

var (
	_ RefreshStore = (*MemoryRefreshStore)(nil)
)
