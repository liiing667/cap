// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type refreshTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newRefreshTestClock(now time.Time) *refreshTestClock {
	return &refreshTestClock{now: now}
}

func (c *refreshTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *refreshTestClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *refreshTestClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

func TestRefreshRotator_ConcurrentRotationCommitsOneGeneration(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clock := newRefreshTestClock(time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC))
	store := NewMemoryRefreshStore()
	initial, err := NewRefreshSession("session", "refresh-0", clock.Now(), time.Hour, 2*time.Hour)
	require.NoError(t, err)
	require.NoError(t, store.Create(ctx, initial))

	var calls atomic.Int32
	exchanger := RefreshTokenExchangerFunc(func(context.Context, RefreshToken) (*oauth2.Token, error) {
		calls.Add(1)
		time.Sleep(10 * time.Millisecond)
		return &oauth2.Token{
			AccessToken:  "access-1",
			RefreshToken: "refresh-1",
		}, nil
	})
	rotator, err := NewRefreshRotator(store, exchanger, WithRefreshNow(clock.Now))
	require.NoError(t, err)

	const requests = 24
	start := make(chan struct{})
	errs := make(chan error, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := rotator.Rotate(ctx, "session", "refresh-0")
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	var succeeded, conflicted int
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrRefreshConflict):
			conflicted++
		default:
			t.Errorf("unexpected concurrent rotation error: %v", err)
		}
	}
	assert.Equal(t, 1, succeeded)
	assert.Equal(t, requests-1, conflicted)
	assert.Equal(t, int32(1), calls.Load())

	committed, err := store.Load(ctx, "session")
	require.NoError(t, err)
	assert.Equal(t, uint64(1), committed.Generation)
	assert.Equal(t, DigestRefreshToken("refresh-1"), committed.Current)
	assert.Len(t, committed.Spent, 1)
	assert.Equal(t, DigestRefreshToken("refresh-0"), committed.Spent[0])
}

func TestRefreshRotator_ConcurrentProcessesReserveOnce(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clock := newRefreshTestClock(time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC))
	store := NewMemoryRefreshStore()
	initial, err := NewRefreshSession("session", "refresh-0", clock.Now(), time.Hour, 2*time.Hour)
	require.NoError(t, err)
	require.NoError(t, store.Create(ctx, initial))

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var calls atomic.Int32
	exchanger := RefreshTokenExchangerFunc(func(context.Context, RefreshToken) (*oauth2.Token, error) {
		calls.Add(1)
		once.Do(func() { close(entered) })
		<-release
		return &oauth2.Token{
			AccessToken:  "access-1",
			RefreshToken: "refresh-1",
		}, nil
	})
	first, err := NewRefreshRotator(store, exchanger, WithRefreshNow(clock.Now))
	require.NoError(t, err)
	second, err := NewRefreshRotator(store, exchanger, WithRefreshNow(clock.Now))
	require.NoError(t, err)

	firstResult := make(chan error, 1)
	go func() {
		_, err := first.Rotate(ctx, "session", "refresh-0")
		firstResult <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first rotation did not start its exchange")
	}

	_, secondErr := second.Rotate(ctx, "session", "refresh-0")
	close(release)
	require.ErrorIs(t, secondErr, ErrRefreshInProgress)
	require.NoError(t, <-firstResult)
	assert.Equal(t, int32(1), calls.Load())

	committed, err := store.Load(ctx, "session")
	require.NoError(t, err)
	assert.Equal(t, uint64(1), committed.Generation)
}

func TestRefreshRotator_TimeoutIsUncertainAcrossRestart(t *testing.T) {
	t.Parallel()

	clock := newRefreshTestClock(time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC))
	store := NewMemoryRefreshStore()
	initial, err := NewRefreshSession("session", "refresh-0", clock.Now(), time.Hour, 2*time.Hour)
	require.NoError(t, err)
	require.NoError(t, store.Create(context.Background(), initial))

	var calls atomic.Int32
	exchanger := RefreshTokenExchangerFunc(func(ctx context.Context, _ RefreshToken) (*oauth2.Token, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	rotator, err := NewRefreshRotator(store, exchanger, WithRefreshNow(clock.Now))
	require.NoError(t, err)

	timeoutCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = rotator.Rotate(timeoutCtx, "session", "refresh-0")
	require.ErrorIs(t, err, ErrRefreshUncertain)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, int32(1), calls.Load())

	// Retrying the same old token must not start another exchange.
	_, err = rotator.Rotate(context.Background(), "session", "refresh-0")
	require.ErrorIs(t, err, ErrRefreshUncertain)
	assert.Equal(t, int32(1), calls.Load())

	// A new process observes the durable uncertain state, not a ready token.
	restarted, err := NewRefreshRotator(store, exchanger, WithRefreshNow(clock.Now))
	require.NoError(t, err)
	_, err = restarted.Rotate(context.Background(), "session", "refresh-0")
	require.ErrorIs(t, err, ErrRefreshUncertain)
	assert.Equal(t, int32(1), calls.Load())

	session, err := store.Load(context.Background(), "session")
	require.NoError(t, err)
	assert.Equal(t, RefreshSessionUncertain, session.State)
	assert.Equal(t, uint64(0), session.Generation)
}

func TestRefreshRotator_RestartKeepsGenerationAndSpentHistory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clock := newRefreshTestClock(time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC))
	store := NewMemoryRefreshStore()
	var calls atomic.Int32
	exchanger := RefreshTokenExchangerFunc(func(_ context.Context, token RefreshToken) (*oauth2.Token, error) {
		calls.Add(1)
		switch token {
		case "refresh-0":
			return &oauth2.Token{AccessToken: "access-1", RefreshToken: "refresh-1"}, nil
		case "refresh-1":
			return &oauth2.Token{AccessToken: "access-2", RefreshToken: "refresh-2"}, nil
		default:
			return nil, errors.New("unexpected refresh token")
		}
	})
	first, err := NewRefreshRotator(store, exchanger, WithRefreshNow(clock.Now))
	require.NoError(t, err)
	_, err = first.Create(ctx, "session", "refresh-0")
	require.NoError(t, err)
	result, err := first.Rotate(ctx, "session", "refresh-0")
	require.NoError(t, err)
	require.True(t, result.Rotated)
	assert.Equal(t, uint64(1), result.Generation())

	// Simulate a process restart by persisting the session through its JSON
	// representation and restoring it into a new store instance.
	encoded, err := json.Marshal(result.Session)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "refresh-0")
	assert.NotContains(t, string(encoded), "refresh-1")
	var restored RefreshSession
	require.NoError(t, json.Unmarshal(encoded, &restored))
	restartedStore := NewMemoryRefreshStore()
	require.NoError(t, restartedStore.Create(ctx, restored))

	second, err := NewRefreshRotator(restartedStore, exchanger, WithRefreshNow(clock.Now))
	require.NoError(t, err)
	result, err = second.Rotate(ctx, "session", "refresh-1")
	require.NoError(t, err)
	require.True(t, result.Rotated)
	assert.Equal(t, uint64(2), result.Generation())

	session, err := restartedStore.Load(ctx, "session")
	require.NoError(t, err)
	assert.Equal(t, uint64(2), session.Generation)
	assert.Len(t, session.Spent, 2)
	assert.Equal(t, DigestRefreshToken("refresh-0"), session.Spent[0])
	assert.Equal(t, DigestRefreshToken("refresh-1"), session.Spent[1])
	assert.Equal(t, DigestRefreshToken("refresh-2"), session.Current)

	clock.Advance(DefaultRefreshReplayGrace + time.Second)
	_, err = second.Rotate(ctx, "session", "refresh-0")
	require.ErrorIs(t, err, ErrRefreshReplay)
	assert.Equal(t, int32(2), calls.Load())

	session, err = restartedStore.Load(ctx, "session")
	require.NoError(t, err)
	assert.Equal(t, RefreshSessionRevoked, session.State)
	_, err = second.Rotate(ctx, "session", "refresh-2")
	require.ErrorIs(t, err, ErrRefreshRevoked)
	assert.Equal(t, int32(2), calls.Load())
}

func TestRefreshRotator_ReplayGraceFencesConcurrentPreviousToken(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clock := newRefreshTestClock(time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC))
	store := NewMemoryRefreshStore()
	var calls atomic.Int32
	exchanger := RefreshTokenExchangerFunc(func(context.Context, RefreshToken) (*oauth2.Token, error) {
		calls.Add(1)
		return &oauth2.Token{AccessToken: "access-1", RefreshToken: "refresh-1"}, nil
	})
	rotator, err := NewRefreshRotator(store, exchanger, WithRefreshNow(clock.Now))
	require.NoError(t, err)
	_, err = rotator.Create(ctx, "session", "refresh-0")
	require.NoError(t, err)
	_, err = rotator.Rotate(ctx, "session", "refresh-0")
	require.NoError(t, err)

	_, err = rotator.Rotate(ctx, "session", "refresh-0")
	require.ErrorIs(t, err, ErrRefreshConflict)
	session, err := store.Load(ctx, "session")
	require.NoError(t, err)
	assert.Equal(t, RefreshSessionReady, session.State)
	assert.Equal(t, uint64(1), session.Generation)
	assert.Equal(t, int32(1), calls.Load())

	clock.Advance(DefaultRefreshReplayGrace + time.Second)
	_, err = rotator.Rotate(ctx, "session", "refresh-0")
	require.ErrorIs(t, err, ErrRefreshReplay)
	session, err = store.Load(ctx, "session")
	require.NoError(t, err)
	assert.Equal(t, RefreshSessionRevoked, session.State)
	assert.Equal(t, int32(1), calls.Load())
}

func TestRefreshRotator_AbsoluteLifetimeIsNeverExtended(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	start := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	clock := newRefreshTestClock(start)
	store := NewMemoryRefreshStore()
	var calls atomic.Int32
	exchanger := RefreshTokenExchangerFunc(func(_ context.Context, token RefreshToken) (*oauth2.Token, error) {
		calls.Add(1)
		switch token {
		case "refresh-0":
			return &oauth2.Token{AccessToken: "access-1", RefreshToken: "refresh-1"}, nil
		case "refresh-1":
			return &oauth2.Token{AccessToken: "access-2", RefreshToken: "refresh-2"}, nil
		default:
			return nil, errors.New("unexpected refresh token")
		}
	})
	rotator, err := NewRefreshRotator(
		store,
		exchanger,
		WithRefreshNow(clock.Now),
		WithRefreshIdleTimeout(time.Hour),
		WithRefreshAbsoluteTimeout(2*time.Hour),
		WithRefreshReplayGrace(0),
	)
	require.NoError(t, err)
	created, err := rotator.Create(ctx, "session", "refresh-0")
	require.NoError(t, err)

	first, err := rotator.Rotate(ctx, "session", "refresh-0")
	require.NoError(t, err)
	assert.Equal(t, created.AbsoluteExpiresAt, first.Session.AbsoluteExpiresAt)
	assert.Equal(t, uint64(1), first.Generation())

	clock.Advance(30 * time.Minute)
	second, err := rotator.Rotate(ctx, "session", "refresh-1")
	require.NoError(t, err)
	assert.Equal(t, created.AbsoluteExpiresAt, second.Session.AbsoluteExpiresAt)
	assert.Equal(t, clock.Now().Add(time.Hour), second.Session.IdleExpiresAt)
	assert.Equal(t, uint64(2), second.Generation())

	clock.Set(start.Add(2 * time.Hour))
	_, err = rotator.Rotate(ctx, "session", "refresh-2")
	require.ErrorIs(t, err, ErrRefreshExpired)
	session, err := store.Load(ctx, "session")
	require.NoError(t, err)
	assert.Equal(t, RefreshSessionRevoked, session.State)
	assert.Equal(t, int32(2), calls.Load())
}

func TestRefreshRotator_NonRotatingResponseDoesNotAdvanceGeneration(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clock := newRefreshTestClock(time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC))
	store := NewMemoryRefreshStore()
	exchanger := RefreshTokenExchangerFunc(func(context.Context, RefreshToken) (*oauth2.Token, error) {
		return &oauth2.Token{AccessToken: "access-1", RefreshToken: "refresh-0"}, nil
	})
	rotator, err := NewRefreshRotator(store, exchanger, WithRefreshNow(clock.Now))
	require.NoError(t, err)
	_, err = rotator.Create(ctx, "session", "refresh-0")
	require.NoError(t, err)

	result, err := rotator.Rotate(ctx, "session", "refresh-0")
	require.NoError(t, err)
	assert.False(t, result.Rotated)
	assert.Equal(t, uint64(0), result.Generation())
	session, err := store.Load(ctx, "session")
	require.NoError(t, err)
	assert.Equal(t, uint64(0), session.Generation)
	assert.Empty(t, session.Spent)
}

type refreshCommitFailureStore struct {
	RefreshStore
	fail atomic.Bool
}

func (s *refreshCommitFailureStore) CompareAndSwap(ctx context.Context, expected, next RefreshSession) error {
	if s.fail.Load() && expected.State == RefreshSessionRotating && next.State == RefreshSessionReady {
		return errors.New("synthetic commit failure")
	}
	return s.RefreshStore.CompareAndSwap(ctx, expected, next)
}

func TestRefreshRotator_CommitFailureDoesNotPublishToken(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clock := newRefreshTestClock(time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC))
	memory := NewMemoryRefreshStore()
	store := &refreshCommitFailureStore{RefreshStore: memory}
	exchanger := RefreshTokenExchangerFunc(func(context.Context, RefreshToken) (*oauth2.Token, error) {
		return &oauth2.Token{AccessToken: "access-1", RefreshToken: "refresh-1"}, nil
	})
	rotator, err := NewRefreshRotator(store, exchanger, WithRefreshNow(clock.Now))
	require.NoError(t, err)
	_, err = rotator.Create(ctx, "session", "refresh-0")
	require.NoError(t, err)

	store.fail.Store(true)
	result, err := rotator.Rotate(ctx, "session", "refresh-0")
	require.ErrorIs(t, err, ErrRefreshUncertain)
	assert.Nil(t, result.Token)
	assert.Equal(t, uint64(0), result.Session.Generation)

	session, err := memory.Load(ctx, "session")
	require.NoError(t, err)
	assert.Equal(t, RefreshSessionUncertain, session.State)
	assert.Equal(t, uint64(0), session.Generation)
	assert.Empty(t, session.Spent)
}

func TestRefreshRotator_ProviderGrantRejectionRevokesFamily(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clock := newRefreshTestClock(time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC))
	store := NewMemoryRefreshStore()
	exchanger := RefreshTokenExchangerFunc(func(context.Context, RefreshToken) (*oauth2.Token, error) {
		return nil, &oauth2.RetrieveError{
			Response:  &http.Response{StatusCode: http.StatusBadRequest},
			ErrorCode: "invalid_grant",
		}
	})
	rotator, err := NewRefreshRotator(store, exchanger, WithRefreshNow(clock.Now))
	require.NoError(t, err)
	_, err = rotator.Create(ctx, "session", "refresh-0")
	require.NoError(t, err)

	_, err = rotator.Rotate(ctx, "session", "refresh-0")
	require.ErrorIs(t, err, ErrRefreshRevoked)
	session, err := store.Load(ctx, "session")
	require.NoError(t, err)
	assert.Equal(t, RefreshSessionRevoked, session.State)
	assert.Equal(t, uint64(0), session.Generation)
}

func TestProvider_RotateTokenDoesNotMutateOldSession(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "refresh-0" {
			http.Error(w, "unexpected refresh request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-1",
			"refresh_token": "refresh-1",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(srv.Close)

	cfg, err := NewConfig(
		srv.URL,
		"client-id",
		"client-secret",
		[]Alg{ES256},
		nil,
		WithProviderConfig(&ProviderConfig{
			AuthURL:     srv.URL + "/authorize",
			TokenURL:    srv.URL + "/token",
			UserInfoURL: srv.URL + "/userinfo",
			JWKSURL:     srv.URL + "/jwks",
		}),
	)
	require.NoError(t, err)
	provider, err := NewProvider(cfg)
	require.NoError(t, err)
	t.Cleanup(provider.Done)

	_, priv := TestGenerateKeys(t)
	idToken := IDToken(testDefaultJWT(t, priv, time.Minute, "nonce", nil))
	current, err := NewToken(idToken, &oauth2.Token{
		AccessToken:  "old-access",
		RefreshToken: "refresh-0",
		Expiry:       time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	store := NewMemoryRefreshStore()
	rotator, err := NewRefreshRotator(store, provider)
	require.NoError(t, err)
	_, err = rotator.Create(context.Background(), "session", "refresh-0")
	require.NoError(t, err)

	next, err := provider.RotateToken(context.Background(), current, rotator, "session")
	require.NoError(t, err)
	assert.Equal(t, uint64(1), next.Generation())
	assert.Equal(t, RefreshToken("refresh-1"), next.RefreshToken())
	assert.Equal(t, AccessToken("access-1"), next.AccessToken())

	// The old session snapshot must remain exactly what it was.
	assert.Equal(t, uint64(0), current.Generation())
	assert.Equal(t, RefreshToken("refresh-0"), current.RefreshToken())
	assert.Equal(t, AccessToken("old-access"), current.AccessToken())
}

func TestTk_WithTokenGeneration(t *testing.T) {
	t.Parallel()

	_, priv := TestGenerateKeys(t)
	idToken := IDToken(testDefaultJWT(t, priv, time.Minute, "nonce", nil))
	tk, err := NewToken(idToken, nil, WithTokenGeneration(7))
	require.NoError(t, err)
	assert.Equal(t, uint64(7), tk.Generation())
}
