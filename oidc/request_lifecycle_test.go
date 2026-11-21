// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReq_FreezeFreezesAuthenticationParameters(t *testing.T) {
	verifier, err := NewCodeVerifier()
	require.NoError(t, err)
	replacement, err := NewCodeVerifier()
	require.NoError(t, err)

	req, err := NewRequest(1*time.Minute, "https://redirect", WithPKCE(verifier))
	require.NoError(t, err)
	originalState := req.State()
	originalNonce := req.Nonce()
	originalVerifier := req.PKCEVerifier().Verifier()

	require.NoError(t, req.Freeze())
	assert.True(t, req.Frozen())
	assert.Equal(t, uint64(1), req.Generation())

	// These fields are private, but mutating them demonstrates that the values
	// captured at authentication initiation are the ones returned afterwards.
	req.state = "changed-state"
	req.nonce = "changed-nonce"
	req.withVerifier = replacement

	assert.Equal(t, originalState, req.State())
	assert.Equal(t, originalNonce, req.Nonce())
	assert.Equal(t, originalVerifier, req.PKCEVerifier().Verifier())

	require.NoError(t, req.Freeze())
	assert.Equal(t, uint64(2), req.Generation())
	assert.Equal(t, originalState, req.State())
	assert.Equal(t, originalNonce, req.Nonce())
	assert.Equal(t, originalVerifier, req.PKCEVerifier().Verifier())
}

func TestReq_ConsumeIsSingleUse(t *testing.T) {
	req, err := NewRequest(1*time.Minute, "https://redirect")
	require.NoError(t, err)

	require.NoError(t, req.Consume())
	assert.True(t, req.IsConsumed())
	assert.True(t, errors.Is(req.Consume(), ErrRequestConsumed))
	assert.True(t, errors.Is(req.Freeze(), ErrRequestConsumed))
}

func TestReq_ExchangeAndNonceConsumptionRequireFrozenFlow(t *testing.T) {
	req, err := NewRequest(1*time.Minute, "https://redirect")
	require.NoError(t, err)

	// Direct/stateless use remains repeatable.
	require.NoError(t, req.ConsumeExchange())
	require.NoError(t, req.ConsumeExchange())
	require.NoError(t, req.ConsumeNonce())
	require.NoError(t, req.ConsumeNonce())

	require.NoError(t, req.Freeze())
	require.NoError(t, req.ConsumeExchange())
	assert.True(t, errors.Is(req.ConsumeExchange(), ErrRequestConsumed))
	require.NoError(t, req.ConsumeNonce())
	assert.True(t, errors.Is(req.ConsumeNonce(), ErrRequestConsumed))
}

func TestProvider_AuthURLFreezesRequestValues(t *testing.T) {
	ctx := context.Background()
	tp := StartTestProvider(t)
	tp.SetExpectedAuthCode("test-code")
	redirect := "https://test-redirect"
	p := testNewProvider(t, "test-client-id", "test-client-secret", redirect, tp)

	base, err := NewRequest(1*time.Minute, redirect)
	require.NoError(t, err)
	request := &countingRequest{Request: base}

	gotURL, err := p.AuthURL(ctx, request)
	require.NoError(t, err)
	assert.Contains(t, gotURL, "state="+base.State())
	assert.Contains(t, gotURL, "nonce="+base.Nonce())
	assert.Equal(t, 1, request.stateCalls)
	assert.Equal(t, 1, request.nonceCalls)
	assert.Equal(t, 1, request.verifierCalls)
	assert.Equal(t, 1, request.generationCalls)
}

// countingRequest stands in for a stateful third-party Request implementation.
// AuthURL must read each authentication parameter only once.
type countingRequest struct {
	Request
	stateCalls      int
	nonceCalls      int
	verifierCalls   int
	generationCalls int
}

func (r *countingRequest) State() string {
	r.stateCalls++
	return r.Request.State()
}

func (r *countingRequest) Nonce() string {
	r.nonceCalls++
	return r.Request.Nonce()
}

func (r *countingRequest) PKCEVerifier() CodeVerifier {
	r.verifierCalls++
	return r.Request.PKCEVerifier()
}

func (r *countingRequest) Generation() uint64 {
	r.generationCalls++
	return 1
}
