// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package callback

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AuthCodeFailureConsumesStateAcrossHandlers(t *testing.T) {
	ctx := context.Background()
	tp := oidc.StartTestProvider(t)
	tp.SetExpectedAuthCode("valid-code")
	callbackSrv := httptest.NewTLSServer(nil)
	defer callbackSrv.Close()

	redirect := callbackSrv.URL
	tp.SetAllowedRedirectURIs([]string{redirect})
	p := testNewProvider(t, "test-client-id", "test-client-secret", redirect, tp)

	oidcRequest, err := oidc.NewRequest(1*time.Minute, redirect)
	require.NoError(t, err)

	firstHandler, err := AuthCode(ctx, p, &SingleRequestReader{Request: oidcRequest}, testSuccessFn, testFailFn)
	require.NoError(t, err)

	// A provider error must consume the pending state even though no token
	// exchange happened.
	first := callbackRequest(t, oidcRequest.State(), "error", "access_denied")
	firstRecorder := httptest.NewRecorder()
	firstHandler.ServeHTTP(firstRecorder, first)
	require.Equal(t, http.StatusUnauthorized, firstRecorder.Code)

	// Rebuild the handler and reader, as would happen after a restart.  The
	// same state must not be usable for an authorization code exchange.
	secondHandler, err := AuthCode(ctx, p, &SingleRequestReader{Request: oidcRequest}, testSuccessFn, testFailFn)
	require.NoError(t, err)
	second := callbackRequest(t, oidcRequest.State(), "code", "valid-code")
	secondRecorder := httptest.NewRecorder()
	secondHandler.ServeHTTP(secondRecorder, second)
	require.Equal(t, http.StatusInternalServerError, secondRecorder.Code)
	assertCallbackDescriptionContains(t, secondRecorder, "not found")

	// A repeated provider-error callback must also be rejected.
	thirdHandler, err := AuthCode(ctx, p, &SingleRequestReader{Request: oidcRequest}, testSuccessFn, testFailFn)
	require.NoError(t, err)
	third := callbackRequest(t, oidcRequest.State(), "error", "access_denied")
	thirdRecorder := httptest.NewRecorder()
	thirdHandler.ServeHTTP(thirdRecorder, third)
	require.Equal(t, http.StatusInternalServerError, thirdRecorder.Code)
	assertCallbackDescriptionContains(t, thirdRecorder, "not found")

	// The failed callback consumed the nonce and exchange as well, so a caller
	// which retained the request cannot bypass the callback handler.
	_, err = p.Exchange(ctx, oidcRequest, oidcRequest.State(), "valid-code")
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrRequestConsumed)
}

func Test_ImplicitFailureConsumesStateAcrossHandlers(t *testing.T) {
	ctx := context.Background()
	tp := oidc.StartTestProvider(t)
	callbackSrv := httptest.NewTLSServer(nil)
	defer callbackSrv.Close()

	redirect := callbackSrv.URL
	tp.SetAllowedRedirectURIs([]string{redirect})
	p := testNewProvider(t, "test-client-id", "test-client-secret", redirect, tp)

	oidcRequest, err := oidc.NewRequest(1*time.Minute, redirect, oidc.WithImplicitFlow())
	require.NoError(t, err)

	firstHandler, err := Implicit(ctx, p, &SingleRequestReader{Request: oidcRequest}, testSuccessFn, testFailFn)
	require.NoError(t, err)
	first := callbackRequest(t, oidcRequest.State(), "error", "access_denied")
	firstRecorder := httptest.NewRecorder()
	firstHandler.ServeHTTP(firstRecorder, first)
	require.Equal(t, http.StatusUnauthorized, firstRecorder.Code)

	secondHandler, err := Implicit(ctx, p, &SingleRequestReader{Request: oidcRequest}, testSuccessFn, testFailFn)
	require.NoError(t, err)
	second := callbackRequest(t, oidcRequest.State(), "id_token", "dummy-token")
	secondRecorder := httptest.NewRecorder()
	secondHandler.ServeHTTP(secondRecorder, second)
	require.Equal(t, http.StatusInternalServerError, secondRecorder.Code)
	assertCallbackDescriptionContains(t, secondRecorder, "not found")

	// The failed callback consumed the nonce as well.
	_, err = p.VerifyIDToken(ctx, oidc.IDToken("dummy-token"), oidcRequest)
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrRequestConsumed)
}

func Test_AuthCodeConcurrentCallbacksConsumeOnce(t *testing.T) {
	ctx := context.Background()
	tp := oidc.StartTestProvider(t)
	tp.SetExpectedAuthCode("concurrent-code")
	callbackSrv := httptest.NewTLSServer(nil)
	defer callbackSrv.Close()

	redirect := callbackSrv.URL
	tp.SetAllowedRedirectURIs([]string{redirect})
	p := testNewProvider(t, "test-client-id", "test-client-secret", redirect, tp)

	oidcRequest, err := oidc.NewRequest(1*time.Minute, redirect)
	require.NoError(t, err)
	tp.SetExpectedAuthNonce(oidcRequest.Nonce())

	handler, err := AuthCode(ctx, p, &SingleRequestReader{Request: oidcRequest}, testSuccessFn, testFailFn)
	require.NoError(t, err)

	const attempts = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		success int
	)
	requests := make([]*http.Request, attempts)
	for i := 0; i < attempts; i++ {
		requests[i] = callbackRequest(t, oidcRequest.State(), "code", "concurrent-code")
	}
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(req *http.Request) {
			defer wg.Done()
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code == http.StatusOK {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}(requests[i])
	}
	wg.Wait()
	require.Equal(t, 1, success)
}

func callbackRequest(t *testing.T, state string, key string, value string) *http.Request {
	t.Helper()
	form := url.Values{}
	form.Set("state", state)
	form.Set(key, value)
	req, err := http.NewRequest(http.MethodPost, "/callback", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func assertCallbackDescriptionContains(t *testing.T, recorder *httptest.ResponseRecorder, want string) {
	t.Helper()
	var response AuthenErrorResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.Contains(t, response.Description, want)
}
