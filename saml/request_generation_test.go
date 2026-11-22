// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package saml_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/saml"
	"github.com/hashicorp/cap/saml/handler"
	"github.com/hashicorp/cap/saml/models/core"
	testprovider "github.com/hashicorp/cap/saml/test"
)

const (
	generationEntityID = "http://hashicorp-cap.test"
	generationACS      = "http://test.me/saml/acs"
	generationIDP      = "http://test.idp"
	responseRequestID  = "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"
)

func generationClock() clockwork.Clock {
	return clockwork.NewFakeClockAt(time.Date(2015, 7, 15, 0, 0, 0, 0, time.UTC))
}

func generationConfig(t *testing.T, ids ...string) *saml.Config {
	t.Helper()

	opts := []saml.Option{
		saml.WithMetadataParameters(saml.MetadataParameters{
			Issuer:          generationIDP,
			SingleSignOnURL: "http://test.idp/sso",
			IDPCertificate:  testEncodedMetadataCert,
			Binding:         core.ServiceBindingHTTPPost,
		}),
	}
	if len(ids) > 0 {
		next := 0
		opts = append(opts, saml.WithGenerateAuthRequestID(func() (string, error) {
			if next >= len(ids) {
				return "", fmt.Errorf("test request ID sequence exhausted")
			}
			id := ids[next]
			next++
			return id, nil
		}))
	}
	cfg, err := saml.NewConfig(
		generationEntityID,
		generationACS,
		"",
		opts...,
	)
	require.NoError(t, err)
	return cfg
}

func generationSP(t *testing.T, ids ...string) (*saml.ServiceProvider, *saml.Config) {
	t.Helper()
	cfg := generationConfig(t, ids...)
	sp, err := saml.NewServiceProvider(cfg)
	require.NoError(t, err)
	return sp, cfg
}

func unsignedResponseFor(requestID string) string {
	raw := strings.ReplaceAll(responseUnsigned, responseRequestID, requestID)
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

func TestSAMLRequestGenerationFreezesIdentityPerTab(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	sp, _ := generationSP(t, "_tab-one", "_tab-two")

	_, first, err := sp.AuthnRequestPost("relay-one")
	r.NoError(err)
	_, second, err := sp.AuthnRequestPost("relay-two")
	r.NoError(err)

	r.Equal("_tab-one", first.ID)
	r.Equal("_tab-two", second.ID)
	r.Equal("relay-one", first.RelayState)
	r.Equal("relay-two", second.RelayState)
	r.NotZero(first.Generation)
	r.NotZero(second.Generation)
	r.NotEqual(first.Generation, second.Generation)
	r.Equal(first.Generation, first.RequestGeneration)
	r.Equal(first.Generation, first.TabGeneration)
	r.Equal(second.Generation, second.RequestGeneration)
	r.Equal(second.Generation, second.TabGeneration)

	firstState, ok := sp.RequestState(first.ID)
	r.True(ok)
	r.Equal(first.Generation, firstState.Generation)
	r.Equal("relay-one", firstState.RelayState)
	r.Equal(saml.RelayStateDigest("relay-one"), firstState.RelayStateDigest)
	r.Equal(first.MetadataGeneration, firstState.MetadataGeneration)
	r.Equal(first.MetadataIssuer, firstState.Issuer)
	r.Equal(first.CertificateFingerprints, firstState.CertificateFingerprints)

	secondState, ok := sp.RequestState(second.ID)
	r.True(ok)
	r.Equal(second.Generation, secondState.Generation)
	r.Equal("relay-two", secondState.RelayState)

	// Initiating the second tab must not replace the first tab's request.
	firstStateAgain, ok := sp.RequestState(first.ID)
	r.True(ok)
	r.Equal("relay-one", firstStateAgain.RelayState)
	r.Equal(first.Generation, firstStateAgain.Generation)
}

func TestSAMLRequestGenerationConsumesACSOnce(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	sp, _ := generationSP(t, responseRequestID)
	_, authn, err := sp.AuthnRequestPost("relay-one")
	r.NoError(err)

	encoded := unsignedResponseFor(responseRequestID)
	res, err := sp.ParseACSResponse(
		encoded,
		authn.ID,
		"relay-one",
		saml.InsecureSkipSignatureValidation(),
		saml.WithClock(generationClock()),
	)
	r.NoError(err)
	r.Equal(authn.ID, res.RequestID)
	r.Equal("relay-one", res.RelayState)
	r.Equal(saml.RelayStateDigest("relay-one"), res.RelayStateDigest)
	r.Equal(authn.Generation, res.Generation)
	r.Equal(authn.Generation, res.RequestGeneration)
	r.Equal(authn.Generation, res.TabGeneration)
	r.Equal(authn.MetadataGeneration, res.MetadataGeneration)
	r.Equal(authn.MetadataIssuer, res.MetadataIssuer)
	r.Equal(authn.CertificateFingerprints, res.CertificateFingerprints)

	state, ok := sp.RequestState(authn.ID)
	r.True(ok)
	r.True(state.Consumed())

	_, err = sp.ParseACSResponse(
		encoded,
		authn.ID,
		"relay-one",
		saml.InsecureSkipSignatureValidation(),
		saml.WithClock(generationClock()),
	)
	r.ErrorIs(err, saml.ErrRequestStateConsumed)
}

func TestSAMLRequestGenerationRejectsMismatchedRelayStateAndGeneration(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	sp, _ := generationSP(t, responseRequestID)
	_, authn, err := sp.AuthnRequestPost("relay-one")
	r.NoError(err)
	encoded := unsignedResponseFor(responseRequestID)

	_, err = sp.ParseACSResponse(
		encoded,
		authn.ID,
		"relay-two",
		saml.InsecureSkipSignatureValidation(),
		saml.WithClock(generationClock()),
	)
	r.ErrorIs(err, saml.ErrRequestStateMismatch)

	_, err = sp.ParseACSResponse(
		encoded,
		authn.ID,
		"relay-one",
		saml.InsecureSkipSignatureValidation(),
		saml.WithClock(generationClock()),
		saml.WithRequestGeneration(authn.Generation+1),
	)
	r.ErrorIs(err, saml.ErrRequestStateMismatch)

	// Rejected attempts must not consume the generation.
	state, ok := sp.RequestState(authn.ID)
	r.True(ok)
	r.False(state.Consumed())
}

func TestSAMLRequestGenerationConcurrentACSOnlyOneSession(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	sp, _ := generationSP(t, responseRequestID)
	_, authn, err := sp.AuthnRequestPost("relay-one")
	r.NoError(err)
	encoded := unsignedResponseFor(responseRequestID)

	const attempts = 16
	var wg sync.WaitGroup
	results := make(chan error, attempts)
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			_, err := sp.ParseACSResponse(
				encoded,
				authn.ID,
				"relay-one",
				saml.InsecureSkipSignatureValidation(),
				saml.WithClock(generationClock()),
			)
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	consumed := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, saml.ErrRequestStateConsumed):
			consumed++
		default:
			r.NoError(err)
		}
	}
	r.Equal(1, successes)
	r.Equal(attempts-1, consumed)

	state, ok := sp.RequestState(authn.ID)
	r.True(ok)
	r.True(state.Consumed())
}

func TestSAMLRequestGenerationConcurrentTabsCoexist(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	sp, _ := generationSP(t) // default UUID generator

	const tabs = 16
	var wg sync.WaitGroup
	ids := make(chan string, tabs)
	generations := make(chan uint64, tabs)
	errs := make(chan error, tabs)
	wg.Add(tabs)
	for i := 0; i < tabs; i++ {
		go func(i int) {
			defer wg.Done()
			_, authn, err := sp.AuthnRequestPost(fmt.Sprintf("relay-%d", i))
			if err != nil {
				errs <- err
				return
			}
			ids <- authn.ID
			generations <- authn.Generation
		}(i)
	}
	wg.Wait()
	close(ids)
	close(generations)
	close(errs)

	for err := range errs {
		r.NoError(err)
	}
	seenIDs := map[string]struct{}{}
	idList := make([]string, 0, tabs)
	for id := range ids {
		seenIDs[id] = struct{}{}
		idList = append(idList, id)
	}
	r.Len(seenIDs, tabs)
	for _, id := range idList {
		state, ok := sp.RequestState(id)
		r.True(ok)
		r.False(state.Consumed())
	}
	seenGenerations := map[uint64]struct{}{}
	for generation := range generations {
		seenGenerations[generation] = struct{}{}
	}
	r.Len(seenGenerations, tabs)
}

func TestSAMLRequestGenerationCancelAndRestoreDoNotResurrect(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	sp, cfg := generationSP(t, responseRequestID)
	_, authn, err := sp.AuthnRequestPost("relay-one")
	r.NoError(err)
	state, ok := sp.RequestState(authn.ID)
	r.True(ok)

	serialized, err := json.Marshal(state)
	r.NoError(err)
	var persisted saml.RequestState
	r.NoError(json.Unmarshal(serialized, &persisted))

	r.NoError(sp.CancelRequest(authn.ID))
	_, err = sp.ParseACSResponse(
		unsignedResponseFor(responseRequestID),
		authn.ID,
		"relay-one",
		saml.InsecureSkipSignatureValidation(),
		saml.WithClock(generationClock()),
	)
	r.ErrorIs(err, saml.ErrRequestStateCancelled)

	// A restart must not restore a pre-cancel copy into a usable request.
	restarted, err := saml.NewServiceProvider(cfg)
	r.NoError(err)
	r.NoError(restarted.RestoreRequestState(persisted))
	restored, ok := restarted.RequestState(authn.ID)
	r.True(ok)
	r.True(restored.Cancelled())
	_, err = restarted.ParseACSResponse(
		unsignedResponseFor(responseRequestID),
		authn.ID,
		"relay-one",
		saml.InsecureSkipSignatureValidation(),
		saml.WithClock(generationClock()),
	)
	r.ErrorIs(err, saml.ErrRequestStateCancelled)
}

func TestSAMLRequestGenerationMultiTabSurvivesRestart(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	firstID := responseRequestID
	secondID := "second-tab-request-id"
	sp, _ := generationSP(t, firstID, secondID)

	_, first, err := sp.AuthnRequestPost("relay-one")
	r.NoError(err)
	_, second, err := sp.AuthnRequestPost("relay-two")
	r.NoError(err)
	firstState, ok := sp.RequestState(first.ID)
	r.True(ok)
	secondState, ok := sp.RequestState(second.ID)
	r.True(ok)

	// A fresh Config and ServiceProvider model a process restart. The caller
	// persists the two tab states and restores them independently.
	restarted, err := saml.NewServiceProvider(generationConfig(t))
	r.NoError(err)
	r.NoError(restarted.RestoreRequestState(firstState))
	r.NoError(restarted.RestoreRequestState(secondState))

	// A response from the first tab cannot satisfy the second tab's request.
	_, err = restarted.ParseACSResponse(
		unsignedResponseFor(firstID),
		secondID,
		"relay-one",
		saml.InsecureSkipSignatureValidation(),
		saml.WithClock(generationClock()),
	)
	r.Error(err)
	firstStillPending, ok := restarted.RequestState(firstID)
	r.True(ok)
	r.False(firstStillPending.Consumed())

	firstRes, err := restarted.ParseACSResponse(
		unsignedResponseFor(firstID),
		firstID,
		"relay-one",
		saml.InsecureSkipSignatureValidation(),
		saml.WithClock(generationClock()),
	)
	r.NoError(err)
	r.Equal(first.Generation, firstRes.Generation)

	secondRes, err := restarted.ParseACSResponse(
		unsignedResponseFor(secondID),
		secondID,
		"relay-two",
		saml.InsecureSkipSignatureValidation(),
		saml.WithClock(generationClock()),
	)
	r.NoError(err)
	r.Equal(second.Generation, secondRes.Generation)

	_, err = restarted.ParseACSResponse(
		unsignedResponseFor(firstID),
		firstID,
		"relay-one",
		saml.InsecureSkipSignatureValidation(),
		saml.WithClock(generationClock()),
	)
	r.ErrorIs(err, saml.ErrRequestStateConsumed)
}

func TestSAMLRequestGenerationLegacyResponseStillParses(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	sp, _ := generationSP(t)
	res, err := sp.ParseResponse(
		unsignedResponseFor(responseRequestID),
		responseRequestID,
		saml.InsecureSkipSignatureValidation(),
		saml.WithClock(generationClock()),
	)
	r.NoError(err)
	r.Equal(responseRequestID, res.RequestID)
	_, ok := sp.RequestState(responseRequestID)
	r.False(ok)
}

func TestSAMLRequestGenerationDirectCreateKeepsExistingResults(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	tp := testprovider.NewTestProvider(t)
	cfg, err := saml.NewConfig(
		generationEntityID,
		generationACS,
		"",
		saml.WithMetadataXML(tp.MetadataXML(t)),
	)
	r.NoError(err)
	sp, err := saml.NewServiceProvider(cfg)
	r.NoError(err)

	post, err := sp.CreateAuthnRequest("abc123", core.ServiceBindingHTTPPost)
	r.NoError(err)
	r.Equal("http://test.idp/saml/post", post.Destination)
	r.Equal(generationACS, post.AssertionConsumerServiceURL)

	redirect, err := sp.CreateAuthnRequest("abc123", core.ServiceBindingHTTPRedirect)
	r.NoError(err)
	r.Equal("https://test.idp/saml/redirect", redirect.Destination)

	custom, err := sp.CreateAuthnRequest(
		"abc123",
		core.ServiceBindingHTTPRedirect,
		saml.WithAssertionConsumerServiceURL("http://secondary.me/saml/acs"),
	)
	r.NoError(err)
	r.Equal("http://secondary.me/saml/acs", custom.AssertionConsumerServiceURL)
}

func TestSAMLRequestGenerationSecondTabCannotOverwriteRequestOwnership(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	cfg := generationConfig(t, "_fixed-request", "_fixed-request")
	sp, err := saml.NewServiceProvider(cfg)
	r.NoError(err)

	_, first, err := sp.AuthnRequestPost("relay-one")
	r.NoError(err)
	firstState, ok := sp.RequestState(first.ID)
	r.True(ok)

	_, _, err = sp.AuthnRequestPost("relay-two")
	r.ErrorIs(err, saml.ErrRequestStateMismatch)

	stateAfter, ok := sp.RequestState(first.ID)
	r.True(ok)
	r.Equal("relay-one", stateAfter.RelayState)
	r.Equal(firstState.Generation, stateAfter.Generation)
	r.False(stateAfter.Consumed())
}

func TestSAMLRequestGenerationKeepsFrozenMetadataAfterConfigChange(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	sp, cfg := generationSP(t, responseRequestID)
	_, authn, err := sp.AuthnRequestPost("relay-one")
	r.NoError(err)
	originalState, ok := sp.RequestState(authn.ID)
	r.True(ok)
	r.Equal(generationIDP, originalState.Issuer)

	// Point the same Config at a different IdP. A pending request must keep
	// the issuer and certificate set that produced its AuthnRequest.
	cfg.MetadataParameters.Issuer = "http://new.idp"
	cfg.MetadataParameters.SingleSignOnURL = "http://new.idp/sso"

	updatedMetadata, err := sp.MetadataSnapshot()
	r.NoError(err)
	r.Equal("http://new.idp", updatedMetadata.Issuer)
	r.NotEqual(originalState.MetadataGeneration, updatedMetadata.Generation)

	res, err := sp.ParseACSResponse(
		unsignedResponseFor(responseRequestID),
		authn.ID,
		"relay-one",
		saml.InsecureSkipSignatureValidation(),
		saml.WithClock(generationClock()),
	)
	r.NoError(err)
	r.Equal(generationIDP, res.MetadataIssuer)
	r.Equal(originalState.MetadataGeneration, res.MetadataGeneration)
	r.Equal(originalState.CertificateFingerprints, res.CertificateFingerprints)
}

func TestSAMLRequestGenerationACSHandlerAdmitsOnce(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	tp := testprovider.NewTestProvider(t)
	cfg, err := saml.NewConfig(
		generationEntityID,
		generationEntityID+"/saml/acs",
		"",
		saml.WithMetadataXML(tp.MetadataXML(t)),
		saml.WithGenerateAuthRequestID(func() (string, error) {
			return "test-request-id", nil
		}),
	)
	r.NoError(err)
	sp, err := saml.NewServiceProvider(cfg)
	r.NoError(err)
	_, authn, err := sp.AuthnRequestPost("relay-one")
	r.NoError(err)
	acs, err := handler.ACSHandlerFunc(sp)
	r.NoError(err)

	form := url.Values{}
	form.Set(
		"SAMLResponse",
		base64.StdEncoding.EncodeToString(
			[]byte(tp.SamlResponse(t, testprovider.WithResponseAndAssertionSigned())),
		),
	)
	form.Set("RelayState", "relay-one")
	newRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, generationACS, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}

	first := httptest.NewRecorder()
	acs(first, newRequest())
	firstReq := first.Result()
	r.Equal(http.StatusOK, firstReq.StatusCode)
	r.Equal(authn.ID, firstReq.Header.Get("X-SAML-Request-ID"))
	r.Equal(saml.RelayStateDigest("relay-one"), firstReq.Header.Get("X-SAML-RelayState-Digest"))

	second := httptest.NewRecorder()
	acs(second, newRequest())
	r.Equal(http.StatusUnauthorized, second.Result().StatusCode)
	r.Equal("consumed", second.Result().Header.Get("X-SAML-Rejection-Stage"))
}

func TestSAMLRequestGenerationACSHandlerKeepsLegacyCalls(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	tp := testprovider.NewTestProvider(t)
	cfg, err := saml.NewConfig(
		generationEntityID,
		generationEntityID+"/saml/acs",
		"",
		saml.WithMetadataXML(tp.MetadataXML(t)),
	)
	r.NoError(err)
	sp, err := saml.NewServiceProvider(cfg)
	r.NoError(err)
	acs, err := handler.ACSHandlerFunc(sp)
	r.NoError(err)

	form := url.Values{}
	form.Set(
		"SAMLResponse",
		base64.StdEncoding.EncodeToString(
			[]byte(tp.SamlResponse(t, testprovider.WithResponseAndAssertionSigned())),
		),
	)
	req := httptest.NewRequest(http.MethodPost, generationACS, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	acs(recorder, req)
	r.Equal(http.StatusOK, recorder.Result().StatusCode)
}
