// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package saml_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/saml"
	"github.com/hashicorp/cap/saml/models/core"
	testprovider "github.com/hashicorp/cap/saml/test"
)

const (
	samlGenEntityID = "http://hashicorp-cap.test"
	samlGenACS      = "http://hashicorp-cap.test/saml/acs"
	samlGenRequest  = "test-request-id"
)

func startSAMLGenerationProvider(t *testing.T) (*testprovider.TestProvider, *saml.Config) {
	t.Helper()
	r := require.New(t)

	tp := testprovider.StartTestProvider(t)
	cfg, err := saml.NewConfig(
		samlGenEntityID,
		samlGenACS,
		fmt.Sprintf("%s/saml/metadata", tp.ServerURL()),
	)
	r.NoError(err)
	return tp, cfg
}

func samlGenerationResponse(t *testing.T, tp *testprovider.TestProvider) string {
	t.Helper()
	raw := tp.SamlResponse(t, testprovider.WithResponseAndAssertionSigned())
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

func TestSAMLGenerationConsistency_RequestStateUsesFrozenMetadata(t *testing.T) {
	tp, cfg := startSAMLGenerationProvider(t)

	r := require.New(t)
	sp, err := saml.NewServiceProvider(cfg)
	r.NoError(err)

	authn, err := sp.CreateAuthnRequest(samlGenRequest, core.ServiceBindingHTTPPost)
	r.NoError(err)
	r.Equal(samlGenRequest, authn.ID)
	r.NotEmpty(authn.MetadataGeneration)
	r.Equal("http://test.idp", authn.MetadataIssuer)
	r.NotEmpty(authn.CertificateFingerprints)

	state, ok := sp.RequestState(authn.ID)
	r.True(ok)
	r.Equal(authn.MetadataGeneration, state.MetadataGeneration)
	r.Equal(authn.MetadataIssuer, state.Issuer)
	r.Equal(authn.CertificateFingerprints, state.CertificateFingerprints)

	// A metadata refresh from this point on must fail.  Parsing the response
	// must use the certificate set that was frozen for the AuthnRequest.
	tp.Close()

	got, err := sp.ParseResponse(samlGenerationResponse(t, tp), authn.ID)
	r.NoError(err)
	r.Equal(samlGenRequest, got.RequestID)
	r.Equal("http://test.idp", got.MetadataIssuer)
	r.Equal(state.MetadataGeneration, got.MetadataGeneration)
	r.Equal(state.CertificateFingerprints, got.CertificateFingerprints)

	consumed, ok := sp.RequestState(authn.ID)
	r.True(ok)
	r.True(consumed.Consumed())

	_, err = sp.ParseResponse(samlGenerationResponse(t, tp), authn.ID)
	r.ErrorIs(err, saml.ErrRequestStateConsumed)
}

func TestSAMLGenerationConsistency_RequestStateSurvivesProviderRecreation(t *testing.T) {
	tp, cfg := startSAMLGenerationProvider(t)

	r := require.New(t)
	sp, err := saml.NewServiceProvider(cfg)
	r.NoError(err)

	authn, err := sp.CreateAuthnRequest(samlGenRequest, core.ServiceBindingHTTPPost)
	r.NoError(err)
	resp := samlGenerationResponse(t, tp)
	tp.Close()

	// Recreating the ServiceProvider is the in-process equivalent of a
	// restart.  The pending request and its metadata generation must still be
	// available and must not trigger a final metadata fetch.
	restarted, err := saml.NewServiceProvider(cfg)
	r.NoError(err)
	state, ok := restarted.RequestState(authn.ID)
	r.True(ok)
	r.Equal(authn.MetadataGeneration, state.MetadataGeneration)
	r.Equal(authn.MetadataIssuer, state.Issuer)

	got, err := restarted.ParseResponse(resp, authn.ID)
	r.NoError(err)
	r.Equal(state.MetadataGeneration, got.MetadataGeneration)
	r.Equal(state.Issuer, got.MetadataIssuer)
	r.Equal(state.CertificateFingerprints, got.CertificateFingerprints)
}

func TestSAMLGenerationConsistency_RequestStateJSONRestore(t *testing.T) {
	tp, cfg := startSAMLGenerationProvider(t)

	r := require.New(t)
	sp, err := saml.NewServiceProvider(cfg)
	r.NoError(err)
	authn, err := sp.CreateAuthnRequest(samlGenRequest, core.ServiceBindingHTTPPost)
	r.NoError(err)
	state, ok := sp.RequestState(authn.ID)
	r.True(ok)

	serialized, err := json.Marshal(state)
	r.NoError(err)
	var restoredState saml.RequestState
	r.NoError(json.Unmarshal(serialized, &restoredState))

	resp := samlGenerationResponse(t, tp)
	tp.Close()

	// A fresh Config has no shared runtime.  The session state carried by the
	// caller is sufficient to validate the response after a restart.
	freshCfg, err := saml.NewConfig(
		samlGenEntityID,
		samlGenACS,
		fmt.Sprintf("%s/saml/metadata", tp.ServerURL()),
	)
	r.NoError(err)
	restarted, err := saml.NewServiceProvider(freshCfg)
	r.NoError(err)
	r.NoError(restarted.RestoreRequestState(restoredState))

	got, err := restarted.ParseResponse(resp, authn.ID)
	r.NoError(err)
	r.Equal(state.MetadataGeneration, got.MetadataGeneration)
	r.Equal(state.Issuer, got.MetadataIssuer)
	r.Equal(state.CertificateFingerprints, got.CertificateFingerprints)
}

func TestSAMLGenerationConsistency_RelayStateBinding(t *testing.T) {
	tp, cfg := startSAMLGenerationProvider(t)
	defer tp.Close()

	r := require.New(t)
	sp, err := saml.NewServiceProvider(cfg)
	r.NoError(err)

	_, authn, err := sp.AuthnRequestPost("relay-state")
	r.NoError(err)
	r.Equal("relay-state", authn.RelayState)

	_, err = sp.ParseACSResponse("not-a-saml-response", authn.ID, "different-relay-state")
	r.ErrorIs(err, saml.ErrRequestStateMismatch)

	_, err = sp.ParseACSResponse("not-a-saml-response", authn.ID, "relay-state")
	r.NotErrorIs(err, saml.ErrRequestStateMismatch)
}

func TestSAMLGenerationConsistency_MetadataSnapshotSurvivesRestart(t *testing.T) {
	tp, cfg := startSAMLGenerationProvider(t)

	r := require.New(t)
	sp, err := saml.NewServiceProvider(cfg)
	r.NoError(err)
	before, err := sp.MetadataSnapshot()
	r.NoError(err)
	r.NotZero(before.Generation)
	r.NotEmpty(before.Issuer)
	r.NotEmpty(before.CertificateFingerprints)

	tp.Close()

	restarted, err := saml.NewServiceProvider(cfg)
	r.NoError(err)
	after, err := restarted.MetadataSnapshot(saml.WithStale(true))
	r.NoError(err)
	r.Equal(before.Generation, after.Generation)
	r.Equal(before.Issuer, after.Issuer)
	r.Equal(before.CertificateFingerprints, after.CertificateFingerprints)
}

func TestSAMLGenerationConsistency_ResponseRequestID(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	const response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="request-id"/>`
	got, err := saml.ResponseRequestID(base64.StdEncoding.EncodeToString([]byte(response)))
	r.NoError(err)
	r.Equal("request-id", got)

	_, err = saml.ResponseRequestID("")
	r.ErrorIs(err, saml.ErrInvalidParameter)
}
