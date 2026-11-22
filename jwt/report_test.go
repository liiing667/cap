// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/require"
)

type gsbReportTestKeySet struct {
	claims     map[string]interface{}
	err        error
	stage      FailureStage
	issuer     string
	alg        Alg
	kid        string
	source     string
	generation uint64
}

func (f *gsbReportTestKeySet) VerifySignature(context.Context, string) (map[string]interface{}, error) {
	return f.claims, f.err
}

func (f *gsbReportTestKeySet) VerifySignatureWithReport(context.Context, string) (map[string]interface{}, KeySetReport, error) {
	report := KeySetReport{
		Issuer:           f.issuer,
		Alg:              f.alg,
		Kid:              f.kid,
		KeySetSource:     f.source,
		KeySetGeneration: f.generation,
		Stage:            f.stage,
		FailureStage:     f.stage,
		Verified:         f.err == nil,
	}
	return f.claims, report, f.err
}

func (f *gsbReportTestKeySet) KeySetSource() string     { return f.source }
func (f *gsbReportTestKeySet) KeySetGeneration() uint64 { return f.generation }

func gsbReportTestClaims(issuer string) map[string]interface{} {
	now := time.Now()
	return map[string]interface{}{
		"iss": issuer,
		"sub": "alice@example.com",
		"iat": float64(now.Add(-time.Minute).Unix()),
		"exp": float64(now.Add(time.Hour).Unix()),
	}
}

func TestGSB32042ValidateWithReportPreservesGeneration(t *testing.T) {
	claims := gsbReportTestClaims("https://issuer.example/")
	token := oidc.TestSignJWT(t, priv, string(RS256), claims, []byte("old-kid"))

	keySet := &gsbReportTestKeySet{
		claims:     claims,
		issuer:     "https://issuer.example/",
		alg:        RS256,
		kid:        "old-kid",
		source:     "https://issuer.example/jwks",
		generation: 7,
	}
	validator, err := NewValidator(keySet)
	require.NoError(t, err)

	got, report, err := validator.ValidateWithReport(context.Background(), token, Expected{
		Issuer: "https://issuer.example/",
	})
	require.NoError(t, err)
	require.Equal(t, claims, got)
	require.NotNil(t, report)
	require.True(t, report.Verified)
	require.True(t, report.IssuerVerified)
	require.Equal(t, "https://issuer.example/", report.Issuer)
	require.Equal(t, RS256, report.Alg)
	require.Equal(t, "old-kid", report.Kid)
	require.Equal(t, "https://issuer.example/jwks", report.KeySetSource)
	require.Equal(t, uint64(7), report.KeySetGeneration)
	require.Equal(t, "", report.FailureStage)
	require.Equal(t, StageComplete, report.Stage)
	require.Equal(t, "RS256", report.Algorithm)
	require.Equal(t, "old-kid", report.KeyID)
	require.Equal(t, "https://issuer.example/jwks", report.Source)
	require.Equal(t, uint64(7), report.Generation)
	require.True(t, report.OK())
	require.True(t, report.Valid)
}

func TestGSB32042ValidateWithReportFailureKeepsTokenIdentity(t *testing.T) {
	claims := gsbReportTestClaims("https://issuer.example/")
	token := oidc.TestSignJWT(t, priv, string(RS256), claims, []byte("new-kid"))

	refreshErr := &KeySetError{
		Stage:      StageKeySetRefresh,
		Source:     "https://issuer.example/jwks",
		Generation: 8,
		Kid:        "new-kid",
		Err:        errors.New("refresh rejected"),
	}
	keySet := &gsbReportTestKeySet{
		// Deliberately return stale claims: a failed verification must not
		// publish them, and the report must use this token's header.
		claims:     gsbReportTestClaims("https://old-issuer.example/"),
		err:        refreshErr,
		stage:      StageKeySetRefresh,
		issuer:     "https://old-issuer.example/",
		alg:        RS256,
		kid:        "old-kid",
		source:     "https://issuer.example/jwks",
		generation: 8,
	}
	validator, err := NewValidator(keySet)
	require.NoError(t, err)
	keySetReportFromErr, ok := ReportFromError(refreshErr)
	require.True(t, ok)
	require.Equal(t, StageKeySetRefresh, keySetReportFromErr.Stage)
	require.Equal(t, "new-kid", keySetReportFromErr.Kid)

	got, report, err := validator.ValidateWithReport(context.Background(), token, Expected{})
	require.Error(t, err)
	require.Nil(t, got)
	require.NotNil(t, report)
	require.Nil(t, report.Claims)
	require.False(t, report.Verified)
	require.Equal(t, "https://issuer.example/", report.Issuer)
	require.Equal(t, RS256, report.Alg)
	require.Equal(t, "new-kid", report.Kid)
	require.Equal(t, "https://issuer.example/jwks", report.KeySetSource)
	require.Equal(t, uint64(8), report.KeySetGeneration)
	require.Equal(t, StageKeySetRefresh, report.FailureStage)
	require.Equal(t, StageKeySetRefresh, report.Stage)
	require.Equal(t, "RS256", report.Algorithm)
	require.Equal(t, "new-kid", report.KeyID)
	require.Equal(t, "https://issuer.example/jwks", report.Source)
	require.Equal(t, uint64(8), report.Generation)
	require.False(t, report.OK())
	require.False(t, report.Valid)

	reported, ok := ReportFromError(err)
	require.True(t, ok)
	require.Equal(t, report, reported)
	require.Equal(t, StageKeySetRefresh, ErrorStage(err))

	var asReport ValidationReport
	require.True(t, errors.As(err, &asReport))
	require.Equal(t, StageKeySetRefresh, asReport.Stage)
	require.Equal(t, "new-kid", asReport.KeyID)
	require.Equal(t, uint64(8), asReport.Generation)

	var keySetReport KeySetReport
	require.True(t, errors.As(err, &keySetReport))
	require.Equal(t, StageKeySetRefresh, keySetReport.Stage)
	require.Equal(t, "new-kid", keySetReport.KeyID)
	require.Equal(t, uint64(8), keySetReport.Generation)
	require.Error(t, keySetReport.Err)

	var validationErr *ValidationError
	require.True(t, errors.As(err, &validationErr))
	require.Equal(t, StageKeySetRefresh, validationErr.Stage)
	require.Equal(t, "new-kid", validationErr.KeyID)
	require.Equal(t, uint64(8), validationErr.Generation)

	// The original Validate signature is unchanged, but its error still carries
	// the same structured evidence for existing callers.
	_, err = validator.Validate(context.Background(), token, Expected{})
	require.Error(t, err)
	reported, ok = ReportFromError(err)
	require.True(t, ok)
	require.Equal(t, StageKeySetRefresh, reported.FailureStage)
	require.Equal(t, "new-kid", reported.Kid)
}

func TestGSB32042ValidateReportsDoNotLeakAcrossTokens(t *testing.T) {
	oldClaims := gsbReportTestClaims("https://old.example/")
	newClaims := gsbReportTestClaims("https://new.example/")
	oldToken := oidc.TestSignJWT(t, priv, string(RS256), oldClaims, []byte("old-kid"))
	newToken := oidc.TestSignJWT(t, priv, string(RS256), newClaims, []byte("new-kid"))

	oldKeySet := &gsbReportTestKeySet{
		claims:     oldClaims,
		issuer:     "https://old.example/",
		alg:        RS256,
		kid:        "old-kid",
		source:     "jwks://old",
		generation: 1,
	}
	newKeySet := &gsbReportTestKeySet{
		claims:     newClaims,
		issuer:     "https://new.example/",
		alg:        RS256,
		kid:        "new-kid",
		source:     "jwks://new",
		generation: 2,
	}

	validator, err := NewValidatorWithKeySetSearcher(func(_ context.Context, kid string) (KeySet, error) {
		switch kid {
		case "old-kid":
			return oldKeySet, nil
		case "new-kid":
			return newKeySet, nil
		default:
			return nil, errors.New("unknown kid")
		}
	})
	require.NoError(t, err)

	_, oldReport, err := validator.ValidateWithReport(context.Background(), oldToken, Expected{})
	require.NoError(t, err)
	require.Equal(t, "old-kid", oldReport.Kid)
	require.Equal(t, "https://old.example/", oldReport.Issuer)
	require.Equal(t, "jwks://old", oldReport.KeySetSource)
	require.Equal(t, uint64(1), oldReport.KeySetGeneration)

	_, newReport, err := validator.ValidateWithReport(context.Background(), newToken, Expected{})
	require.NoError(t, err)
	require.Equal(t, "new-kid", newReport.Kid)
	require.Equal(t, "https://new.example/", newReport.Issuer)
	require.Equal(t, "jwks://new", newReport.KeySetSource)
	require.Equal(t, uint64(2), newReport.KeySetGeneration)
}

func TestGSB32042ValidateWithReportKeySetLookupFailure(t *testing.T) {
	claims := gsbReportTestClaims("https://issuer.example/")
	token := oidc.TestSignJWT(t, priv, string(RS256), claims, []byte("missing-kid"))

	validator, err := NewValidatorWithKeySetSearcher(func(context.Context, string) (KeySet, error) {
		return nil, errors.New("key set not found")
	})
	require.NoError(t, err)

	got, report, err := validator.ValidateWithReport(context.Background(), token, Expected{})
	require.Error(t, err)
	require.Nil(t, got)
	require.Equal(t, StageKeySetLookup, report.Stage)
	require.Equal(t, "https://issuer.example/", report.Issuer)
	require.Equal(t, RS256, report.Alg)
	require.Equal(t, "missing-kid", report.Kid)
	require.Empty(t, report.KeySetSource)
	require.Zero(t, report.KeySetGeneration)
	require.False(t, report.Verified)
	require.Error(t, report.Err)
}

func TestGSB32042ValidateWithReportClaimsFailureStage(t *testing.T) {
	keySet, err := NewStaticKeySet([]crypto.PublicKey{priv.Public()})
	require.NoError(t, err)
	validator, err := NewValidator(keySet)
	require.NoError(t, err)

	claims := gsbReportTestClaims("https://actual.example/")
	token := oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))

	got, report, err := validator.ValidateWithReport(context.Background(), token, Expected{
		Issuer: "https://expected.example/",
	})
	require.Error(t, err)
	require.Nil(t, got)
	require.Equal(t, StageIssuer, report.Stage)
	require.Equal(t, "https://actual.example/", report.Issuer)
	require.True(t, report.IssuerVerified)
	require.Equal(t, RS256, report.Alg)
	require.Equal(t, testKeyID, report.Kid)
	require.Equal(t, "static", report.KeySetSource)
	require.Equal(t, uint64(1), report.KeySetGeneration)
	require.False(t, report.Verified)
	require.Error(t, report.Err)
}

func TestGSB32042JSONWebKeySetRefreshGeneration(t *testing.T) {
	tp := oidc.StartTestProvider(t)
	tp.SetSigningKeys(priv, priv.Public(), oidc.RS256, "old-kid")

	keySet, err := NewJSONWebKeySetWithOptions(
		context.Background(),
		tp.Addr()+wellKnownJWKS,
		tp.CACert(),
		WithKeySetStaleWindow(-1),
	)
	require.NoError(t, err)

	claims := gsbReportTestClaims("https://issuer.example/")
	oldToken := oidc.TestSignJWT(t, priv, string(RS256), claims, []byte("old-kid"))

	_, firstReport, err := keySet.(ReportingKeySet).VerifySignatureWithReport(context.Background(), oldToken)
	require.NoError(t, err)
	require.True(t, firstReport.Verified)
	require.True(t, firstReport.OK())
	require.Equal(t, StageComplete, firstReport.Stage)
	require.Equal(t, "old-kid", firstReport.Kid)
	require.NotZero(t, firstReport.KeySetGeneration)
	require.Equal(t, firstReport.KeySetGeneration, firstReport.Generation)
	require.Equal(t, tp.Addr()+wellKnownJWKS, firstReport.KeySetSource)
	require.Equal(t, firstReport.KeySetSource, firstReport.Source)

	// A refresh that observes the same key material must not invent a new
	// generation for the report.
	_, repeatReport, err := keySet.(ReportingKeySet).VerifySignatureWithReport(context.Background(), oldToken)
	require.NoError(t, err)
	require.Equal(t, firstReport.KeySetGeneration, repeatReport.KeySetGeneration)

	// Rotate the issuer's JWKS. The next successful verification publishes a
	// complete new generation, and the removed key must no longer verify.
	tp.SetSigningKeys(priv2, priv2.Public(), oidc.RS256, "new-kid")
	newToken := oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte("new-kid"))

	_, secondReport, err := keySet.(ReportingKeySet).VerifySignatureWithReport(context.Background(), newToken)
	require.NoError(t, err)
	require.True(t, secondReport.Verified)
	require.Equal(t, "new-kid", secondReport.Kid)
	require.Greater(t, secondReport.KeySetGeneration, firstReport.KeySetGeneration)

	_, oldReport, err := keySet.(ReportingKeySet).VerifySignatureWithReport(context.Background(), oldToken)
	require.Error(t, err)
	require.False(t, oldReport.Verified)
	require.False(t, oldReport.OK())
	require.Equal(t, StageSignature, oldReport.Stage)
	require.Equal(t, StageSignature, oldReport.FailedStage())
	require.Equal(t, "old-kid", oldReport.Kid)
	require.Equal(t, StageSignature, oldReport.FailureStage)
	require.Equal(t, secondReport.KeySetGeneration, oldReport.KeySetGeneration)
	require.Error(t, oldReport.Err)
	require.Contains(t, oldReport.Error(), "stage=signature")
}

func TestGSB32042ValidatorReportRevokesRotatedKeyWithSameKid(t *testing.T) {
	tp := oidc.StartTestProvider(t)
	tp.SetSigningKeys(priv, priv.Public(), oidc.RS256, testKeyID)

	keySet, err := NewJSONWebKeySetWithOptions(
		context.Background(),
		tp.Addr()+wellKnownJWKS,
		tp.CACert(),
		WithKeySetStaleWindow(-1),
	)
	require.NoError(t, err)
	validator, err := NewValidator(keySet)
	require.NoError(t, err)

	claims := gsbReportTestClaims("https://issuer.example/")
	oldToken := oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))

	_, firstReport, err := validator.ValidateWithReport(context.Background(), oldToken, Expected{
		Issuer: "https://issuer.example/",
	})
	require.NoError(t, err)
	require.True(t, firstReport.Verified)
	require.Equal(t, testKeyID, firstReport.Kid)

	// Rotate the key material but keep the kid. A cache that first trusts
	// cached keys would keep accepting the revoked key indefinitely.
	tp.SetSigningKeys(priv2, priv2.Public(), oidc.RS256, testKeyID)
	newToken := oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID))

	_, rotatedReport, err := validator.ValidateWithReport(context.Background(), newToken, Expected{
		Issuer: "https://issuer.example/",
	})
	require.NoError(t, err)
	require.True(t, rotatedReport.Verified)
	require.Greater(t, rotatedReport.KeySetGeneration, firstReport.KeySetGeneration)
	require.Equal(t, testKeyID, rotatedReport.Kid)

	_, revokedReport, err := validator.ValidateWithReport(context.Background(), oldToken, Expected{
		Issuer: "https://issuer.example/",
	})
	require.Error(t, err)
	require.False(t, revokedReport.Verified)
	require.Equal(t, StageSignature, revokedReport.FailureStage)
	require.Equal(t, rotatedReport.KeySetGeneration, revokedReport.KeySetGeneration)
	require.Equal(t, testKeyID, revokedReport.Kid)
}

func TestGSB32042JSONWebKeySetRefreshFailurePreservesGeneration(t *testing.T) {
	tp := oidc.StartTestProvider(t)
	tp.SetSigningKeys(priv, priv.Public(), oidc.RS256, testKeyID)
	defer tp.SetInvalidJWKS(false)

	keySet, err := NewJSONWebKeySet(context.Background(), tp.Addr()+wellKnownJWKS, tp.CACert())
	require.NoError(t, err)

	claims := gsbReportTestClaims("https://issuer.example/")
	token := oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))

	_, firstReport, err := keySet.(ReportingKeySet).VerifySignatureWithReport(context.Background(), token)
	require.NoError(t, err)
	require.True(t, firstReport.Verified)

	// The refresh fails, but the complete previous generation is still within
	// its stale window. The result and generation stay on that generation, and
	// the failure is visible in RefreshError.
	tp.SetInvalidJWKS(true)
	_, staleReport, err := keySet.(ReportingKeySet).VerifySignatureWithReport(context.Background(), token)
	require.NoError(t, err)
	require.True(t, staleReport.Verified)
	require.Equal(t, firstReport.KeySetGeneration, staleReport.KeySetGeneration)
	require.NotEmpty(t, staleReport.RefreshError)

	// A token that does not exist in the stale generation must not inherit the
	// old token's kid or result from the failed refresh.
	otherToken := oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte("other-kid"))
	_, newReport, err := keySet.(ReportingKeySet).VerifySignatureWithReport(context.Background(), otherToken)
	require.Error(t, err)
	require.False(t, newReport.Verified)
	require.Equal(t, StageKeySetRefresh, newReport.Stage)
	require.Equal(t, "other-kid", newReport.Kid)
	require.Equal(t, firstReport.KeySetGeneration, newReport.KeySetGeneration)
	require.NotEmpty(t, newReport.RefreshError)
}
