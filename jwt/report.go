// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// FailureStage identifies the part of JWT validation that rejected a token.
// Reports always carry the stage so a caller can distinguish a malformed
// token, a key set lookup or refresh failure, a signature failure, and a
// claims validation failure.
type FailureStage = string

const (
	// StageStart is used before a validation attempt has selected a stage.
	StageStart FailureStage = "start"
	// StageParseToken means the compact JWS could not be parsed.
	StageParseToken FailureStage = "parse_token"
	// StageKeyID means the token did not carry the kid required by a key set
	// searcher.
	StageKeyID FailureStage = "kid"
	// StageKeySetLookup means the key set searcher failed or returned no key
	// set.
	StageKeySetLookup FailureStage = "key_set_lookup"
	// StageKeySetRefresh means a key set refresh failed and no complete key
	// generation could be used.
	StageKeySetRefresh FailureStage = "key_set_refresh"
	// StageSignature means the token signature did not verify against the
	// selected key set generation.
	StageSignature FailureStage = "signature"
	// StageAlgorithm means the JWS alg header was missing, unsupported, or not
	// one of the expected algorithms.
	StageAlgorithm FailureStage = "algorithm"
	// StageClaims means the payload could not be decoded into claims or
	// contained ambiguous registered claim names.
	StageClaims FailureStage = "claims"
	// StageIssuer means the iss claim did not match Expected.Issuer.
	StageIssuer FailureStage = "issuer"
	// StageSubject means the sub claim did not match Expected.Subject.
	StageSubject FailureStage = "subject"
	// StageID means the jti claim did not match Expected.ID.
	StageID FailureStage = "id"
	// StageAudience means the aud claim did not match Expected.Audiences.
	StageAudience FailureStage = "audience"
	// StageTimeClaims means the nbf, exp, or iat claims were invalid.
	StageTimeClaims FailureStage = "time_claims"
	// StageComplete means validation completed successfully.
	StageComplete FailureStage = "complete"
)

// Short aliases for callers that prefer the stage name without the Stage
// prefix.
const (
	FailureStageStart         = StageStart
	FailureStageParseToken    = StageParseToken
	FailureStageKeyID         = StageKeyID
	FailureStageKeySetLookup  = StageKeySetLookup
	FailureStageKeySetRefresh = StageKeySetRefresh
	FailureStageSignature     = StageSignature
	FailureStageAlgorithm     = StageAlgorithm
	FailureStageClaims        = StageClaims
	FailureStageIssuer        = StageIssuer
	FailureStageSubject       = StageSubject
	FailureStageID            = StageID
	FailureStageAudience      = StageAudience
	FailureStageTimeClaims    = StageTimeClaims
	FailureStageComplete      = StageComplete

	StageParse   = StageParseToken
	StageKid     = StageKeyID
	StageLookup  = StageKeySetLookup
	StageRefresh = StageKeySetRefresh
	StageAlg     = StageAlgorithm
	StageClaim   = StageClaims
)

// KeySetReport describes the key set generation and key that participated in
// one signature verification attempt. A report is built from a single
// snapshot: issuer, alg, kid, source, generation, and result never come from
// different key set generations.
type KeySetReport struct {
	// Issuer is the token issuer when it can be read from the payload, or the
	// expected/configured issuer when the payload cannot be read.
	Issuer string `json:"issuer,omitempty"`

	// Alg is the JWS alg header of the token being reported.
	Alg Alg `json:"alg,omitempty"`

	// Algorithm is the string form of Alg.
	Algorithm string `json:"algorithm,omitempty"`

	// Kid is the JWS kid header of the token being reported.
	Kid string `json:"kid,omitempty"`

	// KeyID is the string form of Kid.
	KeyID string `json:"key_id,omitempty"`

	// KeySetSource identifies where the selected keys came from, for example a
	// JWKS URL, a static key set, or a custom KeySet implementation.
	KeySetSource string `json:"key_set_source,omitempty"`

	// Source is an alias for KeySetSource.
	Source string `json:"source,omitempty"`

	// KeySetGeneration is the monotonically increasing generation of the key
	// set snapshot used for this attempt. A refresh publishes a complete new
	// generation atomically; a failed refresh leaves the previous complete
	// generation visible or fails closed.
	KeySetGeneration uint64 `json:"key_set_generation,omitempty"`

	// Generation is an alias for KeySetGeneration.
	Generation uint64 `json:"generation,omitempty"`

	// Stage is the stage that rejected the token. It is empty when Verified
	// is true.
	Stage FailureStage `json:"stage,omitempty"`

	// FailureStage is the descriptive alias for Stage.
	FailureStage FailureStage `json:"failure_stage,omitempty"`

	// Verified is true only when the signature and all requested claims checks
	// completed successfully against this generation.
	Verified bool `json:"verified"`

	// Valid is an alias for Verified.
	Valid bool `json:"valid"`

	// IssuerVerified is true when Issuer came from a signature-verified
	// payload. When false, Issuer is informational only and must not be used
	// for an authorization decision.
	IssuerVerified bool `json:"issuer_verified"`

	// RefreshError records a key set refresh failure that was covered by the
	// allowed stale key window. Verified can still be true when the token
	// verified against the complete previous generation.
	RefreshError string `json:"refresh_error,omitempty"`

	// Err is the underlying verification error, if any.
	Err error `json:"-"`
}

func (r *KeySetReport) setStage(stage FailureStage) {
	if r == nil {
		return
	}
	r.Stage = stage
	r.FailureStage = stage
}

// FailedStage returns the stage that rejected the token, or an empty stage on
// success.
func (r KeySetReport) FailedStage() FailureStage {
	if r.FailureStage != "" {
		return r.FailureStage
	}
	if r.Stage != "" && r.Stage != StageComplete && r.Stage != StageStart {
		return r.Stage
	}
	return ""
}

// OK reports whether the reported verification completed successfully.
func (r KeySetReport) OK() bool { return r.Verified || r.Valid }

// Report returns the retained key set report.
func (r KeySetReport) Report() KeySetReport { return r }

// Error makes a KeySetReport usable as an error value.
func (r KeySetReport) Error() string {
	if r.Err == nil {
		return "jwt key set verification complete"
	}
	if stage := r.FailedStage(); stage != "" {
		return fmt.Sprintf("%v (stage=%s key_set_source=%q key_set_generation=%d kid=%q)",
			r.Err, stage, r.KeySetSource, r.KeySetGeneration, r.Kid)
	}
	return r.Err.Error()
}

// Unwrap returns the underlying key set verification error, if any.
func (r KeySetReport) Unwrap() error { return r.Err }

func (r *KeySetReport) syncAliases() {
	if r == nil {
		return
	}
	r.Algorithm = string(r.Alg)
	r.KeyID = r.Kid
	r.Source = r.KeySetSource
	r.Generation = r.KeySetGeneration
	r.Valid = r.Verified
	if r.Verified {
		r.Stage = StageComplete
	} else {
		r.Stage = r.FailureStage
	}
}

// ValidationReport is the complete report for one Validator.Validate call. It
// is returned by ValidateWithReport and is also available through errors.As on
// errors returned by Validate.
type ValidationReport struct {
	KeySetReport

	// Claims contains the verified claims on success. It is nil on failure.
	Claims map[string]interface{} `json:"-"`

	// Err is the underlying validation error, if any.
	Err error `json:"-"`
}

// Report is an alias for ValidationReport.
type Report = ValidationReport

// Error makes a ValidationReport usable as an error value. This allows callers
// to use errors.As(err, &report) when they only need the retained diagnostics.
func (r ValidationReport) Error() string {
	if err := r.Unwrap(); err != nil {
		if stage := r.FailedStage(); stage != "" {
			return fmt.Sprintf("%v (stage=%s issuer=%q alg=%q kid=%q key_set_source=%q key_set_generation=%d)",
				err, stage, r.Issuer, r.Alg, r.Kid, r.KeySetSource, r.KeySetGeneration)
		}
		return err.Error()
	}
	return "jwt validation complete"
}

// Unwrap returns the underlying validation error, if any.
func (r ValidationReport) Unwrap() error {
	if r.Err != nil {
		return r.Err
	}
	if r.KeySetReport.Err != nil {
		return r.KeySetReport.Err
	}
	return nil
}

// Report returns the retained report.
func (r ValidationReport) Report() ValidationReport { return r }

// As exposes the embedded key set report as a KeySetReport target.
func (r ValidationReport) As(target any) bool {
	switch reportTarget := target.(type) {
	case *ValidationReport:
		*reportTarget = r
		return true
	case **ValidationReport:
		report := r
		*reportTarget = &report
		return true
	case *KeySetReport:
		*reportTarget = r.KeySetReport
		return true
	case **KeySetReport:
		report := r.KeySetReport
		*reportTarget = &report
		return true
	default:
		return false
	}
}

// ValidationError carries the ValidationReport for a failed validation.
// Error returns the underlying error text unchanged for compatibility with
// existing callers; use Report or ReportFromError to inspect structured
// evidence.
type ValidationError struct {
	*ValidationReport
	Report *ValidationReport
	Err    error
}

// Error implements error.
func (e *ValidationError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

// Unwrap returns the underlying validation error.
func (e *ValidationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// As allows callers to use errors.As(err, &report) with a ValidationReport
// target in addition to ReportFromError.
func (e *ValidationError) As(target any) bool {
	if e == nil || e.Report == nil {
		return false
	}
	switch reportTarget := target.(type) {
	case **ValidationReport:
		*reportTarget = e.Report
		return true
	case *ValidationReport:
		*reportTarget = *e.Report
		return true
	case *KeySetReport:
		*reportTarget = e.Report.KeySetReport
		return true
	case **KeySetReport:
		report := e.Report.KeySetReport
		*reportTarget = &report
		return true
	default:
		return false
	}
}

// ValidationReport returns the structured report attached to the error.
func (e *ValidationError) ValidationReport() *ValidationReport {
	if e == nil {
		return nil
	}
	return e.Report
}

// FailedStage returns the failure stage carried by the report.
func (e *ValidationError) FailedStage() FailureStage {
	if e == nil {
		return ""
	}
	if e.Report != nil {
		return e.Report.FailedStage()
	}
	if e.ValidationReport != nil {
		return e.Stage
	}
	return ""
}

// DetailedError includes the stage and generation evidence normally kept in
// the report. Error deliberately remains the plain underlying error so that
// existing callers comparing error strings are not affected.
func (e *ValidationError) DetailedError() string {
	if e == nil {
		return ""
	}
	msg := e.Error()
	if e.Report == nil {
		return msg
	}
	return fmt.Sprintf("%s (stage=%s issuer=%q alg=%q kid=%q key_set_source=%q key_set_generation=%d)",
		msg,
		e.Report.FailedStage(),
		e.Report.Issuer,
		e.Report.Alg,
		e.Report.Kid,
		e.Report.KeySetSource,
		e.Report.KeySetGeneration,
	)
}

// ReportFromError extracts a ValidationReport from err.
func ReportFromError(err error) (*ValidationReport, bool) {
	var validationErr *ValidationError
	if errors.As(err, &validationErr) && validationErr.Report != nil {
		return validationErr.Report, true
	}
	var report ValidationReport
	if errors.As(err, &report) {
		return &report, true
	}
	return nil, false
}

// ErrorStage returns the failure stage recorded by a validation or key set
// error, or an empty string when the error carries no stage.
func ErrorStage(err error) string {
	var report ValidationReport
	if errors.As(err, &report) {
		return report.FailedStage()
	}
	var keySetReport KeySetReport
	if errors.As(err, &keySetReport) {
		return keySetReport.FailedStage()
	}
	var validationErr *ValidationError
	if errors.As(err, &validationErr) && validationErr.Report != nil {
		return validationErr.Report.FailedStage()
	}
	var keySetErr *KeySetError
	if errors.As(err, &keySetErr) {
		return keySetErr.Stage
	}
	return ""
}

// KeySetError records a key set level failure together with the source and
// generation that were selected before the failure. A refresh failure cannot
// rewrite the report with a generation that was never published.
type KeySetError struct {
	Stage      FailureStage
	Source     string
	Generation uint64
	Kid        string
	Err        error
}

// Error implements error.
func (e *KeySetError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return fmt.Sprintf("%v (stage=%s key_set_source=%q key_set_generation=%d kid=%q)",
		e.Err, e.Stage, e.Source, e.Generation, e.Kid)
}

// Unwrap returns the underlying key set error.
func (e *KeySetError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Report returns the key set report retained by the error.
func (e *KeySetError) Report() KeySetReport {
	if e == nil {
		return KeySetReport{}
	}
	report := KeySetReport{
		Kid:              e.Kid,
		KeySetSource:     e.Source,
		KeySetGeneration: e.Generation,
		Stage:            e.Stage,
		FailureStage:     e.Stage,
		Err:              e.Err,
	}
	report.syncAliases()
	return report
}

// As exposes the retained report as a KeySetReport target.
func (e *KeySetError) As(target any) bool {
	if e == nil {
		return false
	}
	switch reportTarget := target.(type) {
	case *ValidationReport:
		*reportTarget = ValidationReport{KeySetReport: e.Report(), Err: e.Err}
		return true
	case **ValidationReport:
		report := ValidationReport{KeySetReport: e.Report(), Err: e.Err}
		*reportTarget = &report
		return true
	case *KeySetReport:
		*reportTarget = e.Report()
		return true
	case **KeySetReport:
		report := e.Report()
		*reportTarget = &report
		return true
	default:
		return false
	}
}

// failureStageFromError returns the stage recorded by a KeySetError, or the
// supplied fallback.
func failureStageFromError(err error, fallback FailureStage) FailureStage {
	var keySetErr *KeySetError
	if errors.As(err, &keySetErr) && keySetErr.Stage != "" {
		return keySetErr.Stage
	}
	return fallback
}

// unverifiedIssuer extracts the iss claim without verifying the token. The
// value is used only for report evidence and is marked IssuerVerified=false
// until the signature has been verified.
func unverifiedIssuer(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Issuer
}

// unverifiedHeader extracts the JWS alg and kid without verifying the token.
// Like unverifiedIssuer, these values are report evidence only.
func unverifiedHeader(token string) (kid string, alg Alg) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ""
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ""
	}
	var joseHeader struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(header, &joseHeader); err != nil {
		return "", ""
	}
	return joseHeader.Kid, Alg(joseHeader.Alg)
}
