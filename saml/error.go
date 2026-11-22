// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package saml

import "errors"

var (
	ErrInternal             = errors.New("internal error")
	ErrBindingUnsupported   = errors.New("Configured binding unsupported by the IDP")
	ErrInvalidTLSCert       = errors.New("invalid tls certificate")
	ErrInvalidParameter     = errors.New("invalid parameter")
	ErrMissingAssertions    = errors.New("missing assertions")
	ErrInvalidTime          = errors.New("invalid time")
	ErrInvalidAudience      = errors.New("invalid audience")
	ErrMissingSubject       = errors.New("subject missing")
	ErrMissingAttributeStmt = errors.New("attribute statement missing")
	ErrInvalidSignature     = errors.New("invalid signature")

	ErrRequestStateMissing    = errors.New("saml request state missing")
	ErrRequestStateConsumed   = errors.New("saml request state already consumed")
	ErrRequestStateCancelled  = errors.New("saml request state cancelled")
	ErrRequestStateMismatch   = errors.New("saml request state mismatch")
	ErrRequestStateExpired    = errors.New("saml request state expired")
	ErrRequestStateIncomplete = errors.New("saml request state incomplete")
)
