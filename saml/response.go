// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/jonboulle/clockwork"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/hashicorp/cap/saml/models/core"
)

type parseResponseOptions struct {
	clock                            clockwork.Clock
	skipRequestIDValidation          bool
	skipAssertionConditionValidation bool
	skipSignatureValidation          bool
	assertionConsumerServiceURL      string
	validateResponseSignature        bool
	validateAssertionSignature       bool
	relayState                       string
	relayStateSet                    bool
	requireRequestState              bool
	cache                            bool
	useStale                         bool
}

func parseResponseOptionsDefault() parseResponseOptions {
	return parseResponseOptions{
		clock:                            clockwork.NewRealClock(),
		skipRequestIDValidation:          false,
		skipAssertionConditionValidation: false,
		skipSignatureValidation:          false,
		validateResponseSignature:        false,
		validateAssertionSignature:       false,
		cache:                            true,
	}
}

func getParseResponseOptions(opt ...Option) parseResponseOptions {
	opts := parseResponseOptionsDefault()
	ApplyOpts(&opts, opt...)
	return opts
}

// InsecureSkipRequestIDValidation disables/skips if the given requestID matches
// the InResponseTo parameter in the SAML response. This options should only
// be used for testing purposes.
func InsecureSkipRequestIDValidation() Option {
	return func(o interface{}) {
		if o, ok := o.(*parseResponseOptions); ok {
			o.skipRequestIDValidation = true
		}
	}
}

// InsecureSkipAssertionConditionValidation disables/skips validation of the assertion
// conditions within the SAML response. This options should only be used for
// testing purposes.
func InsecureSkipAssertionConditionValidation() Option {
	return func(o interface{}) {
		if o, ok := o.(*parseResponseOptions); ok {
			o.skipAssertionConditionValidation = true
		}
	}
}

// InsecureSkipSignatureValidation disables/skips validation of the SAML Response and its assertions.
// This options should only be used for testing purposes.
func InsecureSkipSignatureValidation() Option {
	return func(o interface{}) {
		if o, ok := o.(*parseResponseOptions); ok {
			o.skipSignatureValidation = true
		}
	}
}

// ValidateResponseSignature requires a valid signature on the top-level SAML
// response envelope.
func ValidateResponseSignature() Option {
	return func(o interface{}) {
		if o, ok := o.(*parseResponseOptions); ok {
			o.validateResponseSignature = true
		}
	}
}

// ValidateAssertionSignature enables assertion-signature policy checks.
//
// Behavior:
//   - If the response envelope is signed and valid, assertions are accepted as
//     covered by that signature. Any assertion signatures that are present must
//     still validate.
//   - If the response envelope is not signed, each assertion must be signed and
//     valid.
func ValidateAssertionSignature() Option {
	return func(o interface{}) {
		if o, ok := o.(*parseResponseOptions); ok {
			o.validateAssertionSignature = true
		}
	}
}

// WithRelayState binds the RelayState returned by the identity provider to the
// RelayState that was stored when the AuthnRequest was created.  It is only
// meaningful together with a RequestState produced by this package; legacy
// callers that do not create an AuthnRequest through the ServiceProvider keep
// their existing behavior.
func WithRelayState(relayState string) Option {
	return func(o interface{}) {
		if o, ok := o.(*parseResponseOptions); ok {
			o.relayState = relayState
			o.relayStateSet = true
		}
	}
}

// RequireRequestState makes ParseResponse fail when the request ID has no
// recoverable state.  ACS handlers should use this option so a signed response
// cannot be detached from the AuthnRequest that produced it.
func RequireRequestState() Option {
	return func(o interface{}) {
		if o, ok := o.(*parseResponseOptions); ok {
			o.requireRequestState = true
		}
	}
}

// ParseResponse parses and validates a SAML Reponse.
//
// Options:
// - InsecureSkipRequestIDValidation
// - InsecureSkipAssertionConditionValidation
// - InsecureSkipSignatureValidation
// - ValidateResponseSignature
// - ValidateAssertionSignature
// - WithAssertionConsumerServiceURL
// - WithClock
// - WithRelayState
// - RequireRequestState
// - WithCache
// - WithStale
func (sp *ServiceProvider) ParseResponse(
	samlResp string,
	requestID string,
	opt ...Option,
) (*core.Response, error) {
	const op = "saml.(ServiceProvider).ParseResponse"
	opts := getParseResponseOptions(opt...)

	switch {
	case sp == nil:
		return nil, fmt.Errorf("%s: missing service provider %w", op, ErrInternal)
	case samlResp == "":
		return nil, fmt.Errorf("%s: missing saml response: %w", op, ErrInvalidParameter)
	case requestID == "":
		return nil, fmt.Errorf("%s: missing request ID: %w", op, ErrInvalidParameter)
	case isNil(opts.clock):
		return nil, fmt.Errorf(
			"%s: error initializing parser: %s: missing clock: %w",
			op,
			"saml.(ServiceProvider).internalParser",
			ErrInvalidParameter,
		)
	case opts.skipSignatureValidation && (opts.validateResponseSignature || opts.validateAssertionSignature):
		return nil, fmt.Errorf("%s: option `skip signature validation` cannot be true with any validate signature option : %w", op, ErrInvalidParameter)
	}

	state, hasState := sp.RequestState(requestID)
	switch {
	case hasState && state.Consumed():
		return nil, fmt.Errorf(
			"%s: SAML response for request ID %q was already consumed: %w",
			op,
			requestID,
			ErrRequestStateConsumed,
		)
	case hasState && state.Expired(opts.clock.Now()):
		err := fmt.Errorf(
			"%s: metadata generation for request ID %q is no longer valid: %w",
			op,
			requestID,
			ErrRequestStateExpired,
		)
		sp.noteRequestFailure(requestID, "metadata-validity", err)
		return nil, err
	case hasState && opts.relayStateSet && state.RelayState != opts.relayState:
		err := fmt.Errorf(
			"%s: RelayState for request ID %q doesn't match the value bound to the AuthnRequest: %w",
			op,
			requestID,
			ErrRequestStateMismatch,
		)
		sp.noteRequestFailure(requestID, "relay-state", err)
		return nil, err
	case !hasState && opts.requireRequestState:
		return nil, fmt.Errorf(
			"%s: no pending SAML request state for request ID %q: %w",
			op,
			requestID,
			ErrRequestStateMissing,
		)
	}

	assertionConsumerServiceURL := opts.assertionConsumerServiceURL
	if hasState {
		switch {
		case assertionConsumerServiceURL == "":
			assertionConsumerServiceURL = state.AssertionConsumerServiceURL
		case state.AssertionConsumerServiceURL != "" &&
			assertionConsumerServiceURL != state.AssertionConsumerServiceURL:
			err := fmt.Errorf(
				"%s: ACS URL for request ID %q doesn't match the value bound to the AuthnRequest: %w",
				op,
				requestID,
				ErrRequestStateMismatch,
			)
			sp.noteRequestFailure(requestID, "acs-url", err)
			return nil, err
		}
	}

	var trust *idpTrust
	if hasState && (state.DescriptorCount > 0 || len(state.Certificates) > 0) {
		trust = trustFromRequestState(state)
	} else {
		snap, err := sp.idpMetadataSnapshot(
			WithCache(opts.cache),
			WithStale(opts.useStale),
		)
		if err != nil {
			err = fmt.Errorf("%s: %w", "saml.(ServiceProvider).internalParser", err)
			sp.noteRequestFailure(requestID, "metadata", err)
			return nil, fmt.Errorf("%s: error initializing parser: %w", op, err)
		}
		trust = snap.trust()
	}

	// We use github.com/russellhaering/gosaml2 for SAMLResponse signature and condition validation.
	ip, err := sp.internalParserWithTrust(
		opts.skipSignatureValidation,
		assertionConsumerServiceURL,
		opts.clock,
		trust,
		state.ServiceProviderEntityID,
	)
	if err != nil {
		sp.noteRequestFailure(requestID, "metadata", err)
		return nil, fmt.Errorf("%s: error initializing parser: %w", op, err)
	}

	// This will validate the response and all assertions.
	response, err := ip.ValidateEncodedResponse(samlResp)
	switch {
	case err != nil:
		sp.noteRequestFailure(requestID, "response-signature", err)
		return nil, fmt.Errorf("%s: unable to validate encoded response: %w", op, err)
	case len(response.Assertions) == 0:
		// note: this is currently unreachable since the call to
		// ip.ValidateEncodedResponse(...) above will return an err if there are
		// no assertions, but we've left this here since it's a required for our
		// implementation as well.
		err := fmt.Errorf("%s: %w", op, ErrMissingAssertions)
		sp.noteRequestFailure(requestID, "assertions", err)
		return nil, err
	case !opts.skipRequestIDValidation && response.InResponseTo != requestID:
		err := fmt.Errorf(
			"InResponseTo (%s) doesn't match the expected requestID (%s)",
			response.InResponseTo,
			requestID,
		)
		sp.noteRequestFailure(requestID, "request-id", err)
		return nil, err
	case !opts.skipAssertionConditionValidation:
		// Verify conditions for all assertions
		for _, assert := range response.Assertions {
			warnings, err := ip.VerifyAssertionConditions(&assert)
			switch {
			case err != nil:
				sp.noteRequestFailure(requestID, "assertion-conditions", err)
				return nil, fmt.Errorf("%s: %w", op, err)
			case warnings.InvalidTime:
				// note: this is currently unreachable since the call to
				// ip.ValidateEncodedResponse(...) above will return an err if
				// the time is invalid, but we've left this here since it's a
				// required for our implementation as well.
				err := fmt.Errorf("%s: %w", op, ErrInvalidTime)
				sp.noteRequestFailure(requestID, "assertion-time", err)
				return nil, err
			case warnings.NotInAudience:
				err := fmt.Errorf("%s: %w", op, ErrInvalidAudience)
				sp.noteRequestFailure(requestID, "audience", err)
				return nil, err
			case assert.Subject == nil || assert.Subject.NameID == nil:
				// note: this is currently unreachable since the call to
				// ip.ValidateEncodedResponse(...) above will return an err if
				// there isn't a subject, but we've left this here since it's a
				// required for our implementation as well.
				err := fmt.Errorf("%s: %w", op, ErrMissingSubject)
				sp.noteRequestFailure(requestID, "subject", err)
				return nil, err
			case assert.Subject.SubjectConfirmation != nil &&
				assert.Subject.SubjectConfirmation.SubjectConfirmationData != nil &&
				assert.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo != requestID:
				err := fmt.Errorf(
					"SubjectConfirmationData.InResponseTo (%s) doesn't match the expected requestID (%s)",
					assert.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo,
					requestID,
				)
				sp.noteRequestFailure(requestID, "subject-confirmation", err)
				return nil, err
			case assert.AttributeStatement == nil:
				err := fmt.Errorf("%s: %w", op, ErrMissingAttributeStmt)
				sp.noteRequestFailure(requestID, "attribute-statement", err)
				return nil, err
			}
		}
	}

	samlResponse := core.Response{Response: *response}
	if opts.validateResponseSignature || opts.validateAssertionSignature {
		// func ip.ValidateEncodedResponse(...) above only requires either `response or all its `assertions` are signed,
		// but does not require both. The validateSignature function will validate either response or assertion
		// or both is surely signed depending on the parse response options given.
		if err := validateSignature(&samlResponse, op, opts); err != nil {
			sp.noteRequestFailure(requestID, "signature-policy", err)
			return nil, err
		}
	}

	var metadataIssuer string
	var metadataGeneration uint64
	var certificateFingerprints []string
	var relayState string
	if hasState {
		relayState = state.RelayState
	}
	if hasState && (state.DescriptorCount > 0 || len(state.Certificates) > 0) {
		metadataIssuer = state.Issuer
		metadataGeneration = state.MetadataGeneration
		certificateFingerprints = append([]string(nil), state.CertificateFingerprints...)
	} else if trust != nil {
		metadataIssuer = trust.issuer
		metadataGeneration = trust.generation
		certificateFingerprints = append([]string(nil), trust.certificateFingerprints...)
	}
	if opts.relayStateSet {
		relayState = opts.relayState
	}
	samlResponse.RequestID = requestID
	samlResponse.RelayState = relayState
	samlResponse.MetadataIssuer = metadataIssuer
	samlResponse.MetadataGeneration = metadataGeneration
	samlResponse.CertificateFingerprints = certificateFingerprints

	if hasState {
		consumed, err := sp.runtime.consume(requestID, opts.clock.Now())
		switch {
		case err != nil:
			sp.noteRequestFailure(requestID, "consume", err)
			return nil, fmt.Errorf(
				"%s: SAML response for request ID %q was already consumed: %w",
				op,
				requestID,
				ErrRequestStateConsumed,
			)
		case !consumed:
			err := fmt.Errorf(
				"%s: unable to commit SAML response for request ID %q: %w",
				op,
				requestID,
				ErrRequestStateMissing,
			)
			sp.noteRequestFailure(requestID, "consume", err)
			return nil, err
		}
	}

	return &samlResponse, nil
}

// ParseACSResponse parses an ACS response while binding the response to the
// RelayState returned by the identity provider.
func (sp *ServiceProvider) ParseACSResponse(
	samlResp string,
	requestID string,
	relayState string,
	opt ...Option,
) (*core.Response, error) {
	options := append([]Option(nil), opt...)
	options = append(options, WithRelayState(relayState))
	return sp.ParseResponse(samlResp, requestID, options...)
}

// ResponseRequestID extracts the InResponseTo request ID from a base64-encoded
// SAML response.  ACS handlers use it to locate the recoverable AuthnRequest
// state before validating or consuming the response.
func ResponseRequestID(samlResp string) (string, error) {
	const op = "saml.ResponseRequestID"

	if samlResp == "" {
		return "", fmt.Errorf("%s: missing saml response: %w", op, ErrInvalidParameter)
	}

	trimmed := strings.TrimPrefix(strings.TrimSpace(samlResp), "\ufeff")
	raw := []byte(trimmed)
	if !strings.HasPrefix(trimmed, "<") {
		normalized := strings.Join(strings.Fields(samlResp), "")
		var decoded []byte
		for _, encoding := range []*base64.Encoding{
			base64.StdEncoding,
			base64.RawStdEncoding,
			base64.URLEncoding,
			base64.RawURLEncoding,
		} {
			value, err := encoding.DecodeString(normalized)
			if err == nil {
				decoded = value
				break
			}
		}
		if decoded == nil {
			return "", fmt.Errorf("%s: unable to decode SAML response: %w", op, ErrInvalidParameter)
		}
		raw = decoded
	}

	var response struct {
		XMLName      xml.Name
		InResponseTo string `xml:"InResponseTo,attr"`
	}
	if err := xml.Unmarshal(raw, &response); err != nil {
		return "", fmt.Errorf("%s: unable to parse SAML response: %w", op, ErrInvalidParameter)
	}
	if response.XMLName.Local != "Response" {
		return "", fmt.Errorf("%s: expected a SAML Response element: %w", op, ErrInvalidParameter)
	}
	if response.InResponseTo == "" {
		return "", fmt.Errorf("%s: missing InResponseTo: %w", op, ErrInvalidParameter)
	}
	return response.InResponseTo, nil
}

func (sp *ServiceProvider) internalParser(
	skipSignatureValidation bool,
	assertionConsumerServiceURL string,
	clock clockwork.Clock,
) (*saml2.SAMLServiceProvider, error) {
	snap, err := sp.idpMetadataSnapshot()
	if err != nil {
		const op = "saml.(ServiceProvider).internalParser"
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return sp.internalParserWithTrust(
		skipSignatureValidation,
		assertionConsumerServiceURL,
		clock,
		snap.trust(),
		"",
	)
}

func (sp *ServiceProvider) internalParserWithTrust(
	skipSignatureValidation bool,
	assertionConsumerServiceURL string,
	clock clockwork.Clock,
	trust *idpTrust,
	serviceProviderEntityID string,
) (*saml2.SAMLServiceProvider, error) {
	const op = "saml.(ServiceProvider).internalParser"
	switch {
	case isNil(clock):
		return nil, fmt.Errorf("%s: missing clock: %w", op, ErrInvalidParameter)
	}
	if trust == nil {
		snap, err := sp.idpMetadataSnapshot()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		trust = snap.trust()
	}
	switch {
	case trust == nil:
		return nil, fmt.Errorf("%s: missing IdP metadata: %w", op, ErrInternal)
	case trust.descriptorCount != 1:
		return nil, fmt.Errorf("%s: expected one IdP descriptor and got %d: %w", op, trust.descriptorCount, ErrInternal)
	}

	var certStore dsig.MemoryX509CertificateStore
	for _, xcert := range trust.certificates {
		parsed, err := parseX509Certificate(xcert)
		if err != nil {
			return nil, fmt.Errorf("%s: unable to parse cert: %w", op, err)
		}
		certStore.Roots = append(certStore.Roots, parsed) // append works just fine with a nil slice
	}

	if assertionConsumerServiceURL == "" {
		assertionConsumerServiceURL = sp.cfg.AssertionConsumerServiceURL
	}
	if serviceProviderEntityID == "" {
		serviceProviderEntityID = sp.cfg.EntityID
	}

	return &saml2.SAMLServiceProvider{
		IdentityProviderIssuer:      trust.issuer,
		IDPCertificateStore:         &certStore,
		ServiceProviderIssuer:       serviceProviderEntityID,
		AudienceURI:                 serviceProviderEntityID,
		AssertionConsumerServiceURL: assertionConsumerServiceURL,
		SkipSignatureValidation:     skipSignatureValidation,
		Clock:                       dsig.NewFakeClock(clock),
	}, nil
}

// parseX509Certificate parses the contents of a <ds:X509Certificate> which is a
// base64-encoded ASN.1 DER certificate. It does not parse PEM-encoded certificates.
func parseX509Certificate(cert string) (*x509.Certificate, error) {
	const op = "saml.parseCert"
	switch {
	case cert == "":
		return nil, fmt.Errorf("%s: missing certificate: %w", op, ErrInvalidParameter)
	default:
		regex := regexp.MustCompile(`\s+`)
		cert = regex.ReplaceAllString(cert, "")
		if cert == "" {
			return nil, fmt.Errorf("%s: certificate was only whitespace: %w", op, ErrInvalidParameter)
		}
	}
	certBytes, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return nil, fmt.Errorf("cannot decode certificate: %s", err)
	}
	parsedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse certificate: %s", err)
	}

	return parsedCert, nil
}

func parsePEMCertificate(cert []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(cert)
	if block == nil {
		return nil, fmt.Errorf("no certificate found")
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("extra data found after certificate: %s", rest)
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("wrong block type found: %q", block.Type)
	}

	return x509.ParseCertificate(block.Bytes)
}

func validateSignature(response *core.Response, op string, opts parseResponseOptions) error {
	switch {
	case response.SignatureValidated:
		// When decoding a signed response, the internal decoder will automatically
		// verify the validity of both the response signature and any assertions
		// that are signed. Any unsigned assertions will be handled by the response
		// envelope signature. Only when all of this is true will the internal
		// decoder set the SignatureValidated field be set to true.
		return nil
	case !response.SignatureValidated && opts.validateResponseSignature:
		// Our response envelope is not signed but we require it
		return fmt.Errorf("%s: %w", op, ErrInvalidSignature)
	case !response.SignatureValidated && opts.validateAssertionSignature:
		// Our response envelope is not signed but we require that each assertion
		// is signed. The internal decoder will have set SignatureValidated on
		// each assertion in this code path. We can use to determine whether or not
		// it is valid.
		for assert := range slices.Values(response.Assertions()) {
			// note: at one time func ip.ValidateEncodedResponse(...) above allows all signed or all unsigned
			// assertions, and will give error if there is a mix of both. We are still looping on all assertions
			// instead of retrieving signature for one assertion, so we do not depend on dependency implementation.
			if !assert.SignatureValidated {
				return fmt.Errorf("%s: %w", op, ErrInvalidSignature)
			}
		}

		return nil
	default:
		// This ought to be unreachable but we'll catch here.
		return fmt.Errorf("%s: %w", op, ErrInvalidSignature)
	}
}
