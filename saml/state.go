// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package saml

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/cap/saml/models/core"
	"github.com/hashicorp/cap/saml/models/metadata"
)

// MetadataSnapshot is an immutable description of an identity provider
// metadata document.  Every AuthnRequest and SAML response validation is tied
// to one of these snapshots so an issuer, a certificate set and a request can
// never be mixed across metadata generations.
type MetadataSnapshot struct {
	Generation              uint64
	Issuer                  string
	Certificates            []string
	CertificateFingerprints []string
	Destinations            map[core.ServiceBinding]string
	ValidUntil              *time.Time
}

// RequestState is the recoverable state for one SAML authentication request.
//
// The state is safe to serialize and restore with encoding/json.  Callers that
// keep authentication sessions across process restarts can store a RequestState
// in that session and restore it with ServiceProvider.RestoreRequestState.
type RequestState struct {
	RequestID  string              `json:"request_id"`
	RelayState string              `json:"relay_state,omitempty"`
	Binding    core.ServiceBinding `json:"binding,omitempty"`

	ServiceProviderEntityID      string `json:"service_provider_entity_id,omitempty"`
	AssertionConsumerServiceURL string `json:"assertion_consumer_service_url,omitempty"`

	MetadataGeneration uint64 `json:"metadata_generation"`
	Issuer             string `json:"issuer"`

	Certificates            []string `json:"certificates,omitempty"`
	CertificateFingerprints []string `json:"certificate_fingerprints,omitempty"`
	DescriptorCount         int      `json:"descriptor_count,omitempty"`
	Destinations            map[core.ServiceBinding]string `json:"destinations,omitempty"`

	ValidUntil *time.Time `json:"valid_until,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`

	FailureStage  string `json:"failure_stage,omitempty"`
	FailureReason string `json:"failure_reason,omitempty"`
}

// Clone returns a deep copy of the request state.
func (r RequestState) Clone() RequestState {
	out := r
	out.Certificates = append([]string(nil), r.Certificates...)
	out.CertificateFingerprints = append([]string(nil), r.CertificateFingerprints...)
	if r.ValidUntil != nil {
		v := *r.ValidUntil
		out.ValidUntil = &v
	}
	if r.ConsumedAt != nil {
		v := *r.ConsumedAt
		out.ConsumedAt = &v
	}
	if r.Destinations != nil {
		out.Destinations = make(map[core.ServiceBinding]string, len(r.Destinations))
		for binding, destination := range r.Destinations {
			out.Destinations[binding] = destination
		}
	}
	return out
}

// Consumed reports whether the request state has already been used to build a
// session.
func (r RequestState) Consumed() bool {
	return r.ConsumedAt != nil
}

// Expired reports whether the metadata snapshot that produced this request is
// no longer valid at now.
func (r RequestState) Expired(now time.Time) bool {
	return r.ValidUntil != nil && !now.Before(*r.ValidUntil)
}

type metadataSnapshot struct {
	generation              uint64
	sourceKey               string
	metadata                *metadata.EntityDescriptorIDPSSO
	issuer                  string
	certificates            []string
	certificateFingerprints []string
	descriptorCount         int
	destinations            map[core.ServiceBinding]string
	validUntil              *time.Time
	cachedUntil             *time.Time
}

func (m *metadataSnapshot) trust() *idpTrust {
	if m == nil {
		return nil
	}
	return &idpTrust{
		generation:              m.generation,
		issuer:                  m.issuer,
		certificates:            m.certificates,
		certificateFingerprints: m.certificateFingerprints,
		descriptorCount:         m.descriptorCount,
		validUntil:              m.validUntil,
	}
}

func (m *metadataSnapshot) export() *MetadataSnapshot {
	if m == nil {
		return nil
	}
	out := &MetadataSnapshot{
		Generation:              m.generation,
		Issuer:                  m.issuer,
		Certificates:            append([]string(nil), m.certificates...),
		CertificateFingerprints: append([]string(nil), m.certificateFingerprints...),
		Destinations:            make(map[core.ServiceBinding]string, len(m.destinations)),
	}
	for binding, destination := range m.destinations {
		out.Destinations[binding] = destination
	}
	if m.validUntil != nil {
		v := *m.validUntil
		out.ValidUntil = &v
	}
	return out
}

type idpTrust struct {
	generation              uint64
	issuer                  string
	certificates            []string
	certificateFingerprints []string
	descriptorCount         int
	validUntil              *time.Time
}

func trustFromRequestState(state RequestState) *idpTrust {
	descriptorCount := state.DescriptorCount
	if descriptorCount == 0 && len(state.Certificates) > 0 {
		descriptorCount = 1
	}
	return &idpTrust{
		generation:              state.MetadataGeneration,
		issuer:                  state.Issuer,
		certificates:            append([]string(nil), state.Certificates...),
		certificateFingerprints: append([]string(nil), state.CertificateFingerprints...),
		descriptorCount:         descriptorCount,
		validUntil:              state.ValidUntil,
	}
}

func newMetadataSnapshot(ed *metadata.EntityDescriptorIDPSSO, now time.Time, sourceKey string) *metadataSnapshot {
	snap := &metadataSnapshot{
		metadata:        ed,
		sourceKey:       sourceKey,
		issuer:          ed.EntityID,
		descriptorCount: len(ed.IDPSSODescriptor),
		destinations:    map[core.ServiceBinding]string{},
	}
	if ed.ValidUntil != nil {
		v := *ed.ValidUntil
		snap.validUntil = &v
	}
	if ed.CacheDuration != nil {
		v := now.Add(time.Duration(*ed.CacheDuration))
		snap.cachedUntil = &v
	}

	// The response parser only supports a single IdP descriptor.  Preserve the
	// exact same rule here so a malformed document cannot acquire a partial
	// certificate set before it is rejected by ParseResponse.
	if snap.descriptorCount == 1 && ed.IDPSSODescriptor[0] == nil {
		snap.descriptorCount = 0
	}
	if snap.descriptorCount == 1 {
		descriptor := ed.IDPSSODescriptor[0]
		for _, keyDescriptor := range descriptor.KeyDescriptor {
			switch keyDescriptor.Use {
			case "", metadata.KeyTypeSigning:
				for _, cert := range keyDescriptor.KeyInfo.X509Data.X509Certificates {
					normalized := normalizeCertificate(cert.Data)
					snap.certificates = append(snap.certificates, normalized)
					snap.certificateFingerprints = append(
						snap.certificateFingerprints,
						certificateFingerprint(normalized),
					)
				}
			}
		}
	}

	// Destination lookup intentionally spans every descriptor, matching
	// EntityDescriptorIDPSSO.GetLocationForBinding.
	for _, descriptor := range ed.IDPSSODescriptor {
		if descriptor == nil {
			continue
		}
		for _, sso := range descriptor.SingleSignOnService {
			if _, ok := snap.destinations[sso.Binding]; !ok {
				snap.destinations[sso.Binding] = sso.Location
			}
		}
	}

	return snap
}

func metadataSourceKey(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	switch {
	case cfg.MetadataURL != "":
		return "url:" + cfg.MetadataURL
	case cfg.MetadataXML != "":
		sum := sha256.Sum256([]byte(cfg.MetadataXML))
		return "xml:" + hex.EncodeToString(sum[:])
	case cfg.MetadataParameters != nil:
		params := cfg.MetadataParameters
		sum := sha256.Sum256([]byte(strings.Join([]string{
			params.Issuer,
			params.SingleSignOnURL,
			normalizeCertificate(params.IDPCertificate),
			string(params.Binding),
		}, "\x00")))
		return "parameters:" + hex.EncodeToString(sum[:])
	default:
		return ""
	}
}

func newRequestState(
	id string,
	relayState string,
	binding core.ServiceBinding,
	snap *metadataSnapshot,
	now time.Time,
	serviceProviderEntityID string,
) RequestState {
	state := RequestState{
		RequestID:                   id,
		RelayState:                  relayState,
		Binding:                     binding,
		ServiceProviderEntityID:     serviceProviderEntityID,
		MetadataGeneration:          snap.generation,
		Issuer:                      snap.issuer,
		Certificates:                append([]string(nil), snap.certificates...),
		CertificateFingerprints:     append([]string(nil), snap.certificateFingerprints...),
		DescriptorCount:             snap.descriptorCount,
		Destinations:                make(map[core.ServiceBinding]string, len(snap.destinations)),
		CreatedAt:                   now,
	}
	if snap.validUntil != nil {
		v := *snap.validUntil
		state.ValidUntil = &v
	}
	for b, destination := range snap.destinations {
		state.Destinations[b] = destination
	}
	return state
}

type serviceRuntime struct {
	mu         sync.Mutex
	generation uint64
	snapshot   *metadataSnapshot
	requests   map[string]*RequestState
}

func newServiceRuntime() *serviceRuntime {
	return &serviceRuntime{requests: map[string]*RequestState{}}
}

func (r *serviceRuntime) currentSnapshot() *metadataSnapshot {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.snapshot
}

func (r *serviceRuntime) installSnapshot(snap *metadataSnapshot) *metadataSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.snapshot != nil && sameMetadataTrust(r.snapshot, snap) {
		snap.generation = r.snapshot.generation
	} else {
		r.generation++
		snap.generation = r.generation
	}
	r.snapshot = snap
	return snap
}

func sameMetadataTrust(a, b *metadataSnapshot) bool {
	switch {
	case a == nil || b == nil:
		return false
	case a.sourceKey != b.sourceKey:
		return false
	case a.issuer != b.issuer:
		return false
	case a.descriptorCount != b.descriptorCount:
		return false
	case !sameMetadataTime(a.validUntil, b.validUntil):
		return false
	case len(a.certificateFingerprints) != len(b.certificateFingerprints):
		return false
	}
	for i := range a.certificateFingerprints {
		if a.certificateFingerprints[i] != b.certificateFingerprints[i] {
			return false
		}
	}
	if len(a.destinations) != len(b.destinations) {
		return false
	}
	for binding, destination := range a.destinations {
		if b.destinations[binding] != destination {
			return false
		}
	}
	return true
}

func sameMetadataTime(a, b *time.Time) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.Equal(*b)
	}
}

func (r *serviceRuntime) request(id string) (RequestState, bool) {
	if r == nil {
		return RequestState{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.requests[id]
	if !ok {
		return RequestState{}, false
	}
	return state.Clone(), true
}

func (r *serviceRuntime) putRequest(state RequestState) (RequestState, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.requests == nil {
		r.requests = map[string]*RequestState{}
	}
	existing, ok := r.requests[state.RequestID]
	if ok {
		if existing.Consumed() {
			return existing.Clone(), false, ErrRequestStateConsumed
		}
		if existing.RelayState == "" && state.RelayState != "" {
			existing.RelayState = state.RelayState
		}
		return existing.Clone(), false, nil
	}
	state = state.Clone()
	r.requests[state.RequestID] = &state
	return state.Clone(), true, nil
}

func (r *serviceRuntime) bindRelayState(id, relayState string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.requests[id]
	if !ok {
		if relayState == "" {
			return nil
		}
		return fmt.Errorf("no pending request state for request ID %q: %w", id, ErrRequestStateMissing)
	}
	switch {
	case state.RelayState == relayState:
		return nil
	case state.RelayState == "":
		state.RelayState = relayState
		return nil
	default:
		return fmt.Errorf(
			"relay state for request ID %q is already bound to a different value: %w",
			id,
			ErrRequestStateMismatch,
		)
	}
}

func (r *serviceRuntime) setAssertionConsumerServiceURL(id, acsURL string) {
	if acsURL == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.requests[id]
	if !ok {
		return
	}
	// Keep the first ACS URL bound to a request ID.  A repeat initiation with
	// the same ID must not move an already-frozen transaction to another ACS.
	if state.AssertionConsumerServiceURL == "" {
		state.AssertionConsumerServiceURL = acsURL
	}
}

func (r *serviceRuntime) setServiceProviderEntityID(id, entityID string) {
	if entityID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.requests[id]
	if !ok {
		return
	}
	if state.ServiceProviderEntityID == "" {
		state.ServiceProviderEntityID = entityID
	}
}

func (r *serviceRuntime) consume(id string, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.requests[id]
	if !ok {
		return false, nil
	}
	if state.Consumed() {
		return false, ErrRequestStateConsumed
	}
	v := now
	state.ConsumedAt = &v
	state.FailureStage = ""
	state.FailureReason = ""
	return true, nil
}

func (r *serviceRuntime) noteFailure(id, stage string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.requests[id]
	if !ok {
		return
	}
	state.FailureStage = stage
	if err != nil {
		state.FailureReason = err.Error()
	}
}

func (r *serviceRuntime) allRequests() []RequestState {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RequestState, 0, len(r.requests))
	for _, state := range r.requests {
		out = append(out, state.Clone())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].RequestID < out[j].RequestID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// RequestState returns the recoverable state for a SAML request ID.
func (sp *ServiceProvider) RequestState(requestID string) (RequestState, bool) {
	if sp == nil || sp.runtime == nil {
		return RequestState{}, false
	}
	return sp.runtime.request(requestID)
}

// RequestStates returns all request states known to this service provider,
// ordered by creation time.  It is intended for audits and for callers that
// persist authentication sessions across restarts.
func (sp *ServiceProvider) RequestStates() []RequestState {
	if sp == nil || sp.runtime == nil {
		return nil
	}
	return sp.runtime.allRequests()
}

// HasRequestState reports whether this service provider has issued any
// AuthnRequest that has a recoverable state.
func (sp *ServiceProvider) HasRequestState() bool {
	if sp == nil || sp.runtime == nil {
		return false
	}
	sp.runtime.mu.Lock()
	defer sp.runtime.mu.Unlock()
	return len(sp.runtime.requests) > 0
}

// RestoreRequestState restores a previously exported RequestState.  It is
// idempotent and never resurrects a state that was already consumed.
//
// The restored state carries the trusted issuer and certificate set for the
// request.  Callers must store it in integrity-protected session storage; a
// tampered state would describe a different identity provider.
func (sp *ServiceProvider) RestoreRequestState(state RequestState) error {
	const op = "saml.ServiceProvider.RestoreRequestState"

	switch {
	case sp == nil:
		return fmt.Errorf("%s: missing service provider: %w", op, ErrInternal)
	case state.RequestID == "":
		return fmt.Errorf("%s: request ID not set: %w", op, ErrInvalidParameter)
	}
	if sp.runtime == nil {
		sp.runtime = newServiceRuntime()
	}

	sp.runtime.mu.Lock()
	defer sp.runtime.mu.Unlock()
	if sp.runtime.requests == nil {
		sp.runtime.requests = map[string]*RequestState{}
	}
	existing, ok := sp.runtime.requests[state.RequestID]
	if ok && existing.Consumed() {
		// A consumed request must never become usable again, even when an
		// older persisted copy is restored.
		return nil
	}
	if ok {
		if state.ConsumedAt == nil {
			// Keep the most advanced failure evidence from the live state.
			state.FailureStage = existing.FailureStage
			state.FailureReason = existing.FailureReason
		}
		if existing.RelayState != "" {
			state.RelayState = existing.RelayState
		}
		if existing.AssertionConsumerServiceURL != "" {
			state.AssertionConsumerServiceURL = existing.AssertionConsumerServiceURL
		}
		if existing.ServiceProviderEntityID != "" {
			state.ServiceProviderEntityID = existing.ServiceProviderEntityID
		}
		if existing.DescriptorCount > 0 || len(existing.Certificates) > 0 {
			// A restored copy may be older than the live transaction.  The
			// live trust state wins so a stale session file cannot replace a
			// request's issuer or certificate set.
			state.MetadataGeneration = existing.MetadataGeneration
			state.Issuer = existing.Issuer
			state.Certificates = existing.Certificates
			state.CertificateFingerprints = existing.CertificateFingerprints
			state.DescriptorCount = existing.DescriptorCount
			state.Destinations = existing.Destinations
			state.ValidUntil = existing.ValidUntil
		}
	}
	cloned := state.Clone()
	sp.runtime.requests[state.RequestID] = &cloned
	return nil
}

func (sp *ServiceProvider) noteRequestFailure(requestID, stage string, err error) {
	if sp == nil || sp.runtime == nil {
		return
	}
	sp.runtime.noteFailure(requestID, stage, err)
}

func normalizeCertificate(cert string) string {
	return strings.Join(strings.Fields(cert), "")
}

func certificateFingerprint(normalizedCert string) string {
	if normalizedCert == "" {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(normalizedCert)
	if err != nil {
		raw = []byte(normalizedCert)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// CertificateFingerprint returns the SHA-256 fingerprint of a PEM or
// base64-encoded DER certificate.  The result is lower-case hexadecimal.
func CertificateFingerprint(cert string) string {
	if block, _ := pem.Decode([]byte(cert)); block != nil {
		sum := sha256.Sum256(block.Bytes)
		return hex.EncodeToString(sum[:])
	}
	return certificateFingerprint(normalizeCertificate(cert))
}
