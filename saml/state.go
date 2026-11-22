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

const (
	defaultMaxRequestStates    = 4096
	defaultRequestTombstoneTTL = time.Hour
)

// MetadataSnapshot is an immutable description of an identity provider
// metadata document. AuthnRequests and response validation are tied to one of
// these snapshots so an issuer, a signing certificate set and a request can
// never be mixed across metadata generations.
type MetadataSnapshot struct {
	Generation              uint64                         `json:"generation"`
	Issuer                  string                         `json:"issuer"`
	Certificates            []string                       `json:"certificates,omitempty"`
	CertificateFingerprints []string                       `json:"certificate_fingerprints,omitempty"`
	Destinations            map[core.ServiceBinding]string `json:"destinations,omitempty"`
	ValidUntil              *time.Time                     `json:"valid_until,omitempty"`
}

// RequestState is the recoverable state for one SAML authentication request.
//
// A request generation is allocated when the request is admitted. The request
// ID, RelayState, binding, ACS URL, metadata generation and tab generation are
// frozen at that point. The state is safe to serialize with encoding/json, so
// callers can keep authentication sessions across a process restart and restore
// them with ServiceProvider.RestoreRequestState.
type RequestState struct {
	RequestID  string              `json:"request_id"`
	RelayState string              `json:"relay_state,omitempty"`
	Binding    core.ServiceBinding `json:"binding,omitempty"`

	// RelayStateDigest is the SHA-256 digest of RelayState. It is intended for
	// audit records that should not persist a raw RelayState value.
	RelayStateDigest string `json:"relay_state_digest,omitempty"`

	// Generation is the request/tab generation. RequestGeneration and
	// TabGeneration are kept as explicit aliases for callers that name the
	// same value after the participating object.
	Generation        uint64 `json:"generation"`
	RequestGeneration uint64 `json:"request_generation,omitempty"`
	TabGeneration     uint64 `json:"tab_generation,omitempty"`

	ServiceProviderEntityID     string `json:"service_provider_entity_id,omitempty"`
	AssertionConsumerServiceURL string `json:"assertion_consumer_service_url,omitempty"`

	MetadataGeneration uint64 `json:"metadata_generation"`
	Issuer             string `json:"issuer"`
	// MetadataIssuer mirrors Issuer for callers that keep metadata evidence
	// separate from the request identity.
	MetadataIssuer string `json:"metadata_issuer,omitempty"`

	Certificates            []string `json:"certificates,omitempty"`
	CertificateFingerprints []string `json:"certificate_fingerprints,omitempty"`
	DescriptorCount         int      `json:"descriptor_count,omitempty"`

	Destinations map[core.ServiceBinding]string `json:"destinations,omitempty"`
	ValidUntil   *time.Time                     `json:"valid_until,omitempty"`

	CreatedAt   time.Time  `json:"created_at"`
	ConsumedAt  *time.Time `json:"consumed_at,omitempty"`
	CancelledAt *time.Time `json:"cancelled_at,omitempty"`

	// Committed is set once the request has been handed to a browser through a
	// POST or redirect binding. An uncommitted request may still be rebuilt by
	// callers of the lower-level CreateAuthnRequest API.
	Committed bool `json:"committed,omitempty"`

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
	if r.CancelledAt != nil {
		v := *r.CancelledAt
		out.CancelledAt = &v
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

// Cancelled reports whether the request was explicitly abandoned.
func (r RequestState) Cancelled() bool {
	return r.CancelledAt != nil
}

// Terminal reports whether the request can no longer produce a session.
func (r RequestState) Terminal() bool {
	return r.Consumed() || r.Cancelled()
}

// Expired reports whether the metadata snapshot that produced this request is
// no longer valid at now.
func (r RequestState) Expired(now time.Time) bool {
	return r.ValidUntil != nil && !now.Before(*r.ValidUntil)
}

// Report returns an audit line for the request. It includes the request ID and
// the RelayState digest, but not the raw RelayState value.
func (r RequestState) Report() string {
	stage := r.FailureStage
	if stage == "" && r.Consumed() {
		stage = "consumed"
	}
	if stage == "" && r.Cancelled() {
		stage = "cancelled"
	}
	return fmt.Sprintf(
		"request_id=%q relay_state_digest=%q generation=%d "+
			"metadata_generation=%d issuer=%q binding=%q stage=%q",
		r.RequestID,
		r.RelayStateDigest,
		r.Generation,
		r.MetadataGeneration,
		r.Issuer,
		r.Binding,
		stage,
	)
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
		issuer:                  firstNonEmpty(state.Issuer, state.MetadataIssuer),
		certificates:            append([]string(nil), state.Certificates...),
		certificateFingerprints: append([]string(nil), state.CertificateFingerprints...),
		descriptorCount:         descriptorCount,
		validUntil:              state.ValidUntil,
	}
}

func newMetadataSnapshot(
	ed *metadata.EntityDescriptorIDPSSO,
	now time.Time,
	sourceKey string,
) *metadataSnapshot {
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

	// The response parser only supports one IdP descriptor. Preserve the same
	// rule here so an invalid document cannot acquire a partial certificate set
	// before ParseResponse rejects it.
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
	acsURL string,
) RequestState {
	state := RequestState{
		RequestID:                   id,
		RelayState:                  relayState,
		RelayStateDigest:            RelayStateDigest(relayState),
		Binding:                     binding,
		ServiceProviderEntityID:     serviceProviderEntityID,
		AssertionConsumerServiceURL: acsURL,
		MetadataGeneration:          snap.generation,
		Issuer:                      snap.issuer,
		MetadataIssuer:              snap.issuer,
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
	mu           sync.Mutex
	generation   uint64
	snapshot     *metadataSnapshot
	requests     map[string]*RequestState
	maxRequests  int
	tombstoneTTL time.Duration
}

func newServiceRuntime() *serviceRuntime {
	return &serviceRuntime{
		requests:     map[string]*RequestState{},
		maxRequests:  defaultMaxRequestStates,
		tombstoneTTL: defaultRequestTombstoneTTL,
	}
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
	case !sameTime(a.validUntil, b.validUntil):
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

func sameTime(a, b *time.Time) bool {
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

func (r *serviceRuntime) putRequest(state RequestState, commit bool) (RequestState, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initLocked()
	r.pruneLocked(state.CreatedAt)

	existing, ok := r.requests[state.RequestID]
	if ok {
		switch {
		case existing.Consumed():
			return existing.Clone(), false, fmt.Errorf(
				"request ID %q was already consumed: %w",
				state.RequestID,
				ErrRequestStateConsumed,
			)
		case existing.Cancelled():
			return existing.Clone(), false, fmt.Errorf(
				"request ID %q was cancelled: %w",
				state.RequestID,
				ErrRequestStateCancelled,
			)
		case existing.Expired(state.CreatedAt):
			return existing.Clone(), false, fmt.Errorf(
				"request ID %q is bound to an expired metadata generation: %w",
				state.RequestID,
				ErrRequestStateExpired,
			)
		}

		if state.RequestGeneration != 0 && existing.Generation != state.RequestGeneration {
			return existing.Clone(), false, fmt.Errorf(
				"request ID %q is bound to generation %d, not %d: %w",
				state.RequestID,
				existing.Generation,
				state.RequestGeneration,
				ErrRequestStateMismatch,
			)
		}
		if state.RelayState != "" || existing.RelayState != "" {
			switch {
			case existing.RelayState == "":
				existing.RelayState = state.RelayState
				existing.RelayStateDigest = RelayStateDigest(state.RelayState)
			case state.RelayState == "":
				// A caller that does not know RelayState may still reuse the
				// frozen request. The response checks the frozen value.
			case state.RelayState != existing.RelayState:
				return existing.Clone(), false, fmt.Errorf(
					"RelayState for request ID %q is already bound to a different value: %w",
					state.RequestID,
					ErrRequestStateMismatch,
				)
			}
		}
		if state.AssertionConsumerServiceURL != "" {
			switch {
			case existing.AssertionConsumerServiceURL == "":
				existing.AssertionConsumerServiceURL = state.AssertionConsumerServiceURL
			case existing.AssertionConsumerServiceURL != state.AssertionConsumerServiceURL &&
				!existing.Committed:
				// CreateAuthnRequest is a lower-level API and historically
				// allowed rebuilding the same ID with a different ACS URL.
				// Once an initiation binding commits the request, the first
				// ACS value wins.
				existing.AssertionConsumerServiceURL = state.AssertionConsumerServiceURL
			}
		}
		if state.ServiceProviderEntityID != "" &&
			existing.ServiceProviderEntityID == "" {
			existing.ServiceProviderEntityID = state.ServiceProviderEntityID
		}
		if commit {
			existing.Committed = true
		}
		return existing.Clone(), false, nil
	}

	state = state.Clone()
	if state.RequestGeneration != 0 {
		if state.RequestGeneration > r.generation {
			r.generation = state.RequestGeneration
		}
		state.Generation = state.RequestGeneration
	} else {
		r.generation++
		state.Generation = r.generation
	}
	state.RequestGeneration = state.Generation
	state.TabGeneration = state.Generation
	state.RelayStateDigest = RelayStateDigest(state.RelayState)
	state.Committed = commit
	r.requests[state.RequestID] = &state
	return state.Clone(), true, nil
}

func (r *serviceRuntime) bindRelayState(id, relayState string, commit bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initLocked()
	state, ok := r.requests[id]
	if !ok {
		if relayState == "" {
			return nil
		}
		return fmt.Errorf(
			"no pending request state for request ID %q: %w",
			id,
			ErrRequestStateMissing,
		)
	}
	switch {
	case state.Consumed():
		return fmt.Errorf("request ID %q was already consumed: %w", id, ErrRequestStateConsumed)
	case state.Cancelled():
		return fmt.Errorf("request ID %q was cancelled: %w", id, ErrRequestStateCancelled)
	case state.RelayState == relayState:
	case state.RelayState == "":
		state.RelayState = relayState
		state.RelayStateDigest = RelayStateDigest(relayState)
	default:
		return fmt.Errorf(
			"relay state for request ID %q is already bound to a different value: %w",
			id,
			ErrRequestStateMismatch,
		)
	}
	if commit {
		state.Committed = true
	}
	return nil
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
	// Keep the first ACS URL once the request has been committed to a browser.
	if state.AssertionConsumerServiceURL == "" || !state.Committed {
		state.AssertionConsumerServiceURL = acsURL
	}
}

func (r *serviceRuntime) commitRequest(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.requests[id]
	if !ok {
		return fmt.Errorf("no request state for request ID %q: %w", id, ErrRequestStateMissing)
	}
	switch {
	case state.Consumed():
		return fmt.Errorf("request ID %q was already consumed: %w", id, ErrRequestStateConsumed)
	case state.Cancelled():
		return fmt.Errorf("request ID %q was cancelled: %w", id, ErrRequestStateCancelled)
	}
	state.Committed = true
	return nil
}

func (r *serviceRuntime) consume(id string, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.requests[id]
	if !ok {
		return false, nil
	}
	switch {
	case state.Consumed():
		return false, fmt.Errorf("request ID %q was already consumed: %w", id, ErrRequestStateConsumed)
	case state.Cancelled():
		return false, fmt.Errorf("request ID %q was cancelled: %w", id, ErrRequestStateCancelled)
	case state.Expired(now):
		return false, fmt.Errorf("request ID %q is bound to an expired metadata generation: %w", id, ErrRequestStateExpired)
	}
	v := now
	state.ConsumedAt = &v
	state.FailureStage = ""
	state.FailureReason = ""
	return true, nil
}

func (r *serviceRuntime) cancel(id string, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.requests[id]
	if !ok {
		return false, fmt.Errorf("no request state for request ID %q: %w", id, ErrRequestStateMissing)
	}
	switch {
	case state.Consumed():
		return false, fmt.Errorf("request ID %q was already consumed: %w", id, ErrRequestStateConsumed)
	case state.Cancelled():
		return true, nil
	}
	v := now
	state.CancelledAt = &v
	state.FailureStage = "cancelled"
	return true, nil
}

func (r *serviceRuntime) noteFailure(id, stage string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.requests[id]
	if !ok {
		return
	}
	if state.Terminal() {
		// Do not overwrite the terminal evidence with a late failure from a
		// concurrent replay.
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

func (r *serviceRuntime) hasAny() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests) > 0
}

func (r *serviceRuntime) hasPending(now time.Time) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, state := range r.requests {
		if !state.Terminal() && !state.Expired(now) {
			return true
		}
	}
	return false
}

func (r *serviceRuntime) restore(state RequestState) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initLocked()
	if state.RequestID == "" {
		return fmt.Errorf("request ID not set: %w", ErrInvalidParameter)
	}
	if !state.complete() {
		return fmt.Errorf(
			"request ID %q has incomplete metadata evidence: %w",
			state.RequestID,
			ErrRequestStateIncomplete,
		)
	}
	existing, ok := r.requests[state.RequestID]
	if ok && existing.Terminal() {
		// A consumed or cancelled request must never become usable again,
		// even when an older persisted copy is restored.
		return nil
	}
	if ok {
		if existing.RelayState != "" {
			state.RelayState = existing.RelayState
		}
		if existing.RelayStateDigest != "" {
			state.RelayStateDigest = existing.RelayStateDigest
		}
		if existing.AssertionConsumerServiceURL != "" {
			state.AssertionConsumerServiceURL = existing.AssertionConsumerServiceURL
		}
		if existing.ServiceProviderEntityID != "" {
			state.ServiceProviderEntityID = existing.ServiceProviderEntityID
		}
		if existing.DescriptorCount > 0 || len(existing.Certificates) > 0 {
			state.MetadataGeneration = existing.MetadataGeneration
			state.Issuer = existing.Issuer
			state.MetadataIssuer = existing.MetadataIssuer
			state.Certificates = existing.Certificates
			state.CertificateFingerprints = existing.CertificateFingerprints
			state.DescriptorCount = existing.DescriptorCount
			state.Destinations = existing.Destinations
			state.ValidUntil = existing.ValidUntil
		}
		state.Committed = state.Committed || existing.Committed
		if existing.FailureStage != "" {
			state.FailureStage = existing.FailureStage
			state.FailureReason = existing.FailureReason
		}
		if existing.ConsumedAt != nil {
			state.ConsumedAt = existing.ConsumedAt
		}
		if existing.CancelledAt != nil {
			state.CancelledAt = existing.CancelledAt
		}
	}
	state = state.Clone()
	state.normalizeLocked(&r.generation)
	cloned := state
	r.requests[state.RequestID] = &cloned
	r.pruneLocked(state.CreatedAt)
	return nil
}

func (r *serviceRuntime) initLocked() {
	if r.requests == nil {
		r.requests = map[string]*RequestState{}
	}
	if r.maxRequests <= 0 {
		r.maxRequests = defaultMaxRequestStates
	}
	if r.tombstoneTTL <= 0 {
		r.tombstoneTTL = defaultRequestTombstoneTTL
	}
}

func (r *serviceRuntime) pruneLocked(now time.Time) {
	if len(r.requests) == 0 {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	for id, state := range r.requests {
		if !state.Terminal() {
			continue
		}
		at := state.ConsumedAt
		if state.CancelledAt != nil && (at == nil || state.CancelledAt.After(*at)) {
			at = state.CancelledAt
		}
		if at != nil && now.Sub(*at) > r.tombstoneTTL {
			delete(r.requests, id)
		}
	}
	if len(r.requests) <= r.maxRequests {
		return
	}

	// Evict terminal requests first. Pending requests are only evicted when a
	// caller has accumulated more than the hard limit.
	type candidate struct {
		id       string
		at       time.Time
		terminal bool
	}
	candidates := make([]candidate, 0, len(r.requests))
	for id, state := range r.requests {
		at := state.CreatedAt
		if state.ConsumedAt != nil {
			at = *state.ConsumedAt
		}
		if state.CancelledAt != nil && state.CancelledAt.After(at) {
			at = *state.CancelledAt
		}
		candidates = append(candidates, candidate{id: id, at: at, terminal: state.Terminal()})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].terminal != candidates[j].terminal {
			return candidates[i].terminal
		}
		return candidates[i].at.Before(candidates[j].at)
	})
	for _, c := range candidates {
		if len(r.requests) <= r.maxRequests {
			break
		}
		delete(r.requests, c.id)
	}
}

func (r RequestState) complete() bool {
	return firstNonEmpty(r.Issuer, r.MetadataIssuer) != "" &&
		(r.DescriptorCount > 0 || len(r.Certificates) > 0)
}

func (r *RequestState) normalizeLocked(lastGeneration *uint64) {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	if r.Generation == 0 {
		r.Generation = firstNonZero(r.RequestGeneration, r.TabGeneration)
	}
	if r.Generation == 0 {
		*lastGeneration = *lastGeneration + 1
		r.Generation = *lastGeneration
	}
	if r.Generation > *lastGeneration {
		*lastGeneration = r.Generation
	}
	r.RequestGeneration = r.Generation
	r.TabGeneration = r.Generation
	if r.MetadataIssuer == "" {
		r.MetadataIssuer = r.Issuer
	}
	if r.Issuer == "" {
		r.Issuer = r.MetadataIssuer
	}
	r.RelayStateDigest = RelayStateDigest(r.RelayState)
}

// RequestState returns the recoverable state for a SAML request ID.
func (sp *ServiceProvider) RequestState(requestID string) (RequestState, bool) {
	if sp == nil || sp.runtime == nil {
		return RequestState{}, false
	}
	return sp.runtime.request(requestID)
}

// RequestStates returns all request states known to this service provider,
// ordered by creation time.
func (sp *ServiceProvider) RequestStates() []RequestState {
	if sp == nil || sp.runtime == nil {
		return nil
	}
	return sp.runtime.allRequests()
}

// HasRequestState reports whether this service provider has admitted any
// AuthnRequest. Consumed and cancelled tombstones are included.
func (sp *ServiceProvider) HasRequestState() bool {
	if sp == nil || sp.runtime == nil {
		return false
	}
	return sp.runtime.hasAny()
}

// HasPendingRequestState reports whether at least one admitted request can
// still produce a session.
func (sp *ServiceProvider) HasPendingRequestState() bool {
	if sp == nil || sp.runtime == nil {
		return false
	}
	return sp.runtime.hasPending(time.Now())
}

// CancelRequest abandons a request. A cancelled request can never be used to
// establish a session, and restoring an older copy of the state will not
// resurrect it.
func (sp *ServiceProvider) CancelRequest(requestID string) error {
	const op = "saml.ServiceProvider.CancelRequest"
	switch {
	case sp == nil:
		return fmt.Errorf("%s: missing service provider: %w", op, ErrInternal)
	case requestID == "":
		return fmt.Errorf("%s: missing request ID: %w", op, ErrInvalidParameter)
	case sp.runtime == nil:
		return fmt.Errorf("%s: no request state for request ID %q: %w", op, requestID, ErrRequestStateMissing)
	}
	if _, err := sp.runtime.cancel(requestID, time.Now()); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// CancelRequestState is an alias for CancelRequest.
func (sp *ServiceProvider) CancelRequestState(requestID string) error {
	return sp.CancelRequest(requestID)
}

// CancelAuthnRequest is an alias for CancelRequest.
func (sp *ServiceProvider) CancelAuthnRequest(requestID string) error {
	return sp.CancelRequest(requestID)
}

// RestoreRequestState restores a previously exported RequestState. It is
// idempotent and never resurrects a state that was already consumed or
// cancelled.
//
// The restored state carries the trusted issuer and certificate set for the
// request. Callers must store it in integrity-protected session storage; a
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
	if err := sp.runtime.restore(state); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (sp *ServiceProvider) noteRequestFailure(requestID, stage string, err error) {
	if sp == nil || sp.runtime == nil {
		return
	}
	sp.runtime.noteFailure(requestID, stage, err)
}

// RelayStateDigest returns the lower-case SHA-256 digest of relayState. An
// empty RelayState has an empty digest.
func RelayStateDigest(relayState string) string {
	if relayState == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(relayState))
	return hex.EncodeToString(sum[:])
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
// base64-encoded DER certificate. The result is lower-case hexadecimal.
func CertificateFingerprint(cert string) string {
	if block, _ := pem.Decode([]byte(cert)); block != nil {
		sum := sha256.Sum256(block.Bytes)
		return hex.EncodeToString(sum[:])
	}
	return certificateFingerprint(normalizeCertificate(cert))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstNonZero(values ...uint64) uint64 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
