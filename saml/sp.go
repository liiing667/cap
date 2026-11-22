// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package saml

import (
	_ "embed"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/hashicorp/cap/saml/models/core"
	"github.com/hashicorp/cap/saml/models/metadata"
	"github.com/jonboulle/clockwork"
	dsig "github.com/russellhaering/goxmldsig/types"
)

//go:embed authn_request.gohtml
var postBindingTempl string

type metadataOptions struct {
	wantAssertionsSigned bool
	nameIDFormats        []core.NameIDFormat
	acsServiceBinding    core.ServiceBinding
	additionalACSs       []metadata.Endpoint
}

func metadataOptionsDefault() metadataOptions {
	return metadataOptions{
		wantAssertionsSigned: true,
		acsServiceBinding:    core.ServiceBindingHTTPPost,
	}
}

func getMetadataOptions(opt ...Option) metadataOptions {
	opts := metadataOptionsDefault()
	ApplyOpts(&opts, opt...)
	return opts
}

// InsecureWantAssertionsUnsigned provides a way to optionally request that you
// want insecure/unsigned assertions.
func InsecureWantAssertionsUnsigned() Option {
	return func(o interface{}) {
		if o, ok := o.(*metadataOptions); ok {
			o.wantAssertionsSigned = false
		}
	}
}

// WithMetadataNameIDFormat provides an optional name ID formats, which are
// added to the existing set.
func WithMetadataNameIDFormat(format ...core.NameIDFormat) Option {
	return func(o interface{}) {
		if o, ok := o.(*metadataOptions); ok {
			o.nameIDFormats = append(o.nameIDFormats, format...)
		}
	}
}

// WithACSServiceBinding provides an optional service binding.
func WithACSServiceBinding(b core.ServiceBinding) Option {
	return func(o interface{}) {
		if o, ok := o.(*metadataOptions); ok {
			o.acsServiceBinding = b
		}
	}
}

// WithAdditionalACSEndpoint provides an optional additional ACS endpoint
func WithAdditionalACSEndpoint(b core.ServiceBinding, location url.URL) Option {
	return func(o interface{}) {
		if o, ok := o.(*metadataOptions); ok {
			o.additionalACSs = append(o.additionalACSs, metadata.Endpoint{
				Binding:  b,
				Location: location.String(),
			})
		}
	}
}

// ServiceProvider defines a type for service providers
type ServiceProvider struct {
	cfg *Config

	metadata            *metadata.EntityDescriptorIDPSSO
	metadataCachedUntil *time.Time
	metadataLock        sync.Mutex
	metadataSnapshot    *metadataSnapshot
	runtime             *serviceRuntime
}

// NewServiceProvider creates a new ServiceProvider.
func NewServiceProvider(cfg *Config) (*ServiceProvider, error) {
	const op = "saml.NewServiceProvider"

	if cfg == nil {
		return nil, fmt.Errorf(
			"%s: no provider config provided",
			op,
		)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf(
			"%s: insufficient provider config: %w",
			op, err,
		)
	}

	if cfg.runtime == nil {
		cfg.runtime = newServiceRuntime()
	}
	if cfg.ValidUntil == nil {
		cfg.ValidUntil = defaultValidUntil
	}
	if cfg.GenerateAuthRequestID == nil {
		cfg.GenerateAuthRequestID = DefaultGenerateAuthRequestID
	}

	sp := &ServiceProvider{
		cfg:     cfg,
		runtime: cfg.runtime,
	}
	sp.restoreMetadataSnapshot()
	return sp, nil
}

func (sp *ServiceProvider) restoreMetadataSnapshot() {
	if sp == nil || sp.runtime == nil {
		return
	}
	snap := sp.runtime.currentSnapshot()
	if snap == nil || snap.sourceKey != metadataSourceKey(sp.cfg) {
		return
	}
	sp.metadata = snap.metadata
	sp.metadataSnapshot = snap
	if snap.cachedUntil != nil {
		cachedUntil := *snap.cachedUntil
		sp.metadataCachedUntil = &cachedUntil
	}
}

// Config returns the service provider config.
func (sp *ServiceProvider) Config() *Config {
	return sp.cfg
}

// CreateMetadata creates the metadata XML for the service provider.
//
// Options:
// - InsecureWantAssertionsUnsigned
// - WithNameIDFormats
// - WithACSServiceBinding
// - WithAdditonalACSEndpoint
func (sp *ServiceProvider) CreateMetadata(opt ...Option) *metadata.EntityDescriptorSPSSO {
	validUntil := sp.cfg.ValidUntil()

	opts := getMetadataOptions(opt...)

	spsso := metadata.EntityDescriptorSPSSO{}
	spsso.EntityID = sp.cfg.EntityID
	spsso.ValidUntil = &validUntil

	spssoDescriptor := &metadata.SPSSODescriptor{}
	spssoDescriptor.ProtocolSupportEnumeration = metadata.ProtocolSupportEnumerationProtocol
	spssoDescriptor.NameIDFormat = opts.nameIDFormats
	spssoDescriptor.AuthnRequestsSigned = false // always false for now until request signing is supported.
	spssoDescriptor.WantAssertionsSigned = opts.wantAssertionsSigned
	spssoDescriptor.AssertionConsumerService = []metadata.IndexedEndpoint{
		{
			Endpoint: metadata.Endpoint{
				Binding:  opts.acsServiceBinding,
				Location: sp.cfg.AssertionConsumerServiceURL,
			},
			Index: 1,
		},
	}

	for i, a := range opts.additionalACSs {
		spssoDescriptor.AssertionConsumerService = append(
			spssoDescriptor.AssertionConsumerService,
			metadata.IndexedEndpoint{
				Endpoint: a,
				Index:    i + 2, // The first index is already taken.
			},
		)
	}

	spsso.SPSSODescriptor = []*metadata.SPSSODescriptor{spssoDescriptor}

	return &spsso
}

type idpMetadataOptions struct {
	cache    bool
	useStale bool
	clock    clockwork.Clock
}

func idpMetadataOptionsDefault() idpMetadataOptions {
	return idpMetadataOptions{
		cache:    true,
		useStale: false,
		clock:    clockwork.NewRealClock(),
	}
}

func getIDPMetadataOptions(opt ...Option) idpMetadataOptions {
	opts := idpMetadataOptionsDefault()
	ApplyOpts(&opts, opt...)
	return opts
}

// WithCache control whether we should cache IDP Metadata.
func WithCache(cache bool) Option {
	return func(o interface{}) {
		switch opts := o.(type) {
		case *idpMetadataOptions:
			opts.cache = cache
		case *authnRequestOptions:
			opts.cache = cache
		case *parseResponseOptions:
			opts.cache = cache
		}
	}
}

// WithStale control whether we should use a stale IDP Metadata document if
// refreshing it fails.
func WithStale(stale bool) Option {
	return func(o interface{}) {
		switch opts := o.(type) {
		case *idpMetadataOptions:
			opts.useStale = stale
		case *authnRequestOptions:
			opts.useStale = stale
		case *parseResponseOptions:
			opts.useStale = stale
		}
	}
}

// IDPMetadata fetches the metadata XML document from the configured identity provider.
// Options:
// - WithClock
// - WithCache
// - WithStale
func (sp *ServiceProvider) IDPMetadata(opt ...Option) (*metadata.EntityDescriptorIDPSSO, error) {
	snap, err := sp.idpMetadataSnapshot(opt...)
	if err != nil {
		return nil, err
	}
	return snap.metadata, nil
}

// MetadataSnapshot returns the immutable metadata generation currently in use.
// Options are the same as IDPMetadata.
func (sp *ServiceProvider) MetadataSnapshot(opt ...Option) (*MetadataSnapshot, error) {
	snap, err := sp.idpMetadataSnapshot(opt...)
	if err != nil {
		return nil, err
	}
	return snap.export(), nil
}

// IDPMetadataSnapshot is an alias for MetadataSnapshot.
func (sp *ServiceProvider) IDPMetadataSnapshot(opt ...Option) (*MetadataSnapshot, error) {
	return sp.MetadataSnapshot(opt...)
}

// MetadataGeneration returns the generation of the current metadata snapshot,
// or zero when no metadata has been loaded yet.
func (sp *ServiceProvider) MetadataGeneration() uint64 {
	if sp == nil {
		return 0
	}
	sp.metadataLock.Lock()
	defer sp.metadataLock.Unlock()
	if sp.metadataSnapshot == nil {
		return 0
	}
	return sp.metadataSnapshot.generation
}

func (sp *ServiceProvider) idpMetadataSnapshot(opt ...Option) (*metadataSnapshot, error) {
	const op = "saml.ServiceProvider.FetchIDPMetadata"

	opts := getIDPMetadataOptions(opt...)

	isValid := func(md *metadata.EntityDescriptorIDPSSO) bool {
		if md == nil {
			return false
		}
		if md.ValidUntil == nil {
			return true
		}
		return opts.clock.Now().Before(*md.ValidUntil)
	}

	isValidSnapshot := func(snap *metadataSnapshot) bool {
		if snap == nil || snap.metadata == nil {
			return false
		}
		if snap.validUntil == nil {
			return true
		}
		return opts.clock.Now().Before(*snap.validUntil)
	}

	isAlive := func(snap *metadataSnapshot, expireAt *time.Time) bool {
		if snap == nil || !opts.cache || expireAt == nil {
			return false
		}

		return opts.clock.Now().Before(*expireAt)
	}

	if sp == nil {
		return nil, fmt.Errorf("%s: missing service provider: %w", op, ErrInternal)
	}
	if sp.cfg == nil {
		return nil, fmt.Errorf("%s: missing service provider config: %w", op, ErrInternal)
	}
	if sp.runtime == nil {
		sp.runtime = newServiceRuntime()
	}

	// Metadata state is always guarded. WithCache(false) bypasses the cached
	// value, but it must not race with a concurrent cached read.
	sp.metadataLock.Lock()
	defer sp.metadataLock.Unlock()

	sourceKey := metadataSourceKey(sp.cfg)
	if sp.metadataSnapshot == nil && sp.metadata != nil {
		// Reconstruct the snapshot when a caller (or an older code path)
		// populated only the metadata pointer.
		snap := newMetadataSnapshot(sp.metadata, opts.clock.Now(), sourceKey)
		if sp.metadataCachedUntil != nil {
			cachedUntil := *sp.metadataCachedUntil
			snap.cachedUntil = &cachedUntil
		}
		sp.metadataSnapshot = sp.runtime.installSnapshot(snap)
		if sp.metadataSnapshot.cachedUntil != nil {
			cachedUntil := *sp.metadataSnapshot.cachedUntil
			sp.metadataCachedUntil = &cachedUntil
		}
	}
	if sp.metadataSnapshot != nil && sp.metadataSnapshot.sourceKey != sourceKey {
		// A configuration change points at a different metadata source. Never
		// serve the previous source's issuer/certificate pair.
		sp.metadata = nil
		sp.metadataSnapshot = nil
		sp.metadataCachedUntil = nil
	}

	if opts.cache {
		switch {
		case !isValidSnapshot(sp.metadataSnapshot):
			sp.metadata = nil
			sp.metadataSnapshot = nil
			sp.metadataCachedUntil = nil
		case isValidSnapshot(sp.metadataSnapshot) && isAlive(sp.metadataSnapshot, sp.metadataCachedUntil):
			return sp.metadataSnapshot, nil
		}
	}

	var err error
	var ed *metadata.EntityDescriptorIDPSSO

	// Order of switch case determines IDP metadata config precedence
	switch {
	case sp.cfg.MetadataURL != "":
		ed, err = fetchIDPMetadata(sp.cfg.MetadataURL)
		switch {
		case err != nil && opts.useStale && isValidSnapshot(sp.metadataSnapshot):
			// An error occurred but we have a cached metadata document that
			// we can use
			return sp.metadataSnapshot, nil
		case err != nil:
			return nil, fmt.Errorf("%s: %w", op, err)
		}

	case sp.cfg.MetadataXML != "":
		ed, err = parseIDPMetadata([]byte(sp.cfg.MetadataXML))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}

	case sp.cfg.MetadataParameters != nil:
		ed, err = constructIDPMetadata(sp.cfg.MetadataParameters)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}

	default:
		return nil, fmt.Errorf("%s: no IDP metadata configuration set: %w", op, ErrInvalidParameter)
	}

	if !isValid(ed) {
		if opts.useStale && isValidSnapshot(sp.metadataSnapshot) {
			return sp.metadataSnapshot, nil
		}
		return nil, fmt.Errorf("the IDP configuration was only valid until %s", ed.ValidUntil.Format(time.RFC3339))
	}

	snap := sp.runtime.installSnapshot(newMetadataSnapshot(ed, opts.clock.Now(), sourceKey))
	sp.metadata = ed
	sp.metadataSnapshot = snap
	sp.metadataCachedUntil = nil
	if snap.cachedUntil != nil {
		cachedUntil := *snap.cachedUntil
		sp.metadataCachedUntil = &cachedUntil
	}

	return snap, nil
}

func fetchIDPMetadata(metadataURL string) (*metadata.EntityDescriptorIDPSSO, error) {
	res, err := http.Get(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch identity provider metadata: %w", err)
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read http body: %w", err)
	}

	meta, err := parseIDPMetadata(raw)
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		if err != nil {
			// Preserve the parse error for error bodies that are not a
			// metadata document.
			return nil, err
		}
		return nil, fmt.Errorf(
			"failed to fetch identity provider metadata: unexpected HTTP status %s",
			res.Status,
		)
	}
	if err != nil {
		return nil, err
	}

	return meta, err
}

func parseIDPMetadata(rawXML []byte) (*metadata.EntityDescriptorIDPSSO, error) {
	var ed metadata.EntityDescriptorIDPSSO
	if err := xml.Unmarshal(rawXML, &ed); err != nil {
		return nil, fmt.Errorf("failed to parse identity provider XML metadata: %w", err)
	}

	// [SDP-MD03] https://kantarainitiative.github.io/SAMLprofiles/saml2int.html#_metadata_and_trust_management
	// IDPMetadata without a validUntil attribute on its root element MUST be rejected. IDPMetadata whose root element’s validUntil
	// attribute extends beyond a deployer- or community-imposed threshold MUST be rejected.
	// TODO: VALIDATE

	return &ed, nil
}

func constructIDPMetadata(params *MetadataParameters) (*metadata.EntityDescriptorIDPSSO, error) {
	cert, err := parsePEMCertificate([]byte(params.IDPCertificate))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	keyDescriptor := metadata.KeyDescriptor{
		Use: metadata.KeyTypeSigning,
		KeyInfo: metadata.KeyInfo{
			KeyInfo: dsig.KeyInfo{
				X509Data: dsig.X509Data{
					X509Certificates: []dsig.X509Certificate{
						{
							Data: base64.StdEncoding.EncodeToString(cert.Raw),
						},
					},
				},
			},
		},
	}

	idpSSODescriptor := &metadata.IDPSSODescriptor{
		SSODescriptor: metadata.SSODescriptor{
			RoleDescriptor: metadata.RoleDescriptor{
				KeyDescriptor: []metadata.KeyDescriptor{keyDescriptor},
			},
		},
		WantAuthnRequestsSigned: false,
		SingleSignOnService: []metadata.Endpoint{
			{
				Binding:  params.Binding,
				Location: params.SingleSignOnURL,
			},
		},
	}

	return &metadata.EntityDescriptorIDPSSO{
		EntityDescriptor: metadata.EntityDescriptor{
			EntityID: params.Issuer,
		},
		IDPSSODescriptor: []*metadata.IDPSSODescriptor{idpSSODescriptor},
	}, nil
}
