
# [`saml package`](./saml)

[![Go Reference](https://pkg.go.dev/badge/github.com/hashicorp/cap/saml.svg)](https://pkg.go.dev/github.com/hashicorp/cap/saml)

A package for writing clients that integrate with SAML Providers.

The SAML library orients mainly on the implementation profile for
[federation interoperability](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html)
(also known as interoperable SAML), a set of software conformance requirements
intended to facilitate interoperability within the context of full mesh identity
federations. It supports the Web Browser SSO profile with HTTP-Post and
HTTP-Redirect as supported service bindings. The default SAML settings follow
the requirements of the interoperable SAML
[deployment profile](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html#_service_provider_requirements).

## Example usage

```go
    // Create a new saml config providing the necessary provider information:
    cfg, err := saml.NewConfig(<entityID>, <acs>, <metadata>, options...)
	// handle error

    // Use the config to create the service provider:
    sp, err := saml.NewServiceProvider(cfg)
    // handle error

    // With the service provider you can create saml authentication requests:

    // Generate a saml auth request with HTTP Post-Binding
    template, err := sp.AuthRequestPost("relay state", options...)
    // handle error

    // Generate a saml auth request with HTTP Request-Binding
    redirectURL, err := sp.AuthRequestRedirect("relay state", options...)
    // handle error

    // Parsing a SAML response:
    r.ParseForm()
    samlResp := r.PostForm.Get("SAMLResponse")

    response, err := sp.ParseResponse(samlResp, "Response ID", options...)
    // handle error
```

You can find the full demo code in the [`saml/demo`](./saml/demo/main.go)
package.

## ParseResponse signature validation policy

`ParseResponse` always validates any signatures that are present, but the
required signature policy is controlled by options:

- `ValidateResponseSignature()`: requires a valid signature on the top-level
    SAML `Response`.
- `ValidateAssertionSignature()`: if the response is signed and valid,
    assertions are accepted as covered by that signature; if the response is not
    signed, each assertion must be signed and valid.
- Using both options requires a valid response signature and validates any
    assertion signatures that are present.

## Multi-tab request generations

`AuthnRequestPost`, `AuthnRequestRedirect`, and `CreateAuthnRequest` admit each
request as an independent generation. At admission the service provider freezes:

- the request ID returned by `Config.GenerateAuthRequestID` (the default is a
  UUID prefixed with `_`), exposed as `AuthnRequest.ID` and
  `RequestState.RequestID`;
- the `RelayState` passed to `AuthnRequestPost`/`AuthnRequestRedirect` (or
  `WithRelayState`), exposed as `AuthnRequest.RelayState` and
  `RequestState.RelayState`, with a SHA-256 digest in
  `RequestState.RelayStateDigest`;
- the request/tab generation in `AuthnRequest.Generation`,
  `AuthnRequest.RequestGeneration`, and `AuthnRequest.TabGeneration`;
- the IdP issuer, signing certificate set, certificate fingerprints, SSO
  destinations, ACS URL, and metadata generation.

Request states are keyed by request ID, not by a process-global "current
request". Concurrent tabs therefore coexist, and a second initiation cannot
replace an unfinished request's response ownership. Reusing a request ID is
allowed only while it is pending and only with the same frozen RelayState and
(after commitment) the same ACS URL.

The ACS handler extracts `InResponseTo` from the SAML response and accepts that
specific generation. A successful response consumes the request atomically;
replaying the same response, racing callers, or restoring an already consumed
state returns `ErrRequestStateConsumed`. `CancelRequest` records a cancellation
tombstone and later responses return `ErrRequestStateCancelled`.

`ParseResponse`/`ParseACSResponse` use the frozen metadata generation for
request-bound responses. Callers that still pass manually managed requests
without creating them through this package keep the historical `ParseResponse`
behavior and the ACS handler's legacy fallback while no request is pending.

For a process restart, persist the value returned by `RequestState` (it is
JSON-serializable) in integrity-protected session storage and restore it with
`RestoreRequestState`. `RequestStates` returns all known states for auditing.
`RequestState.Report` includes the request ID, RelayState digest, request and
metadata generations, issuer, binding, and rejection stage.
