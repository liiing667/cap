
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

## Request and metadata generations

`CreateAuthnRequest`, `AuthnRequestPost`, and `AuthnRequestRedirect` freeze the
metadata generation used for the request. The generation contains the IdP
issuer, the signing certificate set, the certificate fingerprints, and the SSO
destinations. `ParseResponse` uses that frozen generation instead of reloading
metadata, so a metadata refresh failure, a tenant change, or a process restart
cannot pair one tenant's issuer with another tenant's certificate.

A request is consumed once a response has been accepted. Replaying the same
request ID is rejected with `ErrRequestStateConsumed`. Callers that persist
authentication sessions can store the value returned by `ServiceProvider.RequestState`
and restore it with `ServiceProvider.RestoreRequestState` after a restart.
Reusing an unconsumed request ID keeps the original metadata generation,
RelayState, and ACS binding instead of silently replacing them.
`ParseACSResponse` additionally binds the ACS `RelayState` to the value stored
with the request. The ACS handler requires a matching recoverable request
state once the provider has issued an AuthnRequest; a fresh provider that only
uses manually managed requests keeps the historical behavior.

`WithStale(true)` continues to allow a complete, still-valid metadata snapshot
to be used when a refresh fails. Metadata snapshots are replaced atomically:
an update is either not visible at all or is visible with its full issuer and
certificate set.
