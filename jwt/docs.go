// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

/*
Package jwt provides signature verification and claims set validation for JSON Web Tokens (JWT)
of the JSON Web Signature (JWS) form.

JWT claims set validation provided by the package includes the option to validate
all registered claim names defined in https://tools.ietf.org/html/rfc7519#section-4.1.

JOSE header validation provided by the the package includes the option to validate the "alg"
(Algorithm) Header Parameter defined in https://tools.ietf.org/html/rfc7515#section-4.1.

JWT signature verification is supported by providing keys from the following sources:

  - JSON Web Key Set (JWKS) URL
  - OIDC Discovery mechanism
  - Local public keys

Validator.ValidateWithReport returns a ValidationReport that identifies the
issuer, JWS alg and kid, key set source, key set generation, and failure stage
for one validation attempt. Remote JWKS refreshes are published as complete
generations, so a token is never verified against one generation and reported
against another.

JWT signature verification supports the following asymmetric algorithms as defined in
https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1:

  - RS256: RSASSA-PKCS1-v1_5 using SHA-256
  - RS384: RSASSA-PKCS1-v1_5 using SHA-384
  - RS512: RSASSA-PKCS1-v1_5 using SHA-512
  - ES256: ECDSA using P-256 and SHA-256
  - ES384: ECDSA using P-384 and SHA-384
  - ES512: ECDSA using P-521 and SHA-512
  - PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256
  - PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
  - PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512
  - EdDSA: Ed25519 using SHA-512
*/
package jwt
