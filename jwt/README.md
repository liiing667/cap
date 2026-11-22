# jwt
[![Go Reference](https://pkg.go.dev/badge/github.com/hashicorp/cap/jwt.svg)](https://pkg.go.dev/github.com/hashicorp/cap/jwt)

Package jwt provides signature verification and claims set validation for JSON Web Tokens (JWT)
of the JSON Web Signature (JWS) form.

Primary types provided by the package:

* `KeySet`: Represents a set of keys that can be used to verify the signatures of JWTs.
  A KeySet is expected to be backed by a set of local or remote keys.

* `Validator`: Provides signature verification and claims set validation behavior for JWTs.

* `Expected`: Defines the expected claims values to assert when validating a JWT.

* `Alg`: Represents asymmetric signing algorithms.

* `ValidationReport`: Records the key set generation, source, token identity,
  and failure stage for one validation attempt.

### Validation reports and key set generations

`Validator.ValidateWithReport` returns a `ValidationReport` alongside the
claims and error. The report is built from the same key set snapshot used to
verify the token and records:

* the token `issuer` (with `IssuerVerified` distinguishing a verified payload
  from an unverified report-only value);
* the JWS `alg` and `kid`;
* the `key_set_source` and `key_set_generation`;
* the `stage` / `failure_stage`, such as `parse_token`, `key_set_lookup`,
  `key_set_refresh`, `signature`, `algorithm`, or `time_claims`; successful
  validation uses the `complete` stage.

Remote key sets publish complete generations. A successful refresh replaces the
whole JWKS atomically and increments the generation only when the key material
changes. A failed refresh keeps the previous complete generation for a bounded
stale window (configurable with `WithKeySetStaleWindow`) or fails closed. A
token that triggered a refresh is never verified against one generation and
reported against another.

The existing `Validate` and `ValidateAllowMissingIatNbfExp` signatures are
unchanged. Errors returned by them carry the same report and can be inspected
with:

```go
report, ok := jwt.ReportFromError(err)
```

### Time claims

Explicit NumericDate `0` values in `iat`, `nbf`, and `exp` represent the Unix epoch.
Omitted or JSON `null` time claims are internally derived when relevant.
`Validate` requires at least one non-null time claim.
`ValidateAllowMissingIatNbfExp` skips time validation only when all three time claims are omitted or null.

### Examples:

Please see [docs_test.go](./docs_test.go) for additional usage examples.
