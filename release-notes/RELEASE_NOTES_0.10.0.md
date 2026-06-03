# OpenBao Rust SDK 0.10.0 Release Notes

## Version

- Version: 0.10.0
- Release date: 2026-06-03
- Git tag: `v0.10.0`
- Git commit: see the signed `v0.10.0` tag object
- License: MIT OR Apache-2.0

## Summary

`0.10.0` is the Identity and auth completion line. This release adds typed
Identity OIDC token/provider administration, Identity MFA management, and the
system MFA validation step while preserving the crate's secret-handling rules:
generated ID tokens, token introspection inputs, MFA provider credentials, TOTP
QR/URL outputs, MFA passcodes, returned client tokens, and accessors use
`SecretString`, debug output is redacted, and list-like responses remain
bounded.

## Added

- Identity OIDC token backend config read/write helpers.
- Identity OIDC signing key create/read/list/delete/rotate helpers.
- Identity OIDC role create/read/list/delete helpers.
- Signed ID token generation and token introspection helpers.
- OIDC discovery metadata and public JWKS read helpers.
- OIDC provider, scope, client, and assignment admin helpers.
- Named-provider OIDC discovery metadata and public JWKS read helpers.
- Identity MFA Duo, Okta, PingID, and TOTP method management helpers.
- TOTP MFA secret generation, administrative generation, and administrative
  destroy helpers.
- Identity MFA login-enforcement create/read/list/delete helpers.
- `/sys/mfa/validate` helper for completing MFA-enforced login flows.
- Mock HTTP tests for the documented Identity OIDC token backend paths.
- Mock HTTP tests for the documented Identity OIDC provider admin paths.
- Mock HTTP tests for the documented Identity MFA management paths.
- Mock HTTP test for the documented system MFA validation path.

## Security Notes

- Signed Identity OIDC tokens are returned as `SecretString`.
- OIDC introspection requests expose the token only while serializing the
  request body.
- Confidential OIDC client secrets returned by OpenBao are stored as
  `SecretString` and redacted from `Debug`.
- Duo secret/integration keys, Okta API tokens, PingID settings-file payloads,
  and generated TOTP QR/URL outputs are stored as `SecretString` and redacted
  from `Debug`.
- MFA validation passcodes, returned client tokens, and token accessors are
  stored as `SecretString` and redacted from `Debug`.
- JWKS, list, and provider/client metadata map responses are bounded during
  deserialization.
- Identity OIDC introspection/discovery extra claim maps are bounded during
  deserialization, and oversized JWKS key lists now fail without draining the
  full sequence.
- Identity OIDC bounded JSON map and discovery string-list checks run before
  parsing or converting the first oversized entry.
- JSON object string validation now rejects oversized inputs before parsing, and
  ACL policy string generation escapes HCL template interpolation starts.
- Bootstrap convergence docs now warn at the top-level API that `ensure_*`
  operations require external serialization when concurrent runners target the
  same cluster.

## Release Readiness

- External pentest feedback for the release line was reviewed and actionable
  items were resolved before tagging.
- GitHub CI was green before tagging.
