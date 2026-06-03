# openbao 0.10.0 Release Notes

Status: in development.

## Summary

`0.10.0` is the Identity and auth completion line. The first slice adds typed
Identity OIDC token backend support while preserving the crate's secret-handling
rules: generated ID tokens and token introspection inputs use `SecretString`,
debug output is redacted, and list-like responses remain bounded.

## Added

- Identity OIDC token backend config read/write helpers.
- Identity OIDC signing key create/read/list/delete/rotate helpers.
- Identity OIDC role create/read/list/delete helpers.
- Signed ID token generation and token introspection helpers.
- OIDC discovery metadata and public JWKS read helpers.
- OIDC provider, scope, client, and assignment admin helpers.
- Named-provider OIDC discovery metadata and public JWKS read helpers.
- Mock HTTP tests for the documented Identity OIDC token backend paths.
- Mock HTTP tests for the documented Identity OIDC provider admin paths.

## Security Notes

- Signed Identity OIDC tokens are returned as `SecretString`.
- OIDC introspection requests expose the token only while serializing the
  request body.
- Confidential OIDC client secrets returned by OpenBao are stored as
  `SecretString` and redacted from `Debug`.
- JWKS, list, and provider/client metadata map responses are bounded during
  deserialization.

## Still In Scope For 0.10.0

- Identity MFA Duo, Okta, PingID, and TOTP method management.
- Identity MFA login-enforcement helpers.
- `/sys/mfa/validate` for MFA-enforced login completion.
