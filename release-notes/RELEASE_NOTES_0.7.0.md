# OpenBao Rust SDK 0.7.0 Release Notes

## Version

- Version: 0.7.0
- Release date: Unreleased
- Git tag: `v0.7.0` planned
- Git commit: tag target for `v0.7.0`
- License: MIT OR Apache-2.0

## Scope

- Stable modules carried from `0.6.0`: client configuration, direct token auth,
  AppRole login, token lifecycle helpers, KV v1/v2, Transit, sys health/seal
  status, loopback-only dev bootstrap, mount/auth mount management, response
  wrapping, ACL policies, capabilities, audit devices, exact lease helpers,
  plugin catalog helpers, environment-based client construction, Kubernetes
  auth, TLS certificate auth, PKI helpers, Userpass auth, JWT/OIDC helpers,
  database secrets helpers, SSH helpers, TOTP helpers, admin bootstrap,
  production operator APIs behind explicit gates, and optional Transit byte
  helpers.
- New `0.7.0` work currently implemented: AppRole role and SecretID
  administration helpers for role create/read/list/delete, RoleID read/update,
  SecretID generate/list/lookup, SecretID destroy by value or accessor, custom
  SecretID assignment, SecretID tidy, plus admin bootstrap support for auth
  method enablement, AppRole role convergence, explicit SecretID issuance, and
  Cubbyhole read/write/delete/list helpers, plus Kubernetes secrets engine
  config, role, role-list, role-delete, and service account credential helpers,
  plus RabbitMQ connection config, lease config, role, role-list, role-delete,
  and generated credential helpers, plus identity entity, group, entity-alias,
  and group-alias lifecycle helpers, plus LDAP config, root rotation, static
  roles/credentials, dynamic roles/credentials, and library check-out/check-in
  helpers, plus typed custom plugin wrapper pattern documentation.
- Ergonomic additions include `duration_to_bao_string`, common duration-based
  TTL builder overloads, `SharedClient`/`Client::into_shared`, bootstrap report
  lookup helpers, KV v2 service config write helpers, a Cubbyhole service
  config read helper, and broader concrete-type prelude exports.
- Remaining `0.7.0` planned work: none.
- Minimum supported Rust: 1.90.0.

## Security Notes

- AppRole RoleIDs, SecretIDs, SecretID accessors, and returned tokens are
  represented as `SecretString` and redacted from debug output.
- SecretID accessor listings are deserialized into bounded secret string lists.
- AppRole response lists and metadata maps use the crate's bounded
  deserializers to limit allocations from compromised or malformed servers.
- AppRole duration builder helpers validate TTL strings before request
  dispatch.
- Admin bootstrap reports redact issued AppRole SecretID material.
- Cubbyhole list responses use bounded key deserialization, and Cubbyhole paths
  use the same structured validation as other secret engines.
- Kubernetes secrets generated service account tokens and lease IDs are
  secret-aware and redacted from debug output.
- RabbitMQ connection URIs, administrator passwords, generated passwords, and
  lease IDs are secret-aware and redacted from debug output.
- RabbitMQ role `vhosts` and `vhost_topics` permission strings are validated as
  JSON objects before request dispatch.
- Identity returned lists and metadata maps are bounded during deserialization,
  and request collection sizes are validated before dispatch.
- LDAP bind passwords, client TLS private keys, static passwords, dynamic
  passwords, library checkout passwords, and lease IDs are secret-aware and
  redacted from debug output.
- LDAP configs that set `insecure_tls=true` require the
  `insecure-ldap-tls-acknowledged` Cargo feature.
- AppRole, Userpass, JWT, and TLS certificate auth CIDR fields are validated
  locally before writes, and AppRole SecretID metadata is checked as a JSON
  object string.
- API error message sanitization is byte-bounded, and AppRole bootstrap docs
  document the unavoidable read-compare-write race for concurrent runs.
- API error strings are sanitized before storage in `Error::Api`.
- Auth token headers are rebuilt per request instead of cached in the client,
  and empty or whitespace-only tokens are rejected at validation time.
- The sensitive loopback HTTP test bypass requires the explicit
  `sensitive-http-test-only` feature.
- Lease IDs are length-bounded before JSON request-body use, and
  `Kv2ServiceConfig` debug output redacts key names as well as values.
- Custom plugin guidance recommends typed wrappers around `request_json`, path
  validation, `SecretString` for secret-bearing fields, hand-written redacted
  `Debug`, and tests for documented methods and paths.

## Security And Stability Gate

- Gate command: `scripts/release_0_7_gate.sh`
- Result: pending.
- Pentest report: pending.
- `cargo audit` result: pending.
- `cargo deny check` result: pending.
- CodeQL result: pending.
- Podman OpenBao integration result: pending.
- SBOM generation result: pending.
- Reproducible package result: pending.

## Known Limitations

- AppRole delegated per-property endpoints are not yet typed separately because
  the full role update endpoint can configure the same fields. They can still
  be reached through `Client::request_json` if an ACL design delegates only a
  single role property path.
- Custom plugin APIs are intentionally not modeled as a generic trait because
  plugin schemas are deployment-specific. Use the documented wrapper pattern
  for typed local APIs.
- Bootstrap dry-run preview, broader bootstrap coverage for LDAP/RabbitMQ/
  Kubernetes secrets/Identity state, typed capability wrappers, shared key-list
  traits, and optional RFC3339 timestamp parsing remain planned for later
  release lines.
