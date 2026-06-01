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
  and generated credential helpers.
- Remaining `0.7.0` planned work: identity; LDAP secrets engine; typed custom
  plugin API pattern documentation.
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
