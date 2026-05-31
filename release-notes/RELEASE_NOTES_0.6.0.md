# OpenBao Rust SDK 0.6.0 Release Notes

## Version

- Version: 0.6.0
- Release date: Unreleased
- Git tag: `v0.6.0` planned
- Git commit: tag target for `v0.6.0`
- License: MIT OR Apache-2.0

## Scope

- Stable modules carried from `0.5.0`: client configuration, direct token auth,
  AppRole login, token lifecycle helpers, KV v1/v2, Transit, sys health/seal
  status, loopback-only dev bootstrap, mount/auth mount management, response
  wrapping, ACL policies, capabilities, audit devices, exact lease helpers,
  plugin catalog helpers, environment-based client construction, Kubernetes
  auth, TLS certificate auth, PKI helpers, Userpass auth, JWT/OIDC helpers,
  database secrets helpers, TOTP helpers, and optional Transit byte helpers.
- New `0.6.0` work currently implemented: bounded ACL policy builder helpers
  for common KV v2 and Transit least-privilege rules; TOTP key
  create/read/list/delete, code generation, and code validation.
- Remaining `0.6.0` planned work: SSH helpers, idempotent admin bootstrap
  builder, and production init/unseal/rekey/rotate APIs behind an explicit
  feature with strong documentation warnings.
- Default Cargo features: `approle`, `cert-auth`, `database`, `jwt-auth`,
  `kubernetes-auth`, `userpass`, `token`, `kv1`, `kv2`, `pki`, `totp`, `transit`,
  `sys`, `rustls-tls`.
- Non-default Cargo features: `allow-sha1`, `native-tls`,
  `native-tls-acknowledged`, `transit-bytes`.
- Minimum supported Rust: 1.90.0.
- Rust compatibility evidence: release gate will refresh full test suite and
  clippy on 1.90.0 plus feature checks through the latest stable Rust before
  tagging.

## Security Changes

- ACL policy builder support starts with a narrow typed subset: known
  capabilities only, no mixed `deny` rules, bounded rule count, bounded output
  size, validated paths, and escaped HCL path strings.
- Helper-generated KV v2 and Transit ACL paths require literal mount, prefix,
  and key inputs; callers can still use explicit raw policy paths when they
  intentionally need OpenBao wildcards.
- TOTP generated codes, OTP URLs, QR barcodes, imported OTP URLs, and imported
  root keys are represented with `SecretString` and redacted from debug output.

## Security And Stability Gate

- Gate command: `scripts/release_0_6_gate.sh`
- Result: pending.
- Pentest report: pending.
- `cargo audit` result: pending.
- `cargo deny check` result: pending.
- CodeQL result: pending.
- Podman OpenBao integration result: pending.
- SBOM generation result: pending.
- Reproducible package result: pending.

## Known Limitations

- SSH and production init/unseal/rekey helpers are not implemented yet.
- The ACL policy builder intentionally does not cover advanced ACL fields such
  as required parameters, allowed parameters, denied parameters, or wrapping
  TTL constraints. Use `sys::PolicyWriteRequest` directly for advanced policy
  documents.
