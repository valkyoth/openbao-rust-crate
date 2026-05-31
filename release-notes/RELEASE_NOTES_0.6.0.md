# OpenBao Rust SDK 0.6.0 Release Notes

## Version

- Version: 0.6.0
- Release date: 2026-05-31
- Git tag: `v0.6.0`
- Git commit: tag target for `v0.6.0`
- License: MIT OR Apache-2.0

## Scope

- Stable modules carried from `0.5.0`: client configuration, direct token auth,
  AppRole login, token lifecycle helpers, KV v1/v2, Transit, sys health/seal
  status, loopback-only dev bootstrap, mount/auth mount management, response
  wrapping, ACL policies, capabilities, audit devices, exact lease helpers,
  plugin catalog helpers, environment-based client construction, Kubernetes
  auth, TLS certificate auth, PKI helpers, Userpass auth, JWT/OIDC helpers,
  database secrets helpers, SSH helpers, TOTP helpers, and optional Transit
  byte helpers.
- New `0.6.0` work: bounded ACL policy builder helpers
  for common KV v2 and Transit least-privilege rules; TOTP key
  create/read/list/delete, code generation, and code validation; SSH roles,
  zero-address roles, IP role lookup, OTP credentials, default issuer config,
  issuer list/submit/read/update/delete, authenticated CA public-key metadata,
  CA signing, generated certificate/key issuance, and OTP verification;
  idempotent admin bootstrap builder for KV v2 mounts, Transit mounts, Transit
  keys, ACL policies, KV v2 string secret values, and explicit scoped
  service-token issuance; explicitly gated production init, unseal, seal,
  legacy rekey, key-share rotation, and keyring rotation APIs.
- Remaining `0.6.0` planned work: none. AppRole administration and auth-method
  bootstrap orchestration moved into the `0.7.0` release plan.
- Default Cargo features: `approle`, `cert-auth`, `database`, `jwt-auth`,
  `kubernetes-auth`, `userpass`, `token`, `kv1`, `kv2`, `pki`, `ssh`, `totp`,
  `transit`, `sys`, `rustls-tls`.
- Non-default Cargo features: `allow-sha1`, `native-tls`,
  `native-tls-acknowledged`, `operator-ops`, `operator-ops-acknowledged`,
  `transit-bytes`.
- Minimum supported Rust: 1.90.0.
- Rust compatibility evidence: release gate covers full test suite and clippy
  on the configured toolchain plus feature checks through the latest stable
  Rust in CI.

## Security Changes

- ACL policy builder support starts with a narrow typed subset: known
  capabilities only, no mixed `deny` rules, bounded rule count, bounded output
  size, validated paths, and escaped HCL path strings.
- Helper-generated KV v2 and Transit ACL paths require literal mount, prefix,
  and key inputs; callers can still use explicit raw policy paths when they
  intentionally need OpenBao wildcards.
- TOTP generated codes, OTP URLs, QR barcodes, imported OTP URLs, and imported
  root keys are represented with `SecretString` and redacted from debug output.
- SSH OTP credentials, OTP verification requests, generated private keys, and
  submitted CA private keys are represented with `SecretString` and redacted
  from debug output.
- SSH role listing accepts OpenBao's documented `keys` response field, while
  preserving support for the `roles` shape used by lookup-style endpoints.
- SSH role, sign, and issue requests now validate duration strings, reject
  control characters in principal/CIDR fields, reject unsupported SSH public-key
  prefixes, and reject weak generated RSA key sizes before request dispatch.
- Admin bootstrap reports redact issued token material and bootstrap operation
  debug output avoids exposing KV v2 string secret values.
- Admin bootstrap compares existing and desired KV v2 secret values with
  constant-time equality, bounds plans to 512 operations, and treats duplicate
  mount/Transit-key creation races as unchanged state.
- Production operator APIs are unavailable in default builds and require both
  `operator-ops` and `operator-ops-acknowledged`; responses containing root,
  unseal, recovery, or rekey material redact that material from debug output.
- `Client::with_token` is deprecated in favor of `Client::try_with_token` so
  invalid token header values can fail at client construction.
- Token create TTL, explicit-max-TTL, and period fields are validated before
  token creation requests are sent.
- Token renewal increments are validated before request dispatch.
- Token creation has policy/default-policy builder helpers, KV v2 service
  configs can require keys by name, KV v2 list supports pagination, common API
  status checks have `Error` inspectors, and mount/auth enable requests have
  lease-TTL builders.
- Dev-state TLS private-key patterns are explicitly ignored. The current
  working tree has no tracked `deploy/podman/dev-state` key material.

## Security And Stability Gate

- Gate command: `scripts/release_0_6_gate.sh`
- Result: final local release gate passed on 2026-05-31.
- Pentest report: local `PENTEST.md` reviewed on 2026-05-31; actionable local
  findings fixed and the report was deleted before commit.
- Gap analysis: local `GAP_ANALYSIS.md` reviewed on 2026-05-31; smaller API and
  documentation gaps fixed, and AppRole admin plus auth-method bootstrap work
  moved into the `0.7.0` release plan. The local report was deleted before
  commit.
- `cargo audit` result: passed on 2026-05-31.
- `cargo deny check` result: passed on 2026-05-31 with duplicate dependency
  warnings only.
- CodeQL result: passed in GitHub on 2026-05-31.
- Podman OpenBao integration result: passed on 2026-05-31 against OpenBao
  `v2.5.4` on the local `9940` dev endpoint.
- SBOM generation result: passed on 2026-05-31; SBOM written to
  `target/sbom/openbao.cdx.json`.
- Reproducible package result: passed on 2026-05-31 with
  `cargo package --locked --allow-dirty`; package verification is now part of
  the release gate.

## Known Limitations

- Raw unauthenticated SSH public-key reads are intentionally not implemented;
  callers that need raw text/plain public-key endpoints should use an external
  HTTP client and treat the result as public key material.
- The ACL policy builder intentionally does not cover advanced ACL fields such
  as required parameters, allowed parameters, denied parameters, or wrapping
  TTL constraints. Use `sys::PolicyWriteRequest` directly for advanced policy
  documents.
