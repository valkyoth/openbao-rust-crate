# OpenBao Rust SDK 0.9.0 Release Notes

## Version

- Version: 0.9.0
- Release date: Unreleased
- Git tag: `v0.9.0` planned
- Git commit: tag target for `v0.9.0`
- License: MIT OR Apache-2.0

## Scope

- Stable modules carried from `0.8.0`: client configuration, direct token auth,
  AppRole login and administration, LDAP/RADIUS/Kerberos auth, Kubernetes auth,
  TLS certificate auth, Userpass auth, JWT/OIDC helpers, token lifecycle and
  token-role helpers, KV v1/v2, Transit, PKI, database, SSH, TOTP, Cubbyhole,
  Kubernetes secrets, RabbitMQ secrets, Identity, LDAP secrets, sys backend
  helpers, loopback-only dev bootstrap, admin bootstrap, policy builders,
  audit devices, lease helpers, plugin catalog helpers, production operator
  APIs behind explicit gates, optional Transit byte helpers, optional timestamp
  parsing, and advisory FIPS posture helpers.
- New `0.9.0` work currently implemented: release-line version bump,
  stabilization audit documentation, migration guidance, release-note skeleton,
  and the `0.9.0` release gate script.
- Remaining `0.9.0` planned work: public API audit, migration guide
  completion, decisions or implementations for retry/backoff, token
  auto-renewal, lease tracking, shared pagination, remaining bootstrap
  convergence, Identity OIDC/MFA scope, PKI root/named-issuer scope,
  optional tracing, seal-status watching, HTTP/2 configuration, response
  fixtures, fuzz targets, and quantum-readiness posture design.
- Minimum supported Rust: 1.90.0.

## Security Notes

- The `0.9.0` line is the API stabilization candidate. New public API should be
  added only when it is expected to survive into `1.0` or when the release
  notes clearly document why it remains experimental.
- Retry and auto-renewal helpers must avoid retrying non-idempotent writes by
  default and must not hide token or lease revocation failures.
- Lease-tracking helpers must avoid background tasks that silently keep secret
  material alive longer than caller-owned handles require.
- Pagination helpers must preserve bounded allocation behavior and keep secret
  accessor lists out of generic string-list ergonomics.
- Migration guidance must not recommend disabling TLS verification, using
  root tokens in application services, logging token accessors, or using
  loopback-only dev bootstrap outside fresh local development instances.
- Quantum-readiness guidance is advisory only until OpenBao exposes stable
  upstream primitives. It must not claim post-quantum safety for current
  OpenBao deployments.

## Security And Stability Gate

- Gate command: `scripts/release_0_9_gate.sh`
- Result: pending.
- Pentest report: pending.
- `cargo audit` result: pending.
- `cargo deny check` result: pending.
- CodeQL result: pending.
- Podman OpenBao integration result: pending.
- SBOM generation result: pending.
- Reproducible package result: pending.

## Known Limitations

- Token auto-renewal, lease tracking, retry policy/backoff, shared pagination,
  Identity OIDC provider/MFA management, PKI root rotate/replace, named issuer
  issue/sign flows, tracing/OpenTelemetry, seal-status watching, HTTP/2
  transport configuration, public response serde fixtures, fuzz targets, and
  application-side secret-struct wrappers are not finished at the start of the
  `0.9.0` line.
