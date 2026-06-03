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
  the known-limitations decision register, `RenewalHint`, lease tidy, safe
  custom plugin wrapper building blocks, and the `0.9.0` release gate script.
- Remaining `0.9.0` planned work: public API audit, migration guide
  completion, opt-in retry/backoff, non-secret pagination ergonomics, PKI role
  and Identity entity/group bootstrap convergence, PKI root/named-issuer scope
  review, response fixtures, fuzz targets, and quantum-readiness posture
  design.
- Finalization rule: the OpenBao `2.5.x` endpoint matrix expanded the
  pre-`1.0` plan through `0.15.0`. `0.9.0` handles stabilization foundations;
  `0.10.0` through `0.14.0` handle Identity/auth, Transit, PKI, and System
  completion; `0.15.0` is the endpoint-closure release where no matrix row may
  remain classified as `decision`.
- Minimum supported Rust: 1.90.0.

## Security Notes

- The `0.9.0` line is the API stabilization candidate. New public API should be
  added only when it is expected to survive into `1.0` or when the release
  notes clearly document why it remains experimental.
- Retry helpers must avoid retrying non-idempotent writes by default and must
  not hide token or lease revocation failures.
- Token and lease renewal helpers avoid background tasks that silently keep
  secret material alive longer than caller-owned handles require.
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

## Known Limitations And Decisions

- Committed `0.9.0` work, no owner decision required unless implementation or
  pentest risk changes: explicit opt-in retry policy, shared pagination for
  non-secret string lists, PKI role and Identity entity/group bootstrap
  convergence, public response fixtures, fuzz targets for path validation/API
  error decoding/response envelopes, public API audit, migration guide
  completion, and an advisory quantum-readiness design note.
- Rejected for stable scope: background token auto-renewal, background lease
  tracking, and `LeaseHandle` wrappers. Applications own the renewal loop,
  renewal-failure policy, and shutdown ordering; use `RenewalHint` for timing
  and increment guidance.
- Rejected for stable scope: generic `Plugin`/`SecretEngine` traits, codegen,
  and macro approaches. Deployment-specific plugin wrappers should use
  `PluginMount`, public path validators, and bounded list helpers instead.
- Implement in `0.10.0`: Identity OIDC admin/discovery/token/introspection
  rows, MFA method and login-enforcement rows, and `sys/mfa/validate`; classify
  named-provider OIDC `/authorize`, `/token`, and `/userinfo` as external
  browser protocol flows.
- Implement or decide in `0.10.0`: token `create-orphan`/`renew-accessor` and
  AppRole delegated per-property rows.
- Implement or decide in `0.11.0`: Transit BYOK/import, wrapping-key,
  cache/config, CSR/certificate, and soft-delete rows.
- Implement or decide in `0.12.0`/`0.13.0`: PKI named issuer/root/public-read,
  CEL, sign-verbatim, OCSP, revocation-list, and ACME-boundary rows.
- Implement or decide in `0.14.0`: system generate-root/recovery-token,
  decode-token, password policies, monitor/internal rows, resultant ACL, and
  legacy recovery-key rekey.
- Decide before `0.15.0`: tracing/OpenTelemetry hooks, seal-status watchers,
  HTTP/2 transport knobs, application-side secret-struct wrappers, certificate
  or public-key pinning, and advanced ACL policy-builder fields.
- Reject for stable feature scope unless a pentest or downstream integration
  proves otherwise before `1.0.0`: full ACME protocol flows, full JOSE/JWKS
  construction, and raw unauthenticated SSH public-key reads. The crate keeps
  safe lower-level helpers or documented alternatives for those workflows.
- Permanent boundary: request-body bytes can be zeroized by this crate before
  handoff, but buffers owned by `reqwest`, TLS providers, the operating system,
  allocator, or network devices remain outside this crate's control.
