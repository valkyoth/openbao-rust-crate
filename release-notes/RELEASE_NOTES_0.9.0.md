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
  custom plugin wrapper building blocks, optional `tracing` instrumentation,
  optional HTTP/2 transport support, token `create-orphan` and
  `renew-accessor` helpers, AppRole delegated role-property helpers, and the
  operator-gated PKI default root deletion helper, plus explicit
  `RetryPolicy`/`request_json_with_retry` exponential-backoff ergonomics and
  shared `ListPageOptions` pagination for non-secret string-list endpoints,
  plus AdminBootstrap convergence for PKI roles and Identity entities/groups;
  the `0.9.0` release gate script is also present.
- Remaining `0.9.0` planned work: public API audit, migration guide
  completion, PKI named-issuer scope review, response fixtures, fuzz targets,
  and quantum-readiness posture design.
- Finalization rule: the OpenBao `2.5.x` endpoint matrix expanded the
  pre-`1.0` plan through `0.15.0`. `0.9.0` handles stabilization foundations;
  `0.10.0` through `0.14.0` handle Identity/auth, Transit, PKI, and System
  completion; `0.15.0` is the endpoint-closure release where no matrix row may
  remain classified as `planned` or `decision`.
- Minimum supported Rust: 1.90.0.

## Security Notes

- The `0.9.0` line is the API stabilization candidate. New public API should be
  added only when it is expected to survive into `1.0` or when the release
  notes clearly document why it remains experimental.
- Retry helpers are explicit and call-site scoped. Default typed helpers remain
  single-shot, and callers must not use retry policies for non-idempotent writes
  unless the application owns the duplicate-operation risk.
- Token and lease renewal helpers avoid background tasks that silently keep
  secret material alive longer than caller-owned handles require.
- `ListPageOptions` bounds list page size and validates cursors. Token
  accessors, lease IDs, and other secret-bearing lists stay out of generic
  pagination ergonomics.
- Optional tracing emits only method, validated path, and response status. It
  must never emit full URLs, headers, request bodies, response bodies, tokens,
  namespaces, or raw transport-error strings.
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
- Implement in `0.11.0`: Transit wrapping-key, import/import-version, BYOK
  export, soft-delete/restore, cache/global config, CSR generation, and
  certificate install rows. `wrapping_key` returns a public PEM string; import
  wrappers accept only pre-wrapped `SecretString` ciphertext, reject empty
  ciphertext constructors, redact ciphertext/context in `Debug`, and document
  that raw key bytes must not be passed to endpoint wrappers. BYOK export
  returns wrapped ciphertext as `SecretString`. A pre-`1.0.0` optional
  client-side wrapping helper is planned behind `transit-import` with
  feature-gated `rsa` and `aes-gcm` dependencies, secret-aware inputs, redacted
  output handling, and no security-certification claims.
- Implement in `0.12.0`: PKI default issuer/key config, named-issuer
  issue/sign, root rotate/replace, standalone key generation, sign-verbatim
  behind operator gates, revoke-with-key, cluster/auto-tidy config, and
  current-doc field expansion for role/generation/CRL/tidy structs. Destructive
  `DELETE /pki/root` is resolved in `0.9.0` as `Pki::delete_root` behind
  `operator-ops` plus `operator-ops-acknowledged`, requiring
  `PkiRootDeletion::confirm()` at the call site.
- Implement in `0.13.0`: PKI revocation/CRL management, CEL roles and
  issue/sign, named-issuer sign-intermediate/sign-self-issued, delta CRL
  rotation, and cross-sign rows. Unauthenticated public CA/certificate/CRL
  reads and OCSP responder endpoints are external protocol/public-distribution
  boundaries.
- Implement in `0.14.0`: system generate-root/recovery-token, decode-token,
  legacy recovery-key rekey behind operator gates; password policy CRUD/list/
  generate and resultant ACL without gates; and typed operator-gated in-flight
  request inspection with `SecretString` token accessors and bounded response
  maps. Rejected for stable scope: sys/config/ui, sys/monitor streaming,
  internal router inspection, internal counters, and internal request
  inspection.
- Implement in `0.15.0`: a bounded `wait_until_unsealed` helper behind an
  explicit Tokio helper feature, typed response-wrapping ergonomics with
  redacted wrapping tokens and typed unwrap, selective AdminBootstrap
  convergence for PKI mounts/roles, database mounts/dynamic and static roles,
  and SSH mounts/roles, plus ACL policy-builder wrapping-TTL constraints.
  Rejected for stable scope: request-level seal back-pressure, per-engine
  wrapped method duplication, PKI CA setup in bootstrap, database connection
  configuration in bootstrap, SSH CA setup in bootstrap, KV v1 bootstrap
  convergence, and ACL parameter-constraint HCL generation.
- Runtime HTTP/2 transport knobs are rejected; use the non-default `http2`
  feature for TLS ALPN HTTP/2 negotiation, and keep default builds HTTP/1.1-only.
  HTTP/3 is rejected for stable scope. Certificate and public-key pinning are
  rejected for stable scope; use root-only trust with an internal CA or
  self-signed OpenBao certificate instead. Tracing is resolved with a
  non-default `tracing` feature; OpenTelemetry SDK dependencies and custom
  request hooks are rejected for stable scope, and W3C `traceparent`
  propagation is deferred past `1.0.0`.
- Reject for stable feature scope unless a pentest or downstream integration
  proves otherwise before `1.0.0`: full JOSE/JWKS construction and raw
  unauthenticated SSH public-key reads. The crate keeps safe lower-level
  helpers or documented alternatives for those workflows.
- Permanent ACME boundary: account, order, authorization, challenge, polling,
  and certificate download flows stay with dedicated ACME clients. This crate
  provides typed OpenBao ACME config, EAB provisioning, and directory URL
  helpers for that handoff, with EAB HMAC keys kept in `SecretString`.
- Permanent boundary: request-body bytes can be zeroized by this crate before
  handoff, but buffers owned by `reqwest`, TLS providers, the operating system,
  allocator, or network devices remain outside this crate's control.
