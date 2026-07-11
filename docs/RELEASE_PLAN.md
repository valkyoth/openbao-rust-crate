# Release Plan

This plan starts at `0.1.0` and reached `1.0.0`, the first stable release.
The exact OpenBao `2.5.5` inventory contains `644` unique documented rows and
`663` expanded method/path operations. The pre-`1.0` matrix's `597/643`
coverage claim has been withdrawn: the exact-source audit found an omitted
HEAD operation and page-level classifications without helper, field, security,
transport, or test evidence. The replacement baseline has `79`
`confirmed-gap` and `565` `unverified` rows and publishes no support percentage.
[`OPENBAO_2_5_FULL_SUPPORT_AUDIT.md`](OPENBAO_2_5_FULL_SUPPORT_AUDIT.md)
records the evidence and confirmed gaps. The pre-`1.0` line extended through
`0.15.0`; that final scope was trialed before the stable API freeze.

After `1.0.0`, the expected line is stable maintenance, security fixes,
OpenBao compatibility fixes, and reviewed security-focused minor updates. Every
release must be functional enough to publish for external testing. No tag is
cut until the owner provides a pentest report for the exact release commit.

`1.0.1` is the first post-stable patch release. It contains only hardening and
documentation updates: TLS-floor validation, root-only trust preservation when
adding configured roots, KV v2 bootstrap comparison discipline, and clearer
residual-memory documentation.

`1.0.2` is a stable maintenance update for dependency refreshes, CI action pin
updates, and crates.io README cleanup. It does not change OpenBao endpoint
coverage or the public SDK API surface.

`1.1.0` is a security-type migration release. It replaces the public
`zeroize::Zeroizing<Vec<u8>>` byte-buffer API with
`sanitization::SecretVec`, removes the direct `zeroize` dependency and the
`openbao::Zeroizing` / `openbao::Zeroize` re-exports, and keeps the stable
OpenBao endpoint boundary intact.

`1.1.2` refreshes the stable `1.1.x` dependency and CI tooling pins and makes
Rust `1.96.1` the primary checked toolchain while preserving the documented
Rust `1.90.0` compatibility floor.

`2.0.0` adds explicit multi-version OpenBao compatibility and establishes a
major-version boundary for the reviewed security hardening. It is delivered as
ordered, pentest-gated commits on `main`, without intermediate crate versions
or tags. The complete architecture, exact historical release inventory,
security invariants, commit sequence, and stop criteria are defined in
[`OPENBAO_VERSION_COMPATIBILITY_PLAN.md`](OPENBAO_VERSION_COMPATIBILITY_PLAN.md).
The package metadata identifies `main` as unreleased `2.0.0` throughout the
breaking checkpoint series. No package or tag is published until every
checkpoint is complete and the exact release candidate passes the full
historical matrix and final pentest.

## Standing Release Gates

Every release:

- checks latest Rust and key dependency versions;
- verifies the documented Rust support range for the release;
- runs `cargo fmt --all --check`;
- runs `cargo clippy --all-targets --all-features -- -D warnings`;
- runs `cargo test --all-targets --all-features`;
- runs doctests;
- builds docs with all features;
- runs `cargo audit`;
- runs `cargo deny check`;
- generates an SBOM;
- runs bounded Kani proof harnesses when a compatible `cargo-kani` toolchain is
  installed;
- validates release metadata;
- records pentest report status before tag.

## Finalization Policy

- `1.0.0` used a narrower definition of complete support: every endpoint row
  was addressed, but protocol handoffs and explicit rejections were accepted.
- The `2.0.0` goal supersedes that boundary for OpenBao `2.5.5`. All 644
  documented rows, 663 expanded operations, and their request/response
  contracts must be first-class typed or typed-gated coverage. Generic raw
  requests, URL-only handoffs, `partial`, `external`, and `rejected`
  classifications do not count.
- Compatibility with OpenBao `2.0.0` through `2.5.5` is version-specific and
  append-only. New server profiles must not overwrite the behavior retained
  for an older supported server.
- Arbitrary undocumented external plugin schemas and third-party service
  behavior remain outside the core-server support claim.

## Downstream Ergonomics Backlog

Read-only review of Mjolni and Pawalyze on 2026-05-28 showed recurring
OpenBao glue that should become first-class crate ergonomics instead of being
reimplemented in applications:

- env-based client construction from `OPENBAO_ADDR`, `BAO_ADDR`, `VAULT_ADDR`,
  token aliases, namespace, and CA/root-only trust settings;
- KV v2 service config loading into `BTreeMap<String, SecretString>` and typed
  structs, with optional fallback behavior for local development;
- optional-feature byte-oriented Transit helpers that base64 encode/decode
  internally for encrypt, decrypt, HMAC, sign, verify, and envelope-key
  wrapping without adding the dependency to default builds;
- Transit signing helpers for JWT/JWKS use cases, including safe extraction of
  raw signature bytes and asymmetric public key metadata;
- idempotent admin bootstrap helpers for mounts, Transit keys, policies, KV
  secret patching, and scoped service-token creation;
- policy builder helpers for common KV v2 and Transit capabilities so projects
  do not assemble ACL HCL with ad hoc strings;
- best-effort FIPS posture helpers that validate crate request options against
  FIPS-oriented allowlists and emit an audit report, without claiming OpenBao,
  the host, TLS backend, or HSM/KMS module is certified;
- quantum-readiness design notes that inventory algorithms and clearly state
  that current helpers are advisory only until OpenBao exposes stable support;
- migration examples for projects currently using `vaultrs` or bespoke
  `reqwest` wrappers.

## Version Plan

### 0.1.0 - Secure Core And KV v2

Stop condition:

- secure client config exists;
- direct token auth works;
- AppRole login works;
- KV v2 read/write/list/delete works;
- system health and seal status work;
- local TLS OpenBao podman dev instance exists on ports `9940` and `9941`;
- docs explain first-use flows and limitations.

Publishable value:

- users can authenticate and read/write versioned secrets safely.

### 0.2.0 - Token, KV Completeness, And Mount Management

Stop condition:

- token lookup, renew, revoke, create, and accessor lookup helpers;
- KV v1 support;
- KV v2 metadata, undelete, destroy, patch, versions, and config support;
- sys mounts/auth mounts enable, tune, list, disable;
- response wrapping lookup, wrap, unwrap, rewrap;
- ACL policy list/read/write/delete and capability checks for self, token, and
  accessor;
- integration tests cover real OpenBao container flow.

Publishable value:

- users can manage common secret mounts and token lifecycle.

### 0.3.0 - Transit And Audit

Stop condition:

- transit key create/read/list/delete;
- encrypt, decrypt, rewrap, datakey, random, hash, hmac, sign, verify;
- audit device enable/list/disable/hash;
- lease lookup/renew/revoke supported only on non-legacy safe endpoints;
- loopback-only dev bootstrap for fresh local OpenBao instances;
- timing-sensitive docs for transit use cases.

Publishable value:

- users can delegate cryptographic operations to OpenBao.

### 0.4.0 - PKI, Kubernetes Auth, TLS Cert Auth

Stop condition:

- PKI roles, issue, sign, revoke, tidy, CA and CRL endpoints;
- Kubernetes auth login/config/role helpers;
- TLS certificate auth login/config/cert helpers;
- certificate examples and tests avoid writing private keys to logs.
- env-based client construction helper for common `OPENBAO_*`, `BAO_*`, and
  `VAULT_*` deployment variables;
- KV v2 service config loader for maps and typed structs.

Publishable value:

- users can automate certificates, workload auth, and service startup secret
  loading without custom OpenBao glue.

### 0.5.0 - Database, JWT/OIDC, Userpass

Stop condition:

- database engine config, roles, static roles, rotate root, credentials;
- JWT/OIDC role config and JWT login;
- userpass create/update/delete/login;
- byte-oriented Transit convenience helpers for envelope encryption and HMAC
  lookup-token patterns;
- Transit signing/JWS helpers for RSA and ECDSA JWT signing workflows;
- examples show short-lived database credentials.

Publishable value:

- users can retrieve dynamic credentials, support common human/machine auth,
  and move application crypto glue onto typed OpenBao helpers.

### 0.6.0 - SSH, TOTP, Production Init/Unseal Safety

Stop condition:

- SSH issuer, CA/sign, and OTP helpers;
- TOTP key/code/validate helpers;
- idempotent admin bootstrap builder for mounts, Transit keys, ACL policies,
  KV secret patching, and scoped service-token creation;
- ACL policy builder for common KV v2 and Transit permissions;
- production init, unseal, rekey, rotate APIs behind explicit feature and
  warnings;
- tests prove production init/unseal APIs cannot be called accidentally from
  default docs.

Publishable value:

- users can support operational bootstrap, least-privilege service setup, and
  MFA-style workflows.

### 0.7.0 - Remaining Secret Engines And Identity

Stop condition:

- AppRole admin role and SecretID lifecycle helpers;
- admin bootstrap support for auth method enablement and AppRole role/SecretID
  provisioning;
- Cubbyhole read/write/delete/list helpers;
- Kubernetes secrets engine config, role, list, delete, and credential helpers;
- RabbitMQ secrets engine connection, lease, role, and credential helpers;
- identity entities/groups/aliases;
- LDAP secrets engine;
- typed custom plugin API pattern documented with public `PluginMount`, path
  validation, and bounded string-list helper building blocks; generic plugin
  traits are rejected because plugin schemas are deployment-specific.

Publishable value:

- broad OpenBao coverage for plugin-style engines and identity operations.

### 0.8.0 - Remaining Auth And System Backend

Stop condition:

- LDAP, RADIUS, and Kerberos auth coverage implemented;
- sys policies, capabilities, plugins catalog/reload, metrics, storage,
  leader, HA status, locked users;
- OpenAPI discovery helper.
- `FipsPosture` helper that can validate supported request builders and typed
  Transit choices against a conservative allowlist, warn on SHA-1, SHA-3,
  Ed25519, ChaCha20/XChaCha20, plaintext backup/exportable keys, convergent
  encryption, weak RSA sizes, and non-HSM/KMS seal assumptions, and produce a
  machine-readable report of what the crate could and could not verify is
  implemented for crate-visible Transit and seal-assumption choices.
- Bootstrap dry-run preview support for read-only change planning before
  applying state is implemented for current bootstrap operations.
- Bootstrap convergence helpers for LDAP, RabbitMQ, Kubernetes secrets, and
  Identity resources where OpenBao exposes stable read/write APIs.
- Typed capability wrappers over `sys/capabilities-self`, including helpers
  such as `can_read`, are implemented.
- Shared `ListEntries` trait for structurally identical string list responses
  is implemented.
- Optional timestamp parsing helpers behind a lightweight `time` feature are
  implemented.
- JWT/OIDC browser-flow helpers for authorization URL, callback, and
  direct/device polling are implemented.
- Token role write/read/list/delete, token tidy, and revoke-orphan helpers are
  implemented.
- Transit key config update, key rotation, export, backup, restore, trim, and
  batch encrypt/decrypt/rewrap/sign/verify helpers are implemented.
- PKI role merge-patch, tidy status, and tidy cancel helpers are implemented.
- Identity entity/group lookup and entity merge helpers are implemented.
- Lease prefix revoke, force prefix revoke, and lease count helpers are
  implemented.
- `Error::is_rate_limited`, `Error::is_temporary`, and
  `Error::is_permission_denied` helpers are implemented.
- Runtime-neutral `Sys::wait_ready_with_delay` is implemented for startup and
  integration-test polling. KV v2 versioned typed reads were already covered by
  `read_version` and `read_data_version`.
- Runtime logger level read/set/reset helpers and installed OpenBao version
  history listing are implemented.
- Namespace list, create, read, patch, and delete helpers are implemented.
- Rate-limit quota config and named rate-limit quota helpers are implemented.
- Host diagnostics and locked-user list/filter/unlock helpers are implemented.
- Integrated Storage Raft join/configuration/peer/bootstrap and Autopilot JSON
  helpers are implemented; join helper configuration requires HTTPS leader
  addresses and HTTPS auto-join schemes.
- Prometheus metrics text output and capped Integrated Storage Raft snapshot
  download/restore helpers are implemented through a private raw-body
  transport path that keeps HTTPS/token enforcement and response-size limits.
- Raw storage read/write/list/delete helpers are implemented behind
  `operator-ops` plus `operator-ops-acknowledged`; values are secret-aware and
  key lists are bounded.
- Pprof diagnostic helpers are implemented behind `operator-ops` plus
  `operator-ops-acknowledged`; payloads are returned in sanitizing byte buffers
  under the configured response-size cap. Streaming monitor and unstable
  internal inspect endpoints remain deferred.
- HA status and remount/mount-migration start/status helpers are implemented.
- Key status and CORS config read/write/delete helpers are implemented; CORS
  wildcard origins are rejected locally.
- Active-node step-down is implemented behind `operator-ops` plus
  `operator-ops-acknowledged`.
- Sanitized config state and audited request-header configuration helpers are
  implemented.
- Internal UI namespace and mount discovery helpers are implemented with an
  explicit note that OpenBao does not guarantee endpoint stability.
- `/sys/tools/random` and `/sys/tools/hash` helpers are implemented with
  documented source/algorithm allowlists, a local random-byte limit, and
  secret-aware response fields.

Publishable value:

- operators can automate most OpenBao administration tasks and get a
  non-certifying compliance posture report for OpenBao usage.

### 0.9.0 - API Stabilization Candidate

Committed implementation items for `0.9.0` that do not require an owner
decision:

- explicit opt-in retry/backoff; default requests remain single-shot so
  non-idempotent writes are not retried by accident;
- shared pagination for non-secret string list endpoints; token accessors and
  secret-bearing lists remain separate;
- bootstrap convergence for PKI roles and Identity entities/groups;
- representative serde response fixtures for public API responses;
- fuzz targets for path validation, API error decoding, and response envelope
  parsing;
- public API audit for names, constructors, feature gates, secret handling,
  docs, examples, and semver expectations;
- migration docs from older `openbao` versions, `vaultrs`, and raw `reqwest`
  wrappers;
- advisory quantum-readiness design note with no post-quantum safety claims.

Stop condition:

- generated OpenBao `2.5.x` endpoint matrix exists and is the coverage source
  of truth;
- API stability audit document exists and is maintained for every remaining
  pre-`1.0` decision;
- historical release-note `Known Limitations` have current decisions recorded;
- public API audit completed;
- migration guide from `0.1` through `0.9` exists and is completed;
- migration guide from `vaultrs` and bespoke `reqwest` OpenBao wrappers exists
  and is completed;
- background token auto-renewal, background lease tracking, and `LeaseHandle`
  wrappers are rejected with API notes; `RenewalHint` covers caller-owned
  timing for token and lease renewal loops;
- system lease tidy is implemented;
- explicit retry policy with exponential backoff is implemented;
- a shared non-secret paginated-list abstraction is implemented;
- admin bootstrap convergence for PKI roles and Identity entities/groups is
  implemented;
- token `create-orphan` and `renew-accessor` helpers are implemented;
- AppRole delegated role-property read/write/delete helpers are implemented
  for every documented OpenBao `2.5.x` per-property path;
- optional `tracing` crate instrumentation is implemented without a default
  dependency; OpenTelemetry SDK dependencies and custom request hooks are
  rejected for stable scope, W3C `traceparent` propagation is deferred, the
  non-default `http2` feature is implemented without a runtime transport knob,
  HTTP/3 is rejected for stable scope, and stable-scope ergonomics decisions
  for bounded seal polling, response wrapping, bootstrap convergence, and ACL
  policy-builder fields are recorded for `0.15.0`;
- public response serde fixtures are added;
- leaf certificate and SPKI pinning are rejected for stable scope; root-only
  trust with an internal CA or self-signed OpenBao certificate is documented as
  the supported server-identity assurance pattern;
- quantum-readiness design note that tracks OpenBao support, avoids premature
  API promises, and defines how hybrid/post-quantum profiles will be exposed
  once stable upstream primitives exist;
- all docs examples compile;
- real OpenBao integration suite covers supported default features;
- fuzz tests cover path validation, error decoding, and response envelopes.

Publishable value:

- downstream users can trial the near-stable API.

### 0.10.0 - Identity And Auth Completion

Stop condition:

- Identity OIDC config, key CRUD/rotate, role CRUD/list, provider/scope/client/
  assignment CRUD/list, signed ID token generation, token introspection,
  discovery, and JWKS read helpers are implemented;
- named-provider OIDC `/authorize`, `/token`, and `/userinfo` rows are
  documented as external browser protocol flows that belong with a dedicated
  OIDC library;
- Identity MFA Duo, Okta, PingID, and TOTP method management, MFA TOTP
  generate/admin-generate/admin-destroy, and login-enforcement rows are
  implemented with secret-aware request/response types and redacted `Debug`;
- system MFA validate is implemented as the required second step for
  MFA-enforced login flows;
- endpoint matrix is regenerated and all affected rows have updated statuses;
- tests cover redaction for new OIDC/MFA request and response types.

Publishable value:

- identity-heavy deployments can manage OpenBao Identity and MFA flows with
  typed helpers or clear external/raw boundaries.

### 0.11.0 - Transit Advanced Key Management

Stop condition:

- Transit wrapping-key is implemented and returns the RSA wrapping public key
  PEM as a non-secret `String`;
- Transit key import and import-version are implemented with request types
  that accept pre-wrapped ciphertext as `SecretString` or public-key-only
  import material, optional derivation context as `SecretString`, custom
  redacted `Debug`, and constructors that reject empty import material;
- Transit BYOK export is implemented with response types that carry the
  destination-wrapped ciphertext blob as `SecretString` and use custom
  redacted `Debug`;
- every import method documents the boundary explicitly: raw private or
  symmetric key bytes must not be passed to the default endpoint wrappers;
  callers fetch the wrapping key, wrap key material externally through their
  HSM, OpenSSL, or chosen crypto library, and pass only the base64 ciphertext
  blob to the crate unless they explicitly enable the software
  `transit-import` helper;
- Transit soft-delete and soft-delete-restore helpers are implemented;
- Transit cache config and global key config helpers are implemented;
- Transit CSR generation and certificate install helpers are implemented with
  PEM strings documented as public certificate material;
- the endpoint-wrapper boundary is documented clearly: the core wrappers do
  not perform client-side AES-KWP/RSA-OAEP wrapping unless the non-default
  `transit-import` helper is explicitly enabled;
- an optional `transit-import` wrapping helper is implemented in this `0.11.0`
  line, with optional `openssl` and `aes-kw` dependencies only when the
  feature is enabled;
- the `transit-import` helper accepts raw private or symmetric key bytes
  through sanitizing inputs, returns the OpenBao wrapped-key blob as
  `SecretString`, has redacted `Debug`, and is documented as an ergonomic
  client-side helper rather than an OpenBao, FIPS, HSM, or post-quantum
  security guarantee;
- `transit-bytes` remains optional and no default dependency growth is added;
- endpoint matrix is regenerated and Transit planned rows are implemented or
  reclassified.

Publishable value:

- operators can automate advanced Transit key lifecycle work without bespoke
  request wrappers, while keeping key-material handling explicit.

### 0.12.0 - PKI Tier 1 Multi-Issuer And Authority Lifecycle

Stop condition:

- default issuer/key configuration read/write helpers are implemented for
  `/pki/config/issuers` and `/pki/config/keys`;
- named-issuer issue and sign helpers are implemented as explicit-issuer
  extensions of the existing `issue` and `sign` methods;
- root rotate, multi-issuer root generation, root replace, standalone key
  generation, and intermediate issuer generation helpers are implemented;
- sign-verbatim helpers are implemented behind `operator-ops` plus
  `operator-ops-acknowledged` because they bypass normal role constraints;
- destructive `DELETE /pki/root` is already resolved in `0.9.0` as a dedicated
  `Pki::delete_root` method behind `operator-ops` plus
  `operator-ops-acknowledged`, requiring `PkiRootDeletion::confirm()`;
- revoke-with-key is implemented for certificate-owner proof-of-possession
  revocation without broad PKI admin access;
- cluster config and auto-tidy config helpers are implemented because they are
  current OpenBao PKI management rows not covered by the Tier 1 user list;
- `PkiRole`, root/intermediate generation requests, `PkiCrlConfig`, and
  tidy request/status structs are expanded with the current OpenBao fields
  identified in the `0.9.0` PKI review;
- unauthenticated public CA/certificate/CRL endpoints are documented as
  external protocol/public-distribution reads for TLS stacks, CRL checkers, or
  an external HTTP client;
- endpoint matrix is regenerated and the PKI Tier 1 rows are resolved.

Publishable value:

- PKI operators can manage multi-issuer defaults, issuer-specific issuance,
  authority rotation, key generation, and complex role/config fields through
  typed helpers.

### 0.13.0 - PKI Specialized Flows

Stop condition:

- revoked-cert list, revocation-queue list, detailed cert list, issuer CRL
  resign, and sign-revocation-list helpers are implemented;
- CEL role list/read/write/patch/delete plus CEL issue/sign helpers are
  implemented with a version-stability note for this newer OpenBao feature;
- named-issuer sign-intermediate and sign-self-issued variants are implemented
  for multi-issuer hierarchy and cross-signed trust-anchor workflows;
- intermediate cross-sign helpers are implemented behind `operator-ops` plus
  `operator-ops-acknowledged`;
- delta CRL rotation is implemented to complete the CRL rotation surface;
- OCSP GET/POST rows are documented as external OCSP responder protocol
  endpoints that should be handled by OCSP/TLS client tooling;
- full ACME account/order/authorization/challenge flows remain permanently
  classified as `external`; typed ACME config, EAB provisioning, and directory
  URL helpers are documented as the supported SDK boundary;
- endpoint matrix is regenerated and no PKI row remains `decision` unless it
  is intentionally moved to `0.15.0` for closure.

Publishable value:

- specialized PKI workflows are either typed or have stable documented
  external boundaries before the final system-backend pass.

### 0.14.0 - System Backend Completion

Stop condition:

- sys/config/ui header rows are rejected for stable scope because OpenBao no
  longer ships the embedded UI and the residual header use case is narrow
  server administration;
- generate-root, generate-recovery-token, decode-token, and legacy
  recovery-key rekey helpers are implemented behind `operator-ops` plus
  `operator-ops-acknowledged`;
- password policy CRUD/list/generate helpers are implemented without a feature
  gate, and generated passwords return `SecretString`;
- resultant ACL is implemented without a feature gate, with a documented
  internal-endpoint stability caveat and conservative capability maps;
- sys/monitor streaming and internal router inspection are rejected for stable
  scope; monitor needs a deliberate streaming API design, and router
  inspection has no stable OpenBao compatibility contract;
- in-flight request inspection is implemented as a typed operator-gated
  diagnostic helper with `SecretString` token accessors and bounded response
  maps;
- internal counters are rejected because `/sys/metrics` covers the observability
  use case and the internal counter API has no stable compatibility contract;
- internal request inspection is rejected because it is underdocumented and
  either overlaps capability/resultant-ACL helpers or belongs to OpenBao
  internal debugging;
- all system endpoint decisions are reflected in the matrix and support table;
- operator-risk additions preserve the existing `operator-ops` plus
  `operator-ops-acknowledged` pattern.

Publishable value:

- OpenBao system backend rows are fully addressed with typed helpers or stable
  documented boundaries.

### 0.15.0 - Endpoint Closure And Stable Candidate

Stop condition:

- endpoint matrix has zero `decision` rows;
- endpoint matrix has zero `planned` rows;
- every row is `typed`, `typed-gated`, `partial`, `raw`, `external`, or
  explicitly rejected in linked documentation;
- strict typed coverage and addressed coverage percentages are recorded in
  README, API coverage docs, release notes, and changelog;
- all remaining historical `Known Limitations` are resolved, rejected, or
  documented as permanent boundaries;
- public API names, constructors, feature flags, and module layout are frozen
  for `1.0.0`;
- bounded `wait_until_unsealed` readiness polling is implemented behind an
  explicit Tokio helper feature; request-level seal back-pressure is rejected
  as application retry-middleware policy;
- typed response-wrapping ergonomics are implemented through a wrapping
  context and `WrappedResponse<T>` with redacted `SecretString` wrapping
  tokens and typed unwrap; per-engine wrapped method variants are rejected;
- AdminBootstrap convergence is expanded to PKI mounts/roles, database
  mounts/dynamic and static roles, and SSH mounts/roles; PKI CA setup,
  database connection configuration, SSH CA setup, and KV v1 convergence are
  rejected for bootstrap scope;
- ACL policy builder wrapping-TTL constraints and helper variants are
  implemented; parameter-constraint generation is rejected because safe output
  requires a complete HCL value serializer;
- examples, migration guide, custom plugin pattern, security docs, and release
  notes reflect the final stable scope;
- full release gate and pentest pass on the exact release candidate.

Publishable value:

- downstream users can trial the final API and endpoint-scope decisions before
  `1.0.0`.

### 1.0.0 - First Stable Release

Stop condition:

- complete documented support for the selected stable API surface;
- no unresolved pre-`1.0` feature backlog remains;
- endpoint matrix still has zero `decision` rows after final regeneration;
- endpoint matrix still has zero `planned` rows after final regeneration;
- all rejected or permanently out-of-scope items are documented with stable
  reasons and safe alternatives where applicable;
- no known high or critical findings from pentest;
- `cargo audit` clean or documented non-exploitable exceptions;
- `cargo deny check` clean;
- SBOM generated;
- docs.rs build verified;
- semver policy documented;
- security response policy finalized.

Publishable value:

- production-ready stable OpenBao SDK for Rust. After `1.0.0`, planned work is
  limited to `1.x` security, correctness, OpenBao compatibility,
  documentation, dependency, and reviewed security-type migration updates.

### 1.0.1 - Patch Hardening

Stop criteria:

- TLS floors below TLS 1.2 fail before the HTTP client is built;
- TLS 1.2 configurations require `tls12-acknowledged`;
- adding a root certificate after `only_root_certificates` preserves root-only
  trust instead of silently widening to platform roots;
- KV v2 bootstrap secret comparison avoids short-circuiting across desired
  keys;
- residual HTTP header memory and rand/getrandom duplicate-version tracking
  are documented.

### 1.0.2 - Dependency And Documentation Maintenance

Stop criteria:

- direct `base64-ng` dependency is updated to the latest reviewed release;
- semver-compatible transitive dependencies are refreshed with `cargo update`;
- pinned GitHub Actions match the latest versions checked by
  `scripts/check_latest_crates.sh`;
- README no longer carries historical pre-`1.0` release narration on the
  crates.io landing page;
- release notes and metadata validation cover the `1.0.2` candidate.

### 1.1.0 - Sanitization Secret Buffer Migration

Stop criteria:

- direct `zeroize` dependency is removed from `Cargo.toml`;
- `sanitization` is a direct dependency with the `alloc` feature enabled;
- public byte-buffer helpers return `sanitization::SecretVec`;
- crate root and prelude re-export `sanitization`, `SecretVec`,
  `SecureSanitize`, and `sanitize_bytes`;
- README, migration guide, security notes, API audit, and release notes explain
  the source migration from `Zeroizing<Vec<u8>>` to `SecretVec`;
- OpenBao `2.5.5` release notes are reviewed, the endpoint matrix is
  regenerated, local integration testing is pinned to `2.5.5`, and any
  user-visible patch-release API behavior is reflected in typed helpers;
- full all-feature compile, tests, release gates, dependency/tool version
  checks, and GitHub CI pass before tagging.

### 1.1.1 - Security Dependency Refresh

Stop criteria:

- `base64-ng` is updated to `1.2.3`;
- `sanitization` is updated to `1.2.2`;
- `cargo update --dry-run` reports no remaining Rust-1.90-compatible lockfile
  updates;
- cargo security tooling and pinned GitHub Actions match the latest versions
  checked by `scripts/check_latest_crates.sh`;
- release notes, changelog, README, and metadata validation cover the `1.1.1`
  candidate;
- all-feature tests and GitHub CI pass before tagging.

### 1.1.2 - Rust 1.96.1 Toolchain And Dependency Refresh

Stop criteria:

- package metadata is updated to `1.1.2`;
- `rust-toolchain.toml` and the CI Rust installer use Rust `1.96.1` as the
  primary checked toolchain;
- `rust-version = "1.90"` remains the MSRV and all-feature compatibility is
  checked back to Rust `1.90.0`;
- direct dependency pins are refreshed to the latest reviewed versions checked
  by `scripts/check_latest_crates.sh`;
- semver-compatible transitive dependencies are refreshed with `cargo update`;
- pinned GitHub Actions match the latest versions checked by
  `scripts/check_latest_crates.sh`;
- release notes, changelog, README, and metadata validation cover the `1.1.2`
  candidate;
- all-feature tests and GitHub CI pass before tagging.

### 2.0.0 - Multi-Version OpenBao Compatibility

Implementation is governed by
[`OPENBAO_VERSION_COMPATIBILITY_PLAN.md`](OPENBAO_VERSION_COMPATIBILITY_PLAN.md).
There are no intermediate version bumps or tags: each ordered commit must pass
required CI and an exact-commit pentest before the next goal begins.

Stop criteria:

- immutable compatibility profiles cover every listed stable OpenBao release
  from `2.0.0` through `2.5.5`;
- the corrected OpenBao `2.5.5` matrix covers all 644 rows and 663 expanded
  operations as typed or typed-gated, with zero unverified or confirmed-gap
  rows and explicit request/response field evidence;
- exact and range requirements, strict detection, explicit assumed mode, and
  acknowledged unknown-newer behavior are implemented and documented; verified
  policies use one public, credential-free health probe and a cancellation-safe
  per-client cache;
- typed endpoint dispatch selects a reviewed version variant before request
  transmission, derives methods from immutable evidence, validates concrete
  path/query shape, and never retries a different route after an HTTP or decode
  failure;
- endpoint removals in newer OpenBao releases do not overwrite compatible
  older profiles, except where crate security policy explicitly blocks an
  unsafe operation;
- request-field availability and response-shape differences are validated by
  version;
- every endpoint/profile cell has a tested or explicitly bounded status;
- pull-request, scheduled, and release compatibility matrices are enforced;
- the README and security documentation distinguish tested wire compatibility
  from security endorsement of an old server;
- all standard release gates, the all-release integration gate, GitHub checks,
  and the final exact-commit pentest pass before tagging `v2.0.0`.
