# Release Plan

This plan starts at `0.1.0` and ends at `1.0.0`, the first stable release.
The endpoint-by-endpoint OpenBao `2.5.x` matrix generated on 2026-06-03 found
`643` documented endpoint rows, `457` strict typed or operator-gated rows, and
`167` rows still needing an implementation, rejection, raw-wrapper policy, or
external-client policy decision. Because there is no rush to force stability,
the pre-`1.0` line now extends through `0.15.0` so those gaps can be closed
deliberately.

After `1.0.0`, the expected line is `1.0.x` maintenance, security fixes,
compatibility fixes, and documentation corrections only. Every pre-`1.0`
release must be functional enough to publish for external testing. No tag is
cut until the owner provides a pentest report for the exact release commit.

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
- validates release metadata;
- records pentest report status before tag.

## Finalization Policy

- Anything valuable enough for the stable crate must land between `0.9.0` and
  `0.15.0`, or be explicitly rejected/delegated before `1.0.0`.
- The stable readiness target is not blindly `100% typed`; it is `100%`
  addressed endpoint rows. A row may be addressed as `typed`, `typed-gated`,
  `partial`, `raw`, `external`, or rejected with a documented safe
  alternative.
- No endpoint row may remain classified as `decision` when `1.0.0` is tagged.
- After `1.0.0`, new feature work is not planned. Only `1.0.x` security,
  correctness, compatibility, and documentation updates are assumed.

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
- typed custom plugin API pattern documented.

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
  `operator-ops-acknowledged`; payloads are returned in zeroizing byte buffers
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
- small auth/token gaps from the matrix are implemented or assigned to
  `0.10.0`;
- optional tracing/OpenTelemetry, seal-status watcher/back-pressure, HTTP/2
  transport configuration, and application-side secret-struct wrappers have
  deferral decisions recorded; public response serde fixtures are added;
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
- token `create-orphan` and `renew-accessor` helpers are implemented or
  explicitly rejected;
- AppRole delegated per-property endpoints are either implemented as narrow
  helpers or permanently documented as `Client::request_json` rows because full
  role read/write is already typed;
- endpoint matrix is regenerated and all affected rows have updated statuses;
- tests cover redaction for new OIDC/MFA/token request and response types.

Publishable value:

- identity-heavy deployments can manage OpenBao Identity and MFA flows with
  typed helpers or clear external/raw boundaries.

### 0.11.0 - Transit Advanced Key Management

Stop condition:

- Transit key import, import-version, wrapping-key, BYOK export, key config,
  cache config, CSR generation, certificate install, soft-delete, and
  soft-delete-restore rows are implemented or explicitly rejected;
- imported key material and wrapped key material use secret-aware request and
  response types with custom `Debug`;
- risky operations are documented with operator warnings and feature gates if
  the API can expose import/export material outside OpenBao;
- `transit-bytes` remains optional and no default dependency growth is added;
- endpoint matrix is regenerated and Transit decision rows are resolved.

Publishable value:

- operators can automate advanced Transit key lifecycle work without bespoke
  request wrappers, while keeping key-material handling explicit.

### 0.12.0 - PKI Advanced Issuer, Root, And Public Read Coverage

Stop condition:

- named issuer issue/sign/sign-intermediate helpers;
- root rotate, root replace, root delete, issuers/key generation, intermediate
  issuer generation, and issuer/key config helpers;
- CA, certificate, CRL, delta-CRL, issuer JSON/DER/PEM, raw certificate, and
  detailed certificate list read helpers;
- cluster config, auto-tidy config, config issuers, config keys, CRL delta
  rotation, issuer CRL resign, and sign-revocation-list helpers;
- response-size caps and binary/text handling are documented for public
  certificate and CRL endpoints;
- endpoint matrix is regenerated and the main PKI administrative/public-read
  rows are resolved.

Publishable value:

- PKI operators can manage multi-issuer OpenBao PKI deployments and public CA
  material through typed helpers.

### 0.13.0 - PKI Specialized Flows And ACME Boundary

Stop condition:

- CEL role list/read/write/patch/delete plus CEL issue/sign helpers are
  implemented or rejected;
- sign-self-issued, sign-verbatim, revoke-with-key, revoked-cert list,
  revocation-queue list, OCSP GET/POST, and intermediate cross-sign helpers
  are implemented or rejected;
- full ACME account/order/authorization/challenge flows are either implemented
  or, more likely, permanently classified as `external` with directory URL and
  EAB helpers documented as the supported SDK boundary;
- endpoint matrix is regenerated and no PKI row remains `decision` unless it
  is intentionally moved to `0.15.0` for closure.

Publishable value:

- specialized PKI workflows are either typed or have stable documented
  external boundaries before the final system-backend pass.

### 0.14.0 - System Backend Completion

Stop condition:

- system config UI header helpers are implemented or rejected;
- generate-root and generate-recovery-token ceremony helpers are implemented
  behind explicit operator gates or rejected in favor of OpenBao CLI/operator
  process documentation;
- decode-token and password policy CRUD/generate helpers are implemented or
  rejected;
- monitor streaming, in-flight request, internal counters, internal inspect,
  resultant ACL, and legacy recovery-key rekey rows are implemented, rejected,
  or classified as permanent internal/streaming/operator boundaries;
- all system endpoint decisions are reflected in the matrix and support table;
- operator-risk additions preserve the existing `operator-ops` plus
  `operator-ops-acknowledged` pattern.

Publishable value:

- OpenBao system backend rows are fully addressed with typed helpers or stable
  documented boundaries.

### 0.15.0 - Endpoint Closure And Stable Candidate

Stop condition:

- endpoint matrix has zero `decision` rows;
- every row is `typed`, `typed-gated`, `partial`, `raw`, `external`, or
  explicitly rejected in linked documentation;
- strict typed coverage and addressed coverage percentages are recorded in
  README, API coverage docs, release notes, and changelog;
- all remaining historical `Known Limitations` are resolved, rejected, or
  documented as permanent boundaries;
- public API names, constructors, feature flags, and module layout are frozen
  for `1.0.0`;
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
  limited to `1.0.x` security, correctness, compatibility, and documentation
  updates.
