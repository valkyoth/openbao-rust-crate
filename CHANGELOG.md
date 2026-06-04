# Changelog

All notable changes to this project are documented here.

## 0.12.0 - Unreleased

### Added

- Started the `0.12.0` PKI Tier 1 multi-issuer and authority lifecycle line.
- Added PKI default issuer and default key configuration read/write helpers
  for `/pki/config/issuers` and `/pki/config/keys`.
- Added named-issuer PKI issue/sign helpers for
  `/pki/issuer/:issuer_ref/issue/:name` and
  `/pki/issuer/:issuer_ref/sign/:name`.
- Added PKI root rotate, root replace, multi-issuer root/intermediate
  generation, and standalone key generation helpers.
- Added PKI cluster config, auto-tidy config, and revoke-with-key helpers.

### Maintenance

- Updated GitHub Actions pins for `Swatinem/rust-cache` and
  `taiki-e/install-action`, and bumped the CI `cargo-deny` install version.

## 0.11.0 - 2026-06-03

### Added

- Started the `0.11.0` Transit advanced key-management line.
- Added Transit wrapping-key, import/import-version, BYOK export,
  soft-delete/restore, global key config, cache config, CSR generation, and
  certificate-chain install helpers.
- Added secret-aware BYOK import/export request and response types so wrapped
  ciphertext and derivation contexts are stored as `SecretString` and redacted
  from `Debug`.
- Added public-key-only Transit import request constructors for OpenBao import
  paths that accept public key material instead of wrapped private key blobs.
- Added the optional `transit-import` software wrapping helper for preparing
  OpenBao AES-KWP/RSA-OAEP import blobs without adding dependencies to default
  builds.

### Security

- Documented the Transit BYOK wrapper boundary: default endpoint wrappers
  accept only externally wrapped ciphertext or public-key-only import material
  and do not accept raw private or symmetric key bytes.
- Restricted `request_json_with_retry` to `RetryableMethod` so write verbs
  cannot be retried accidentally through the raw retry helper.
- Added KV v2 CAS protection to `AdminBootstrap` secret-value convergence,
  rejecting concurrent modification instead of silently overwriting it where
  OpenBao exposes version checks.
- Tightened OpenBao path validation to reject non-ASCII and percent characters
  before URL construction.
- Corrected Transit sign response public-key handling to treat returned public
  keys as public `String` data while keeping signatures secret-aware.
- Added local validation for Transit export/BYOK version `0` and changed BYOK
  export version selection to `Option<u64>`.
- Kept Transit/System base64 secret helper output to a single allocation that
  is moved directly into `SecretString`, avoiding duplicate plaintext copies
  while relying on `SecretString` zeroization on drop.
- Removed an impossible `unreachable!` conversion path from retryable LIST
  request handling.
- Removed the now-dead `%{` HCL escaping branch after policy path validation
  began rejecting percent characters.
- Deprecated TOTP SHA-1 selection for new deployments while retaining legacy
  RFC 4226 compatibility.

## 0.10.0 - 2026-06-03

### Added

- Started the `0.10.0` Identity and auth completion line.
- Added typed Identity OIDC token backend helpers for config read/write,
  signing key create/read/list/delete/rotate, role create/read/list/delete,
  signed ID token generation, token introspection, discovery metadata, and
  public JWKS reads.
- Added typed Identity OIDC provider, scope, client, and assignment admin
  helpers, including named-provider discovery and JWKS reads while keeping
  browser OIDC protocol flows outside the SDK boundary.
- Added `Sys::validate_mfa` for `/sys/mfa/validate`, completing the typed
  second step for MFA-enforced login flows.
- Added Identity MFA Duo, Okta, PingID, and TOTP method helpers, including TOTP
  secret generation/admin actions and MFA login-enforcement CRUD/list helpers.
- Added secret-aware Identity OIDC token and introspection request types with
  redacted `Debug` output.
- Added secret-aware Identity OIDC client response handling so returned client
  secrets are stored as `SecretString` and redacted from `Debug`.
- Added secret-aware MFA validation request and auth response handling so
  passcodes, returned client tokens, and accessors are redacted from `Debug`.
- Added secret-aware Identity MFA provider credential and generated TOTP secret
  handling so Duo/Okta/PingID credentials and TOTP QR/URL outputs are redacted
  from `Debug`.
- Added bounded deserialization for Identity OIDC signing-key lists, role lists,
  provider/client metadata maps, nullable discovery metadata lists, and JWKS key
  arrays.
- Added bounded deserialization for Identity OIDC introspection/discovery extra
  claim maps, accepted exact-limit JWKS key lists, and fail-early oversized JWKS
  handling.
- Tightened Identity OIDC bounded JSON map and discovery string-list handling
  so bounds are checked before parsing or converting the first oversized item.
- Added mock HTTP coverage for the documented Identity OIDC token backend paths.
- Added mock HTTP coverage for the documented Identity OIDC provider admin and
  Identity MFA management paths.

### Changed

- Documented admin bootstrap read-compare-write race scope at the top-level
  `AdminBootstrap` API.
- Capped JSON object string validation before parsing and escaped HCL template
  interpolation starts in generated ACL policy strings.
- Clarified deprecated `Client::with_token`, Transit plaintext residual-memory,
  tracing path sensitivity, AppRole `bind_secret_id`, and KV v2 metadata policy
  helper documentation.

## 0.9.0 - 2026-06-03

### Added

- Started the `0.9.0` API stabilization candidate line.
- Added API stabilization audit documentation for public API review,
  near-`1.0` design decisions, and deferred work tracking.
- Added a known-limitations decision register that reviews historical release
  limitations and assigns each to resolved, `0.9.0` implementation,
  documentation review, intentional deferral, or permanent external boundary.
- Added migration guidance for users upgrading from earlier `openbao` releases,
  `vaultrs`, or bespoke `reqwest` OpenBao/Vault wrappers.
- Added a generated OpenBao `2.5.x` endpoint-by-endpoint coverage matrix with
  `643` documented endpoint rows, `72.9%` strict typed or operator-gated
  coverage, explicit pre-`1.0.0` planned rows, and zero remaining owner-decision
  rows.
- Added a `0.9.0` release-note skeleton and release gate script.
- Expanded the pre-`1.0` release strategy through `0.15.0` so Identity/auth,
  Transit advanced key management, PKI advanced and specialized flows, system
  backend completion, and endpoint closure can be handled without rushing
  risky APIs into `0.9.0`.
- Recorded the Identity OIDC and MFA scope decision: admin CRUD, discovery,
  token generation, introspection, and MFA login validation were assigned to
  the `0.10.0` line, while named-provider browser protocol flows remain
  external.
- Added `RenewalHint` for caller-owned token and lease renewal loops and typed
  `/sys/leases/tidy` maintenance support.
- Added safe custom plugin wrapper building blocks: `PluginMount`, public path
  validators, `BoundedStringList`, and the public bounded string-list
  deserializer.
- Recorded the PKI advanced issuer/root decision: Tier 1 multi-issuer config,
  root lifecycle, sign-verbatim, revoke-with-key, and current-doc struct-field
  completion are planned for `0.12.0`; Tier 2 revocation/CRL management, CEL,
  named-issuer hierarchy, delta-CRL, and cross-sign rows are planned for
  `0.13.0`; unauthenticated public CA/CRL/cert and OCSP protocol reads are
  external boundaries.
- Recorded the Transit import/BYOK boundary: wrapping-key, import and
  import-version, BYOK export, soft-delete/restore, cache/global config, CSR,
  and certificate-install rows are assigned to the `0.11.0` line; the current
  line implements those wrappers with already-wrapped `SecretString` material
  or public-key-only import material. The optional `transit-import` helper is
  implemented with feature-gated `openssl` and `aes-kw` dependencies and
  follows OpenBao's documented AES-KWP/RSA-OAEP software wrapping flow.
- Tightened the Transit import/BYOK implementation contract: wrapping-key
  returns public PEM, import constructors must reject empty pre-wrapped
  ciphertext, BYOK export returns redacted `SecretString` ciphertext, and raw
  key bytes must never be passed to endpoint wrappers.
- Added a non-default `tracing` feature that instruments the shared HTTP
  dispatch point with method, validated path, and response status events.
- Added a non-default `http2` feature that enables reqwest HTTP/2 support and
  lets TLS ALPN negotiate HTTP/2 when the OpenBao server supports it.
- Added token `create_orphan` and `renew_accessor` helpers, resolving the
  remaining token endpoint decision rows and completing the accessor-only
  renew/revoke administration path.
- Added typed AppRole delegated role-property helpers for OpenBao's documented
  `policies`, SecretID limits, token TTL/max TTL, bind-secret-id, CIDR, and
  period endpoints, including the documented reset/delete operations.
- Added operator-gated PKI default root deletion via `Pki::delete_root` and
  `PkiRootDeletion::confirm()` so `DELETE /pki/root` is available only through
  an explicit destructive-operation call site.
- Added `RetryPolicy` and `Client::request_json_with_retry` for explicit,
  caller-approved exponential backoff on temporary OpenBao failures.
- Added `ListPageOptions` as the shared pagination request shape for
  non-secret string-list endpoints and routed existing paginated list helpers
  through the shared validation/bounds logic.
- Added AdminBootstrap convergence for PKI roles and Identity entities/groups,
  using read-compare-write helpers that compare only caller-supplied desired
  fields.
- Added explicit `planned` and `rejected` endpoint-matrix statuses and recorded
  system backend decisions: config-ui, sys/monitor streaming, internal router
  inspection, internal counters, and internal request inspection are rejected
  for stable scope; root/recovery token ceremonies, decode-token, password
  policies, resultant ACL, legacy recovery-key rekey, and typed operator-gated
  in-flight request inspection are planned for `0.14.0`.
- Recorded the `0.15.0` stable-scope ergonomics decisions: bounded
  `wait_until_unsealed` polling, typed response-wrapping ergonomics, selective
  PKI/database/SSH bootstrap convergence, and ACL wrapping-TTL policy builder
  support are planned before `1.0.0`; request-level back-pressure, KV v1
  bootstrap convergence, and ACL parameter-constraint HCL generation are
  rejected for stable scope.
- Added representative public response serde fixtures for health, KV v2, PKI,
  Identity, and token auth response shapes.
- Added cargo-fuzz target scaffolding for path validation, API error decoding,
  and response envelope parsing.
- Added `docs/QUANTUM_READINESS.md` to define the crate's advisory-only
  quantum-readiness posture and the rules for future hybrid/post-quantum
  primitive exposure.

### Security

- Stabilization work starts with documentation of non-goals and deferred
  high-risk helpers so new APIs do not accidentally overpromise around
  auto-renewal, lease tracking, retries, pagination, tracing, quantum-ready
  posture, or production bootstrap convergence.
- Background token auto-renewal and background lease tracking are explicitly
  rejected for stable scope; applications own renewal loops, failure policy,
  and shutdown ordering.
- Generic plugin/secret-engine traits are rejected for stable scope because
  plugin schemas are deployment-specific; typed local wrappers should use the
  public plugin building blocks instead.
- OpenTelemetry SDK dependencies and custom request hooks are rejected for
  stable scope; W3C `traceparent` propagation is deferred past `1.0.0`.
- Leaf certificate and SPKI pinning are rejected for stable scope; root-only
  trust with an internal CA or self-signed OpenBao certificate is documented as
  the supported pattern.
- Runtime HTTP/2 transport knobs are rejected because ALPN handles negotiation;
  HTTP/3 is rejected for stable scope.
- Retry/backoff remains opt-in and call-site explicit; default typed helpers
  stay single-shot so non-idempotent writes are not retried by accident.
- Generic pagination intentionally excludes token accessors, lease IDs, and
  other secret-bearing list values so secret-specific handling is preserved.
- Full ACME account/order/authorization/challenge flows remain external to the
  crate; typed ACME config, EAB provisioning, and directory URL helpers are the
  supported handoff to dedicated ACME clients.
- Refined the PKI roadmap from the current OpenBao docs: Tier 1 multi-issuer
  config/root/sign-verbatim/revoke-with-key and missing role/generation/CRL/
  tidy fields move to `0.12.0`; Tier 2 revocation/CEL/cross-sign/delta-CRL
  work stays in `0.13.0`; unauthenticated public CA/CRL/cert and OCSP protocol
  reads are external boundaries.
- Stable response-wrapping ergonomics are planned as typed wrapping-token
  handles with redacted `SecretString` fields; per-engine wrapped method
  duplication is rejected to avoid API-surface sprawl.
- ACL parameter constraints remain outside `AclPolicyBuilder` because safe
  generation requires a complete HCL value serializer; callers should continue
  using reviewed policy documents for those advanced rules.
- Quantum-readiness documentation avoids post-quantum safety claims for current
  OpenBao deployments and treats crate-visible posture helpers as advisory
  evidence only.
- Resolved the 2026-06-03 pentest follow-up by validating Transit
  `auto_rotate_period` on key creation, requiring CIDR host bits to be zeroed,
  making the public `BoundedStringList` inner vector private with a checked
  constructor, excluding permanent 501/505 responses from retry-temporary
  classification, removing the unreachable `Error::Http(reqwest::Error)`
  variant, redacting LDAP auth PEM material in `Debug`, rejecting spaces in
  OpenBao path validation, and rejecting zero `Duration` values in duration
  builder helpers before they become `0s`.
- Kept the 32 MiB response cap default for `0.9.0` because snapshot/raw-byte
  workflows already rely on the documented override model; small-response
  clients should continue lowering `OpenBaoConfig::max_response_bytes`.

## 0.8.0 - 2026-06-02

### Added

- Started the `0.8.0` development line for remaining auth-method and system
  backend coverage.
- LDAP auth login, method configuration, group policy mapping, user
  policy/group mapping, list, read, and delete helpers.
- RADIUS auth login, method configuration, user policy mapping, user
  read/list/delete, and paginated user-list helpers.
- Kerberos auth login with SPNEGO negotiate headers, service-account/keytab
  config, Kerberos LDAP config, and group policy mapping helpers.
- JWT/OIDC browser-flow helpers for authorization URL, callback, and
  direct/device polling.
- Token role write/read/list/delete, token tidy, and revoke-orphan helpers.
- Transit key config update, key rotation, export, backup, restore, trim, and
  batch encrypt/decrypt/rewrap/sign/verify helpers.
- PKI role merge-patch, tidy status, and tidy cancel helpers.
- Identity entity/group lookup and entity merge helpers.
- System leader status, OpenAPI discovery, and JSON telemetry metrics helpers.
- Internal UI namespace and mount discovery helpers.
- HA status helper with bounded node lists.
- Key status helper for barrier encryption key metadata.
- Host diagnostics helper for `/sys/host-info`.
- Sanitized config state JSON helper.
- Audited request-header list/read/write/delete helpers.
- CORS configuration read/write/delete helpers.
- Runtime logger level read/set/reset helpers and installed OpenBao version
  history listing.
- Namespace list, create, read, patch, and delete helpers.
- Rate-limit quota config and named rate-limit quota list/create/read/delete
  helpers.
- Locked-user list/filter and unlock helpers.
- Integrated Storage Raft join, configuration, peer remove/promote/demote,
  HA bootstrap, and Autopilot JSON helpers.
- Capped Integrated Storage Raft snapshot download, restore, and force-restore
  helpers.
- Lease prefix revoke, force prefix revoke, and lease count helpers.
- Prometheus text metrics helper for `/sys/metrics?format=prometheus`.
- Remount/mount-migration start and status helpers.
- Operator-gated active-node step-down helper for `/sys/step-down`.
- System tools random byte and hash helpers for `/sys/tools/random` and
  `/sys/tools/hash`.
- Operator-gated raw storage read, write, list, and delete helpers for
  `/sys/raw/:path`.
- Operator-gated pprof diagnostic helpers for `/sys/pprof/:profile`.
- Typed capability views and common `can_read`/`can_update`/`can_delete`/
  `can_list` helpers for system capability responses.
- Read-only admin bootstrap preview with `WouldCreate`, `WouldUpdate`, and
  `WouldIssue` statuses before applying a plan.
- Advisory `FipsPosture` report builder for crate-visible Transit key, hash,
  signature, and seal-assumption choices.
- Shared `ListEntries` trait for common string list responses.
- Optional RFC3339 timestamp parsing helpers behind the `time` feature.
- Runtime-neutral `Sys::wait_ready_with_delay` helper for service startup and
  integration-test polling.
- Additional error predicates: `is_rate_limited`, `is_temporary`, and
  `is_permission_denied`.

### Security

- RADIUS shared secrets, login passwords, returned tokens, and accessors are
  represented as `SecretString` and redacted from debug output.
- RADIUS user lists and login metadata maps use bounded deserializers, and
  CIDR/duration request fields are validated before dispatch.
- RADIUS configuration documents the protocol's UDP and MD5-based authenticator
  risk so high-assurance deployments can prefer stronger auth methods.
- LDAP auth bind passwords, client TLS private keys, login passwords, returned
  tokens, and accessors are represented as secret material where applicable and
  redacted from debug output.
- LDAP auth lists, policy lists, and login metadata maps use bounded
  deserializers, and TLS version, CIDR, duration, and insecure LDAP TLS
  settings are validated before dispatch.
- Kerberos keytabs, SPNEGO tokens, LDAP bind passwords, returned tokens, and
  accessors are secret-aware; Kerberos group lists and login metadata maps are
  bounded, and LDAP TLS version, CIDR, duration, and insecure TLS settings are
  validated before dispatch.
- Metrics support includes JSON and Prometheus text output. Prometheus text
  output uses the private raw-body transport path while preserving
  response-size limits.
- Logger and version-history responses use bounded map/list deserialization.
- Namespace paths are validated against OpenBao namespace naming restrictions,
  and namespace metadata maps are bounded.
- Rate-limit quota rates, duration fields, names, paths, exempt-path lists, and
  optional roles are validated before request dispatch.
- Locked-user namespace, mount-accessor, and alias-identifier lists are bounded
  during deserialization, and unlock path parameters must be single path
  segments.
- Raft join client keys, auto-join metadata, and DR operation tokens are
  represented as secret material and redacted from debug output. Raft server
  lists are bounded, peer IDs are validated, Raft join leader addresses and
  auto-join schemes must use HTTPS, and Autopilot duration/integer fields are
  checked before request dispatch.
- Raft snapshots use the same HTTPS/token protections and response-size caps as
  JSON requests. Downloaded snapshots are returned in zeroizing byte buffers,
  and restore helpers reject empty payloads before dispatch.
- HA node lists are bounded, and remount source, destination, and migration ID
  values are validated before request dispatch.
- CORS origins and headers are bounded, wildcard origins are rejected, and
  configured header names are validated before request dispatch.
- Audited request-header maps are bounded, and header names are validated with
  HTTP header parsing before request dispatch.
- Internal UI namespace lists and mount maps are bounded; UI mount detail paths
  are validated before request dispatch.
- System tools random responses and hash outputs are represented as
  `SecretString` and redacted from debug output; random byte counts are rejected
  when zero or above the local 1 MiB helper limit.
- Raw storage helpers are available only with `operator-ops` plus
  `operator-ops-acknowledged`; raw values use `SecretString`, response key
  lists are bounded, and raw storage paths are validated before dispatch.
- Pprof helpers are available only with `operator-ops` plus
  `operator-ops-acknowledged`; profile payloads are returned in zeroizing byte
  buffers, response-size limits apply, and profiling duration/debug query
  values are validated before dispatch.
- Capability inspection preserves the existing raw string lists while keeping
  unknown future capability names visible through `Capability::Unknown`.
- Bootstrap preview performs read-side comparisons only and never writes state
  or issues credentials.
- `FipsPosture` is intentionally best-effort and records unverifiable
  deployment assumptions instead of claiming OpenBao or the deployment is FIPS
  certified.
- `ListEntries` is implemented only for regular string list responses; secret
  accessor lists keep their dedicated secret-aware types.
- Timestamp parse errors do not echo caller-provided values.
- LDAP auth and Kerberos LDAP TLS version fields now reject deprecated TLS 1.0
  and TLS 1.1 values.
- Local `PENTEST.md` for `0.8.0` was reviewed on 2026-06-02 and deleted before
  commit; actionable local findings were addressed.
- Local `GAP_ANALYSIS.md` for `0.8.0` was reviewed and deleted before commit;
  small endpoint and ergonomics gaps were implemented, and larger background,
  OIDC-provider/MFA, retry, tracing, pagination, bootstrap, and lease-tracking
  systems were recorded in the versioned release plan.
- Follow-up `PENTEST.md` for `0.8.0` was reviewed and deleted before commit;
  readiness polling now retries temporary transport errors until timeout,
  query-bearing OIDC callback requests were verified to use the sensitive
  transport path, `is_permission_denied` semantics were clarified, and
  development TLS key history guidance was documented.

## 0.7.0 - 2026-06-01

### Added

- AppRole role and SecretID administration helpers for role
  create/read/list/delete, RoleID read/update, SecretID generate/list/lookup,
  SecretID destroy by value or accessor, custom SecretID assignment, and
  SecretID tidy.
- Admin bootstrap support for auth method enablement, AppRole role
  convergence, and explicit AppRole SecretID issuance.
- Cubbyhole secrets engine read, optional read, write, delete, and list
  helpers.
- Kubernetes secrets engine configuration, role management, role listing, and
  service account credential generation helpers.
- RabbitMQ secrets engine connection configuration, lease configuration, role
  management, role listing, role deletion, and generated credential helpers.
- Identity entity, group, entity-alias, and group-alias lifecycle helpers with
  bounded list/map deserialization and request collection limits.
- LDAP secrets engine helpers for config, root rotation, static
  roles/credentials, dynamic roles/credentials, library sets, status,
  check-out, check-in, and managed check-in.
- Typed custom plugin wrapper pattern documentation for plugin-specific APIs
  built on `Client::request_json`.
- `duration_to_bao_string`, `SharedClient`, and `Client::into_shared` helpers
  for common Rust application patterns.
- Bootstrap report lookup helpers for issued tokens, issued AppRole SecretIDs,
  convergence checks, and changed-step iteration.
- KV v2 service config write helpers and Cubbyhole service config read helper.
- Duration overloads for common Token, AppRole, Kubernetes secrets, and LDAP
  TTL/period builders.
- Prelude exports for commonly used concrete auth, secrets, sys, and bootstrap
  types.

### Security

- LDAP `insecure_tls=true` now requires the
  `insecure-ldap-tls-acknowledged` Cargo feature before request dispatch.
- AppRole, Userpass, JWT, and TLS certificate auth CIDR fields are validated
  locally before writes.
- AppRole SecretID metadata and RabbitMQ role permission JSON strings are
  validated as JSON object strings before request dispatch.
- API error sanitization now truncates by UTF-8 byte length rather than Unicode
  scalar count.
- OpenBao API error strings are sanitized before storage in `Error::Api`.
- Auth token headers are rebuilt per request instead of cached in the client,
  and empty or whitespace-only tokens are rejected.
- The sensitive loopback HTTP test bypass now requires the explicit
  `sensitive-http-test-only` Cargo feature.
- Lease ID request fields now reject oversized values, and
  `Kv2ServiceConfig` debug output redacts key names.
- AppRole bootstrap docs now call out read-compare-write concurrency behavior
  and the need to serialize competing bootstrap runs externally.

## 0.6.0 - 2026-05-31

### Added

- Bounded ACL policy builder helpers for common KV v2 and Transit
  least-privilege rules.
- TOTP secrets engine helpers for key create/read/list/delete, code
  generation, and code validation with generated URLs, barcodes, and codes
  treated as secret material.
- SSH secrets engine helpers for roles, zero-address roles, IP role lookup,
  OTP credentials, default issuer config, issuer list/submit/read/update/delete,
  authenticated CA public-key metadata, CA signing, generated SSH
  certificate/key issuance, and OTP verification.
- Validating `TokenCreateRequest` duration builders for token TTL,
  explicit-max-TTL, and period fields.
- `SshIssueRequest::with_key_bits` for validating generated SSH key strength.
- `TokenCreateRequest::with_policies` and `without_default_policy` helpers.
- `Kv2ServiceConfig::required`, KV v2 paginated list helpers, common OpenBao
  error inspectors, and mount/auth lease-TTL builder helpers.
- `AdminBootstrap` plan builder for idempotent KV v2 mounts, Transit mounts,
  Transit keys, ACL policies, KV v2 string secret values, and explicit scoped
  service-token issuance.
- Explicitly gated `operator-ops` APIs for production init, unseal, seal,
  legacy rekey, OpenBao key-share rotation, and keyring rotation. The feature
  requires `operator-ops-acknowledged`.

### Fixed

- SSH role listing now accepts OpenBao's documented `keys` response field as
  well as the `roles` field used by IP lookup and zero-address endpoints.
- SSH role/sign/issue requests now reject malformed durations, control
  characters in principal/CIDR fields, unsupported SSH public-key prefixes, and
  weak generated RSA key sizes before sending requests.
- `AdminBootstrap` compares existing and desired KV v2 secret values with
  constant-time equality, bounds the number of planned operations, and treats
  duplicate-create races for mounts and Transit keys as unchanged state.
- Dev-state TLS private-key patterns are explicitly ignored in addition to the
  ignored dev-state directory.
- Token renew increments are validated before request dispatch.

### Documentation

- Added examples for AppRole login, environment-based client construction, and
  admin bootstrap; updated the sys admin example to use `AclPolicyBuilder`.
- Added AppRole admin and auth-method bootstrap orchestration to the `0.7.0`
  release plan.

### Changed

- `Client::with_token` is formally deprecated; use `Client::try_with_token` so
  invalid token header values fail at construction time.

## 0.5.0 - 2026-05-30

### Added

- `Client::try_with_token` for immediate auth-token header validation before
  building an authenticated client.
- Crate-root re-exports for public API dependency types, including
  `SecretString`, `ExposeSecret`, `Method`, `StatusCode`, `Certificate`,
  `Identity`, and `tls`.
- `prelude` module for common application imports.
- `Default` implementations and constructors for common admin request types.
- `Sys::enable_kv2` and `MountEnableRequest::kv2` helpers to avoid the
  stringly typed KV v2 mount setup footgun.
- Database secrets engine helpers for connection config, dynamic/static roles,
  credential reads, root rotation, and static role rotation.
- Typed Transit RSA signature, JWS marshaling, and RSA-PSS salt-length options
  with base64 input constructors for sign/verify workflows.
- `Error::status`, `Error::is_not_found`, `Kv2::read_optional`, and
  `Kv2::read_data_optional` helpers for common absent-secret branching.
- Constructors for PKI issue and Transit encrypt/decrypt/rewrap requests.
- Optional `transit-bytes` feature with raw-byte Transit helpers backed by
  `base64-ng`.
- Userpass auth login plus user create/read/list/delete, password update, and
  policy update helpers.
- JWT auth login plus JWT/OIDC auth method config and role administration
  helpers.

### Fixed

- Response schema decode errors no longer include raw serde value fragments,
  avoiding accidental logging of secret-bearing response data.
- Environment CA certificate read/parse errors no longer echo local filesystem
  paths or parser details.
- Credential-bearing or request-body requests are refused over plain HTTP, even
  when numeric loopback HTTP is enabled for non-sensitive development probes.
- Sensitive request dispatch now uses a separate HTTPS-only HTTP client path to
  make credential transport policy explicit.
- Removed cargo-test-binary path detection from the local HTTP test bypass;
  crate tests now require an explicit debug-only numeric-loopback opt-in.
- OpenBao paths are bounded by byte length and segment count before request URL
  construction.
- Database connection URLs are handled as `SecretString` because DSNs commonly
  embed credentials.
- JWT role leeway fields now use typed `JwtLeeway` values, with JWT time-check
  disabling represented only by the explicit `DisableTimeValidation` variant.
- The KV v2 example no longer prints secret-derived response fields.
- Security documentation now includes a hardened deployment profile for
  avoiding TLS 1.2/native TLS opt-downs and lowering response caps.

### Changed

- Updated optional `base64-ng` Transit byte-helper dependency to `1.0.5`.

## 0.4.0 - 2026-05-29

### Added

- Environment-based client construction from `OPENBAO_*`, `BAO_*`, and
  `VAULT_*` address, token, namespace, CA certificate, root-only trust, and
  loopback HTTP opt-in variables.
- Kubernetes auth login, auth method config, role write/read/list/delete, and
  secret-aware service account JWT handling.
- TLS certificate auth login, auth method config, CA role write/read/list/delete,
  CRL write/read/list/delete, and mutual TLS client identity configuration.
- PKI URL config, role write/read/list/delete, issue, sign, revoke,
  certificate list, and certificate read helpers with secret-aware generated
  private keys.
- PKI root generation, intermediate generation, intermediate signing, signed
  intermediate install, CRL config, CRL rotation, and tidy helpers.
- PKI issuer and key list/read/delete helpers.
- PKI issuer patch/revoke, CA/key import, and key rename helpers.
- PKI ACME configuration and external account binding token helpers.
- PKI ACME directory URL helpers for handing documented directory endpoints to
  ACME clients.
- KV v2 typed data reads and bounded `Kv2ServiceConfig` loading with
  `SecretString` values for environment-style service configuration.
- Per-client `max_response_bytes` configuration for lowering the default 32
  MiB response cap.
- `0.4.0` release-note scaffolding and release gate.

### Changed

- Lowered the minimum supported Rust version from `1.95.0` to `1.90.0`, with
  compatibility checked through Rust `1.96.0`.
- `OpenBaoConfig::user_agent` now validates header control characters at
  configuration time and returns `Result<Self>`.
- Legacy Transit SHA-1 selection now requires the explicit `allow-sha1`
  feature.

### Fixed

- Bounded AppRole login policy lists during deserialization.
- Plugin registration SHA-256 digests now require canonical lowercase hex.
- Documented request-body residual buffer risks and dev bootstrap root-token
  duplication.

## 0.3.0 - 2026-05-28

### Added

- Audit device list, enable, disable, and hash helpers for the system backend.
- Safe exact lease lookup, renew, and revoke helpers using JSON body endpoints.
- Transit key create, read, list, delete, encrypt, decrypt, rewrap, data key,
  random, hash, HMAC, sign, and verify helpers.
- Plugin catalog list, type-list, register, read, delete, and mounted backend
  reload helpers.
- `/sys/init` status and loopback-only `bootstrap_dev` helper for disposable
  local OpenBao development instances.
- `scripts/release_0_3_gate.sh` and `0.3.0` release-note scaffolding.

### Security

- Lease IDs are handled as secret material and redacted from debug output.
- Lease helper scope intentionally excludes prefix, force, and tidy operations.
- Audit device option maps are bounded during deserialization.
- Transit plaintext, ciphertext, data keys, random bytes, hashes, and HMACs
  are represented with `SecretString` where they enter or leave the crate.
- Plugin registration args/env and returned args/env are represented as
  `SecretString`; detailed catalog lists are bounded during deserialization.
- Server-controlled maps for capabilities, mounts, audit devices, KV metadata,
  token metadata, and Transit key versions are bounded during deserialization.
- SHA-1 Transit hashing is deprecated at compile time, plugin registration
  SHA-256 digests are validated as 64-character hex, and native TLS now
  requires the `native-tls-acknowledged` feature.
- Token and AppRole login response structs no longer implement `Clone`,
  avoiding accidental extra token/accessor heap copies.
- `bootstrap_dev` refuses non-loopback and already-initialized targets and is
  documented as unsuitable for production, HSM/KMS auto-unseal, or shared
  environments.

## 0.2.0 - 2026-05-27

### Added

- Token lifecycle helpers for create, lookup, accessor lookup/list, renew, and
  revoke flows.
- KV v1 read, write, delete, and list helpers.
- KV v2 version reads, patch, soft-delete versions, undelete, destroy,
  metadata, and backend config helpers.
- System mount and auth mount list, enable, tune, and disable helpers.
- Response wrapping lookup, wrap, unwrap, and rewrap helpers.
- ACL policy list, read, write, delete, and prefix-list helpers.
- Self, token, and token-accessor capability query helpers.
- Podman-backed real OpenBao integration test for the default `0.2.0`
  feature flow.

### Fixed

- KV v2 patch helpers now send the documented JSON merge patch content type.
- JSON request serialization buffers controlled by the crate are zeroized after
  handoff to the HTTP stack.
- Successful JSON responses now require an `application/json` content type.
- Namespace headers are marked sensitive.
- Token TTL responses reject negative values.
- System TTL/config fields use typed duration and lockout structures instead
  of unbounded JSON values.
- Response string lists are bounded for token policies, accessors, policy
  names, KV list keys, mount header lists, capabilities, and response warnings.
- KV v2 internal path helpers validate operation and mount child path segments.
- Response wrapping TTLs are validated before sending.
- `rustls-tls` now wires to the actual `reqwest/rustls` feature.

## 0.1.0 - 2026-05-27

### Added

- Initial secure OpenBao SDK scaffold.
- Typestate client with unauthenticated and authenticated states.
- Direct token authentication.
- AppRole login support.
- KV v2 read, write, check-and-set write, list, and latest-version delete support.
- System health and seal-status helpers.
- Raw JSON request escape hatch for unsupported endpoints.
- Local TLS OpenBao development instance on ports `9940` and `9941`.
- CI, GitHub CodeQL default setup compatibility, dependency review, release
  gates, and security documentation.

### Security

- Disabled HTTP redirect following to avoid forwarding token headers to another
  origin.
- Enforced TLS 1.3 minimum by default with explicit TLS 1.2 opt-down.
- Added default connection timeout.
- Added custom CA and root-only trust store configuration.
- Removed crate version from the default user agent.
- Zeroized intermediate bearer and JSON serialization buffers.
- Converted AppRole token accessors to `SecretString`.
- Validated AppRole mount paths at construction time.
- Expanded loopback HTTP detection to the full loopback address range.
