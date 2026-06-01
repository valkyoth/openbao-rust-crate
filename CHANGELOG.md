# Changelog

All notable changes to this project are documented here.

## 0.7.0 - Unreleased

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
