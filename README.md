<p align="center">
  <b>Secure, typed, async Rust SDK for OpenBao.</b><br>
  Memory-safe by default. Minimal dependency surface. Built for audited secret workflows.
</p>

<div align="center">
  <a href="https://openbao.org/">OpenBao</a>
  ·
  <a href="docs/OPENBAO_API_COVERAGE.md">API Coverage</a>
  ·
  <a href="docs/RELEASE_PLAN.md">Release Plan</a>
  ·
  <a href="docs/API_STABILITY_AUDIT.md">API Stability</a>
  ·
  <a href="docs/MIGRATION_GUIDE.md">Migration</a>
  ·
  <a href="SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <img src="https://raw.githubusercontent.com/valkyoth/openbao-rust-crate/main/.github/images/openbao_rust_crate.webp" alt="OpenBao Rust crate overview">
</p>

# OpenBao Rust SDK

`openbao` is a secure, typed, async Rust SDK for
[OpenBao](https://openbao.org/), the community-driven open source fork of
Vault. It is designed for audited secret workflows: HTTPS by default, no
redirect forwarding, strict path validation, secret-aware token types, and a
small reviewed dependency surface.

The crate name on crates.io is `openbao`; Rust imports are lowercase:

```rust
use openbao::Client;
```

This README documents the stable `1.1.x` API. The current patch release is
`1.1.2`, which keeps the `1.1.0` owned-secret-buffer migration intact,
refreshes dependency/tooling pins, and makes Rust `1.96.1` the primary checked
toolchain while preserving the Rust `1.90.0` compatibility floor.

The crate is dual-licensed under MIT or Apache-2.0.

## Current Status

Implemented now:

- Async client with typestate authentication.
- Direct token authentication with re-exported `openbao::SecretString`.
- AppRole login plus role and SecretID administration, with role IDs,
  SecretIDs, accessors, and returned tokens treated as secret material.
- Kubernetes auth login plus config and role administration helpers.
- TLS certificate auth login, method config, CA role, and CRL administration
  helpers.
- JWT login plus JWT/OIDC auth method config, role administration, browser
  authorization URL, callback, and direct/device polling helpers.
- LDAP auth login plus config and user/group policy mapping helpers.
- RADIUS login plus config and user policy mapping helpers.
- Kerberos login plus service-account, LDAP config, and group policy mapping
  helpers.
- Userpass login plus user create/read/list/delete, password update, and
  policy update helpers.
- Token create, create-orphan, role create/read/list/delete, lookup, accessor
  lookup/list/renew/revoke, renew, revoke, revoke-orphan, revoke-self, and tidy
  helpers.
- KV v2 read, write, CAS write, patch, list, latest delete, version read,
  version delete, undelete, destroy, metadata, backend config, typed data, and
  secret-aware service config read/write helpers.
- KV v1 read, write, delete, and list helpers.
- Cubbyhole read, optional read, write, delete, and list helpers for
  token-scoped handoff data.
- Kubernetes secrets engine config, role create/read/list/delete, and
  service account credential generation helpers.
- RabbitMQ secrets engine connection config, lease config, role
  create/read/list/delete, and dynamic credential helpers.
- Database connection config, dynamic roles, static roles, root/static
  rotation, and credential helpers.
- Identity entity, group, entity-alias, and group-alias lifecycle, lookup,
  entity merge, OIDC token backend config, signing key CRUD/rotate, role CRUD,
  signed ID token generation, token introspection, discovery, JWKS, OIDC
  provider/scope/client/assignment admin, and named-provider discovery/JWKS
  helpers.
- LDAP secrets engine config, static role, dynamic role, credential, library
  checkout, and check-in helpers.
- SSH role, zero-address role, IP lookup, OTP credential, issuer config,
  issuer list/submit/read/update/delete, CA public-key metadata, CA sign,
  generated certificate/key issue, and OTP verification helpers.
- TOTP key create/read/list/delete, code generation, and code validation
  helpers.
- PKI URL and CRL config, default issuer/key config, root/intermediate
  generation, root rotate/replace, intermediate signing and install,
  multi-issuer issue/sign flows, role write/read/list/delete/patch, CEL roles,
  issue, sign, revoke, revoke-with-key, certificate list/read, issuer/key
  list/read/delete/update, issuer revoke, CA/key import, ACME config/EAB and
  directory URL helpers, CRL and delta-CRL management, tidy, tidy status, and
  tidy cancel helpers.
- Transit key create, read, list, delete, config update, rotate, export, BYOK
  wrapping-key/import/import-version/export helpers, soft-delete/restore,
  cache/global config, CSR generation, certificate-chain install, backup,
  restore, trim, encrypt/decrypt/rewrap batch helpers, data key, random, hash,
  HMAC, sign/verify batch helpers, typed RSA/JWS signing options, optional
  raw-byte helpers, and gated software import-wrapping helpers.
- System health, readiness polling, seal status, leader status, OpenAPI
  discovery, JSON metrics, runtime logger level, version history, namespace
  management, rate-limit quota management, password policies, resultant ACL
  inspection, and loopback-only dev bootstrap helpers.
- Secret and auth mount enable, list, read, tune, and disable helpers.
- Response wrapping lookup, wrap, unwrap, and rewrap helpers.
- Typed response wrapping through `Client::wrapping`, `WrappingContext`, and
  `WrappedResponse<T>`.
- ACL policy list, read, write, delete, and prefix list helpers.
- Bounded ACL policy builder helpers for common KV v2 and Transit
  least-privilege rules, including response-wrapping TTL constraints.
- Idempotent admin bootstrap plan builder for KV v2 mounts, Transit mounts,
  Transit keys, ACL policies, KV v2 string secret values, auth methods,
  AppRole roles, PKI/database/SSH mount and role convergence, explicit scoped
  service-token issuance, and explicit AppRole SecretID issuance.
- Capability checks for the caller token, an explicit token, or a token
  accessor.
- Audit device list, enable, disable, and hash helpers.
- Safe exact lease lookup, renew, revoke, prefix revoke, force prefix revoke,
  and lease count helpers.
- Plugin catalog list, type-list, register, read, delete, and backend reload
  helpers.
- Explicitly gated production init, unseal, seal, rekey, key-share rotation,
  keyring rotation, root/recovery-token generation, decode-token, legacy
  recovery-key rekey, and in-flight request inspection operator APIs.
- Environment-based client construction from common OpenBao/Vault variables.
- Shared authenticated client and Rust `Duration` to OpenBao duration string
  helpers for async application ergonomics.
- Explicit retry/backoff helpers for caller-approved idempotent raw requests.
- Bootstrap read-only preview, report lookup helpers for issued credentials,
  and changed steps.
- Best-effort FIPS-oriented posture reporting for crate-visible Transit and
  deployment assumptions; this is advisory and not a certification claim.
- Shared `ListEntries` ergonomics for common list responses without changing
  their documented fields.
- Optional RFC3339 timestamp parsing helpers behind the `time` feature.
- Optional `tracing` and HTTP/2 features without default dependency or runtime
  transport hooks.
- Raw JSON request escape hatch for endpoints that are not typed yet.
- Operator-gated raw storage read, write, list, and delete helpers.
- Operator-gated pprof diagnostic byte helpers.
- Typed custom plugin wrapper pattern documentation and safe building blocks
  for application-specific OpenBao plugin APIs.
- Local TLS OpenBao Podman stack on `9940` and `9941`.
- Real OpenBao integration test gate using the pinned OpenBao image.

`1.x` is the stable release line. Feature history and patch details live in
[CHANGELOG.md](CHANGELOG.md) and [release-notes](release-notes).

See [API Coverage](docs/OPENBAO_API_COVERAGE.md) and
[Release Plan](docs/RELEASE_PLAN.md) for the stable support policy.

## Trust Dashboard

| Area | Status |
| --- | --- |
| License | `MIT OR Apache-2.0` |
| Rust edition | 2024 |
| Primary Rust toolchain | Rust `1.96.1` |
| MSRV | Rust `1.90.0` |
| Async runtime | Runtime-agnostic client; examples use Tokio |
| HTTP transport | `reqwest` with redirects disabled |
| Default TLS backend | Rustls |
| TLS floor | TLS 1.3 by default; TLS 1.2 requires explicit opt-in |
| Plain HTTP | Rejected by default; sensitive requests still require HTTPS |
| Token storage | `openbao::SecretString` (`secrecy::SecretString`) |
| Secret byte buffers | `openbao::SecretVec` (`sanitization::SecretVec`) |
| Unsafe policy | `unsafe_code = "forbid"` |
| Path validation | Rejects traversal, query/fragment injection, empty segments, controls, and trailing periods |
| Error posture | API error strings are bounded and sanitized before formatting |
| Dependency policy | `cargo deny` plus RustSec audit in the release gate |
| Release evidence | fmt, clippy, tests, docs, deny, audit, SBOM, optional Kani proof harnesses, and real OpenBao integration |
| Pentest gate | Required before tagging a release |

Security details live in [SECURITY.md](SECURITY.md). Release evidence and
release sequencing live in [release-notes](release-notes) and
[docs/RELEASE_PLAN.md](docs/RELEASE_PLAN.md).

## Rust Version Support

The primary checked Rust toolchain is Rust `1.96.1`. The minimum supported
Rust version remains Rust `1.90.0`, and the `1.x` line checks compatibility
back to that floor.

The `1.x` release line tracks compatibility evidence across this supported
range:

| Rust | Required Evidence |
| --- | --- |
| `1.96.1` | Primary release gate: fmt, clippy, tests, docs, deny, audit, SBOM, optional Kani proof harnesses, and real OpenBao integration. |
| `1.95.0` | `cargo check --all-features`. |
| `1.94.0` | `cargo check --all-features`. |
| `1.93.0` | `cargo check --all-features`. |
| `1.92.0` | `cargo check --all-features`. |
| `1.91.0` | `cargo check --all-features`. |
| `1.90.0` | MSRV compatibility check with all features. |

## OpenBao Test Version Support

The SDK targets the OpenBao `2.5.x` API surface. Release testing is pinned to
the newest OpenBao patch release available for that SDK line:

| SDK release line | OpenBao version tested |
| --- | --- |
| `0.1.0` through `1.0.2` | OpenBao `2.5.4` |
| `1.1.0` through `1.1.2` | OpenBao `2.5.5` |

## Install

```toml
[dependencies]
openbao = "1"
serde = { version = "1.0.228", features = ["derive"] }
tokio = { version = "1.52.3", features = ["macros", "rt-multi-thread", "time"] }
```

Some advanced examples below use JSON helper types directly:

```toml
[dependencies]
serde_json = "1.0.150"
```

## Quick Start

Read a KV v2 secret using the secure environment-based constructor:

```rust,no_run
use openbao::{Client, Result, SecretString};
use serde::Deserialize;

#[derive(Deserialize)]
struct DbCredentials {
    username: String,
    password: SecretString,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Reads OPENBAO_ADDR/BAO_ADDR/VAULT_ADDR plus token, namespace, and CA aliases.
    let client = Client::from_env_with_token()?;
    let secret = client
        .kv2("secret")?
        .read::<DbCredentials>("production/database")
        .await?;

    println!("loaded credentials for {}", secret.data.username);
    let _password = secret.data.password;
    Ok(())
}
```

The crate defaults to the common SDK surface:

```toml
[dependencies]
openbao = { version = "1", features = ["approle", "cert-auth", "cubbyhole", "database", "jwt-auth", "kubernetes-auth", "ldap-auth", "kubernetes", "userpass", "token", "kv1", "kv2", "pki", "ssh", "totp", "transit", "sys", "rustls-tls"] }
```

For a smaller build, disable defaults and opt into only what the application
uses:

```toml
[dependencies]
openbao = { version = "1", default-features = false, features = ["kv2", "sys", "rustls-tls"] }
```

Optional RFC3339 timestamp parsing is available behind the lightweight `time`
feature:

```toml
[dependencies]
openbao = { version = "1", features = ["time"] }
```

## Features

| Feature | Default | Purpose |
| --- | --- | --- |
| `approle` | yes | AppRole login, role, delegated role-property, RoleID, and SecretID helpers. |
| `cert-auth` | yes | TLS certificate auth login/config/role/CRL helpers. |
| `cubbyhole` | yes | Token-scoped Cubbyhole read/write/delete/list helpers. |
| `database` | yes | Database secrets engine config, role, credential, and rotation helpers. |
| `identity` | yes | Identity entity, group, entity-alias, and group-alias helpers. |
| `jwt-auth` | yes | JWT login plus JWT/OIDC config, role administration, auth URL, callback, and poll helpers. |
| `kerberos-auth` | yes | Kerberos SPNEGO login, service-account config, LDAP config, and group mapping helpers. |
| `kubernetes-auth` | yes | Kubernetes auth login/config/role helpers. |
| `ldap-auth` | yes | LDAP auth login/config/user/group mapping helpers. |
| `radius-auth` | no | RADIUS login/config/user mapping helpers. Legacy RADIUS uses MD5-based authenticators and requires `radius-auth-acknowledged`; do not use it for classified networks or new high-assurance deployments. |
| `radius-auth-acknowledged` | no | Explicit acknowledgment for audited legacy RADIUS compatibility builds. |
| `kubernetes` | yes | Kubernetes secrets engine config, role, and generated service account token helpers. |
| `ldap` | yes | LDAP secrets engine config, static/dynamic role, credential, and library helpers. |
| `rabbitmq` | yes | RabbitMQ secrets engine connection, lease, role, and credential helpers. |
| `userpass` | yes | Userpass login and user administration helpers. |
| `token` | yes | Token lifecycle, create-orphan, accessor renewal/revocation, token role, tidy, and revoke-orphan helpers. |
| `kv1` | yes | KV v1 secrets engine helpers. |
| `kv2` | yes | KV v2 secrets engine helpers. |
| `pki` | yes | PKI authority, issuer/key metadata/import, role, role patch, issue/sign, revoke, cert read/list, ACME config/EAB/directory URL, CRL config/rotate, tidy, tidy status, and tidy cancel helpers. |
| `ssh` | yes | SSH roles, OTP credentials, issuer management, CA sign/issue, issuer config, and OTP verification helpers. |
| `totp` | yes | TOTP key and code helpers. |
| `transit` | yes | Transit key lifecycle, batch cryptography, and single-operation cryptography helpers. |
| `transit-bytes` | no | Raw-byte Transit convenience helpers using `base64-ng` for OpenBao's base64 request/response fields. |
| `transit-import` | no | Software AES-KWP/RSA-OAEP helper for preparing OpenBao Transit BYOK import blobs. Requires `transit-import-acknowledged`; uses `openssl` and `aes-kw`; requires an audited OpenSSL 1.1.1+ runtime baseline; not an HSM, FIPS, certification, post-quantum, or security-boundary claim. Do not use it for classified or high-assurance key wrapping. |
| `transit-import-acknowledged` | no | Explicit acknowledgment that Transit BYOK software wrapping passes key material through software memory and OpenSSL-managed heap. |
| `sys` | yes | System backend, readiness, leases, quotas, password policies, resultant ACL, storage, diagnostics, and operator-gated helpers. |
| `http2` | no | Enables reqwest HTTP/2 support. ALPN negotiates HTTP/2 when OpenBao supports it and otherwise falls back to HTTP/1.1. |
| `time` | no | Optional RFC3339 timestamp parsing helpers using the `time` crate. |
| `tokio-helpers` | no | Enables Tokio convenience helpers such as `Sys::wait_until_unsealed`. Runtime-neutral variants remain available without this feature. |
| `tracing` | no | Optional request/response instrumentation with method, redacted path shape, and status only. No bodies, tokens, or namespaces are logged; path shapes still reveal operational activity, so strict path-confidentiality deployments should suppress debug `openbao.request` spans, for example with `EnvFilter::new("openbao=info")`. No OpenTelemetry SDK dependency. |
| `kani` | no | Inert feature reserved for Kani proof harness builds. Normal users do not need it; `scripts/check_kani.sh` enables it with the Rust `1.90.0` Kani toolchain. |
| `memory-lock` | no | Enables `sanitization` memory-lock support for secret buffers where the host permits it. Requires `memory-lock-acknowledged`; verify OS mlock/VirtualLock limits and swap policy before enabling. |
| `memory-lock-acknowledged` | no | Explicit acknowledgment for audited memory-lock builds. Memory locking is a host-level hardening control, not a guarantee that HTTP/TLS/kernel buffers avoid swap. |
| `tls12-acknowledged` | no | Explicit acknowledgment for legacy TLS 1.2 compatibility. TLS 1.3 remains the default and is strongly preferred for high-security OpenBao deployments. |
| `allow-sha1-acknowledged` | no | Explicit opt-in for legacy Transit SHA-1 selection. Disabled by default. |
| `allow-weak-jitter-fallback-acknowledged` | no | Explicit acknowledgment for using a timing-based retry jitter fallback if OS randomness fails. Default builds skip jitter rather than use the weak fallback. |
| `rustls-tls` | yes | Rustls transport configuration. |
| `native-tls` | no | Legacy native TLS support. Requires `native-tls-acknowledged` after audit. |
| `native-tls-acknowledged` | no | Explicit acknowledgment for audited native TLS builds. |
| `sensitive-http-test-only` | no | Hidden test escape hatch for this crate's loopback HTTP mock tests. Requires `sensitive-http-test-only-acknowledged`; never enable in application builds. |
| `sensitive-http-test-only-acknowledged` | no | Explicit acknowledgment for this crate's audited loopback HTTP test harness. |
| `operator-ops` | no | Production init, unseal, seal, rekey, key-share rotate, keyring rotate, raw storage, and destructive PKI root deletion APIs. Requires `operator-ops-acknowledged`. |
| `operator-ops-acknowledged` | no | Explicit acknowledgment for audited operator-operation builds. |

## Support Matrix

The detailed OpenBao `2.5.x` endpoint-by-endpoint coverage matrix is tracked
in [docs/OPENBAO_2_5_ENDPOINT_MATRIX.md](docs/OPENBAO_2_5_ENDPOINT_MATRIX.md).
For the stable `1.x` line it records `643` documented endpoint rows, with
`597/643` (`92.8%`) strict typed or operator-gated coverage. All rows are now
addressed by typed, operator-gated, partial, external, or rejected policy, with
zero `planned` and zero `decision` rows.

### Client, Transport, And TLS

| Capability | Status | Notes |
| --- | --- | --- |
| Async client | Yes | Built on `reqwest` with a small public API surface. |
| Typestate auth | Yes | Separate unauthenticated and authenticated client states. |
| HTTPS by default | Yes | Plain HTTP is rejected unless loopback HTTP is explicitly enabled. |
| Redirect protection | Yes | Redirect following is disabled to avoid forwarding token headers. |
| Response size cap | Yes | 32 MiB default with per-client lowering for small-response workflows. |
| Timestamp parsing | Optional | Enable `time` for RFC3339 parsing helpers without changing response field types. |
| TLS floor | Yes | TLS 1.3 minimum by default; audited legacy deployments can opt down to TLS 1.2. |
| HTTP protocol | HTTP/1.1 by default | Enable non-default `http2` for TLS ALPN HTTP/2 negotiation. No runtime HTTP/2 knob is exposed. |
| Custom CA roots | Yes | Extra root certificates can be merged with the platform trust store. |
| Root-only trust stores | Yes | System roots can be bypassed by using only configured root certificates. This is the supported alternative to leaf certificate or SPKI pinning. |
| Client TLS identity | Yes | Optional mutual TLS client identity for TLS certificate auth. |
| Connection timeout | Yes | 5-second connection timeout by default; caller overrides are bounded. |
| User agent fingerprinting | Yes | Default user agent omits the exact crate version. |
| Namespace header | Yes | `X-Vault-Namespace` support for namespace-aware deployments. |
| Environment construction | Yes | Reads `OPENBAO_*`, `BAO_*`, and `VAULT_*` aliases with secure defaults. |
| Raw JSON requests | Yes | Escape hatch for endpoints that are not typed yet. |

### Authentication

| Capability | Status | Notes |
| --- | --- | --- |
| Direct token auth | Yes | Tokens are accepted as `SecretString`. |
| `X-Vault-Token` | Yes | Default documented OpenBao-compatible token header. |
| Bearer auth | Yes | Optional `Authorization: Bearer` header mode. |
| AppRole login/admin | Yes | Role ID, SecretID, accessors, and returned tokens are secret-aware; role, delegated role-property, and SecretID lifecycle helpers are typed. |
| Token accessor handling | Yes | Accessors are treated as secret material. |
| Token lifecycle helpers | Yes | Lookup, accessor lookup/list, create/create-orphan, renew/renew-accessor, revoke, revoke-self, and revoke-accessor helpers. |
| Kubernetes auth | Yes | Login, auth method config, and role administration helpers. |
| TLS certificate auth | Yes | Login, auth method config, CA role administration, and CRL helpers. |
| JWT/OIDC | Yes | JWT login plus JWT/OIDC auth method config, role administration, browser auth URL, callback, and direct/device poll helpers. |
| LDAP auth | Yes | Login, method config, user/group create/read/list/delete policy mapping helpers. |
| RADIUS auth | Gated | Login, method config, user create/read/list/delete, paginated user list helpers. Available only with `radius-auth` plus `radius-auth-acknowledged` because legacy RADIUS uses MD5-based authenticators. |
| Kerberos auth | Yes | SPNEGO login, service-account/keytab config, Kerberos LDAP config, and group create/read/list/delete mapping helpers. |
| Userpass auth | Yes | Login and user create/read/list/delete, password update, and policy update helpers. |

### Secret Engines

| Capability | Status | Notes |
| --- | --- | --- |
| KV v2 read/write | Yes | Typed serialization and deserialization. |
| KV v2 CAS write | Yes | Optional check-and-set version support. |
| KV v2 patch | Yes | JSON merge patch content type. |
| KV v2 list/delete versions | Yes | Metadata list, latest delete, soft delete, undelete, and destroy. |
| KV v2 metadata/config | Yes | Backend, per-key metadata, typed data, and secret-aware service config helpers. |
| KV v1 | Yes | Read, write, delete, and list helpers. |
| Cubbyhole | Yes | Token-scoped read, optional read, write, delete, and list helpers. |
| Kubernetes secrets | Yes | Config, role create/read/list/delete, and generated service account token helpers. |
| RabbitMQ secrets | Yes | Connection config, lease config, role create/read/list/delete, and generated credential helpers. |
| Identity | Partial | Entity, group, entity-alias, and group-alias lifecycle helpers, entity/group lookup, entity merge, OIDC token backend config, signing key CRUD/rotate, role CRUD/list, signed ID token generation, token introspection, discovery, JWKS, OIDC provider/scope/client/assignment admin, named-provider discovery/JWKS, MFA method management, TOTP MFA generation/admin actions, and MFA login-enforcement helpers are implemented. Named-provider OIDC browser protocol flows stay external. |
| LDAP secrets | Yes | Config, root rotation, static roles/credentials, dynamic roles/credentials, and library check-out/check-in helpers. |
| Database credentials | Yes | Connection config/list/read/delete, dynamic roles/credentials, static roles/credentials, and root/static rotation helpers. |
| Transit | Yes | Key create/read/list/delete/config update/rotate/export/backup/restore/trim, encrypt/decrypt/rewrap batch helpers, data key, random, hash, HMAC, sign/verify batch helpers, typed RSA/JWS signing options, optional raw-byte helpers, wrapping-key, import/import-version, BYOK export, soft-delete/restore, cache/global config, CSR generation, and certificate-chain install helpers. Import wrappers accept externally wrapped `SecretString` ciphertext or public-key-only import material; raw private or symmetric key bytes stay outside the default endpoint wrappers. The non-default `transit-import` plus `transit-import-acknowledged` features add a software AES-KWP/RSA-OAEP wrapping helper for audited development and automation use. |
| PKI | Partial | Authority generation/signing/install, URL/CRL config, roles, role patch, issue, sign, named-issuer issue/sign, named-issuer sign-intermediate, revoke, revoke-with-key, revoked/revocation-queue/detailed certificate lists, issuer CRL resign, certificate list/read, issuer/key list/read/delete/update, issuer revoke, default issuer/key config, cluster config, auto-tidy config, root rotate/replace, standalone key generation, multi-issuer root/intermediate generation, operator-gated default root deletion with explicit confirmation, operator-gated sign-verbatim/sign-self-issued/cross-sign/sign-revocation-list, CEL role management and CEL issue/sign, current-doc field expansion for role/generation/CRL/tidy structs, CA/key import, ACME config/EAB/directory URL, CRL rotate, delta CRL rotate, tidy, tidy status, and tidy cancel are implemented. Unauthenticated public CA/CRL/cert and OCSP protocol reads stay external. |
| TOTP | Yes | Key create/read/list/delete, code generation, and code validation helpers. |
| SSH | Partial | Roles, zero-address roles, IP role lookup, OTP credentials, issuer config/list/submit/read/update/delete, authenticated CA public-key metadata, CA sign/issue, and OTP verification are implemented. Raw unauthenticated public-key reads are intentionally not typed. |
| Custom plugin patterns | Yes | Documented wrapper pattern for typed plugin-specific APIs over `Client::request_json`. |

### System Backend And Operations

| Capability | Status | Notes |
| --- | --- | --- |
| Health | Yes | Accepts OpenBao active, standby, sealed, and uninitialized health statuses. |
| Init status | Yes | Typed `/sys/init` status helper. |
| Seal status | Yes | Typed `/sys/seal-status` helper. |
| Leader status | Yes | Typed `/sys/leader` helper. |
| HA status | Yes | Typed `/sys/ha-status` helper with bounded node lists. |
| Key status | Yes | Typed `/sys/key-status` helper. |
| OpenAPI discovery | Yes | Typed JSON helper for `/sys/internal/specs/openapi`. |
| Internal UI helpers | Yes | Internal UI namespace and mount discovery helpers with bounded maps; OpenBao does not guarantee endpoint stability. |
| Metrics | Yes | Typed JSON helper for `/sys/metrics?format=json` and capped Prometheus text helper. |
| Host diagnostics | Yes | JSON helper for `/sys/host-info` platform diagnostics. |
| Pprof diagnostics | Gated | Capped sanitizing byte helpers for `/sys/pprof/:profile`, available only with `operator-ops` plus `operator-ops-acknowledged`. |
| Sanitized config state | Yes | JSON helper for `/sys/config/state/sanitized`. |
| Audited request headers | Yes | List, read, write, and delete `/sys/config/auditing/request-headers` helpers. |
| CORS config | Yes | Read, write, and delete `/sys/config/cors` helpers with bounded lists, header validation, and wildcard-origin rejection. |
| Runtime loggers | Yes | Read, set, and reset transient `/sys/loggers` verbosity levels. |
| Version history | Yes | Typed LIST helper for installed OpenBao version history. |
| Namespaces | Yes | List, create, read, patch, and delete namespace helpers with local name validation. |
| Rate-limit quotas | Yes | Global quota config plus named rate-limit quota list/create/read/delete helpers. |
| Locked users | Yes | List all locked users, filter by mount accessor, and unlock aliases. |
| Raft storage | Yes | Integrated Storage Raft join/configuration/peer/bootstrap, capped snapshot download/restore, and Autopilot JSON helpers; join helpers require HTTPS leader addresses. |
| Remount | Yes | Start mount migrations and poll migration status. |
| Step down | Gated | Active-node handoff helper for `/sys/step-down`, available only with `operator-ops` plus `operator-ops-acknowledged`. |
| System tools | Yes | Random byte generation and hash helpers with bounded random requests and secret-aware outputs. |
| Dev bootstrap | Yes | Fresh numeric-loopback dev instances only; not for production or HSM/KMS deployments. |
| Mount management | Yes | Secret and auth mount enable/list/read/tune/disable helpers. |
| Response wrapping | Yes | Lookup, wrap, unwrap, and rewrap helpers. |
| Policies and capabilities | Yes | ACL policy read/write/list/delete, password policy list/read/write/delete/generate, bounded policy builder helpers, self/token/accessor capability checks, resultant ACL inspection, and typed capability views. |
| MFA validation | Yes | Typed `/sys/mfa/validate` helper for MFA-enforced login flows with secret-aware passcodes, returned tokens, and accessors. |
| Admin bootstrap | Yes | Idempotent plan builder, read-only preview, KV v2/Transit/PKI/database/SSH mounts, Transit keys, ACL policies, KV v2 string values, PKI/database/SSH/AppRole roles, Identity entities/groups, explicit token issuance, and explicit AppRole SecretID issuance. |
| FIPS posture helper | Advisory | Best-effort report for crate-visible Transit choices and deployment assumptions. Does not certify OpenBao or the deployment. |
| List ergonomics | Yes | `ListEntries` exposes `entries`, `iter`, `len`, `is_empty`, and `contains` for common string list responses. |
| Audit devices | Yes | Enable, list, disable, and audit hash helpers. |
| Lease helpers | Yes | Safe exact lookup, renew, revoke, prefix revoke, force prefix revoke, count, tidy, and `RenewalHint` timing helpers for caller-owned renewal loops. |
| Plugin catalog | Yes | List, type-list, register, read, delete, and mounted backend reload helpers. |
| Production init, unseal, rekey, rotate, token ceremonies, in-flight diagnostics, PKI root deletion | Gated | Available only with `operator-ops` plus `operator-ops-acknowledged`; default builds cannot call these APIs. PKI root deletion also requires `PkiRootDeletion::confirm()` at the call site. |
| System backend closure | Yes | Password policies, root/recovery token ceremonies, decode-token, resultant ACL, legacy recovery-key rekey, and in-flight request inspection are implemented; config-ui, monitor streaming, internal router/request inspection, and internal counters are rejected for stable scope. |

## Examples

Create a client from an existing token:

```rust,no_run
use openbao::{Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;

    let health = client.sys().health().await?;
    println!("openbao version: {}", health.version);
    Ok(())
}
```

Create an authenticated client from environment variables:

```rust,no_run
use openbao::{Client, ListEntries, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Reads OPENBAO_ADDR/BAO_ADDR/VAULT_ADDR plus token, namespace, and CA aliases.
    let client = Client::from_env_with_token()?;

    let health = client.sys().health().await?;
    println!("openbao version: {}", health.version);
    Ok(())
}
```

Retry an idempotent raw request with explicit exponential backoff:

```rust,no_run
use std::time::Duration;

use openbao::{Client, Result, RetryPolicy, RetryableMethod};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::from_env_with_token()?;
    let policy = RetryPolicy::exponential(
        3,
        Duration::from_millis(100),
        Duration::from_secs(2),
    )?;

    let health: openbao::sys::Health = client
        .request_json_with_retry(
            RetryableMethod::Get,
            "sys/health",
            Option::<&openbao::Empty>::None,
            policy,
            tokio::time::sleep,
        )
        .await?;

    println!("openbao version: {}", health.version);
    Ok(())
}
```

Retry is never global. `RetryableMethod` exposes only GET, HEAD, and OpenBao
LIST so the helper cannot retry write verbs by accident. Exponential retry
delays include OS-random bounded jitter by default to avoid
synchronized retry waves after temporary OpenBao outages.

Configure a stricter client with a namespace and root-only trust store:

Use `only_root_certificates` when you want to trust only your internal OpenBao
CA and reject every platform or public CA root. This is intentionally preferred
over leaf certificate or public-key pinning because your CA can rotate server
certificates without requiring every client to update a pin. For a self-signed
OpenBao listener certificate, pass that certificate as the sole trusted root.
The rustls-backed HTTP client does not perform OCSP or CRL checking for the
server certificate automatically. Static PEM CRLs can be configured with
`add_certificate_revocation_list_pem` when using `only_root_certificates`;
callers remain responsible for refreshing CRLs and rebuilding clients before
they expire. Deployments that rely on revocation should still issue short-lived
listener certificates and enforce certificate-auth revocation server-side.

```rust,no_run
use openbao::{Client, OpenBaoConfig, Result};
use openbao::Certificate;
use openbao::SecretString;

#[tokio::main]
async fn main() -> Result<()> {
    let ca_pem = std::fs::read("openbao-ca.pem").map_err(|_| {
        openbao::Error::InvalidTlsConfig(
            "failed to read the configured CA certificate file".into(),
        )
    })?;
    let crl_pem = std::fs::read("openbao-ca.crl").map_err(|_| {
        openbao::Error::InvalidTlsConfig(
            "failed to read the configured CRL file".into(),
        )
    })?;
    let ca = Certificate::from_pem(&ca_pem)?;

    let config = OpenBaoConfig::new("https://bao.example.com:8200")?
        .namespace("admin/team-a")?
        .only_root_certificates(vec![ca])?
        .add_certificate_revocation_list_pem(&crl_pem)?;

    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::from_config(config)?.try_with_token(token)?;

    let seal = client.sys().seal_status().await?;
    println!("sealed: {}", seal.sealed);
    Ok(())
}
```

The environment equivalent for root-only trust is
`OPENBAO_CACERT=/path/to/ca.pem` together with
`OPENBAO_TLS_ROOTS_ONLY=true`; CRLs are configured through the explicit Rust
API so callers can own refresh and client rebuild policy.

Authenticate with AppRole:

```rust,no_run
use openbao::{Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new("https://bao.example.com:8200")?;
    let role_id = SecretString::from(std::env::var("APPROLE_ROLE_ID").unwrap_or_default());
    let secret_id = SecretString::from(std::env::var("APPROLE_SECRET_ID").unwrap_or_default());

    let (client, login) = client.login_approle(role_id, secret_id).await?;
    let health = client.sys().health().await?;

    let _token_accessor = login.accessor;
    println!("openbao version: {}", health.version);
    Ok(())
}
```

Authenticate with Userpass:

```rust,no_run
use openbao::{Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new("https://bao.example.com:8200")?;
    let password = SecretString::from(std::env::var("BAO_USERPASS_PASSWORD").unwrap_or_default());

    let (client, login) = client.login_userpass("alice", password).await?;
    let health = client.sys().health().await?;

    let _token_accessor = login.accessor;
    println!("openbao version: {}", health.version);
    Ok(())
}
```

Authenticate with JWT:

```rust,no_run
use openbao::{Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new("https://bao.example.com:8200")?;
    let jwt = SecretString::from(std::env::var("SERVICE_JWT").unwrap_or_default());

    let (client, login) = client.login_jwt(Some("web"), jwt).await?;
    let health = client.sys().health().await?;

    let _token_accessor = login.accessor;
    println!("openbao version: {}", health.version);
    Ok(())
}
```

Start an OIDC browser login and handle the callback without logging returned
token material:

```rust,no_run
use openbao::auth::jwt::{OidcAuthUrlRequest, OidcCallbackRequest};
use openbao::{Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new("https://bao.example.com:8200")?;
    let jwt = client.jwt()?;

    let auth = jwt
        .oidc_auth_url(
            &OidcAuthUrlRequest::new("https://app.example.com/oidc/callback")
                .with_role("web")
                .with_client_nonce("nonce-from-session"),
        )
        .await?;
    println!("redirect the browser to: {}", auth.auth_url);

    let code = SecretString::from(std::env::var("OIDC_CODE").unwrap_or_default());
    let callback = OidcCallbackRequest::with_code(
        std::env::var("OIDC_STATE").unwrap_or_default(),
        code,
    )
    .with_client_nonce("nonce-from-session");

    let (client, login) = jwt.oidc_callback(&callback).await?;
    let health = client.sys().health().await?;

    let _token_accessor = login.accessor;
    println!("openbao version: {}", health.version);
    Ok(())
}
```

Write and read KV v2 data:

```rust,no_run
use openbao::{Client, Result};
use openbao::SecretString;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct DatabaseCredentials {
    username: String,
    password: SecretString,
}

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;
    let kv = client.kv2("secret")?;

    kv.write(
        "production/database",
        DatabaseCredentials {
            username: "app".to_owned(),
            password: SecretString::from("change-me"),
        },
    )
    .await?;

    let secret = kv
        .read::<DatabaseCredentials>("production/database")
        .await?;

    let _username = secret.data.username;
    let _password = secret.data.password;
    let names = kv.list("production").await?;
    let _has_database_entry = names.contains("database");
    println!("database credentials loaded");
    Ok(())
}
```

Use KV v2 check-and-set, patch, and version operations:

```rust,no_run
use openbao::secrets::kv2::{Kv2MetadataOptions, Kv2WriteOptions};
use openbao::{Client, Result};
use openbao::SecretString;
use serde::Serialize;

#[derive(Serialize)]
struct Patch {
    password: SecretString,
}

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;
    let kv = client.kv2("secret")?;

    kv.write_with_options(
        "app/config",
        serde_json::json!({ "username": "app", "password": "first" }),
        Some(Kv2WriteOptions { cas: Some(0) }),
    )
    .await?;

    let second = kv
        .patch("app/config", Patch {
            password: SecretString::from("rotated"),
        })
        .await?;

    let _previous = kv
        .read_version::<serde_json::Value>("app/config", second.version - 1)
        .await?;
    kv.delete_versions("app/config", &[second.version - 1]).await?;
    kv.undelete_versions("app/config", &[second.version - 1]).await?;
    kv.destroy_versions("app/config", &[second.version - 1]).await?;

    kv.patch_metadata(
        "app/config",
        &Kv2MetadataOptions {
            max_versions: Some(10),
            cas_required: Some(true),
            delete_version_after: Some("24h".to_owned()),
            custom_metadata: None,
        },
    )
    .await?;

    Ok(())
}
```

Parse OpenBao timestamps when the `time` feature is enabled:

```rust,no_run
use openbao::{
    Client, Result, SecretString, parse_optional_rfc3339_timestamp,
    parse_rfc3339_timestamp,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct AppConfig {
    enabled: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;
    let secret = client.kv2("secret")?.read::<AppConfig>("services/api").await?;

    let created_at = parse_rfc3339_timestamp(&secret.metadata.created_time)?;
    let deleted_at =
        parse_optional_rfc3339_timestamp(Some(secret.metadata.deletion_time.as_str()))?;

    let _enabled = secret.data.enabled;
    let _audit_times = (created_at, deleted_at);
    Ok(())
}
```

Load service configuration from KV v2:

```rust,no_run
use openbao::{Client, Result};
use openbao::SecretString;
use serde::Deserialize;

#[derive(Deserialize)]
struct AppConfig {
    database_url: SecretString,
    listen_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;
    let kv = client.kv2("secret")?;

    let typed = kv.read_data::<AppConfig>("services/api").await?;
    let env_map = kv.read_service_config("services/api-env").await?;
    kv.write_service_config("services/api-env-copy", &env_map).await?;

    println!("listen: {}", typed.listen_addr);
    println!("loaded {} secret config keys", env_map.len());
    let _database_url_is_not_logged = typed.database_url;
    Ok(())
}
```

Share an authenticated client across async tasks:

```rust,no_run
use openbao::{Client, Result, SecretString, SharedClient};

fn worker_client(token: SecretString) -> Result<SharedClient> {
    Ok(Client::new("https://bao.example.com:8200")?
        .try_with_token(token)?
        .into_shared())
}
```

Read dynamic database credentials:

```rust,no_run
use openbao::{Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;
    let database = client.database("database")?;

    let credentials = database.credentials("readonly").await?;
    let _password = credentials.password;
    println!(
        "database user {} leased for {} seconds",
        credentials.username, credentials.lease_duration
    );
    Ok(())
}
```

Create and validate a TOTP code without logging the generated code:

```rust,no_run
use openbao::secrets::totp::{TotpKeyCreateRequest, TotpValidateRequest};
use openbao::{Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;
    let totp = client.totp("totp")?;

    let created = totp
        .create_key("alice", &TotpKeyCreateRequest::generated("Example", "alice"))
        .await?;
    println!("TOTP bootstrap URL available: {}", created.url.is_some());

    let code = totp.generate_code("alice").await?;
    let validation = totp
        .validate_code("alice", &TotpValidateRequest::new(code.code))
        .await?;

    println!("TOTP code accepted: {}", validation.valid);
    Ok(())
}
```

Issue an SSH certificate and generated private key without logging the key:

```rust,no_run
use openbao::secrets::ssh::{SshIssueKeyType, SshIssueRequest};
use openbao::{Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;
    let ssh = client.ssh("ssh")?;

    let issued = ssh
        .issue("user-cert", &SshIssueRequest::new(SshIssueKeyType::Ed25519))
        .await?;

    println!("SSH certificate length: {}", issued.signed_key.len());
    let _private_key_is_not_logged = issued.private_key;
    Ok(())
}
```

Provision ACME external account binding and hand it to an ACME client:

```rust,no_run
use openbao::{Client, ExposeSecret, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;
    let pki = client.pki("pki")?;

    let eab = pki.generate_role_acme_eab("tls-server").await?;
    let directory_url = pki.role_acme_directory_url("tls-server")?;

    let _eab_hmac_key_for_acme_client = eab.key.expose_secret();

    // Pass `directory_url`, `eab.id`, and the exposed EAB HMAC key to a
    // dedicated ACME client such as instant-acme or acme2. That client owns
    // account registration, nonce handling, challenge responses, polling, and
    // certificate download. Treat `eab.key` as credential material.
    println!("ACME directory: {directory_url}");
    println!("EAB key id: {}", eab.id);

    Ok(())
}
```

Use a KV v1 mount:

```rust,no_run
use openbao::{Client, Result};
use openbao::SecretString;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct Config {
    endpoint: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;
    let kv = client.kv1("legacy-secret")?;

    kv.write("app/config", Config {
        endpoint: "https://api.example.com".to_owned(),
    })
    .await?;

    let config = kv.read::<Config>("app/config").await?;
    let keys = kv.list("app").await?;

    println!("endpoint: {}", config.endpoint);
    println!("keys: {}", keys.keys.len());
    Ok(())
}
```

Encrypt and decrypt through Transit:

```rust,no_run
use openbao::secrets::transit::{TransitDecryptRequest, TransitEncryptRequest};
use openbao::{Client, Result};
use openbao::{ExposeSecret, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;
    let transit = client.transit("transit")?;

    let encrypted = transit
        .encrypt(
            "app-key",
            &TransitEncryptRequest::new(SecretString::from("c2VjcmV0")),
        )
        .await?;

    let decrypted = transit
        .decrypt(
            "app-key",
            &TransitDecryptRequest::new(encrypted.ciphertext),
        )
        .await?;

    println!("plaintext length: {}", decrypted.plaintext.expose_secret().len());
    Ok(())
}
```

Encrypt and decrypt raw bytes with the optional `transit-bytes` feature:

```rust,no_run
use openbao::secrets::transit::{TransitDecryptRequest, TransitEncryptRequest};
use openbao::{Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;
    let transit = client.transit("transit")?;

    let request = TransitEncryptRequest::from_plaintext_bytes(b"secret")?;
    let encrypted = transit.encrypt("app-key", &request).await?;
    let decrypted = transit
        .decrypt("app-key", &TransitDecryptRequest::new(encrypted.ciphertext))
        .await?;

    let plaintext = decrypted.plaintext_bytes()?;
    println!("plaintext length: {}", plaintext.len());
    Ok(())
}
```

Import externally wrapped Transit key material:

```rust,no_run
use openbao::secrets::transit::{
    TransitImportHashFunction, TransitImportRequest, TransitKeyType,
};
use openbao::{Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;
    let transit = client.transit("transit")?;

    let wrapping_key = transit.wrapping_key().await?;
    println!("wrapping key PEM length: {}", wrapping_key.public_key.len());

    let request = TransitImportRequest::new(
        SecretString::from(std::env::var("BAO_WRAPPED_KEY").unwrap_or_default()),
        TransitKeyType::Aes256Gcm96,
    )?
    .with_hash_function(TransitImportHashFunction::Sha256);

    transit.import_key("imported-app-key", &request).await?;
    Ok(())
}
```

Prepare a wrapped import blob with the optional `transit-import` and
`transit-import-acknowledged` features:

This helper is a software convenience path. OpenSSL may allocate intermediate
key buffers outside this crate's sanitization control, so high-assurance deployments
should wrap BYOK material inside an HSM or equivalent audited boundary and pass
only the already-wrapped ciphertext to the default import request types.

```rust,ignore
use openbao::secrets::transit::{
    TransitImportHashFunction, TransitKeyType, TransitWrappedImportKey,
};
use openbao::{Client, Result, SecretString, SecretVec};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;
    let transit = client.transit("transit")?;

    let wrapping_key = transit.wrapping_key().await?;
    let wrapped = TransitWrappedImportKey::wrap_key_material(
        &wrapping_key.public_key,
        SecretVec::from_vec(b"32-byte-import-key-material-here".to_vec()),
        TransitImportHashFunction::Sha256,
    )?;

    let request = wrapped.into_import_request(TransitKeyType::Aes256Gcm96)?;
    transit.import_key("imported-app-key", &request).await?;
    Ok(())
}
```

Manage a Transit key and encrypt a small batch:

```rust,no_run
use openbao::secrets::transit::{
    TransitBatchEncryptRequest, TransitCreateKeyRequest, TransitEncryptRequest,
    TransitTrimRequest, TransitUpdateKeyRequest,
};
use openbao::{Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;
    let transit = client.transit("transit")?;

    transit
        .create_key("app-key", &TransitCreateKeyRequest::default())
        .await?;
    transit.rotate_key("app-key").await?;
    transit
        .update_key("app-key", &TransitUpdateKeyRequest {
            min_decryption_version: Some(1),
            ..Default::default()
        })
        .await?;

    let encrypted = transit
        .batch_encrypt(
            "app-key",
            &TransitBatchEncryptRequest {
                batch_input: vec![
                    TransitEncryptRequest::new(SecretString::from("Zmlyc3Q=")),
                    TransitEncryptRequest::new(SecretString::from("c2Vjb25k")),
                ],
            },
        )
        .await?;

    transit
        .trim_key("app-key", &TransitTrimRequest::new(1)?)
        .await?;

    println!("encrypted items: {}", encrypted.batch_results.len());
    Ok(())
}
```

Sign data for JWS/JWT-style ECDSA workflows:

```rust,no_run
use openbao::secrets::transit::{
    TransitHashAlgorithm, TransitSignRequest, TransitVerifyRequest,
};
use openbao::{Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;
    let transit = client.transit("transit")?;

    let input = SecretString::from("ZXhhbXBsZS1wYXlsb2Fk");
    let signed = transit
        .sign(
            "jwt-signing-key",
            Some(TransitHashAlgorithm::Sha2_256),
            &TransitSignRequest::jws(input.clone()),
        )
        .await?;

    let verified = transit
        .verify(
            "jwt-signing-key",
            Some(TransitHashAlgorithm::Sha2_256),
            &TransitVerifyRequest::jws_with_signature(input, signed.signature),
        )
        .await?;

    println!("signature valid: {}", verified.valid);
    Ok(())
}
```

Create a constrained token role for repeatable service-token issuance:

```rust,no_run
use openbao::auth::token::TokenRole;
use openbao::{Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;

    let role = TokenRole::default()
        .with_allowed_policies(["app-read", "app-transit"])
        .with_token_ttl("30m")?;

    client.token().write_role("app-service", &role).await?;
    let roles = client.token().list_roles().await?;

    println!("configured token roles: {}", roles.keys.len());
    Ok(())
}
```

Create, inspect, renew, and revoke child or orphan tokens:

```rust,no_run
use openbao::auth::token::TokenCreateRequest;
use openbao::{Client, Result};
use openbao::SecretString;
use std::collections::BTreeMap;

#[tokio::main]
async fn main() -> Result<()> {
    let root_or_parent = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(root_or_parent)?;

    let child = client
        .token()
        .create(
            &TokenCreateRequest {
                meta: BTreeMap::from([("owner".to_owned(), "example".to_owned())]),
                display_name: Some("example-child".to_owned()),
                renewable: Some(true),
                ..TokenCreateRequest::default()
            }
            .with_policies(["default"])
            .with_ttl("30m")?
            .with_explicit_max_ttl("1h")?,
        )
        .await?;

    let info = client.token().lookup(&child.client_token).await?;
    println!("renewable: {}", info.renewable);

    let _renewed = client.token().renew(&child.client_token, Some("15m")).await?;
    client.token().revoke_accessor(&child.accessor).await?;

    let orphan = client
        .token()
        .create_orphan(
            &TokenCreateRequest {
                display_name: Some("example-orphan".to_owned()),
                renewable: Some(true),
                ..TokenCreateRequest::default()
            }
            .with_policies(["app-read"])
            .with_ttl("30m")?,
        )
        .await?;

    let _renewed_by_accessor = client
        .token()
        .renew_accessor(&orphan.accessor, Some("15m"))
        .await?;
    client.token().revoke_accessor(&orphan.accessor).await?;
    Ok(())
}
```

Enable a KV v2 mount:

```rust,no_run
use openbao::{Client, Result};
use openbao::SecretString;

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;

    client
        .sys()
        .enable_kv2("apps", Some("application secrets"))
        .await?;

    let mounts = client.sys().list_mounts().await?;
    println!("mount count: {}", mounts.len());
    Ok(())
}
```

Wait for OpenBao readiness with a runtime-provided sleep function:

```rust,no_run
use openbao::{Client, Result, SecretString};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;

    client
        .sys()
        .wait_ready_with_delay(
            Duration::from_secs(30),
            Duration::from_millis(250),
            tokio::time::sleep,
        )
        .await?;

    println!("OpenBao is ready for authenticated requests");
    Ok(())
}
```

Wait until an initialized OpenBao node is unsealed:

```rust,no_run
use openbao::{Client, Result};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new("https://bao.example.com:8200")?;

    let status = client
        .sys()
        .wait_until_unsealed_with_delay(
            Duration::from_secs(60),
            Duration::from_millis(250),
            tokio::time::sleep,
        )
        .await?;

    println!("OpenBao {} is unsealed", status.version);
    Ok(())
}
```

Request a typed response-wrapped JSON result:

```rust,no_run
use openbao::{Client, Method, ResponseEnvelope, Result, SecretString};
use serde::Deserialize;

#[derive(Deserialize)]
struct DbCredential {
    username: String,
    password: SecretString,
}

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;

    let wrapped = client
        .wrapping("5m")?
        .request_json::<ResponseEnvelope<DbCredential>, openbao::Empty>(
            Method::GET,
            "database/creds/reporting",
            None,
        )
        .await?;

    // Deliver wrapped.token() to the intended recipient. The recipient can
    // unwrap once; Debug output redacts the token and accessor.
    let response = wrapped.unwrap().await?;
    println!("issued credential for {}", response.data.username);
    Ok(())
}
```

Count leases and revoke an application lease prefix:

```rust,no_run
use openbao::{Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;

    let counts = client.sys().count_leases(None).await?;
    client
        .sys()
        .revoke_lease_prefix("database/creds/old-service", Some(true))
        .await?;

    println!("lease count buckets: {}", counts.counts.len());
    Ok(())
}
```

Wrap and unwrap JSON data:

```rust,no_run
use openbao::{Client, Result};
use openbao::SecretString;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct WrappedPayload {
    nonce: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;

    let wrap = client
        .sys()
        .wrapping_wrap("5m", &WrappedPayload {
            nonce: "one-time".to_owned(),
        })
        .await?;

    let payload = client
        .sys()
        .wrapping_unwrap::<WrappedPayload>(Some(&wrap.token))
        .await?;

    println!("payload nonce length: {}", payload.nonce.len());
    Ok(())
}
```

Write an ACL policy and check capabilities:

```rust,no_run
use openbao::{AclPolicyBuilder, Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;

    let mut policy = AclPolicyBuilder::new();
    let request = policy
        .allow_kv2_read_prefix("secret", "app")?
        .build_write_request()?;

    client
        .sys()
        .write_policy("app-read", &request)
        .await?;

    let capabilities = client.sys().capabilities_self(["secret/data/app"]).await?;
    let _for_path = capabilities.by_path.get("secret/data/app");
    Ok(())
}
```

Require response wrapping in an ACL policy:

```rust,no_run
use openbao::{AclCapability, AclPolicyBuilder, Result};

fn build_policy() -> Result<String> {
    let mut policy = AclPolicyBuilder::new();
    policy
        .allow_path_with_wrapping(
            "secret/data/app/*",
            [AclCapability::Read],
            Some("30s"),
            Some("5m"),
        )?
        .allow_kv2_read_prefix_with_required_wrapping("secret", "ops", "1m")?;

    policy.build()
}
```

Run a small idempotent service bootstrap:

```rust,no_run
use openbao::auth::token::TokenCreateRequest;
use openbao::bootstrap::AdminBootstrap;
use openbao::secrets::transit::TransitCreateKeyRequest;
use openbao::{AclPolicyBuilder, Client, Result, SecretString};
use std::collections::BTreeMap;

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;

    let mut policy = AclPolicyBuilder::new();
    policy.allow_kv2_read_prefix("secret", "app")?;

    let mut values = BTreeMap::new();
    values.insert("API_KEY".to_owned(), SecretString::from(std::env::var("APP_API_KEY").unwrap_or_default()));

    let mut bootstrap = AdminBootstrap::new();
    bootstrap
        .ensure_kv2_mount("secret", Some("application secrets"))?
        .ensure_transit_mount("transit", Some("application crypto"))?
        .ensure_pki_mount("pki", Some("application certificate roles"))?
        .ensure_database_mount("database", Some("application database roles"))?
        .ensure_ssh_mount("ssh", Some("application SSH roles"))?
        .ensure_policy("app-read", &policy)?
        .ensure_transit_key("transit", "app-key", TransitCreateKeyRequest::default())?
        .ensure_kv2_secret_values("secret", "app/config", values)?
        .issue_service_token(
            "app",
            TokenCreateRequest::default()
                .with_policies(["app-read"])
                .without_default_policy()
                .with_ttl("1h")?,
        )?;

    let preview = bootstrap.preview(&client).await?;
    for step in preview.changed_steps() {
        println!("would change {} {}", step.target_type, step.target);
    }

    let report = bootstrap.run(&client).await?;

    println!("bootstrap steps: {}", report.steps.len());
    let _issued_token_is_not_logged = report.issued_tokens;
    Ok(())
}
```

Build an advisory FIPS-oriented posture report:

```rust,no_run
use openbao::posture::FipsPosture;
use openbao::secrets::transit::{TransitCreateKeyRequest, TransitHashAlgorithm, TransitKeyType};

fn main() {
    let mut posture = FipsPosture::new();
    posture
        .check_transit_create_key(
            "transit/app-key",
            &TransitCreateKeyRequest {
                key_type: Some(TransitKeyType::Aes256Gcm96),
                exportable: Some(false),
                allow_plaintext_backup: Some(false),
                ..Default::default()
            },
        )
        .check_transit_hash_algorithm("transit/hash", TransitHashAlgorithm::Sha2_256)
        .assume_unknown_or_non_hsm_seal("seal");

    let report = posture.finish();
    for finding in &report.findings {
        println!("{:?}: {} - {}", finding.severity, finding.subject, finding.message);
    }
}
```

The posture report only covers choices visible to the SDK. It does not certify
OpenBao, your cryptographic provider, HSM/KMS setup, TLS stack, operating
system, or deployment process.

Enable an audit device and calculate an audit hash:

```rust,no_run
use openbao::{Client, Result, SecretString};
use openbao::sys::AuditEnableRequest;
use std::collections::BTreeMap;

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;

    client
        .sys()
        .enable_audit_device(
            "file",
            &AuditEnableRequest {
                options: BTreeMap::from([(
                    "file_path".to_owned(),
                    "/var/log/openbao/audit.log".to_owned(),
                )]),
                ..AuditEnableRequest::new("file").with_description("local audit file")
            },
        )
        .await?;

    let hash = client
        .sys()
        .audit_hash("file", &SecretString::from("known-secret-value"))
        .await?;

    println!("audit hash prefix: {}", hash.hash.split(':').next().unwrap_or(""));
    Ok(())
}
```

Look up and renew one exact lease:

```rust,no_run
use openbao::{Client, RenewalHint, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let lease_id = SecretString::from(std::env::var("BAO_LEASE_ID").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;

    let lease = client.sys().lookup_lease(&lease_id).await?;
    let hint = RenewalHint::from_ttl(lease.ttl, lease.renewable);

    if let (Some(sleep_for), Some(increment)) =
        (hint.sleep_before_renew, hint.increment_seconds)
    {
        println!("renew after roughly {} seconds", sleep_for.as_secs());
        let renewed = client.sys().renew_lease(&lease_id, Some(increment)).await?;
        println!("renewed lease seconds: {}", renewed.lease_duration);
    }

    Ok(())
}
```

Read and reload a plugin catalog entry:

```rust,no_run
use openbao::sys::{PluginReloadRequest, PluginType};
use openbao::{Client, Result};
use openbao::SecretString;

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;

    let plugins = client.sys().list_plugins_by_type(PluginType::Secret).await?;
    if plugins.keys.iter().any(|name| name == "transit") {
        let _info = client
            .sys()
            .read_plugin(PluginType::Secret, "transit", None)
            .await?;
    }

    client
        .sys()
        .reload_plugin_backend(&PluginReloadRequest {
            plugin: Some("example-plugin".to_owned()),
            mounts: Vec::new(),
            scope: None,
        })
        .await?;

    Ok(())
}
```

Discover OpenBao's OpenAPI document:

```rust,no_run
use openbao::{Client, Result};
use openbao::SecretString;

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;

    let response = client.sys().openapi_document(true).await?;

    println!("openapi keys: {}", response.as_object().map_or(0, |object| object.len()));
    Ok(())
}
```

The raw request layer is intentionally low level. Prefer typed helpers when the
crate supports an endpoint; use raw JSON to bridge missing OpenBao APIs while
coverage grows.

For application-specific OpenBao plugins, keep raw JSON calls behind a small
typed wrapper built with `PluginMount`, the public path validators, and bounded
list helpers such as `BoundedStringList`. See
[Typed Custom Plugin Pattern](docs/CUSTOM_PLUGIN_PATTERN.md) for a complete
request/response wrapper example with path validation, secret redaction, and
test guidance. Generic plugin traits are intentionally out of scope because
plugin schemas are deployment-specific.

## Local OpenBao Dev Instance

The local dev stack uses Podman, TLS, a private CA, and loopback-only ports in
the requested `994x` range.

Prepare the rootless Podman volume and TLS assets without starting OpenBao:

```bash
scripts/openbao_dev.sh prepare
```

This project does not require a `/srv` directory tree for local development:
raft data lives in a Podman-managed volume, and TLS material lives in the
ignored `deploy/podman/dev-state/` directory.

```bash
scripts/openbao_dev.sh up
```

Endpoints:

- API: `https://127.0.0.1:9940`
- Cluster: `https://127.0.0.1:9941`
- CA certificate: `deploy/podman/dev-state/tls/dev-ca.crt`

Initialize and unseal OpenBao using `bao operator init` and
`bao operator unseal`, then export `BAO_ADDR=https://127.0.0.1:9940` and
`BAO_CACERT=deploy/podman/dev-state/tls/dev-ca.crt`.

For disposable local development, the crate can initialize and unseal a fresh
numeric-loopback instance directly:

```rust,no_run
use openbao::{Client, OpenBaoConfig, Result, sys::DevBootstrapOptions};
use openbao::Certificate;

#[tokio::main]
async fn main() -> Result<()> {
    let ca_pem = std::fs::read("deploy/podman/dev-state/tls/dev-ca.crt").map_err(|_| {
        openbao::Error::InvalidTlsConfig(
            "failed to read the configured CA certificate file".into(),
        )
    })?;
    let ca = Certificate::from_pem(&ca_pem)?;

    let config = OpenBaoConfig::new("https://127.0.0.1:9940")?
        .only_root_certificates(vec![ca])?;
    let client = Client::from_config(config)?;

    let bootstrap = client
        .sys()
        .bootstrap_dev(&DevBootstrapOptions::single_key())
        .await?;

    let health = bootstrap.client.sys().health().await?;
    println!("initialized: {}, sealed: {}", health.initialized, health.sealed);
    Ok(())
}
```

`bootstrap_dev` is not a production initialization ceremony. It creates root
and unseal material in process memory, uses Shamir keys, refuses non-loopback
targets, and refuses already initialized servers. Do not use it with HSM/KMS
auto-unseal, shared environments, or any instance that requires operator key
ceremony.

Run the real OpenBao integration flow:

```bash
scripts/openbao_integration.sh
```

The integration script creates a fresh TLS dev instance, initializes and
unseals it, stores the root token in a temporary `0600` file for the test
process, and removes that file when the run exits.

## Kani Proof Harnesses

The crate includes optional Kani proof harnesses for a small set of
allocation-light validation helpers. The current harnesses cover byte-level
OpenBao path rejection policy and duration component parsing. They are bounded
proofs that complement the normal unit, integration, fuzz, Miri, audit, and
deny checks; they are not a whole-crate formal verification claim.

Kani currently runs here with the Rust `1.90.0` toolchain pairing also used by
the sibling `base64-ng` crate. After installing Kani, run the proofs locally
with:

```bash
rustup toolchain install 1.90.0-x86_64-unknown-linux-gnu
cargo kani --version
scripts/check_kani.sh
```

If your installed Kani release supports a newer Rust toolchain, replace the
value below and override the toolchain used by the script:

```bash
OPENBAO_KANI_TOOLCHAIN=<supported-rust-toolchain> scripts/check_kani.sh
```

The normal `scripts/checks.sh` gate also invokes `scripts/check_kani.sh`. When
the compatible Rust toolchain or `cargo-kani` is not installed, the Kani script
prints a skip message instead of failing local development checks. See
[kani/README.md](kani/README.md) for the exact proof scope and current
limitations.

## Release Discipline

Run the normal local checks:

```bash
scripts/checks.sh
```

Run the current release gate:

```bash
scripts/release_0_9_gate.sh
```

Set `OPENBAO_SKIP_INTEGRATION=1` only when Podman is unavailable; release
candidate validation should run the integration gate.

No release tag should be cut unless the matching pentest report status is
reviewed and recorded in the release notes.
