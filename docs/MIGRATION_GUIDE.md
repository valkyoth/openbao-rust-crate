# Migration Guide

This guide tracks migrations between stable OpenBao SDK releases. The current
contract inventory contains 690 logical operation identities across the
supported OpenBao release union. Every operation available in a supported
profile is classified as typed, typed-gated, or security-blocked; there are no
planned, decision, partial, raw, external, rejected, or unlinked generated
contract dispositions.

## From `openbao` 2.0.2 To 2.1.0

`2.1.0` is a source-compatible minor release that adds the exact OpenBao
`2.6.0` profile. Existing applications pinned to an older exact profile keep
the same routes, request-field rules, response compatibility, and capability
results. Selecting an older profile remains a statement about the server that
is actually deployed; it does not emulate an old endpoint on a newer server.

Applications deploying OpenBao `2.6.0` can use strict automatic detection or
select the exact profile explicitly:

```rust
use openbao::{OpenBaoCompatibilityPolicy, OpenBaoVersion};

let policy = OpenBaoCompatibilityPolicy::exact(OpenBaoVersion::new(2, 6, 0))?;
# Ok::<_, openbao::Error>(policy)
```

The release adds typed sealable-namespace, workflow, authenticated
root-generation, JWT CEL, Kubernetes JWT provider, userpass bcrypt-hash,
Kerberos PAC, and identity-template override contracts. Risk-bearing workflow
trace, unauthenticated workflow, identity-template override, and operator
operations retain explicit compile-time and value-level acknowledgement gates.

Existing constructible public structs keep their 2.0 field sets. OpenBao 2.6
response additions are available through explicit methods such as
`seal_status_details`, `lookup_lease_details`, `cors_config_details`,
`version_history_details`, `read_policy_details`, and each engine's
`read_role_details` or `read_config_details`. Use
`configure_with_decode_pac` and `write_cors_config_with_credentials` for the
corresponding 2.6 request fields. This preserves Rust source compatibility
while keeping every reviewed field typed and accessible.

JWT CEL role writes now require
`JwtCelClaimValidationAcknowledgement::all_authorization_claims_are_constrained_in_cel()`.
OpenBao does not reject a signed JWT that omits `aud` merely because
`bound_audiences` is populated, so the CEL program itself must require and
constrain `aud`, `sub`, and every authorization-relevant claim.

CEL expressions are stored as `SecretString` in `JwtCelProgram` and
`JwtCelVariable`. Constructors still accept string literals and owned strings;
read returned source through `expression()` and `ExposeSecret` only where it is
actually needed. CEL login and CEL role operations intentionally discard
server-provided failure bodies because OpenBao can include complete policy
source in compilation or evaluation errors. Match on the HTTP status rather
than relying on a CEL server error string.

Three exact `2.6.0` operations intentionally fail locally: JWT CEL PATCH and
prefixed workflow LIST/SCAN. Tagged OpenBao `2.6.0` drops JWT audience/leeway
constraints during PATCH and has unsafe prefixed workflow handlers. Use full
JWT CEL role replacement and unprefixed workflow listing. These are explicit
security blocks, not postponed SDK implementation.

OpenSSL is a direct development dependency for generating signed JWTs in the
crate's live integration test. It is not compiled for a downstream default
Rustls build. Production builds compile OpenSSL only when an application
explicitly selects an OpenSSL-using feature such as `transit-import` or the
acknowledged native-TLS backend.

The former `Sys::bootstrap_dev` method remains present so existing source still
compiles, but now returns `Error::DevBootstrapDisabled` before network access.
Development tooling must enable `dev-bootstrap` and
`dev-bootstrap-acknowledged`, construct
`DevBootstrapAcknowledgement::confirm_disposable_target()`, and call
`bootstrap_dev_acknowledged`. This is a security behavior change: numeric
loopback cannot distinguish a disposable server from a tunnel or proxy to
production.

Replace consuming `WrappedResponse::unwrap()` calls with
`try_unwrap(&mut self)`. The older method remains deprecated for source
compatibility, but only the mutable-borrowing API preserves the local wrapping
token when its future is cancelled. A transport or decode error is still an
outcome-unknown single-use operation and must not be retried automatically.

## From `openbao` 1.1.2 To 2.0.0

`2.0.0` is the next major release. It combines explicit multi-version OpenBao
compatibility with security-boundary changes that are intentionally not
source-compatible with `1.1.2`.

JWT/OIDC login metadata values now use `SecretString` because OpenBao can
return OAuth access, ID, and refresh tokens in this map:

```rust
use openbao::ExposeSecret;

let role = login
    .metadata
    .get("role")
    .map(ExposeSecret::expose_secret);
```

Database plugin response extension values now use `SecretString` because an
unknown plugin can return credentials or private key material in
`DatabaseConnectionInfo::connection_details`. Expose a reviewed field only at
its point of use:

```rust
use openbao::ExposeSecret;

let connection_url = connection
    .connection_details
    .get("connection_url")
    .map(ExposeSecret::expose_secret);
```

`DatabaseConnectionConfig::extra` also rejects keys that collide with typed
request fields. Move standard fields such as `username`, `password`, and
`connection_url` to their dedicated struct fields instead of inserting them
into `extra`.

OIDC request correlation values now use secret-aware types. The public
`client_nonce` fields on `OidcAuthUrlRequest`, `OidcCallbackRequest`, and
`OidcPollRequest`, plus the `state` fields on callback and poll requests, are
now `SecretString` values. Constructors and builder methods still accept string
literals directly; code that initializes public fields must wrap values:

```rust
use openbao::SecretString;
use openbao::auth::jwt::OidcPollRequest;

let request = OidcPollRequest {
    state: SecretString::from("opaque-state"),
    client_nonce: Some(SecretString::from("session-nonce")),
};
```

OIDC state, nonce, callback credentials, and redirect URIs are also rejected
when they exceed the SDK's documented request bounds.

Public raw JSON, byte, retry, and response-wrapping transports now require
both `raw-api` and `raw-api-acknowledged`. Typed endpoint helpers remain
available without those features. Audit each local raw wrapper before enabling
the acknowledgement:

```toml
[dependencies]
openbao = {
    version = "2",
    features = ["raw-api", "raw-api-acknowledged"]
}
```

OpenBao base URLs must now be origins. Remove embedded credentials,
application paths, query strings, and fragments. Configure authentication with
the typed token or login APIs, and configure namespaces with
`OpenBaoConfig::namespace`.

`Client::tls_backend` reports whether the crate selected Rustls or native TLS.
Selection follows this crate's acknowledged TLS feature policy even when Cargo
feature unification enables another backend on reqwest through a different
dependency.

`2.0.0` adds opt-in runtime server-version policies. Existing constructors
remain offline and unverified unless a policy is selected. New deployments
should select strict verification while constructing the configuration:

```rust
use openbao::{Client, OpenBaoCompatibilityPolicy, OpenBaoConfig};

# fn build() -> openbao::Result<Client> {
let config = OpenBaoConfig::new("https://bao.example.com")?
    .compatibility_policy(OpenBaoCompatibilityPolicy::automatic_strict());
Client::from_config(config)
# }
```

Use `OpenBaoCompatibilityPolicy::exact` for a fixed deployment or `range` for
a controlled rolling upgrade. `assume` avoids the health request when a proxy
blocks it, but reports are never marked verified. Unknown-newer operation
requires an explicit `UnknownNewerOpenBaoAcknowledgement` and should be used
only until the new release receives a locked profile.

Typed helpers now use immutable version-aware dispatch. Unsupported operations
fail locally before body serialization and do not fall back to another route
after a server error. A range probe verifies the one backend that answered the
health request; it does not compute or enforce the capability intersection of
a mixed-version cluster. During rolling upgrades, use backend affinity or call
only operations available throughout the configured range.

Assumed mode does not probe the server. Unknown-newer mode verifies the
reported version but dispatches through the newest known profile, so neither
mode is evidence that every selected route exists. Raw APIs and external
plugins remain caller-versioned boundaries: a compatibility policy cannot
make an arbitrary method/path or deployment-specific plugin schema compatible.
See [OpenBao Server Version Selection](OPENBAO_VERSION_SELECTION.md) for the
full selection, reporting, mixed-cluster, and future-release procedure.

The public `OpenBaoOperationDisposition` enum was also finalized for `2.0.0`.
Replace the former `LegacyTypedClaim` and `LegacyTypedGatedClaim` variants with
`Typed` and `TypedGated`. The obsolete `ExternalBoundary`, `PartialLegacyClaim`,
`OmittedLegacyClaim`, and `UnlinkedHistorical` states no longer exist in the
generated contract; unavailable operations are represented by the profile
rather than a permissive fallback classification.

## From `openbao` 1.0.2 To 1.1.0

`1.1.0` intentionally changes the public owned secret-byte buffer type. The
OpenBao endpoint surface is unchanged, but byte helpers now use
`sanitization::SecretVec` instead of `zeroize::Zeroizing<Vec<u8>>`.

Replace imports:

```rust
// Before
use openbao::{SecretString, Zeroizing};

// After
use openbao::{SecretString, SecretVec};
```

Replace owned byte construction:

```rust
// Before
let material = Zeroizing::new(raw_bytes);

// After
let material = SecretVec::from_vec(raw_bytes);
```

Read returned secret bytes through `with_secret`:

```rust
let plaintext = transit.decrypt("key", &request).await?.plaintext_bytes()?;
plaintext.with_secret(|bytes| {
    // use bytes inside this closure
});
```

Affected public helpers include raw byte request helpers, Transit byte decode
helpers, Transit import software wrapping helpers, system random/hash byte
helpers, pprof byte reads, and Raft snapshot byte downloads.

The crate root and prelude now re-export `sanitization`, `SecretVec`,
`SecureSanitize`, and `sanitize_bytes`. The `zeroize`, `Zeroize`, and
`Zeroizing` re-exports were removed. If your application used those re-exports
for unrelated data, depend on your preferred clearing crate directly.

## From `openbao` 1.0.1 To 1.0.2

`1.0.2` is a source-compatible dependency and release-documentation update.
Normal callers should not need code changes.

Notable maintenance changes:

- `base64-ng` is updated to `1.0.8`.
- Semver-compatible transitive dependencies in `Cargo.lock` are refreshed.
- The crates.io README is shorter and focuses on current SDK support instead
  of historical pre-`1.0` release milestones.
- The pinned `taiki-e/install-action` CI action is updated to the latest v2
  tag checked by the release gate.

## From `openbao` 1.0.0 To 1.0.1

`1.0.1` is a source-compatible patch hardening release. Normal callers should
not need code changes.

Review these behavior changes if you intentionally customized TLS:

- `OpenBaoConfig::min_tls_version(tls::Version::TLS_1_0)` and
  `TLS_1_1` now fail when the client is built.
- `OpenBaoConfig::min_tls_version(tls::Version::TLS_1_2)` now fails at build
  time unless the crate is compiled with `tls12-acknowledged`; the dedicated
  `min_tls_12()` helper was already gated this way.
- `OpenBaoConfig::add_root_certificate()` now preserves root-only trust mode
  after `only_root_certificates()` instead of widening trust back to platform
  roots. Platform roots are used only while the configuration remains in merge
  mode.

No endpoint types, request structs, or response structs changed.

## From `openbao` 0.15 To 1.0

`1.0.0` is source-compatible with normal `0.15.0` application code. It freezes
the public API surface that was trialed in the `0.15.0` stable-candidate line.

Update `Cargo.toml`:

```toml
[dependencies]
openbao = "1"
```

Recommended checks before deploying the stable release:

- run your existing `0.15.0` integration tests with `openbao = "1"`;
- keep feature selections explicit for operator APIs, legacy TLS, RADIUS,
  Transit import software wrapping, and test-only HTTP escape hatches;
- review `SECURITY.md` for accepted residuals around transport buffers,
  bootstrap locking, and software BYOK wrapping;
- use `docs/API_STABILITY_AUDIT.md` for the historical stable boundary and
  `docs/openbao-2.5-contract-matrix.json` for the exact `2.0.0` contract
  backlog. Unverified rows are not support claims.

## From `openbao` 0.14 To 1.0

`1.0.0` is source-compatible with normal `0.14.0` application code, through the
`0.15.0` stable-candidate additions.

Update `Cargo.toml`:

```toml
[dependencies]
openbao = "1"
```

Adopt these final stable-scope additions where they fit:

- use `Sys::wait_until_unsealed_with_delay` for bounded startup or recovery
  polling. Enable `tokio-helpers` only when the direct
  `Sys::wait_until_unsealed` Tokio convenience method is useful;
- use `Client::wrapping("5m")?` and `WrappedResponse<T>` when an application
  needs OpenBao response wrapping without dropping to untyped JSON. Delivery of
  the one-use wrapping token remains caller-owned;
- use `AclPolicyBuilder::allow_path_with_wrapping` or the
  `_with_required_wrapping` helper variants to require response wrapping in
  path rules. Continue using reviewed `PolicyWriteRequest` documents for
  advanced ACL parameter constraints;
- use `AdminBootstrap::ensure_pki_mount`, `ensure_database_mount`, and
  `ensure_ssh_mount` for idempotent mount convergence;
- use `AdminBootstrap::ensure_database_role`,
  `ensure_database_static_role`, and `ensure_ssh_role` for role convergence
  where those engines are already configured;
- keep PKI CA setup, database connection configuration, SSH CA key setup,
  request-level seal back-pressure, and KV v1 convergence outside
  `AdminBootstrap`. Those remain operator or application-policy workflows.

## From `openbao` 0.8 To 0.9

`0.9.0` remains source-compatible with normal `0.8.0` application code and adds
stabilization helpers that are intended to survive into `1.0.0`.

Update `Cargo.toml`:

```toml
[dependencies]
openbao = "1"
```

Keep these `0.8` patterns:

- use `openbao::SecretString` instead of depending on `secrecy` directly;
- prefer `Client::from_env_with_token()` for deployed services;
- keep TLS verification enabled and add root certificates through
  `OpenBaoConfig`;
- use feature gates for operator APIs and Transit byte helpers;
- use `read_optional` or `Error::is_not_found()` for absent secret handling;
- use `Sys::wait_ready_with_delay` for startup polling instead of ad hoc
  retry loops.

Adopt these `0.9` additions where they fit:

- use `RetryPolicy`, `RetryableMethod`, and `Client::request_json_with_retry`
  only for caller-approved idempotent GET, HEAD, or OpenBao LIST raw JSON
  requests. Typed helpers remain single-shot by default so non-idempotent
  writes are not retried accidentally;
- keep existing paginated list helper calls. Internally they now share
  `ListPageOptions`, which validates the `after` cursor and bounds `limit`.
  Token accessors, lease IDs, and other secret-bearing lists intentionally stay
  on dedicated helpers;
- use `AdminBootstrap::ensure_pki_role`,
  `AdminBootstrap::ensure_identity_entity`, and
  `AdminBootstrap::ensure_identity_group` for idempotent service setup. These
  compare only fields set in the desired request and do not perform PKI CA
  setup or database connection configuration;
- use `docs/API_STABILITY_AUDIT.md` for the historical pre-`1.0.0` decisions.
  The replacement `docs/openbao-2.5-contract-matrix.json` is the current exact
  contract backlog; it does not inherit typed status from those old decisions;
- read `docs/QUANTUM_READINESS.md` for the crate's advisory-only posture. It
  does not claim post-quantum safety for current OpenBao deployments.

## From Earlier `openbao` Releases

### 0.1 To 0.3

- Replace direct URL string assembly with typed helpers such as `client.kv2`,
  `client.kv1`, `client.transit`, and `client.sys`.
- Use `try_with_token` for token validation at client construction time.
- Treat Transit plaintext/ciphertext fields as secret material. Do not log
  request or response structs unless their `Debug` implementation is known to
  redact secret-bearing fields.

### 0.4 To 0.6

- Replace manual environment parsing with `Client::from_env_with_token()`.
- Replace local KV config maps with `Kv2ServiceConfig` helpers when loading
  service settings.
- Move byte-oriented Transit glue to the `transit-bytes` feature when raw
  bytes are more natural than OpenBao's base64 strings.
- Use `AclPolicyBuilder` and `AdminBootstrap` for common service setup instead
  of assembling ACL HCL and mount requests with ad hoc strings.
- Keep production init/unseal/rekey/rotate and destructive PKI root deletion
  behind `operator-ops` and `operator-ops-acknowledged`; default builds
  intentionally cannot call those APIs.

### 0.7 To 0.8

- Use concrete auth/admin helpers for AppRole, LDAP, RADIUS, Kerberos,
  Kubernetes auth, TLS certificate auth, Userpass, and JWT/OIDC instead of raw
  JSON calls where supported.
- Use `ListEntries` for ordinary string list responses, but keep token
  accessors and other secret-bearing lists in their dedicated types.
- Use `TokenRole`, Transit lifecycle/batch helpers, PKI tidy/status/cancel,
  Identity lookup/merge, and lease prefix/count helpers instead of
  hand-written endpoint paths.
- Use `Error::is_rate_limited`, `Error::is_temporary`, and
  `Error::is_permission_denied` where caller logic branches on common API
  failures.

## From `vaultrs`

The `openbao` crate is OpenBao-specific and uses `X-Vault-Token` by default
for documented compatibility while keeping the API centered on OpenBao
deployment behavior.

Common migration steps:

- Replace `vaultrs` client construction with `Client::new`,
  `OpenBaoConfig`, or `Client::from_env_with_token`.
- Replace direct token strings with `openbao::SecretString`.
- Replace engine-specific functions with typed handles such as
  `client.kv2("secret")?`, `client.transit("transit")?`, and
  `client.sys()`.
- Review feature flags. `openbao` keeps risky operator and legacy TLS behavior
  behind explicit opt-in features.
- Review error handling. Use `Error::status()`, `Error::is_not_found()`, and
  related predicates rather than matching a transport crate directly when
  possible.

Do not migrate by disabling TLS verification or reusing root tokens in service
configuration. Use scoped service tokens, AppRole SecretIDs, Kubernetes auth,
or another workload auth method appropriate to the deployment.

## From Bespoke `reqwest` Wrappers

Replace hand-written wrappers in layers:

1. Move address, namespace, CA, and token parsing into `OpenBaoConfig` or
   `Client::from_env_with_token`.
2. Replace request URL string concatenation with typed engine handles.
3. Replace raw secret strings with `SecretString` in request and response
   structs.
4. Replace logging of raw HTTP errors with sanitized `openbao::Error`
   handling.
5. Enable `raw-api` plus `raw-api-acknowledged`, then move custom plugin or
   unsupported endpoint calls behind a small local typed wrapper around
   `Client::request_json`. The acknowledgement is required because raw calls
   bypass operation-specific typed validation and feature gates.
6. Add tests that assert documented HTTP method, path, headers, and redaction
   behavior for each local wrapper.

For custom plugin wrappers, prefer `PluginMount`, `validate_mount_path`,
`validate_endpoint_path`, `BoundedStringList`, and
`deserialize_bounded_string_vec` instead of local path concatenation or
unbounded list response types.

## Security Checklist

- Never log tokens, token accessors, lease IDs, Transit plaintext/ciphertext,
  PKI private keys, raw storage values, AppRole SecretIDs, or OpenBao backup
  payloads.
- Do not use loopback HTTP outside fresh local development instances.
- Do not use `bootstrap_dev` for production, shared environments, HSM/KMS
  auto-unseal deployments, or any instance requiring an operator ceremony.
- Do not enable `native-tls`, `operator-ops`, `allow-sha1-acknowledged`,
  `allow-weak-jitter-fallback-acknowledged`, `radius-auth`,
  `radius-auth-acknowledged`, or `insecure-ldap-tls-acknowledged` without
  recording the deployment reason.
- Keep response-size limits low for small-response services.
- Prefer least-privilege policies generated by `AclPolicyBuilder` or reviewed
  policy strings.
