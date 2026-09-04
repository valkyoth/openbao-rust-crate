# Security Model And Operational Guidance

This repository document contains the detailed security model, operational
guidance, accepted residual risks, and release controls for the OpenBao Rust
SDK. The compact [`SECURITY.md`](../SECURITY.md) at the repository root remains
the authoritative vulnerability-reporting policy distributed with the crate.

## Security Baseline

- `unsafe_code = "forbid"` applies to this crate's own Rust sources. It does
  not apply transitively: TLS and cryptographic dependencies can contain unsafe
  Rust, FFI, assembly, or native C code and remain part of the trusted
  computing base. Release review includes the generated SBOM, dependency
  policy, and RustSec results for that complete graph.
- All token-bearing APIs accept `secrecy::SecretString`.
- Secret values must never be logged by this crate.
- Any new auth method must include tests proving token redaction.
- Any endpoint accepting user paths must use the shared path validator.
- Any API that can expose secret material must return caller-selected typed
  payloads, allowing users to wrap sensitive fields in secret types.
- TLS verification must remain enabled by default.
- Redirects must remain disabled by default.
- TLS 1.3 or newer must remain enforced by default; TLS 1.2 requires an explicit legacy opt-down.
- The default TLS backend is Rustls. The `native-tls` feature exists only for
  audited legacy compatibility, may pull OpenSSL on some targets, and requires
  the explicit `native-tls-acknowledged` feature.
- Token accessors are treated as secret material.
- Namespace header values are treated as sensitive metadata.
- Database role credential configuration values are treated as secret
  material because `client_certificate` roles can contain a PEM CA private
  key.
- Plain HTTP is allowed only by explicit numeric loopback IP opt-in, and
  credential-bearing or request-body requests still require HTTPS. This crate's
  own HTTP mock tests use a separate explicit test-only opt-in for numeric
  loopback servers. Hostnames such as `localhost` are rejected.
- Response bodies must remain size-bounded; JSON responses and binary
  responses with an expected `Accept` header must be content-type checked.
- JSON request serialization buffers controlled by this crate must be sanitized
  after handoff to the HTTP stack.
- Third-party GitHub Actions must be pinned to immutable commit SHAs.
- New dependencies require a release-plan justification and `cargo deny` review.
- Historical OpenBao source and image evidence is accepted only through the
  checksum-anchored, duplicate-key-safe offline validator documented in
  `compat/README.md`. Artifact identity alone is not an API compatibility or
  server security endorsement.
- OpenBao 2.6.0 has a different image-signing topology: the release index is
  signed by `release-images.yml`, while the locked Linux amd64 child is bound
  by that verified index and is not independently signed. Validators reject
  any attempt to overstate the child signature or substitute the workflow.
- Compatibility evidence, CI workflows, generators, release scripts, and
  maintainer policy remain in each signed Git tag rather than the crates.io
  source package. The package retains the compiled reviewed registry and
  `.cargo_vcs_info.json` identifies its source commit; release review must use
  both the crate archive and corresponding signed source tag.
- Historical API evidence is accepted only through the separately anchored
  snapshot validator. Tagged documentation remains primary, rendered pages are
  secondary observations, and normalized OpenAPI remains supporting evidence;
  none of these replace version-locked live behavior tests.
- Generated capability profiles expose only stable identifiers and route
  templates from anchored evidence. A documented route is not a typed-helper
  or live-compatibility claim. Security-blocked operation identities are
  maintained in reviewed generator code, and generated documentation cannot
  re-enable them.
- The complete version contract matrix classifies every operation/profile
  cell, but its `100.00%` figure is classification coverage rather than a claim
  that every endpoint ran live. The report binds its capability, request,
  response-fixture, and core-flow inputs by SHA-256; labels live and serde
  evidence as representative; rejects unexplained, contradictory, or
  all-skipped core-flow passes; permits only the six explicit 2.6-only
  unavailable-operation skips on older profiles; and records that no external
  database, directory, cloud, OIDC, MFA, DNS, or broker service was exercised.
- Version-aware typed dispatch selects exactly one reviewed operation before
  request serialization. The method comes from immutable registry evidence;
  concrete paths and required query selectors must match that operation's
  template. Unsupported, overlapping, malformed, external, and
  security-blocked selections fail locally without route probing.
- Typed dispatch never retries another historical route after HTTP 404/405,
  transport, or decode failure. Such fallback could duplicate writes or let a
  server response influence capability selection.
- Both reqwest clients disable transport-owned protocol retries, including
  HTTP/2 NACK replay. Requests repeat only through the explicit SDK retry
  helper, whose type permits GET, HEAD, and LIST but no write method.
- Error bodies are retained only for public requests carrying no token,
  namespace, query, custom header, or request body. Sensitive request failures
  are dropped without downloading or parsing the response body, so reflected
  credentials cannot enter loggable `Error` strings or consume the configured
  response-body budget. Bootstrap create races are resolved by re-reading and
  validating authoritative typed server state rather than classifying error
  text. Consequently, `Error::is_permission_denied` and `Error::is_conflict`
  classify sensitive failures from HTTP 403 and 409 respectively; their
  textual HTTP 400 detection applies only to retained public diagnostics.
  Successful response warnings remain explicitly accessible but are omitted
  from `ResponseEnvelope` debug output.
- Public raw JSON, byte, retry, and response-wrapping transports are disabled
  unless both `raw-api` and `raw-api-acknowledged` are enabled. Raw transports
  bypass typed capability selection, endpoint validation, and
  operation-specific feature gates; keep every enabled use behind a reviewed
  local typed wrapper with fixed methods and paths. A compatibility policy
  verifies the server version before raw transmission but does not prove that
  the caller-selected raw route exists for that version.
- Base URLs are origins only. User credentials, application paths, query
  strings, and fragments are rejected before a client is built.
- Typed JWT/OIDC discovery and JWKS URLs, Kubernetes API hosts, and RabbitMQ
  management endpoints must be absolute HTTPS URLs without embedded
  credentials or fragments. This validates the OpenBao-to-service hop, not
  only the application-to-OpenBao hop.
- The selected reqwest TLS backend is set explicitly from this crate's feature
  policy so dependency feature unification cannot silently replace Rustls with
  native TLS.
- Configured certificate revocation lists fail closed unless Rustls is the
  selected backend. Enabling acknowledged native TLS alongside Rustls selects
  native TLS and therefore rejects CRL-bearing client configurations.
- Reviewed built-in database plugins require typed connection options and
  encrypted TCP transport. PostgreSQL DSNs must resolve to an effective TCP
  host and `sslmode=require`, `verify-ca`, or `verify-full`; MySQL-family DSNs
  must select `tls=true`/`tls=skip-verify` or provide a CA; Cassandra and
  InfluxDB retain OpenBao's secure TLS-on default; and Valkey must explicitly
  enable TLS. Without `insecure-database-tls-acknowledged`, full peer
  verification is also required. The acknowledgement permits encrypted but
  incompletely verified transport, never plaintext. Unix-domain sockets,
  service-file indirection, duplicate security keys, malformed values, and
  explicit TLS disablement fail before credential-bearing serialization.
- Environment CA certificate aliases are limited to regular files no larger
  than 1 MiB. Unix readers use nonblocking, no-follow opens so FIFOs and
  symlinks fail; Windows readers open the path itself and reject reparse points.
  A second post-open size check bounds races and error messages omit paths.
- Typed fields whose availability changes between locked OpenBao profiles are
  validated before secret payload construction. A selected unsupported field
  fails with a secret-free endpoint, field, and version error; it is never
  silently omitted. This guarantee uses the client compatibility profile. A
  client without a configured compatibility policy is unverified and assumes
  the newest reviewed profile, so it does not reject fields merely because the
  actual server may be older. Raw and external-plugin JSON remain outside this
  guarantee.
- Versioned response fixtures are generated only from checksum-locked OpenAPI
  snapshots. Historical aliases use reviewed deterministic precedence, bounded
  maps reject duplicate keys rather than overwriting values, additive unknown
  fields remain tolerated, and unknown server enum values fail decoding rather
  than selecting a default capability.

## Admin Bootstrap Concurrency

`AdminBootstrap` is a convergence helper, not a distributed lock. Its
`ensure_*` operations read OpenBao state, compare it with the desired state, and
then write when a change is needed. OpenBao does not provide check-and-set for
every endpoint this module touches, so multiple bootstrap runners targeting the
same cluster can race and overwrite security-critical configuration such as ACL
policies, AppRole constraints, or secret values.

Run at most one bootstrap plan per target cluster at a time. Use an external
deployment lock, Kubernetes leader election, CI/CD environment lock, or another
operator-controlled serialization mechanism. KV v2 secret convergence uses
OpenBao CAS where available, but other bootstrap operations still require
external serialization. `Error::BootstrapContention` is a best-effort
post-write detection signal when verification sees that a concurrent writer
changed the converged value; it is not a lock and cannot prove that no race
occurred.

## System Log Streaming

The non-default `monitor-stream` feature exposes operational logs that may
contain paths, identifiers, or application-provided values. `MonitorFrame`
stores each line in sanitizing memory and redacts its contents from `Debug`,
while crate tracing records only the request metadata already described in
this policy. Frames and individual retained transport chunks are each capped
at 1 MiB and returned as untrusted bytes; JSON format is not eagerly parsed.
The stream polls the HTTP body directly,
without a producer task or channel, so consumer polling supplies back-pressure.
Dropping the stream drops the response body and cancels the request. Transport-
owned receive chunks remain subject to the residual-memory boundary below.

## OpenBao 2.6 Workflows

Workflow definitions and arbitrary execution input/output are treated as
secret material. `WorkflowWriteRequest`, `WorkflowInfo`, `WorkflowList`, and
`WorkflowData` redact definitions or values from `Debug`; arbitrary JSON is
restricted to an object and capped at 8 MiB in sanitizing storage. Workflow
paths use the same structured validation as other typed endpoints. Failed
workflow response bodies are discarded without deserializing server error text
because errors may echo tokens, definitions, inputs, or intermediate values;
public errors retain only the HTTP status.

Trace execution is not a normal observability API. OpenBao 2.6 trace responses
can contain the caller token, generated request and response bodies, and every
intermediate value. It requires both `workflow-trace` and
`workflow-trace-acknowledged`. Token-free execution and the builder that opts a
workflow into it require both `unauthenticated-workflows` and
`unauthenticated-workflows-acknowledged`; the client calls only the conditional
unauthenticated route and never probes or falls back to authenticated dispatch.

OpenBao 2.6.0 through 2.6.2 have two confirmed upstream workflow defects. Their
update handler discards the supplied `cas` value before storage, so strict
creation and update CAS cannot be relied upon and enabling `cas_required` can
make a workflow unwritable. Their prefixed LIST and SCAN handlers panic. The
SDK models body CAS but rejects CAS-selected workflow writes before transport
for all affected profiles, never retries writes, and classifies prefixed
LIST/SCAN as security-blocked for exact 2.6.0 through 2.6.2.

## OpenBao 2.6 Authentication Contracts

JWT CEL programs are caller-controlled authorization code. The SDK bounds the
number of variables, each expression, failure messages, and total program
size, validates variable identifiers and uniqueness, stores expressions as
`SecretString`, and redacts program text from `Debug`. CEL login, role read,
role write, and role patch responses are decoded from sanitizing buffers.
Their failed response bodies are discarded because OpenBao compilation or
evaluation errors can echo complete CEL source; public errors retain only the
HTTP status. These structural limits do not prove that a valid CEL program is
cheap to compile or execute. Restrict CEL role administration to trusted
operators and enforce OpenBao process CPU, memory, and request limits.

OpenBao 2.6 does not reject a JWT that omits `aud` merely because a CEL role
sets `bound_audiences`. The list filters audiences only when the claim is
present. Every `JwtCelRoleRequest` therefore requires an explicit
`JwtCelClaimValidationAcknowledgement` before `write_cel_role` sends it. The
acknowledgement confirms that the CEL program itself requires and constrains
`aud`, `sub`, and every other authorization-relevant claim. It does not parse
or prove CEL; substring and regular-expression inspection would be bypassable.

Exact OpenBao 2.6.0 JWT CEL PATCH is security-blocked. Tagged runtime source
constructs a replacement entry without preserving `bound_audiences` or the
three leeway fields, which can silently weaken a patched role. Use full POST
replacement through `write_cel_role` for that release. OpenBao 2.6.1 and 2.6.2
preserve those fields; the SDK exposes PATCH for those exact profiles only through
`patch_cel_role_acknowledged`, retaining the explicit claim-validation
acknowledgement required by full CEL role writes.

`JwtConfig::kubernetes_provider` sets only
`provider_config.provider = "kubernetes"`. The typed configuration validator
rejects OIDC discovery, JWKS, static validation keys, and extra provider-map
entries in this mode. OpenBao derives the API endpoint and credentials from
the pod service-account environment; the contradictory discovery-URL guide
shape is intentionally not reproduced.

Userpass bcrypt hashes use `UserpassPasswordHash`, which validates the encoded
shape and OpenBao's accepted cost range of 5 through 12 and redacts the hash
from `Debug`. Separate create/reset helpers serialize only `password_hash`, so
typed callers cannot send it together with plaintext `password`. The hash is
still credential material and remains subject to the transport residual-memory
boundary below.

## OpenBao 2.6 Identity-Template Delimiters

OpenBao 2.6 rejects security-sensitive delimiters rendered from identity
metadata by default. ACL policies reject `/` plus the `*` and `+` wildcard
characters, PKI role templates reject `*` in allowed domains and URI SANs,
and SSH role templates reject `,` in allowed users and domains. Allowing these
characters can turn one untrusted identity value into a different ACL path, a
broader certificate name, or multiple SSH principals.

The SDK deserializes the override booleans for audit/readback, but ordinary
policy and role serialization omits them. Sending `true` requires the
non-default `identity-template-overrides-acknowledged` feature, an explicit
`acknowledge...` constructor for the affected surface, and a selected OpenBao
2.6.0-or-newer profile. Enabling one surface does not enable another, and the
client rejects these fields against every older exact profile before building
or sending the HTTP request. Use them only when all referenced identity
metadata is trusted and constrained independently of the rendered template.

`AdminBootstrap` never opts into these overrides. Preview treats a matching ACL
policy, PKI role, or SSH role with the corresponding override enabled as drift.
Apply fails with `Error::UnsafeBootstrapConfiguration` before mutation because
the ordinary write APIs replace configuration and a partial desired state could
discard unmanaged expiration, CAS, issuance, or SSH restrictions. Operators
must disable the override with a state-preserving administrative operation
before rerunning bootstrap. Post-write verification still returns
`Error::BootstrapContention` if a concurrent writer enables an override during
ordinary convergence.

## Residual Secret Memory

After a JSON request body is handed to `reqwest`, the transport stack, TLS
backend, kernel, or network device may keep independent plaintext or ciphertext
buffers until their own cleanup. This crate sanitizes the serialization buffer it
controls, but it cannot guarantee sanitization of buffers owned by dependencies
or the operating system.
Token and namespace header values are also copied into HTTP-stack header
structures that are marked sensitive for logging but are not sanitized on drop by
the underlying `http`/`hyper`/`reqwest` types.
OpenBao's JWT/OIDC browser callback and direct/device poll endpoints carry
credentials or correlation values in GET query strings. The Identity OIDC
provider also exposes a GET authorize variant. The optional
`oidc-get-callback-acknowledged` helpers avoid additional crate-owned secret
copies where practical, but the resulting URL and transport buffers cannot be
sanitized by this crate. Do not enable the feature until OpenBao, reverse
proxies, service meshes, and observability systems are configured to log the
path only and omit the complete query string. Prefer the Identity provider's
typed POST authorize operation when protocol compatibility allows it.
Tokens loaded from environment variables are moved directly into
`SecretString` without an intermediate trimmed copy, but the operating system's
process environment remains outside the crate's sanitization control. Prefer a
protected credential broker, inherited file descriptor, or dedicated secret
agent where environment-variable residency is unacceptable.

High-assurance deployments should combine this crate with process isolation,
encrypted swap or disabled swap, core-dump restrictions, short process
lifetimes for highly sensitive workflows, and host-level memory protections
appropriate to the environment.

The runtime-neutral readiness helpers cap sleeps to their remaining retry
budget, but cannot interrupt an in-flight HTTP future. Enable `tokio-helpers`
and use `Sys::wait_ready` or `Sys::wait_until_unsealed` when the supplied
timeout must cancel the complete HTTP-and-delay operation at a strict overall
deadline.

Base64 helpers used by Transit byte operations and system random byte helpers
move base64 text into `SecretString`, but exposing text from dependency APIs is
still a residual process-memory risk. High-assurance deployments should treat
the calling process heap as capable of containing encoded secret material until
the relevant `SecretString` values are dropped and cleared.

## Hardened Deployment Profile

For high-assurance builds, keep the default `rustls-tls` backend, do not enable
`native-tls` or `native-tls-acknowledged`, do not enable
`tls12-acknowledged`, and do not call
`OpenBaoConfig::min_tls_version(reqwest::tls::Version::TLS_1_2)`.
Downstream applications can enforce this with CI policy checks that reject
those feature flags and API calls.

If a legacy deployment must use TLS 1.2, the OpenBao server and any
terminating proxy must disable NULL, EXPORT, anonymous, DES/3DES, RC4, and
CBC-mode cipher suites. Prefer AEAD suites such as
`ECDHE-ECDSA-AES256-GCM-SHA384` or `ECDHE-RSA-AES256-GCM-SHA384`. TLS 1.3
remains the hardened default.

The rustls-backed HTTP client supports static PEM certificate revocation lists
with `OpenBaoConfig::add_certificate_revocation_list_pem` or
`OpenBaoConfig::add_certificate_revocation_list_pem_bundle`, but only when
paired with `OpenBaoConfig::only_root_certificates`. This is the hardened
client-side revocation path for deployments that publish CRLs for their
internal OpenBao listener CA.

The crate does not fetch CRL distribution points, refresh CRLs, perform OCSP,
or decide fail-open/fail-closed policy for expired CRL material. Treat those as
operator PKI-lifecycle controls: refresh CRLs and rebuild clients before expiry,
issue short-lived OpenBao listener leaf certificates, rotate the internal CA on
compromise, and configure server-side certificate-auth CRL/OCSP controls where
applicable. Relying on platform or public roots is not recommended for
classified or high-assurance deployments.

Use `Client::try_with_token` for tokens loaded from configuration or returned
by another service so invalid header values fail before the first request.
Lower `OpenBaoConfig::max_response_bytes` for clients that only call
small-response endpoints.
Request bodies default to an 8 MiB limit and cannot be configured above 32
MiB. JSON and form serialization stop before crossing
`OpenBaoConfig::max_request_bytes`; byte bodies are checked before the
unavoidable `reqwest::Body` copy. Use the `raft-stream` feature for larger
Integrated Storage restore payloads. Its exact-length stream rejects overflow
and truncation and avoids a second complete snapshot allocation.

The `operator-ops` feature exposes production init, unseal, seal, rekey,
rotation, and sealable-namespace lifecycle APIs. It is disabled by default and
fails to compile unless `operator-ops-acknowledged` is enabled too. Namespace
creation shares and submitted unseal shares are secret values; transfer them
under an external key ceremony and custody model. Recursive sealed-namespace
deletion is irreversible and does not clean up external lease resources. Do
not enable this feature in normal application clients; reserve it for audited
operator tooling.

The `transit-import` feature is a software BYOK wrapping helper. It depends on
the host OpenSSL runtime through the `openssl` crate and requires an audited
OpenSSL 1.1.1 or newer deployment baseline. It is not an HSM, FIPS,
certification, post-quantum, or security-boundary claim. It also requires the
`transit-import-acknowledged` feature so downstream builds explicitly review
that raw key material and the ephemeral AES wrapping key pass through software
memory and OpenSSL-managed heap. OpenSSL may allocate intermediate key buffers
outside Rust's allocator and outside this crate's sanitization control; those
copies can remain in process heap, swap, crash dumps, or allocator free lists
according to the host runtime. Classified or high-assurance key wrapping must
not use this software helper; perform wrapping in an HSM or equivalent audited
boundary instead.

The `memory-lock` feature changes authenticated client custody. After token
header validation, `Client::try_with_token` transfers the token into
`sanitization::LockedSecretString`; `Client::try_with_locked_token` accepts an
already mapped token without ordinary SDK heap restaging only when that
mapping reports an active operating-system memory lock. Authentication tokens
default to a 16 KiB limit before header or mapped-storage allocation. OpenBao
permits root or sudo operators to choose custom token IDs without publishing a
length ceiling, so `OpenBaoConfig::max_auth_token_bytes` provides an explicit
bounded override up to an absolute 1 MiB ceiling. High-assurance deployments
should retain the default unless their reviewed token format requires more and
their locked-memory quota accounts for the larger allocation. Client
construction fails with `Error::SecretMemoryProtection` if mapping, OS locking,
or OS-random canary setup cannot be established, and request construction fails
if canary verification or its synchronization lock fails.
`Client::authentication_token_is_memory_locked` provides a fallible,
non-secret deployment assertion for the retained allocation.

The feature enables `sanitization`'s reviewed `profile-hardened-native` feature.
Its random canaries detect accidental or adjacent mapping corruption and cause
the SDK to fail closed. Canaries are not an attacker-resistant integrity
boundary. They are defense in depth: an attacker with arbitrary process-memory
write capability can modify both token data and canaries. OS locking also does
not protect against a process compromise.

The mapped token is held behind a standard mutex because the dependency's
integrity-checking mapped type is `Send` but deliberately not `Sync`. Token
header construction is therefore serialized briefly for clients shared across
tasks. If a panic poisons that mutex, the SDK permanently rejects token access
for that client rather than recovering unknown secret state. Reconstruct the
client from a reviewed credential source; do not clear or bypass poison.

This automatic scope is deliberately limited to the long-lived token retained
by an authenticated `Client`. Tokens initially supplied as `SecretString`,
environment variables, or login responses exist transiently in sanitizing
ordinary storage before transfer. Operator responses, unseal and recovery
shares, KV values, request/response fields, and other public `SecretString` or
`SecretVec` values are not transparently converted because feature unification
must not silently change every endpoint's public Rust type. Move those values
into `openbao::sanitization` mapped types at the application custody boundary.

The feature is disabled by default and requires `memory-lock-acknowledged`
because mlock/VirtualLock limits, container permissions, swap policy, and
failure behavior are deployment-specific. Memory locking is a host hardening
control, not a guarantee that transient HTTP header, TLS, kernel, allocator,
or device buffers avoid swap or crash dumps.

The `radius-auth` feature is not enabled by default. RADIUS relies on
MD5-based authenticators and is retained only for audited legacy compatibility.
Enabling it requires the additional `radius-auth-acknowledged` feature.
Classified networks and new high-assurance deployments must not use RADIUS;
prefer certificate auth, Kerberos, or LDAP over TLS with reviewed server validation.
If RADIUS is unavoidable, enforce RadSec or equivalent RADIUS-over-TLS
protection at the infrastructure layer.

LDAP `insecure_tls=true` is rejected unless
`insecure-ldap-tls-acknowledged` is enabled. Even with that acknowledgment, the
crate rejects `insecure_tls=true` when LDAP bind credentials or client private
key material would cross an unverified TLS connection. LDAP and Kerberos LDAP
bind configurations must use `ldaps://` or StartTLS.

Transit SHA-1 selection is unavailable unless
`allow-sha1-acknowledged` is enabled. Do not enable that feature for new or
high-assurance deployments; use SHA-2 or stronger algorithms.

Retry jitter uses OS randomness when available. If OS randomness fails, default
builds skip jitter rather than use a timing-derived fallback. The
`allow-weak-jitter-fallback-acknowledged` feature enables that weak fallback
only for audited platforms where OS randomness is unavailable and retry timing
is not a security control.

The `sensitive-http-test-only` feature is for this crate's mock HTTP tests
only. It must not be enabled in production application builds. Release metadata
checks verify it is not part of the default feature set, and `build.rs` emits a
warning whenever it is compiled. It also requires
`sensitive-http-test-only-acknowledged` so accidental workspace feature
propagation fails closed.

## Dev Bootstrap Warning

`Sys::bootstrap_dev_acknowledged` is available only with `dev-bootstrap` and
`dev-bootstrap-acknowledged`. It is for disposable local OpenBao development
instances only. It refuses non-loopback and already initialized targets, but a
numeric loopback address can terminate an SSH tunnel, Kubernetes port-forward,
reverse proxy, sidecar, or service-mesh route to production. The acknowledgement
therefore confirms a review of the complete network path; it does not prove the
destination is disposable. The legacy `Sys::bootstrap_dev` symbol always fails
closed. Never enable this feature in production workspaces or use it for
staging, shared environments, HSM/KMS-backed auto-unseal, or any environment
that requires an operator key ceremony.

Unstructured system JSON and typed Identity/PKI extension JSON are decoded
under fixed recursion, node, and aggregate string-byte budgets in addition to
the response wire-size cap. One shared budget covers each complete extension
map or vector. Collection overflow is rejected through a deserialization seed
before the excess key or value content is parsed; primitive-only PKI metadata
rejects containers before retaining their contents. Typed lists and maps retain
their endpoint-specific item bounds. Response-wrapping callers should use
`WrappedResponse::try_unwrap(&mut self)`: cancellation preserves the local
token, while any transport or decode failure remains outcome-unknown and must
not be retried automatically. The deprecated consuming `unwrap(self)` remains
only for `2.x` source compatibility and is scheduled for removal in the next
semver-major release.

Production panic boundaries and the no-exception policy are documented in
[`PANIC_POLICY.md`](PANIC_POLICY.md) and enforced by the release gate.

Local Podman development TLS files under `deploy/podman/dev-state/` are
generated per checkout and ignored. Private keys must never be committed. The
release metadata check fails if a tracked file contains a PEM private-key
header.

Release integration tests do not use that persistent development state. The
version-locked harness creates per-run TLS under a private temporary directory,
compiles and ownership-validates the integration test before initialization,
then passes the root token through an anonymous memory-backed descriptor only
to that precompiled executable. Cargo, rustc, proc macros, and build scripts do
not inherit the token or result descriptor. The harness uses in-memory OpenBao
storage and ownership-labeled Podman resources and sanitizes private material
during cleanup. It invokes the locked image's `bao` binary directly so
historical image entrypoint wrappers cannot inject additional configuration or
commands. Test cleanup is verified before a successful completion attestation
is accepted.

Historical compatibility runs include OpenBao releases that may contain fixed
upstream vulnerabilities. They run only as disposable, rootless, read-only
containers with dropped capabilities, no-new-privileges, an internal per-run
network, and a dynamically published loopback API port. Never expose these old
servers to another host or reuse them for application, staging, or production
traffic. Passing historical core tests is a compatibility observation, not a
security endorsement of the server release.

The active matrix covers 24 exact releases from `2.0.0` through `2.6.2`.
Every profile executes the common eight-operation core flow; exact `2.6.0`,
`2.6.1`, and `2.6.2` also execute root-generation routing, sealable namespace,
workflow, JWT CEL, userpass bcrypt-hash, and changed-response-field flows. The previous
21-release result is retained under `compat/core-flow-history/` so promotion
does not erase prior evidence.

Exact `2.6.2` additionally exercises the release's security-sensitive behavior:
unauthenticated workflows must reject internal token-creating operations, PKI
signing must enforce `allowed_ip_sans_cidr` against IP SANs carried in a CSR,
and Transit must verify HMACs generated with a non-default hash algorithm.

The compatibility workflow has read-only repository permissions, persists no
checkout credential, references no repository secret, and deliberately avoids
shared build caches. Each matrix job uploads one fixed sanitized JSON result;
TLS files, tokens, raw responses, server logs, and temporary server data are
outside the artifact path. Aggregation validates the exact expected artifact
set and treats missing, malformed, or job/report-contradictory evidence as an
infrastructure failure rather than a compatibility pass.

Pull-request code remains untrusted even though this workflow exposes no
secrets or write permission. Repository branch protection must require the
fixed aggregate compatibility status and CODEOWNER approval for modifications
to compatibility workflows, controllers, release locks, and validators.

The root token and unseal key necessarily exist in process and HTTP/TLS memory
during initialization; filesystem, allocator, Podman, TLS, kernel, and device
copies remain subject to the residual-memory limitations documented above.

## Known Limitations

Exact certificate or SPKI pinning is not implemented in 0.4.0; use root-only
trust with a private CA when pinning would otherwise be required.

## Pentest Gate

Every release tag requires the project owner's independent pentest review of
the exact release candidate before tag creation. Reports can contain sensitive
local evidence and are not required to be committed or duplicated in release
notes. Automated release gates intentionally do not claim that this human
review occurred; signed tag creation remains the manual enforcement point.

## OpenBao Compatibility

The detailed attacker model, trust boundaries, enforced invariants, and
residual-risk register are maintained in
[`OPENBAO_COMPATIBILITY_THREAT_MODEL.md`](OPENBAO_COMPATIBILITY_THREAT_MODEL.md).

This crate tracks the official OpenBao API documentation. The API is currently
documented as `/v1`, and OpenBao warns that compatibility is not yet guaranteed
for every auth method and secrets engine. Live core-flow evidence for exact
OpenBao `2.0.0` through `2.5.5` releases is labeled `tested-subset`; it does not
extend to every typed helper. Any behavior derived from live testing rather
than documentation must be marked as such in docs and tests.

`OpenBaoCompatibilityPolicy::automatic_strict`, `exact`, and `range` verify
the stable version through one unauthenticated, namespace-free `/sys/health`
request and cache the result only inside that client instance. Compatibility
probe failures retain neither the request URL nor OpenBao response messages.
The reported version is trustworthy only to the extent that the configured TLS
origin and any terminating proxy are trustworthy. For a load-balanced origin,
the probe proves the version of the backend selected for that request; operators
must keep backend versions inside the configured exact or rolling-upgrade range
and enforce that invariant at the load balancer or deployment layer. A range
policy does not compute or enforce the capability intersection of a mixed
cluster. Use backend affinity or restrict calls and fields to those present
throughout the complete range until the rollout is homogeneous.

Assumed mode performs no server verification and is always reported as
`Assumed`. The unknown-newer policy requires
`UnknownNewerOpenBaoAcknowledgement::acknowledge()` and reports the detected
version as acknowledged rather than verified while selecting the newest known
profile. It is a temporary compatibility escape hatch, not evidence that a
newer server preserved every operation. Strict mode remains the recommended
policy. Assumed mode must not be used to force an older route against a newer
server after that route has been removed.

Acknowledged raw transports receive the configured version preflight but
bypass typed operation selection. External plugin schemas are not covered by
core-server profiles and must be pinned and tested independently. See
[`OPENBAO_VERSION_SELECTION.md`](OPENBAO_VERSION_SELECTION.md) for
the complete deployment and future-release procedure.
