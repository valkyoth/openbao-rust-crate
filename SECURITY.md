# Security Policy

Security is the primary design constraint for this crate.

## Supported Versions

Until `1.0.0`, only the latest published pre-`1.0` version receives security
fixes. After `1.0.0`, the project will document a stable support window in this
file.

## Reporting A Vulnerability

Do not open a public issue for suspected vulnerabilities.

Report privately through GitHub Security Advisories for
`valkyoth/openbao-rust-crate`, or contact the maintainers through the private
channel listed in the repository profile.

Please include:

- affected version or commit;
- exact feature flags used;
- operating system and Rust version;
- whether OpenBao was sealed, standby, or active;
- proof of impact;
- reproduction steps that avoid exposing real tokens or secrets.

## Security Baseline

- `unsafe_code = "forbid"`.
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
  evidence as representative; rejects skipped core-flow passes; and records
  that no external database, directory, cloud, OIDC, MFA, DNS, or broker
  service was exercised.
- Version-aware typed dispatch selects exactly one reviewed operation before
  request serialization. The method comes from immutable registry evidence;
  concrete paths and required query selectors must match that operation's
  template. Unsupported, overlapping, malformed, external, and
  security-blocked selections fail locally without route probing.
- Typed dispatch never retries another historical route after HTTP 404/405,
  transport, or decode failure. Such fallback could duplicate writes or let a
  server response influence capability selection.
- Public raw JSON, byte, retry, and response-wrapping transports are disabled
  unless both `raw-api` and `raw-api-acknowledged` are enabled. Raw transports
  bypass typed capability selection, endpoint validation, and
  operation-specific feature gates; keep every enabled use behind a reviewed
  local typed wrapper with fixed methods and paths. A compatibility policy
  verifies the server version before raw transmission but does not prove that
  the caller-selected raw route exists for that version.
- Base URLs are origins only. User credentials, application paths, query
  strings, and fragments are rejected before a client is built.
- The selected reqwest TLS backend is set explicitly from this crate's feature
  policy so dependency feature unification cannot silently replace Rustls with
  native TLS.
- Configured certificate revocation lists fail closed unless Rustls is the
  selected backend. Enabling acknowledged native TLS alongside Rustls selects
  native TLS and therefore rejects CRL-bearing client configurations.
- Reviewed built-in database plugins require typed connection options. Without
  `insecure-database-tls-acknowledged`, PostgreSQL DSNs must explicitly resolve
  to one unambiguous `sslmode=verify-full`; omitted, duplicated,
  service-file-only, empty, unsupported URI syntax, or weaker modes fail
  locally before credential-bearing request serialization.
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

The `operator-ops` feature exposes production init, unseal, seal, rekey, and
rotation APIs. It is disabled by default and fails to compile unless
`operator-ops-acknowledged` is enabled too. Do not enable it in normal
application clients; reserve it for audited operator tooling with an external
key ceremony and custody model.

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

The `memory-lock` feature enables `sanitization` memory-lock support for secret
buffers where the operating system permits it. It is disabled by default and
requires `memory-lock-acknowledged` because mlock/VirtualLock limits, container
permissions, swap policy, and failure behavior are deployment-specific. Memory
locking is a host hardening control, not a guarantee that dependency-owned HTTP,
TLS, kernel, allocator, or device buffers avoid swap or crash dumps.

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
key material would cross an unverified TLS connection.

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

`Sys::bootstrap_dev` is for disposable local OpenBao development instances
only. It refuses non-loopback and already initialized targets, but it still
creates root-token and unseal-key material in the caller process. Do not use it
for production, staging, shared environments, HSM/KMS-backed auto-unseal, or
any environment that requires an operator key ceremony.

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

Every release tag requires a pentest report from the project owner before tag
creation. The release notes must record:

- report identifier or local evidence path;
- tested commit;
- scope;
- unresolved findings;
- accepted risks, if any.

## OpenBao Compatibility

The detailed attacker model, trust boundaries, enforced invariants, and
residual-risk register are maintained in
[`docs/OPENBAO_COMPATIBILITY_THREAT_MODEL.md`](docs/OPENBAO_COMPATIBILITY_THREAT_MODEL.md).

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
[`docs/OPENBAO_VERSION_SELECTION.md`](docs/OPENBAO_VERSION_SELECTION.md) for
the complete deployment and future-release procedure.
