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
- Public raw JSON, byte, retry, and response-wrapping transports are disabled
  unless both `raw-api` and `raw-api-acknowledged` are enabled. Raw transports
  bypass typed request validation and operation-specific feature gates; keep
  every enabled use behind a reviewed local typed wrapper with fixed methods
  and paths.
- Base URLs are origins only. User credentials, application paths, query
  strings, and fragments are rejected before a client is built.
- The selected reqwest TLS backend is set explicitly from this crate's feature
  policy so dependency feature unification cannot silently replace Rustls with
  native TLS.
- Configured certificate revocation lists fail closed unless Rustls is the
  selected backend. Enabling acknowledged native TLS alongside Rustls selects
  native TLS and therefore rejects CRL-bearing client configurations.

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

## Residual Secret Memory

After a JSON request body is handed to `reqwest`, the transport stack, TLS
backend, kernel, or network device may keep independent plaintext or ciphertext
buffers until their own cleanup. This crate sanitizes the serialization buffer it
controls, but it cannot guarantee sanitization of buffers owned by dependencies
or the operating system.
Token and namespace header values are also copied into HTTP-stack header
structures that are marked sensitive for logging but are not sanitized on drop by
the underlying `http`/`hyper`/`reqwest` types.
Tokens loaded from environment variables are moved directly into
`SecretString` without an intermediate trimmed copy, but the operating system's
process environment remains outside the crate's sanitization control. Prefer a
protected credential broker, inherited file descriptor, or dedicated secret
agent where environment-variable residency is unacceptable.

High-assurance deployments should combine this crate with process isolation,
encrypted swap or disabled swap, core-dump restrictions, short process
lifetimes for highly sensitive workflows, and host-level memory protections
appropriate to the environment.

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

This crate tracks the official OpenBao API documentation. The API is currently
documented as `/v1`, and OpenBao warns that compatibility is not yet guaranteed
for every auth method and secrets engine. Any behavior derived from live testing
rather than documentation must be marked as such in docs and tests.
