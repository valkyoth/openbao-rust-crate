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
- JSON request serialization buffers controlled by this crate must be zeroized
  after handoff to the HTTP stack.
- Third-party GitHub Actions must be pinned to immutable commit SHAs.
- New dependencies require a release-plan justification and `cargo deny` review.

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
external serialization.

## Residual Secret Memory

After a JSON request body is handed to `reqwest`, the transport stack, TLS
backend, kernel, or network device may keep independent plaintext or ciphertext
buffers until their own cleanup. This crate zeroizes the serialization buffer it
controls, but it cannot guarantee zeroization of buffers owned by dependencies
or the operating system.

High-assurance deployments should combine this crate with process isolation,
encrypted swap or disabled swap, core-dump restrictions, short process
lifetimes for highly sensitive workflows, and host-level memory protections
appropriate to the environment.

Base64 helpers used by Transit byte operations and system random byte helpers
move base64 text into `SecretString`, but exposing text from dependency APIs is
still a residual process-memory risk. High-assurance deployments should treat
the calling process heap as capable of containing encoded secret material until
the relevant `SecretString` values are dropped and zeroized.

## Hardened Deployment Profile

For high-assurance builds, keep the default `rustls-tls` backend, do not enable
`native-tls` or `native-tls-acknowledged`, and do not call
`OpenBaoConfig::min_tls_12`. Downstream applications can enforce this with CI
policy checks that reject those feature flags and API calls.

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
certification, or post-quantum claim. It also requires the
`transit-import-acknowledged` feature so downstream builds explicitly review
that raw key material and the ephemeral AES wrapping key pass through software
memory and OpenSSL-managed heap. Classified or high-assurance key wrapping
should be performed in an HSM or equivalent audited boundary instead.

The `radius-auth` feature is not enabled by default. RADIUS relies on
MD5-based authenticators and is retained only for audited legacy compatibility.
Enabling it requires the additional `radius-auth-acknowledged` feature. Do not
use RADIUS for classified networks or new high-assurance deployments; prefer
certificate auth, Kerberos, or LDAP over TLS with reviewed server validation.

The `sensitive-http-test-only` feature is for this crate's mock HTTP tests
only. It must not be enabled in production application builds. Release metadata
checks verify it is not part of the default feature set, and `build.rs` emits a
warning whenever it is compiled. It also requires
`sensitive-http-test-only-acknowledged` so accidental workspace feature
propagation fails closed.

The rustls-backed HTTP client does not perform OCSP or CRL revocation checking
for the OpenBao server certificate. Use short-lived listener certificates,
root-only internal CA trust stores, and OpenBao/server-side certificate-auth
CRL/OCSP controls where certificate revocation is part of the deployment threat
model.

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
