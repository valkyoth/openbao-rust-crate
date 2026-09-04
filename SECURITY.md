# Security Policy

Security is the primary design constraint for this crate.

## Supported Versions

Only the latest published stable SDK release receives security fixes. Older
SDK releases may remain wire-compatible but are not security-supported. An
older OpenBao server profile can remain wire-compatible without making that
server release eligible for security maintenance. Upgrade the SDK
independently of the selected OpenBao compatibility profile.

## Reporting A Vulnerability

Do not open a public issue for suspected vulnerabilities.

Report privately through
[GitHub Security Advisories](https://github.com/valkyoth/openbao-rust-crate/security/advisories/new)
or contact the maintainers through the private channel listed in the
repository profile.

Include the affected version or commit, enabled features, operating system,
Rust version, OpenBao state, reproduction steps, and proof of impact. Do not
include real tokens, private keys, unseal material, or production secrets.

## Security Baseline

- `unsafe_code = "forbid"` applies to this crate's own Rust sources. TLS and
  cryptographic dependencies can contain unsafe Rust, FFI, assembly, or native
  code and remain part of the trusted computing base.
- HTTPS, TLS verification, TLS 1.3, and disabled redirects are the defaults.
- TLS 1.2, native TLS, raw transports, operator operations, software Transit
  import wrapping, and other high-risk capabilities require explicit feature
  acknowledgements.
- Tokens, accessors, credentials, and secret response fields use secret-aware
  types and redacted diagnostics.
- Paths, headers, durations, collection sizes, request bodies, and response
  bodies are validated or bounded before use.
- OpenBao compatibility is selected through immutable, fail-closed profiles;
  unknown newer servers are rejected unless explicitly acknowledged.
- Third-party GitHub Actions are pinned to immutable commit SHAs, dependencies
  are checked with `cargo deny` and RustSec, and every release requires a
  reviewed pentest report.

Secret bytes necessarily enter dependency-owned HTTP, TLS, allocator, kernel,
and device buffers that this crate cannot sanitize. Memory locking covers only
the authenticated client's retained token when its acknowledged feature is
enabled; it does not automatically lock every request or response secret.

## Detailed Model

The complete threat model, hardened deployment guidance, feature-specific
controls, compatibility evidence rules, residual-memory analysis, and accepted
limitations are maintained in the signed repository source:

- [Security model and operational guidance](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.5/docs/SECURITY_MODEL.md)
- [OpenBao compatibility threat model](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.5/docs/OPENBAO_COMPATIBILITY_THREAT_MODEL.md)
- [Panic policy](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.5/docs/PANIC_POLICY.md)

Review those documents before enabling any feature whose name ends in
`-acknowledged` or deploying the SDK in a high-assurance environment.
