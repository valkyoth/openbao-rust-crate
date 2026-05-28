# Changelog

All notable changes to this project are documented here.

## 0.3.0 - Unreleased

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
