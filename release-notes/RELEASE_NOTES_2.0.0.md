# OpenBao Rust SDK 2.0.0 Release Notes

## Version

- Version: 2.0.0
- Release date: 2026-07-11
- Git tag: `v2.0.0-release`
- Git commit: see the signed `v2.0.0-release` tag object
- License: MIT OR Apache-2.0

The original GitHub-only `v2.0.0` candidate failed the all-release
compatibility workflow and was not published to crates.io. This replacement
source tag retains the stable Cargo package version `2.0.0`.

## Summary

`2.0.0` adds explicit, fail-closed compatibility profiles for every stable
OpenBao release from `2.0.0` through `2.5.5`. Typed requests select one
reviewed method, route, query shape, request contract, and response contract
for the active exact profile before sensitive request serialization. The SDK
never probes an older route after an HTTP, transport, or decode failure.

The immutable compatibility union contains 666 logical operations and 13,986
operation/profile cells. OpenBao `2.5.5` contains 665 documented operations:
580 typed and 85 typed-gated. Every available cell is typed, typed-gated, or
security-blocked; no generated cell remains planned, partial, raw, external,
rejected, or unverified.

## Compatibility Selection

- `automatic_strict`, exact, and range policies verify the server through one
  public, credential-free `/sys/health` request and cache the result per client.
- Unsupported versions, operations, routes, query selectors, and request
  fields fail locally before request transmission.
- Existing constructors remain offline and unverified for migration
  compatibility. Strict verification is recommended for production.
- Assumed mode is visibly reported as `Assumed`. Unknown newer servers require
  a separate acknowledgement and use the newest known profile temporarily.
- A range policy verifies one selected backend; it does not prove that every
  member of a mixed-version cluster implements the capability intersection.

## OpenBao Server Security Status

Wire compatibility is not security endorsement. OpenBao `2.5.5` is the newest
reviewed profile for this release and is the recommended production target.
The exact profiles below are retained for migrations and legacy deployments
but are security-deprecated because they do not contain all fixes present in
the newest reviewed patch:

- `2.0.0`, `2.0.1`, `2.0.2`, `2.0.3`;
- `2.1.0`, `2.1.1`;
- `2.2.0`, `2.2.1`, `2.2.2`;
- `2.3.1`, `2.3.2`;
- `2.4.0`, `2.4.1`, `2.4.3`, `2.4.4`;
- `2.5.0`, `2.5.1`, `2.5.2`, `2.5.3`, `2.5.4`.

Compatibility evidence cannot establish that an old server is free of known
or future vulnerabilities. Upgrade OpenBao independently of SDK compatibility
wherever operationally possible.

## Breaking Changes From 1.1.2

- Public raw JSON, byte, retry, and response-wrapping transports require both
  `raw-api` and `raw-api-acknowledged`.
- JWT/OIDC metadata, state, nonce, callback credentials, and database plugin
  extension values use secret-aware types where server or plugin data can
  contain credentials.
- OpenBao base URLs must be origins without embedded credentials, paths,
  queries, or fragments.
- OIDC GET callback and poll helpers require the non-default
  `oidc-get-callback-acknowledged` feature.
- CRL-bearing TLS configurations fail closed unless Rustls and a root-only
  configured trust store are selected.
- Request bodies default to an 8 MiB global limit. JSON and form serialization
  stop at the configured bound, byte bodies are checked before copying, and
  large Raft restores use exact-length `raft-stream` helpers that reject empty
  no-progress chunks, overflow, and truncation.
- Callers that require verified server compatibility must configure an exact,
  range, or automatic strict policy. See `docs/MIGRATION_GUIDE.md` for code
  examples and the complete source migration.

## Security Hardening

- Compatibility locks, snapshots, contracts, fixtures, and generated Rust use
  bounded, duplicate-key-safe parsing and checksum anchors.
- Historical integration runs use immutable image digests, disposable
  rootless containers, read-only filesystems, dropped capabilities, isolated
  networks, loopback-only exposure, and memory-backed credential descriptors.
- Database TLS DSNs reject ambiguous, duplicate, weaker, or non-TCP TLS
  configurations before secret request construction. URI validation borrows
  from secret DSNs instead of creating a non-sanitizing URL copy.
- OIDC credential-bearing GET operations require explicit acknowledgement and
  avoid unnecessary crate-owned plaintext copies.
- Database extension values and OIDC introspection claims remain redacted from
  `Debug`; unknown plugin response values fail closed as bounded secrets.

## Evidence And Validation

- Immutable source, image, signature, API snapshot, and contract locks for 21
  exact OpenBao releases.
- 21 checksum-anchored live core-flow results with zero skipped operations.
- Every live core-flow run selects the same exact locked client profile as its
  server release; the oldest and newest boundary releases are also exercised
  locally before tagging.
- A generated 666-operation capability registry and 13,986-cell exact-version
  support matrix.
- Versioned serde fixtures, deterministic mutation tests, cargo-fuzz targets,
  focused Kani proofs, unit tests, mock HTTP tests, doctests, Clippy, Rust MSRV
  checks, dependency policy, RustSec audit, CodeQL, package review, and SBOM.
- The release gate is `scripts/release_2_0_gate.sh`; tagging additionally
  requires a green all-release GitHub compatibility workflow and a clean
  independent pentest for the exact candidate commit.

## Accepted Residual Risks

- Signed source and image identities do not prove correct behavior or absence
  of vulnerabilities; docs, OpenAPI, fixtures, live tests, audits, and pentests
  remain separate evidence.
- Runtime version detection observes one backend and trusts the configured TLS
  origin and any terminating proxy. Mixed clusters require backend affinity or
  use of the complete range intersection.
- Assumed and acknowledged-unknown-newer modes provide weaker evidence and
  must not be reported as verified.
- External plugin schemas and upstream services are deployment-owned and must
  be pinned and tested separately. Raw transports bypass typed capability
  selection after compatibility preflight.
- Live integration is a representative core-flow subset, not execution of all
  13,986 cells. Fuzzing and bounded Kani proofs are not whole-program proofs.
- Dependency-owned HTTP/TLS headers and body buffers, OpenSSL software Transit
  import buffers, kernel/device buffers, environment variables, allocator
  state, swap, and crash dumps cannot be fully sanitized by this crate.
- Bootstrap operations without OpenBao CAS remain subject to concurrent-writer
  races and require an external single-runner or distributed lock.

The complete trust boundaries and mitigations are documented in
`SECURITY.md` and `docs/OPENBAO_COMPATIBILITY_THREAT_MODEL.md`.

## Release Rule

Do not create `v2.0.0-release` until GitHub CI, CodeQL, the full 21-release
compatibility workflow, and the independent exact-commit pentest are green.
