# OpenBao Rust SDK 2.1.3 Release Notes

## Version

- Version: 2.1.3
- Release date: 2026-08-08
- Release tag: `v2.1.3`, created only after every release gate passes
- Release commit: bound by the signed `v2.1.3` tag object
- License: MIT OR Apache-2.0

## Summary

`2.1.3` is a source-compatible dependency, CI-tooling, and security-hardening
maintenance release.
It updates `base64-ng` to `2.0.1`, adopts the current `time` patch release, and
refreshes pinned GitHub Actions. It does not add or remove OpenBao operations,
change public SDK types, or alter exact-version routing.

The crates.io source package is also reduced without weakening the release
gate. Full integration tests, fixtures, compatibility evidence, and detailed
engineering documentation remain in the signed source tag and run before
packaging. The extracted archive runs a focused public-API smoke test and
compiles every packaged example with all features.

The OpenBao compatibility inventory remains 691 operation identities across
23 exact profiles and 15,893 operation/profile cells. Exact OpenBao `2.6.1`
remains the newest reviewed server profile.

## Dependency Updates

- Updated `base64-ng` from `1.3.9` to `2.0.1`. The SDK retains the existing
  redacted secret-buffer integration, uses its constant-time-oriented decoder
  for secret-bearing Transit, system-tool, and operator-token outputs, and does
  not expose `base64-ng` types in its public API.
- Updated `time` from `0.3.54` to `0.3.55`.
- Refreshed the root, fuzz, and TLS-unification fixture lockfiles to the newest
  semver-compatible transitive dependency versions available to their Rust
  toolchains.
- Confirmed all other direct crates and CI cargo tools are current through
  `scripts/checks.sh` on the release date.

`base64-ng` `2.0.1` continues to support Rust `1.90.0`, so the SDK's MSRV is
unchanged.

## GitHub Actions

- Updated `Swatinem/rust-cache` from `2.9.1` to `2.9.2`.
- Updated `taiki-e/install-action` from `2.85.1` to `2.85.10`.
- Confirmed `actions/checkout`, `actions/upload-artifact`, and
  `actions/download-artifact` remain current.
- Retained immutable commit-SHA pins and matching version comments for every
  Action.

## OpenBao Compatibility

OpenBao support is unchanged from `2.1.2`:

- all 23 digest-pinned releases from `2.0.0` through `2.6.1` retain their
  exact compatibility profiles;
- exact `2.6.1` remains the newest reviewed server;
- no route, request-field, response-field, capability, or security-block
  classification changes in this release.

## Security Clarifications

- Secret-bearing Base64 decode paths now use `base64-ng::ct` with opaque error
  mapping and sanitizing result buffers. This is the dependency's
  constant-time-oriented best-effort boundary, not a formal cross-target
  constant-time guarantee.
- Documentation now states precisely that `unsafe_code = "forbid"` applies to
  this crate's Rust sources. Unsafe Rust, FFI, assembly, and native code in TLS
  or cryptographic dependencies remain part of the reviewed trusted computing
  base and generated SBOM.
- The pentest policy records the existing manual control: the project owner
  reviews the exact candidate before signing the tag. Sensitive reports are
  not required in committed release notes, and automated checks do not claim
  to attest that human review.

## Migration

No application source migration is required. Existing feature selections and
OpenBao version-selection behavior remain valid.

Registry archives no longer carry the complete upstream test and documentation
trees. Distro packagers that run the complete upstream suite should use the
signed `v2.1.3` source tag. Cargo consumers and docs.rs builds are unaffected.

## Package Contents

- Replaced the 550 KB repository HTTP integration test and fixture payload
  with a small public-API package smoke test.
- Kept compiled examples, `README.md`, `CHANGELOG.md`, the compact security
  reporting policy, licenses, runtime source, and build metadata.
- Moved detailed security controls and residual-risk guidance to
  `docs/SECURITY_MODEL.md` in the signed repository source.
- Added release checks that reject repository-only docs, fixtures, and full
  integration tests from the archive, cap the README at 600 lines, cap the
  packaged security policy at 8 KiB, and cap the compressed archive at 512 KiB.

## Release Gate

Run `scripts/release_2_1_3_gate.sh`. Tagging additionally requires green
GitHub CI, CodeQL, the all-release compatibility workflow, and clean
independent pentests for the exact release commit.
