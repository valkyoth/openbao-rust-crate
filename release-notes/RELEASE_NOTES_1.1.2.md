# OpenBao Rust SDK 1.1.2 Release Notes

## Version

- Version: 1.1.2
- Release date: 2026-07-04
- Git tag: `v1.1.2`
- Git commit: see the signed `v1.1.2` tag object
- License: MIT OR Apache-2.0

## Summary

`1.1.2` is a source-compatible maintenance release for the stable `1.1.x`
line. It refreshes dependency and CI tooling pins, makes Rust `1.96.1` the
primary checked toolchain, keeps Rust `1.90.0` as the documented MSRV, and adds
bounded Kani proof harness support for selected validation helpers.

OpenBao endpoint coverage, public API semantics, and the `1.1.0`
`sanitization::SecretVec` owned-secret-buffer migration are unchanged.

## Added

- Added optional Kani proof harness support through `scripts/check_kani.sh`.
- Added an inert `kani` feature used only for Kani proof-harness builds.
- Added bounded proof harnesses for byte-level OpenBao path rejection policy
  and allocation-light duration component parsing on the Rust `1.90.0` Kani
  toolchain pairing.

## Changed

- Updated the crate version to `1.1.2`.
- Replaced duration component parsing with a manual checked parser so duration
  validation stays allocation-light and suitable for bounded Kani proofs.
- Updated `base64-ng` to `1.3.5`.
- Updated `rand` to `0.10.2`.
- Updated `time` to `0.3.53`.
- Updated the pinned `taiki-e/install-action` CI action to `v2.82.8`.
- Refreshed semver-compatible transitive dependencies in `Cargo.lock`.
- Updated the pinned development toolchain and CI installer to Rust `1.96.1`.
- Updated README Rust support guidance to describe Rust `1.96.1` as the
  primary release toolchain and Rust `1.90.0` as the compatibility floor.

## Compatibility

- Normal `1.1.x` callers should not need code changes.
- The crate MSRV remains Rust `1.90.0`.
- OpenBao integration testing remains pinned to OpenBao `2.5.5`.
- OpenBao endpoint coverage and request/response semantics are unchanged.
- The Kani harnesses are bounded proof checks only; they are not a whole-crate
  formal-verification claim.

## Validation

- `scripts/check_latest_crates.sh`
- `cargo update --dry-run`
- `cargo +1.90.0 check --all-features`
- `scripts/check_kani.sh`
- `scripts/checks.sh`
- `scripts/validate-release-metadata.sh`

`v1.1.2` should be tagged only after GitHub CI and CodeQL are green for the
release commit.
