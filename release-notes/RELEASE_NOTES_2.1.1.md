# OpenBao Rust SDK 2.1.1 Release Notes

## Version

- Version: 2.1.1
- Release date: 2026-07-21
- Git tag: `v2.1.1`
- Git commit: see the signed `v2.1.1` tag object
- License: MIT OR Apache-2.0

## Summary

`2.1.1` is a dependency maintenance patch for the stable `2.1.x` line. It
updates `sanitization` from `2.0.2` to `2.0.3` and refreshes all repository
lockfiles. There are no SDK API, OpenBao profile, route, request-field,
response-field, or feature-gate changes.

## Compatibility

- Rust `1.97.1` remains the primary release toolchain and Rust `1.90.0`
  remains the MSRV.
- The same 22 exact OpenBao profiles from `2.0.0` through `2.6.0` remain
  supported.
- All 690 logical operation identities and 15,180 operation/profile cells are
  unchanged from `2.1.0`.
- No source migration is required from `2.1.0`.

## Dependency Refresh

- Updated `sanitization` to `2.0.3` with the existing `alloc` feature and
  unchanged default-feature policy.
- Updated the root, fuzz, and native-TLS fixture lockfiles to bind the same
  dependency release.

## Release Gate

Run `scripts/release_2_1_1_gate.sh`. Tagging additionally requires green
GitHub CI, CodeQL, the all-release compatibility workflow, and clean
independent pentests for the exact release commit.
