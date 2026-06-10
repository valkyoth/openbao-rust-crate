# OpenBao Rust SDK 1.0.2 Release Notes

## Version

- Version: 1.0.2
- Release date: 2026-06-10
- Git tag: `v1.0.2`
- Git commit: see the signed `v1.0.2` tag object
- License: MIT OR Apache-2.0

## Summary

`1.0.2` is a source-compatible maintenance release for the stable `1.0.x` line.
It refreshes reviewed dependencies and CI tooling, and trims the crates.io
README so it focuses on current SDK support instead of pre-`1.0` release
history.

This release does not change OpenBao endpoint coverage or the public typed SDK
API surface.

## Changed

- Updated `base64-ng` to `1.0.8`.
- Refreshed semver-compatible transitive dependencies in `Cargo.lock`,
  including `bitflags`, `http`, `log`, `wasm-bindgen` packages, `web-sys`,
  `js-sys`, and `zerocopy`.
- Updated pinned `taiki-e/install-action` CI action to `v2.81.9`.
- Shortened `README.md` for crates.io by removing historical “Delivered in”
  release narration and keeping current support in `Implemented now`.
- Updated migration, release plan, API stability, and release metadata checks
  for the `1.0.2` candidate.

## Compatibility

- Normal `1.0.1` callers should not need code changes.
- The dependency update keeps the same public features and APIs.
- Historical release details remain available in `CHANGELOG.md` and older
  release-note files.

## Validation

- `scripts/checks.sh`
- `cargo fmt --all`
- `cargo test --all-targets --all-features`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo deny check`
- `cargo package --locked --allow-dirty --list`
- `scripts/validate-release-metadata.sh`

`v1.0.2` was tagged after GitHub CI and CodeQL were green for the release
commit.
