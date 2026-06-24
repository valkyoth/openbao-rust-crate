# OpenBao Rust SDK 1.1.1 Release Notes

## Version

- Version: 1.1.1
- Release date: 2026-06-24
- Git tag: `v1.1.1`
- Git commit: see the signed `v1.1.1` tag object
- License: MIT OR Apache-2.0

## Summary

`1.1.1` is a source-compatible security dependency refresh for the stable
`1.1.x` line. It keeps the `1.1.0` `sanitization::SecretVec` API and the
OpenBao endpoint surface unchanged.

## Changed

- Updated `base64-ng` to `1.2.3`.
- Updated `sanitization` to `1.2.2`.
- Verified cargo security tooling and pinned GitHub Actions remain on the
  latest versions checked by `scripts/check_latest_crates.sh`.
- Refreshed release metadata, changelog, README support text, and release plan
  checks for the `1.1.1` candidate.

## Compatibility

- Normal `1.1.0` callers should not need code changes.
- The dependency update keeps the same public features and APIs.
- OpenBao endpoint coverage and request/response semantics are unchanged.

## Validation

- `scripts/check_latest_crates.sh`
- `cargo update --dry-run`
- `cargo test --all-targets --all-features`
- `cargo fmt --all --check`
- `scripts/validate-release-metadata.sh`

`v1.1.1` should be tagged only after GitHub CI and CodeQL are green for the
release commit.
