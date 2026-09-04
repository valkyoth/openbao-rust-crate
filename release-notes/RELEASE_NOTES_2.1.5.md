# OpenBao Rust SDK 2.1.5 Release Notes

## Version

- Version: 2.1.5
- Release date: 2026-09-04
- Release tag: `v2.1.5`, created only after every release gate passes
- Release commit: bound by the signed `v2.1.5` tag object
- License: MIT OR Apache-2.0

## Summary

`2.1.5` is a source-compatible dependency, toolchain, CI, and static-analysis
maintenance release. It does not change the public SDK or any exact OpenBao
compatibility profile. All 24 profiles from OpenBao `2.0.0` through `2.6.2`
retain their reviewed routes, request and response field rules, and security
classifications.

## Dependency And Toolchain Updates

- Updated `base64-ng` from `2.0.1` to `2.0.3`.
- Updated `sanitization` from `2.0.3` to `2.0.4`.
- Refreshed the root, fuzz, and TLS-unification fixture lockfiles to current
  compatible dependency versions.
- Updated the primary Rust toolchain from `1.97.1` to `1.98.1`; Rust `1.90.0`
  remains the checked MSRV.
- Updated `taiki-e/install-action` from `2.86.3` to `2.87.4` with an immutable
  commit-SHA pin.
- Confirmed all other direct crates, CI cargo tools, and pinned GitHub Actions
  are current on the release date.

## Static-Analysis Hardening

The maintenance pass resolves all eleven CodeQL alerts open at its start
without query suppressions or alert dismissals:

- database password and protocol nonce fixtures are built at test runtime
  instead of embedding complete values in source; and
- assertions and panic paths no longer format secret-bearing operation results
  or secret-memory errors into diagnostics.

These changes affect tests and failure reporting only. Runtime request,
response, redaction, and compatibility behavior is unchanged.

## Compatibility

No application migration is required. Exact and automatic compatibility
selection continue to support every locked stable OpenBao release from `2.0.0`
through `2.6.2`. The active inventory remains 691 operation identities across
24 exact profiles and 16,584 operation/profile cells.

## Release Gate

Run `scripts/release_2_1_5_gate.sh`. Tagging additionally requires green
GitHub CI, CodeQL, the all-release compatibility workflow, and clean
independent pentests for the exact release commit.
