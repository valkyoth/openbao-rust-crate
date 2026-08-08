# OpenBao Rust SDK 2.1.3 Release Notes

## Version

- Version: 2.1.3
- Release date: 2026-08-08
- Release tag: `v2.1.3`, created only after every release gate passes
- Release commit: bound by the signed `v2.1.3` tag object
- License: MIT OR Apache-2.0

## Summary

`2.1.3` is a source-compatible dependency and CI-tooling maintenance release.
It updates `base64-ng` to `2.0.1`, adopts the current `time` patch release, and
refreshes pinned GitHub Actions. It does not add or remove OpenBao operations,
change public SDK types, or alter exact-version routing.

The OpenBao compatibility inventory remains 691 operation identities across
23 exact profiles and 15,893 operation/profile cells. Exact OpenBao `2.6.1`
remains the newest reviewed server profile.

## Dependency Updates

- Updated `base64-ng` from `1.3.9` to `2.0.1`. The SDK retains the existing
  redacted secret-buffer encode/decode integration and does not expose
  `base64-ng` types in its public API.
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

## Migration

No application source migration is required. Existing feature selections and
OpenBao version-selection behavior remain valid.

## Release Gate

Run `scripts/release_2_1_3_gate.sh`. Tagging additionally requires green
GitHub CI, CodeQL, the all-release compatibility workflow, and clean
independent pentests for the exact release commit.
