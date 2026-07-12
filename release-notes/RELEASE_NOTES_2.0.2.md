# OpenBao Rust SDK 2.0.2 Release Notes

## Version

- Version: 2.0.2
- Release date: 2026-07-12
- Git tag: `v2.0.2`
- Git commit: see the signed `v2.0.2` tag object
- License: MIT OR Apache-2.0

## Summary

`2.0.2` keeps the stable `2.0.x` API and reduces the crates.io source package
to the files needed by SDK users and package-local verification. Complete
compatibility evidence, CI configuration, deployment helpers, release tooling,
historical release notes, and maintainer plans remain available from the
signed Git source instead of being duplicated in every crate download.

The previous package contained 235 files, occupied approximately 40.2 MiB
unpacked, and compressed to approximately 2.5 MiB. The dominant inputs were
31 MiB of compatibility evidence and 6.9 MiB of documentation, including a
6.4 MiB generated JSON matrix.

The reviewed `2.0.2` package contains 76 files, occupies approximately 2.8 MiB
unpacked, and compresses to approximately 451.4 KiB.

## Published Package Scope

The package retains:

- `src`, `build.rs`, examples, README, changelog, security policy, and licenses;
- user-facing migration, compatibility, coverage, plugin, and security docs;
- ordinary HTTP and serde tests with their required bounded fixtures; and
- the request-field document and TLS fixtures referenced by source unit tests.

The package excludes repository-only GitHub configuration, compatibility
snapshots and matrices, deployment files, scripts, Kani instructions,
historical release notes, maintainer plans and policy, the live
OpenBao integration test, and the complete version-contract evidence test.

Cargo automatically includes `Cargo.lock` for this package's target set; it is
the only repository lockfile present in the published archive. Fuzz and
standalone fixture lockfiles remain repository-only.

These exclusions do not remove runtime compatibility support. The reviewed
operation registry is compiled into `src/generated/openbao_capabilities.rs`.
The signed `v2.0.2` source retains all generation inputs and release evidence.

## Regression Protection

The release gate checks the package file list for forbidden repository-only
paths and rejects a compressed crate archive larger than 2 MiB. The packaged
source is also tested independently so required compile-time fixtures cannot
be omitted accidentally.

## Compatibility And Security

Endpoint behavior, public API contracts, OpenBao profiles, and security policy
are unchanged from `2.0.1`. OpenBao `2.5.5` remains the newest reviewed and
recommended production profile; historical profiles remain wire-compatibility
targets rather than security endorsements.
