# OpenBao Rust SDK 2.0.1 Release Notes

## Version

- Version: 2.0.1
- Release date: 2026-07-11
- Git tag: `v2.0.1`
- Git commit: see the signed `v2.0.1` tag object
- License: MIT OR Apache-2.0

## Summary

`2.0.1` is a documentation correction for the stable `2.0.x` line. The
`2.0.0` release shipped exact, fail-closed compatibility profiles and live
core-flow evidence for all 21 stable OpenBao releases from `2.0.0` through
`2.5.5`, but the README still described `1.1.2` as the latest stable SDK and
`2.0.0` as a release candidate.

This patch corrects that release status and documents how applications use the
current SDK with older OpenBao servers. It does not change endpoint behavior,
public API contracts, compatibility profiles, or security policy.

## Older OpenBao Servers

- Use `OpenBaoCompatibilityPolicy::exact` with the server's actual release for
  a fixed historical deployment.
- Use `automatic_strict` to detect any release already present in the locked
  `2.0.0` through `2.5.5` registry.
- Use an inclusive range only for a controlled rolling upgrade; one health
  response cannot prove every backend has the same capabilities.
- Use `assume` only when a trusted proxy blocks `/sys/health`; its result is
  explicitly `Assumed`, never `Verified`.
- Do not select an old profile against a newer server to recover a removed
  endpoint. Exact verification rejects that mismatch. Historical profiles are
  append-only and remain available for servers genuinely running that release.

Wire compatibility is not a security endorsement. OpenBao `2.5.5` remains the
newest reviewed and recommended production profile in this SDK release.

## Validation

The normal `scripts/release_2_0_gate.sh` validates formatting, Clippy, tests,
doctests, documentation, dependency policy, audit status, generated contracts,
release metadata, and SBOM generation. A signed release tag additionally
requires green GitHub CI, CodeQL, and the version-tag compatibility workflow.
