# OpenBao Rust SDK 2.1.1 Release Notes

## Version

- Version: 2.1.1
- Release date: 2026-07-22
- Git tag: `v2.1.1`
- Git commit: see the signed `v2.1.1` tag object
- License: MIT OR Apache-2.0

## Summary

`2.1.1` is a dependency and memory-protection correction for the stable
`2.1.x` line. It
updates `sanitization` from `2.0.2` to `2.0.3`, updates `base64-ng` from
`1.3.8` to `1.3.9`, refreshes the affected repository lockfiles, and makes the
acknowledged `memory-lock` feature actively protect each authenticated
client's retained token. OpenBao profiles, routes, and request/response field
contracts are unchanged.

## Compatibility

- Rust `1.97.1` remains the primary release toolchain and Rust `1.90.0`
  remains the MSRV.
- The same 22 exact OpenBao profiles from `2.0.0` through `2.6.0` remain
  supported.
- All 690 logical operation identities and 15,180 operation/profile cells are
  unchanged from `2.1.0`.
- Normal builds require no source migration from `2.1.0`. `memory-lock` builds
  receive the compatibility exception described below. Every build now rejects
  authentication tokens larger than 16 KiB.

## Dependency Refresh

- Updated `sanitization` to `2.0.3` with the existing `alloc` feature and
  unchanged default-feature policy.
- Updated `base64-ng` to `1.3.9` with the existing optional dependency and
  `alloc` feature policy.
- Updated the root and fuzz lockfiles for both dependencies. The native-TLS
  fixture lockfile binds `sanitization` but does not enable a feature that
  pulls `base64-ng`.

## Memory-Lock Correction

In `2.1.0`, `memory-lock` enabled dependency support but did not move the
authenticated client's retained token into mapped storage. `2.1.1` corrects
that semantic gap: `try_with_token` transfers the validated token into
`sanitization::LockedSecretString` and fails with
`Error::SecretMemoryProtection` if OS locking or random-canary setup cannot be
established. The feature selects `sanitization`'s reviewed hardened native
profile. `try_with_locked_token` accepts existing mapped custody directly only
when the supplied mapping reports an active OS lock, and
`authentication_token_is_memory_locked` supports fallible deployment
assertions. A safe mutex around the mapped token preserves the authenticated
client's `Send + Sync` contract while serializing canary verification.

All authentication paths enforce a 16 KiB token ceiling before header or
mapped-storage allocation. OS-random canaries detect accidental or adjacent
mapping corruption; they are defense in depth and do not resist an attacker
that can arbitrarily write process memory.

This is an intentional compatibility exception in a non-default,
acknowledgement-gated feature. Other public `SecretString`/`SecretVec` values
retain their established types, and transport-owned copies remain outside the
locking boundary. Applications must still audit OS limits, swap, crash dumps,
and explicit custody transfer for operator material and returned secrets.

## Release Gate

Run `scripts/release_2_1_1_gate.sh`. Tagging additionally requires green
GitHub CI, CodeQL, the all-release compatibility workflow, and clean
independent pentests for the exact release commit.
