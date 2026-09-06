# OpenBao Rust SDK 2.1.6 Release Notes

## Version

- Version: 2.1.6
- Release date: 2026-09-06
- Release tag: `v2.1.6`, created only after every release gate passes
- Release commit: bound by the signed `v2.1.6` tag object
- License: MIT OR Apache-2.0

## Summary

`2.1.6` is a source-compatible security-hardening release for secret-bearing
HTTP buffers. Sensitive JSON, form, and byte requests no longer pass through
an ordinary SDK-created transport `Vec<u8>`. Their sanitizing allocation is
retained by the reqwest body and wiped after the final body clone drops.

OpenBao API routes, compatibility profiles, public SDK types, and feature
acknowledgement boundaries are unchanged from `2.1.5`.

The immutable `taiki-e/install-action` pin is updated from `2.87.4` to
`2.87.6`; the release freshness check reports all other direct crates, CI
cargo tools, and GitHub Actions current on the release date.

## Request Lifecycle

- JSON and form bodies serialize directly into a bounded sanitizing owner.
- Sensitive byte inputs are copied into that same owner after the configured
  request-size bound is checked.
- `bytes::Bytes::from_owner` retains the owner through reqwest body and request
  clones without an additional SDK body allocation.
- Reallocation wipes the replaced allocation; final drop wipes the full live
  allocation and capacity.
- Unit regressions cover serialization failure after partial output, size
  rejection, request cloning, cancellation, connection failure, timeout, and
  successful completion.

## Response Lifecycle

Complete responses continue to accumulate in `SecretVec`. After each HTTP
chunk is copied, the SDK now wipes it when `Bytes::try_into_mut` proves that
the allocation is uniquely owned. The optional monitor stream applies the same
best-effort cleanup when chunks are consumed, rejected, or held when the stream
is dropped.

The SDK cannot prove or enforce cleanup of shared reqwest/Hyper chunks, HTTP or
TLS implementation buffers, allocator copies, kernel or device buffers,
caller-owned input, or memory after forced process termination. Those remain
documented residual risks; this release does not claim universal process-memory
erasure.

## Verification

- Added pointer-identity and final-owner-drop regressions that fail if an
  ordinary SDK transport-body copy is reintroduced.
- Added lifecycle tests for success, partial serialization failure, size-limit
  rejection, cancellation, connection failure, and timeout.
- Expanded the exact OpenBao `2.6.2` TLS/container integration flow with
  Transit encryption and decryption, associated-data binding, explicit key
  version `1`, malformed ciphertext rejection, and incorrect-associated-data
  rejection.
- Replayed all 24 digest-pinned exact OpenBao profiles and re-anchored the
  core-flow evidence to the expanded test definition.
- Existing error, `Debug`, and tracing redaction tests remain part of the full
  release gate.

## Release Gate

Run `scripts/release_2_1_6_gate.sh`. Tagging additionally requires green
GitHub CI, CodeQL, the all-release compatibility workflow, and clean
independent pentests for the exact release commit.
