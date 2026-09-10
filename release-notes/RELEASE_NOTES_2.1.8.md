# OpenBao Rust SDK 2.1.8 Release Notes

## Version

- Version: 2.1.8
- Release date: 2026-09-10
- Release tag: `v2.1.8`, created only after every release gate passes
- Release commit: bound by the signed `v2.1.8` tag object
- License: MIT OR Apache-2.0

## Summary

`2.1.8` is a source-compatible Transit lifecycle assurance release. It does
not change OpenBao routes, compatibility profiles, typed request or response
schemas, or feature gates. The optional `base64-ng` dependency is updated from
`2.0.3` to `2.0.4` using the same `alloc`-only feature configuration, and
`reqwest` is updated from `0.13.4` to `0.13.5` with default features still
disabled. The immutable `taiki-e/install-action` pin is updated from `2.87.7`
to `2.87.9`; all other checked direct crates, CI cargo tools, and GitHub
Actions are current on the release date.

reqwest `0.13.5` uses `base64 0.23` while its current hyper-util dependency
still uses `base64 0.22`. The older line is a narrowly versioned cargo-deny
exception; a third version or different stale line remains visible.

The release closes diagnostic and verification gaps around the sensitive
Transit encrypt/decrypt path. Item-level errors in every Transit batch result
remain available through their public fields but are now redacted from
`Debug`, because OpenBao error strings can reflect raw or Base64 request
material.

## Lifecycle Verification

- The typed `TransitEncryptRequest::from_plaintext_bytes` path is verified to
  retain its sanitizing request-body allocation through production dispatch
  and final HTTP-body-owner destruction.
- Response cancellation is synchronized after a real reqwest response chunk
  has been copied into the sanitizing bounded accumulator. A cleanup probe
  verifies that cancellation destroys the accumulator, wipes at least the
  observed initialized bytes, and observes zeros before final clearing.
- Parser regressions cover escaped Base64 padding, malformed escaped strings,
  truncated JSON, invalid Base64, and secret-free decode diagnostics.
- A chunked Transit response without `Content-Length` is rejected as soon as
  it crosses the configured response limit, without including received secret
  text in the error.
- An isolated tracing subscriber captures typed Transit encrypt and decrypt
  operations and verifies that raw plaintext, Base64 plaintext, ciphertext,
  authentication tokens, and key identifiers are absent from span and event
  fields. Its failure diagnostic is constant and cannot echo a matched secret
  sentinel into CI or code-scanning output.
- Mock HTTP capture is timeout-bounded, size-bounded, and framing-aware. The
  typed lifecycle and tracing fixtures intentionally force multiple short TCP
  reads before asserting on the complete request.
- Existing exact OpenBao `2.6.2` TLS integration continues to cover Transit
  encrypt/decrypt, associated-data binding, an older explicit key version after
  rotation, valid-format ciphertext tampering, and incorrect associated data.

## Memory Guarantee

The SDK guarantees cleanup for the allocations it controls: typed secret
values, Base64 outputs transferred into secret types, sensitive request-body
owners, complete response accumulators, and decoded plaintext byte buffers.
Uniquely owned incoming HTTP chunks are wiped on a best-effort basis after
copying.

The SDK does not claim complete process-memory erasure. Caller buffers, shared
HTTP chunks, serde_json scratch storage, reqwest, Hyper, TLS, allocator,
kernel, device, crash-dump, swap, and forced-termination state remain outside
the crate's cleanup guarantee. Escaped JSON strings can specifically use
serde_json's private ordinary scratch buffer; this cannot be sanitized by the
SDK without an upstream parser capability or a separately reviewed parser.

## Compatibility

No application source migration is required. The MSRV remains Rust `1.90.0`,
the primary toolchain remains Rust `1.98.1`, and all 24 immutable exact
OpenBao release profiles through `2.6.2` are unchanged.

## Release Gate

Run `scripts/release_2_1_8_gate.sh`. Tagging additionally requires green
GitHub CI, CodeQL, the all-release compatibility workflow, exact OpenBao
`2.6.2` TLS integration, and clean independent pentests for the exact release
commit.
