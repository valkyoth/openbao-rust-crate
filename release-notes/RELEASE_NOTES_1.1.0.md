# OpenBao Rust SDK 1.1.0 Release Notes

## Version

- Version: 1.1.0
- Release date: 2026-06-24
- Git tag: `v1.1.0`
- Git commit: see the signed `v1.1.0` tag object
- License: MIT OR Apache-2.0

## Summary

`1.1.0` is a security-buffer migration release for the stable `1.x` line. It
keeps the OpenBao endpoint boundary unchanged, but moves public owned
secret-byte buffers from `zeroize::Zeroizing<Vec<u8>>` to
`sanitization::SecretVec`.

The crate no longer exposes `openbao::Zeroize` or `openbao::Zeroizing`. Callers
that used byte-returning helpers should import `openbao::SecretVec` and inspect
bytes through `SecretVec::with_secret`.

## Changed

- Added a direct `sanitization` dependency with `alloc` support.
- Re-exported `sanitization`, `SecretVec`, `SecureSanitize`, and
  `sanitize_bytes` from the crate root and prelude.
- Changed raw byte request helpers, Transit byte decode helpers, Transit import
  software wrapping helpers, system random/hash byte helpers, pprof byte reads,
  and Raft snapshot byte downloads to use `SecretVec`.
- Removed the direct `zeroize` dependency and the `aes-kw/zeroize` feature from
  this crate's dependency configuration.
- Updated README, migration guide, security notes, API stability audit, and
  quantum-readiness guidance for the sanitization API.

## Compatibility

- This is a source migration for callers that referenced
  `Zeroizing<Vec<u8>>` through this crate.
- Replace `Zeroizing::new(bytes)` with `SecretVec::from_vec(bytes)`.
- Replace direct slice access on returned buffers with
  `secret_vec.with_secret(|bytes| { ... })`.
- `openbao::SecretString` remains the re-exported `secrecy::SecretString`.
  The crate intentionally does not re-export `sanitization::SecretString` under
  that name to avoid ambiguity.

## Validation

- `cargo check --all-features`
- `scripts/checks.sh`
- `cargo fmt --all`
- `cargo test --all-targets --all-features`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo deny check`
- `cargo package --locked --allow-dirty --list`
- `scripts/validate-release-metadata.sh`

`v1.1.0` should be tagged only after GitHub CI and CodeQL are green for the
release commit.
