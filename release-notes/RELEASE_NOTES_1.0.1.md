# OpenBao Rust SDK 1.0.1 Release Notes

## Version

- Version: 1.0.1
- Release date: 2026-06-09
- Git tag: `v1.0.1`
- Git commit: see the signed `v1.0.1` tag object
- License: MIT OR Apache-2.0

## Summary

`1.0.1` is a source-compatible hardening patch for the stable `1.0.x` line. It
does not add endpoint families or change the public typed OpenBao API surface.

The release addresses post-`1.0.0` audit findings around TLS downgrade
configuration, root-only trust preservation, bootstrap comparison discipline,
and documented residual HTTP-stack memory behavior.

## Security

- TLS floors below TLS 1.2 now fail before an HTTP client is built.
- TLS 1.2 configurations now require the `tls12-acknowledged` feature even when
  configured through the generic `OpenBaoConfig::min_tls_version` setter.
- `OpenBaoConfig::add_root_certificate` now preserves root-only trust mode when
  called after `OpenBaoConfig::only_root_certificates`, avoiding silent trust
  expansion back to platform roots.
- KV v2 bootstrap secret convergence now compares every desired key instead of
  short-circuiting on the first mismatch.
- `SECURITY.md` now explicitly records that token and namespace header values
  are copied into HTTP-stack header structures that are not zeroized on drop.
- `deny.toml` now documents why rand/getrandom duplicate-version warnings remain
  visible instead of being skipped.

## Compatibility

- Normal `1.0.0` callers should not need code changes.
- Applications that intentionally set `min_tls_version(TLS_1_2)` must enable
  `tls12-acknowledged`.
- Applications that previously relied on calling `add_root_certificate` after
  `only_root_certificates` to re-enable platform roots must choose that wider
  trust mode explicitly by not entering root-only mode.

## Validation

- `cargo fmt --all`
- `cargo check`
- `cargo test --all-targets`
- `cargo test --all-targets --all-features`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo deny check`
- `scripts/validate-release-metadata.sh`

`v1.0.1` was tagged after GitHub CI and CodeQL were green for the release
commit.
