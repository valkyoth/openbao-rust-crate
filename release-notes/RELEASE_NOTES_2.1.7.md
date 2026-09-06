# OpenBao Rust SDK 2.1.7 Release Notes

## Version

- Version: 2.1.7
- Release date: 2026-09-06
- Release tag: `v2.1.7`, created only after every release gate passes
- Release commit: bound by the signed `v2.1.7` tag object
- License: MIT OR Apache-2.0

## Summary

`2.1.7` moves the SDK's `SecretString` compatibility surface from upstream
`secrecy 0.10.3` to `sanitization-secrecy 2.1.0` and updates the core
`sanitization` dependency from `2.0.4` to `2.1.0`. Owned secret cleanup now
uses the same sanitization family as the SDK's native `SecretVec`, locked-token,
and HTTP-body storage.

The companion dependency is aliased locally as `secrecy`, preserving the
SDK's existing internal imports and the public `openbao::secrecy` path. Its
default features are disabled and only `serde` is enabled, so this SDK does not
request the optional `zeroize-interop` compatibility bridge.

OpenBao routes, compatibility profiles, request and response schemas, wire
formats, and feature acknowledgement boundaries are unchanged from `2.1.6`.
The immutable `taiki-e/install-action` pin is updated from `2.87.6` to
`2.87.7`; the freshness check reports all other direct crates, CI cargo tools,
and GitHub Actions current on the release date.

## Application Compatibility

Applications importing `SecretString` and `ExposeSecret` from `openbao`
continue to use the same source-level API. The provider is also available as
`openbao::sanitization_secrecy`.

The provider migration changes nominal type identity. Applications that
construct or pass an upstream `secrecy::SecretString` directly must instead
use `openbao::SecretString`, or alias `sanitization-secrecy` as `secrecy` in
their own manifest. The migration guide gives the exact dependency form.

The provider preserves the SDK-used behavior: construction from strings,
explicit `ExposeSecret` access, redacted `Debug`, sanitization on drop, and
Serde loading. Its `SecretString` deserializer rejects inputs above 1 MiB;
OpenBao endpoint-specific body and collection bounds continue to apply first.

## Verification

- All default and all-feature source targets compile with the new provider.
- A crates.io-retained package smoke test checks the explicit provider
  re-export, Serde construction, exposure, and debug redaction.
- The client-only `default-features = false, features = ["rustls-tls"]`
  configuration is warning-clean and enforced by Clippy with `-D warnings`;
  normal dead-code diagnostics remain active whenever an endpoint feature is
  selected.
- The temporary compile-time-only `syn 2`/`syn 3` dependency split is an
  explicit, major-line-limited policy exception. Generated package
  verification artifacts are removed before Rust cache cleanup so upstream
  cache-action diagnostics do not obscure CI results.
- Release checks verify that `Cargo.lock` contains `sanitization-secrecy 2.1.0`
  and no upstream package named `secrecy`.
- The root, fuzz, and standalone reqwest-unification lockfiles are refreshed.
- OpenBao's 24 immutable exact-release profiles and 16,584 version-contract
  cells remain unchanged and are reverified by the release gate.

## Release Gate

Run `scripts/release_2_1_7_gate.sh`. Tagging additionally requires green
GitHub CI, CodeQL, the all-release compatibility workflow, and clean
independent pentests for the exact release commit.
