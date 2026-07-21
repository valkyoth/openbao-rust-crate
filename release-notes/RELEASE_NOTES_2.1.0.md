# OpenBao Rust SDK 2.1.0 Release Notes

## Version

- Version: 2.1.0
- Release date: 2026-07-21
- Git tag: `v2.1.0`
- Git commit: see the signed `v2.1.0` tag object
- License: MIT OR Apache-2.0

## Summary

`2.1.0` adds exact, fail-closed OpenBao `2.6.0` compatibility while preserving
the 21 historical profiles from `2.0.0` through `2.5.5`. The active contract
contains 690 stable operation identities, 22 exact profiles, and 15,180
explicit operation/profile cells. Every locked OpenBao image passes its own
exact-profile representative live flow.

The OpenBao `2.6.0` profile resolves all 688 documented operations: 592 are
typed, 93 are typed-gated, and three are security-blocked because the released
server handlers are unsafe. There is no planned, pending, raw, external, or
deferred operation in the profile.

## OpenBao 2.6 APIs

- Added sealable namespace creation, status, seal, unseal, and confirmed
  sealed-namespace deletion.
- Added workflow management, unprefixed LIST/SCAN, bounded execution, and
  separately acknowledged trace and unauthenticated execution.
- Routed root-token generation through the exact release-specific endpoint.
- Added JWT CEL role/login, Kubernetes JWT provider, userpass bcrypt-hash, and
  Kerberos PAC-decoding contracts.
- Added ACL, PKI, and SSH identity-template override readback with explicitly
  acknowledged write paths.
- Added semver-safe `*Details` reads for changed CORS, lease, TOTP,
  seal-status, unseal-status, version-history, Kerberos, ACL, PKI, and SSH
  responses. Explicit 2.6 write methods retain exact-version validation.

## Security

- JWT CEL role writes require a named
  `JwtCelClaimValidationAcknowledgement`. `bound_audiences` does not reject a
  signed JWT that omits `aud`; the CEL program must require and constrain every
  authorization-relevant claim.
- JWT CEL PATCH is blocked for exact `2.6.0` because the server drops audience
  and leeway constraints. Use full role replacement.
- CEL expressions use `SecretString` storage and explicit accessors. CEL login
  and role operations decode successful bodies from sanitizing storage and
  discard failure bodies because OpenBao errors can echo policy source.
- Capability resolution requires an explicit exact, auth-mount, secret-mount,
  or validated Identity binding before dispatch. Mismatched registry/wire
  paths and custom Identity mounts without an operation tail fail locally.
- Monitor streaming yields after at most 64 immediately ready transport chunks
  per executor poll, including empty chunks.
- Prefixed workflow LIST and SCAN are blocked because exact `2.6.0` can panic
  while processing those routes. Unprefixed listing remains supported.
- Workflow CAS-selected writes fail locally because exact `2.6.0` does not
  propagate the CAS value to storage. Workflow writes remain single-shot.
- Namespace shares, workflow documents and output, password hashes, tokens,
  accessors, and topology-bearing response values retain bounded,
  secret-aware decoding and redacted `Debug` behavior.

## OpenSSL Scope

OpenSSL is a direct development dependency so the live integration test can
generate valid RS256 JWTs. Cargo does not compile development dependencies into
a downstream application's normal build. The default Rustls feature set does
not compile OpenSSL.

OpenSSL can still be a production dependency when an application explicitly
enables an OpenSSL-using feature. The optional `transit-import` software BYOK
helper uses OpenSSL deliberately, and the acknowledged `native-tls` backend
may use the platform OpenSSL stack. Those existing opt-in security boundaries
are unchanged.

## Compatibility Evidence

- All 22 digest-pinned OpenBao releases from `2.0.0` through `2.6.0` passed
  their own exact profile.
- Every release runs eight representative core flows; exact `2.6.0` runs six
  additional focused flows.
- Historical profile records remain unchanged; regenerated aggregate hashes
  bind the expanded 2.6 test definition and evidence set.
- Rust `1.97.1` is the primary release toolchain and Rust `1.90.0` remains the
  locked all-target, all-feature MSRV.

## Upgrade Notes

The release is source-compatible with `2.0.2`; `cargo-semver-checks` passes all
196 applicable minor-release checks. Existing constructible response and
request structs retain their 2.0 field sets, while additive OpenBao 2.6
metadata is exposed through named detail types and methods. Applications that
deploy OpenBao `2.6.0` should select strict automatic detection or the exact
`2.6.0` profile. Existing applications selecting older exact profiles retain
their historical dispatch behavior.

Review new acknowledgement features before enabling workflow traces,
unauthenticated workflows, identity-template overrides, or operator
operations. See `docs/MIGRATION_GUIDE.md`, `SECURITY.md`, and
`docs/OPENBAO_VERSION_SELECTION.md`.

## Release Gate

Run `scripts/release_2_1_gate.sh`. Tagging additionally requires green GitHub
CI, CodeQL, the all-release compatibility workflow, and clean independent
pentests for the exact release commit.
