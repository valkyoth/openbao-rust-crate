# OpenBao Rust SDK 2.1.2 Release Notes

## Version

- Version: 2.1.2
- Release date: 2026-07-25
- Release tag: `v2.1.2`, created only after every release gate passes
- Release commit: bound by the signed `v2.1.2` tag object
- License: MIT OR Apache-2.0

## Summary

`2.1.2` adds exact, fail-closed compatibility with OpenBao `2.6.1` while
preserving every historical profile from `2.0.0` through `2.6.0`. The release
adds typed ACL policy PATCH support and enables acknowledged JWT CEL role PATCH
only where the selected OpenBao profile has the upstream constraint-
preservation fix.

The generated compatibility inventory contains 691 operation identities, 23
exact profiles, and 15,893 operation/profile cells. Exact OpenBao `2.6.1`
resolves all 689 documented operations: 594 typed, 93 typed-gated, and two
security-blocked.

## OpenBao 2.6.1

- Locked the exact `v2.6.1` source commit, OCI index and amd64 image digests,
  signature bundle, provenance, tagged documentation, and normalized runtime
  OpenAPI snapshots.
- Recorded the append-only `2.6.0` to `2.6.1` contract diff.
- Added `Sys::patch_policy` for the new ACL policy PATCH operation. The typed
  request supports policy, expiration, TTL, CAS, and CAS-required updates
  while preserving omitted values.
- Added an acknowledged ACL PATCH variant for the identity-template override
  flags already protected on policy writes.
- Added `JwtAuthAdmin::patch_cel_role_acknowledged`. Exact `2.6.0` rejects the
  call locally because that server drops audience and leeway constraints;
  exact `2.6.1` permits it after the upstream fix.
- Deprecated the legacy unacknowledged CEL PATCH method and made it fail
  locally, preserving the security gate for all profiles.

## Security Hardening

- Dynamic and static database role credential configuration now uses bounded
  `SecretString` values. OpenBao permits
  `credential_config.ca_private_key` to contain a PEM CA private key, so the
  former ordinary string map was not an acceptable custody type.
- Database roles and ACL policy request/readback types redact credential
  configuration, statements, and policy documents from `Debug`.
- ACL policy PATCH rejects zero and negative CAS versions before transport.
- The security-support policy now follows the latest published stable SDK
  release without embedding a minor line that can become stale.

## Retained Security Blocks

OpenBao `2.6.1` does not fix every reviewed 2.6 defect:

- prefixed workflow LIST and SCAN remain blocked before transport because the
  server handlers remain unsafe;
- workflow writes selecting CAS or CAS-required remain blocked because those
  values are still discarded before storage.

These are explicit compatibility outcomes, not deferred SDK work.

## Compatibility Evidence

- All 23 digest-pinned OpenBao releases from `2.0.0` through `2.6.1` pass
  their own exact-profile live matrix.
- Every release runs eight representative core flows. Exact `2.6.0` and
  `2.6.1` additionally run six 2.6-specific flows.
- The `2.6.1` live checks verify ACL PATCH omission preservation and JWT CEL
  PATCH claim-constraint preservation.
- Rust `1.97.1` remains the primary release toolchain and Rust `1.90.0`
  remains the MSRV.

## Migration

Selecting `OpenBaoVersion::new(2, 6, 1)` or strict automatic detection enables
the reviewed 2.6.1 routes. Existing exact profiles retain their prior route,
field, and security-block behavior.

Callers using CEL role PATCH should move to
`patch_cel_role_acknowledged(...,
JwtCelClaimValidationAcknowledgement::all_authorization_claims_are_constrained_in_cel())`.
The call remains unavailable on exact 2.6.0. ACL policy replacement methods
are unchanged; use `Sys::patch_policy` only when preserving omitted policy
fields is required.

Database role callers must migrate `credential_config` values from `String`
to `SecretString` through `DatabaseCredentialConfig`. This deliberate
source-compatibility correction prevents PEM CA private keys from entering
ordinary, non-zeroizing role storage.

## Release Gate

Run `scripts/release_2_1_2_gate.sh`. Tagging additionally requires green
GitHub CI, CodeQL, the all-release compatibility workflow, and clean
independent pentests for the exact release commit.
