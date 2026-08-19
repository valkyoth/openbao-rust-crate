# OpenBao Rust SDK 2.1.4 Release Notes

## Version

- Version: 2.1.4
- Release date: 2026-08-19
- Release tag: `v2.1.4`, created only after every release gate passes
- Release commit: bound by the signed `v2.1.4` tag object
- License: MIT OR Apache-2.0

## Summary

`2.1.4` adds exact, fail-closed compatibility for OpenBao `2.6.2`. It does not
add or remove a public SDK endpoint: the adjacent API diff changes only
generated namespace-list metadata. The release instead locks the new server
artifacts, extends all generated compatibility evidence, and tests the
security-sensitive server fixes delivered by OpenBao 2.6.2.

The active inventory contains 691 operation identities across 24 exact
profiles and 16,584 operation/profile cells. Exact OpenBao `2.6.2` has 689
documented operations: 594 typed, 93 typed-gated, and two security-blocked.

## OpenBao 2.6.2 Evidence

- Locked the exact official source commit, lightweight tag, release timestamp,
  signed multi-platform OCI index, Linux AMD64 child digest, keyless Cosign
  identity, transparency-log verification, and embedded provenance subject.
- Captured tagged documentation and normalized runtime OpenAPI from the locked
  release. The extractor follows OpenBao's 2.6.2 source move to
  `website/content/docs/api` and rendered `/docs/api/` paths while preserving
  the historical paths in older immutable profiles.
- Reviewed the 2.6.1-to-2.6.2 diff: `GET /sys/namespaces` has generated
  operation/schema metadata changes, but no route or request/response field is
  added or removed.
- Regenerated the capability registry, Rust route table, response fixtures,
  exact-version support matrix, and all 16,584 contract cells.
- Ran the digest-pinned core flow against every exact OpenBao release from
  `2.0.0` through `2.6.2`; all 24 profiles passed.

## Security Regression Coverage

The exact `2.6.2` live profile additionally proves:

- a token-free workflow cannot dispatch an internal token-creating operation;
- PKI signing rejects a CSR IP SAN outside the role's
  `allowed_ip_sans_cidr`; and
- Transit verifies an HMAC generated with the non-default SHA2-384 algorithm.

These checks cover the release's workflow, PKI, and Transit fixes at the SDK's
real HTTP boundary. Passing compatibility tests is not a security endorsement
of historical OpenBao releases; deploy the newest reviewed server patch.

## Retained Security Blocks

OpenBao 2.6.2 still contains the previously reviewed workflow prefix LIST/SCAN
panic and workflow CAS-local-shadow defects. The SDK therefore continues to
reject prefixed LIST/SCAN dispatch and CAS-selected workflow writes locally for
exact `2.6.0`, `2.6.1`, and `2.6.2`. No fallback request or route probe is
performed.

JWT CEL PATCH remains unavailable on exact `2.6.0`, where omitted constraints
are not preserved. It remains available on exact `2.6.1` and `2.6.2` only
through the explicit claim-validation acknowledgement API.

## Dependency And CI Updates

- Updated `futures-core` from `0.3.33` to `0.3.34`.
- Updated transitive `h2` from `0.4.15` to `0.4.16`, the fixed release for
  `RUSTSEC-2026-0258`.
- Updated `taiki-e/install-action` from `2.85.10` to `2.86.3` with an immutable
  commit-SHA pin.
- Confirmed all other direct crates, CI cargo tools, and pinned GitHub Actions
  are current on the release date.
- Retained Rust `1.97.1` as the primary toolchain and Rust `1.90.0` as the
  checked MSRV.

## Migration

No application source migration is required. Strict automatic detection now
accepts `2.6.2`; exact-policy users may select
`OpenBaoVersion::new(2, 6, 2)`. Existing older exact profiles retain their
original routes, field rules, and security classifications.

## Release Gate

Run `scripts/release_2_1_4_gate.sh`. Tagging additionally requires green
GitHub CI, CodeQL, the all-release compatibility workflow, and clean
independent pentests for the exact release commit.
