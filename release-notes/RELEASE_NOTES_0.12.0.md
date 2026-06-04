# OpenBao Rust SDK 0.12.0 Release Notes

Status: in development.

Readiness: implementation is in progress. Do not tag until local release gates,
GitHub CI, and the external pentest report are green for the exact release
candidate.

## Version

- Version: 0.12.0
- Release date: pending
- Git tag: pending
- Git commit: pending
- License: MIT OR Apache-2.0

## Summary

`0.12.0` is the PKI Tier 1 multi-issuer and authority lifecycle line. The
planned scope is default issuer/key configuration, named-issuer issue/sign,
root rotation and replacement, standalone key generation, sign-verbatim
operator helpers, revoke-with-key, cluster and auto-tidy config, and
current-doc PKI struct-field expansion.

Remaining `0.12.0` planned work: the rest of the PKI Tier 1 implementation and
test coverage, documentation updates, local release gate, external pentest, and
GitHub CI validation.

## Added

- PKI default issuer and default key configuration read/write helpers for
  `/pki/config/issuers` and `/pki/config/keys`.
- Named-issuer PKI issue/sign helpers for
  `/pki/issuer/:issuer_ref/issue/:name` and
  `/pki/issuer/:issuer_ref/sign/:name`.
- PKI authority lifecycle helpers for root rotation, root replacement,
  multi-issuer root/intermediate generation, and standalone key generation.
- PKI cluster config, auto-tidy config, and revoke-with-key helpers.
- Endpoint matrix regeneration for the implemented default issuer/key config
  rows, named-issuer issue/sign rows, authority lifecycle rows, config rows,
  and revoke-with-key row, bringing strict typed coverage to `553/643`
  (`86.0%`).

## Planned Scope

- Operator-gated sign-verbatim helpers.
- Current OpenBao field expansion for PKI role, root/intermediate generation,
  CRL config, and tidy request/status types.
- Endpoint matrix regeneration after the Tier 1 rows are implemented.

## Security Notes

- Sign-verbatim helpers must remain behind `operator-ops` plus
  `operator-ops-acknowledged` because they bypass normal role constraints.
- Raw private key material must remain `SecretString` when any PKI response or
  request field can carry it.
- Public certificate, CSR, and CA material may remain `String` or byte buffers
  when OpenBao documents it as public material.
- The existing `Pki::delete_root(PkiRootDeletion::confirm())` decision remains
  the destructive default-root deletion boundary.

## Security And Stability Gate

- Release gate script: `scripts/release_0_12_gate.sh`
- OpenBao integration command: `scripts/openbao_integration.sh`
- Do not tag until external pentest feedback is reviewed and GitHub CI is
  green.
