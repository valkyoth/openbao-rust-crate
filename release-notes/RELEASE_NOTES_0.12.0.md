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
implemented scope is default issuer/key configuration, named-issuer
issue/sign, root rotation and replacement, standalone key generation,
sign-verbatim operator helpers, revoke-with-key, cluster and auto-tidy config,
and current-doc PKI struct-field expansion.

The `0.12.0` PKI Tier 1 implementation and local documentation pass are
complete. Remaining release work is the local release gate, external pentest,
and GitHub CI validation for the exact release candidate.

## Added

- PKI default issuer and default key configuration read/write helpers for
  `/pki/config/issuers` and `/pki/config/keys`.
- Named-issuer PKI issue/sign helpers for
  `/pki/issuer/:issuer_ref/issue/:name` and
  `/pki/issuer/:issuer_ref/sign/:name`.
- PKI authority lifecycle helpers for root rotation, root replacement,
  multi-issuer root/intermediate generation, and standalone key generation.
- PKI cluster config, auto-tidy config, and revoke-with-key helpers.
- Operator-gated PKI sign-verbatim helpers for default and explicit issuers.
- Current OpenBao field expansion for PKI role, URL, root/intermediate
  generation, CRL config, and tidy request/status types.
- Endpoint matrix regeneration for the implemented default issuer/key config
  rows, named-issuer issue/sign rows, authority lifecycle rows, config rows,
  revoke-with-key row, and gated sign-verbatim rows, bringing strict typed
  coverage to `555/643` (`86.3%`).
- Binary raw-byte response content-type validation when callers supply an
  expected `Accept` header.

## Planned Scope

- No remaining `0.12.0` PKI Tier 1 implementation rows are open. Remaining
  planned endpoint rows are assigned to later releases in the endpoint matrix.

## Security Notes

- Sign-verbatim helpers must remain behind `operator-ops` plus
  `operator-ops-acknowledged` because they bypass normal role constraints.
- Raw private key material must remain `SecretString` when any PKI response or
  request field can carry it.
- Public certificate, CSR, and CA material may remain `String` or byte buffers
  when OpenBao documents it as public material.
- The existing `Pki::delete_root(PkiRootDeletion::confirm())` decision remains
  the destructive default-root deletion boundary.
- `radius-auth` is no longer part of default features and now requires
  `radius-auth-acknowledged` because legacy RADIUS relies on MD5-based
  authenticators.
- Explicit retry backoff now includes bounded jitter by default to avoid
  synchronized retry waves after temporary OpenBao outages.
- LDAP auth path names reject spaces and LDAP filter metacharacters before
  request dispatch.
- Release metadata validation fails if tracked files contain PEM private-key
  headers, and `build.rs` warns when `sensitive-http-test-only` is compiled.

## Security And Stability Gate

- Release gate script: `scripts/release_0_12_gate.sh`
- OpenBao integration command: `scripts/openbao_integration.sh`
- Do not tag until external pentest feedback is reviewed and GitHub CI is
  green.
