# OpenBao Rust SDK 0.13.0 Release Notes

## Version

- Version: 0.13.0
- Status: in development
- Git tag: pending
- Git commit: pending
- License: MIT OR Apache-2.0

## Summary

`0.13.0` is the PKI specialized-flow line. Planned scope includes
revocation/CRL management, CEL role and CEL issue/sign helpers,
named-issuer hierarchy signing, delta-CRL rotation, and operator-gated
cross-sign helpers.

## Added

- Started the `0.13.0` release line.

## Planned Scope

- Revoked certificate list, revocation queue list, detailed certificate list,
  issuer CRL resign, and sign-revocation-list helpers.
- CEL role list/read/write/patch/delete plus CEL issue/sign helpers, with a
  version-stability note for this newer OpenBao feature.
- Named-issuer sign-intermediate and sign-self-issued variants for
  multi-issuer hierarchy and cross-signed trust-anchor workflows.
- Intermediate cross-sign helpers behind `operator-ops` plus
  `operator-ops-acknowledged`.
- Delta CRL rotation to complete the typed CRL rotation surface.
- OCSP GET/POST rows documented as external OCSP responder protocol endpoints
  for OCSP/TLS client tooling.

## Security Notes

- Cross-signing and sign-verbatim style hierarchy operations remain
  operator-only workflows and must stay behind the existing operator feature
  gates where they can bypass ordinary role constraints.
- CEL support should stay typed and bounded, but should carry a stability note
  because CEL roles are newer OpenBao PKI functionality.
- Public CA/certificate/CRL distribution and OCSP protocol endpoints stay
  outside the authenticated SDK boundary.

## Security And Stability Gate

- Release gate script: pending `scripts/release_0_13_gate.sh`
- OpenBao integration command: `scripts/openbao_integration.sh`
- Do not tag `v0.13.0` until local validation, external pentest feedback, and
  GitHub CI are green.
