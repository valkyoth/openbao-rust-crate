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
cross-certification helpers.

## Added

- Started the `0.13.0` release line.
- Named-issuer PKI sign-intermediate helpers for multi-issuer hierarchy
  workflows.
- Revoked certificate list, revocation queue list, and detailed certificate
  list helpers.
- Issuer CRL resign and delta CRL rotation helpers.
- PKI CEL role list/read/write/patch/delete plus CEL issue/sign helpers, with
  a version-stability note for this newer OpenBao feature.
- Operator-gated sign-self-issued, intermediate cross-sign, and
  sign-revocation-list helpers.
- Endpoint matrix update for the implemented `0.13.0` PKI rows, bringing
  strict typed coverage to `572/643` (`89.0%`).

## Planned Scope

- No remaining `0.13.0` PKI specialized-flow implementation rows are open.
- OCSP GET/POST rows documented as external OCSP responder protocol endpoints
  for OCSP/TLS client tooling.

## Security Notes

- Cross-certification and sign-verbatim style hierarchy operations remain
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
