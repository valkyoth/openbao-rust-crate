# OpenBao 2.5.x Endpoint Coverage Matrix

Generated on 2026-06-03 from the official OpenBao 2.5.x API documentation.
The full endpoint row matrix is stored in
`docs/openbao-2.5-endpoint-matrix.csv`.

Sources:

- https://openbao.org/api-docs/auth/
- https://openbao.org/api-docs/secret/
- https://openbao.org/api-docs/system/

## Status Semantics

- `typed`: a first-class typed helper exists in the crate.
- `typed-gated`: a first-class typed helper exists behind explicit operator feature gates.
- `partial`: a typed helper exists, but the documented row differs in method, variant, or exact endpoint shape.
- `raw`: the crate intentionally relies on `Client::request_json` for this row.
- `external`: the workflow is intentionally delegated to an external protocol/client.
- `rejected`: the endpoint is intentionally not covered by this SDK.
- `planned`: the row has a final pre-`1.0.0` implementation decision but is not implemented yet.
- `decision`: the row needs implementation, rejection, raw-wrapper policy, or external-client policy before `1.0.0`.

## Summary

- Total documented endpoint rows: `644`
- Strict typed coverage: `526/644` (81.7%)
- Typed plus partial coverage: `527/644` (81.8%)
- Addressed by typed, partial, raw, external, or rejected policy: `572/644` (88.8%)
- Planned implementation rows before `1.0.0`: `72`
- Open owner decisions before `1.0.0`: `0`

| Status | Count |
| --- | ---: |
| `typed` | 481 |
| `typed-gated` | 45 |
| `partial` | 1 |
| `raw` | 0 |
| `external` | 33 |
| `rejected` | 12 |
| `planned` | 72 |
| `decision` | 0 |

## Area Totals

| Area | Total | Typed | Typed gated | Partial | Raw | External | Rejected | Planned | Decision | Strict % |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `auth` | 105 | 104 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 99.0% |
| `secret` | 348 | 267 | 1 | 0 | 0 | 33 | 0 | 47 | 0 | 77.0% |
| `system` | 191 | 110 | 44 | 0 | 0 | 0 | 12 | 25 | 0 | 80.6% |

## Pages With Non-Typed Rows

| Page | Typed | Typed gated | Partial | Raw | External | Rejected | Planned | Decision |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| [/api-docs/auth/token/](https://openbao.org/api-docs/auth/token/) | 18 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| [/api-docs/secret/identity/oidc-provider/](https://openbao.org/api-docs/secret/identity/oidc-provider/) | 18 | 0 | 0 | 0 | 3 | 0 | 0 | 0 |
| [/api-docs/secret/pki/](https://openbao.org/api-docs/secret/pki/) | 44 | 1 | 0 | 0 | 28 | 0 | 35 | 0 |
| [/api-docs/secret/ssh/](https://openbao.org/api-docs/secret/ssh/) | 22 | 0 | 0 | 0 | 2 | 0 | 0 | 0 |
| [/api-docs/secret/transit/](https://openbao.org/api-docs/secret/transit/) | 19 | 0 | 0 | 0 | 0 | 0 | 12 | 0 |
| [/api-docs/system/config-ui/](https://openbao.org/api-docs/system/config-ui/) | 0 | 0 | 0 | 0 | 0 | 4 | 0 | 0 |
| [/api-docs/system/generate-recovery-token/](https://openbao.org/api-docs/system/generate-recovery-token/) | 0 | 0 | 0 | 0 | 0 | 0 | 4 | 0 |
| [/api-docs/system/generate-root/](https://openbao.org/api-docs/system/generate-root/) | 0 | 0 | 0 | 0 | 0 | 0 | 4 | 0 |
| [/api-docs/system/in-flight-req/](https://openbao.org/api-docs/system/in-flight-req/) | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| [/api-docs/system/inspect/request/](https://openbao.org/api-docs/system/inspect/request/) | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| [/api-docs/system/inspect/router/](https://openbao.org/api-docs/system/inspect/router/) | 0 | 0 | 0 | 0 | 0 | 4 | 0 | 0 |
| [/api-docs/system/internal-counters/](https://openbao.org/api-docs/system/internal-counters/) | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 |
| [/api-docs/system/internal-ui-resultant-acl/](https://openbao.org/api-docs/system/internal-ui-resultant-acl/) | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| [/api-docs/system/monitor/](https://openbao.org/api-docs/system/monitor/) | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| [/api-docs/system/policies-password/](https://openbao.org/api-docs/system/policies-password/) | 0 | 0 | 0 | 0 | 0 | 0 | 6 | 0 |
| [/api-docs/system/rekey-recovery-key/](https://openbao.org/api-docs/system/rekey-recovery-key/) | 0 | 0 | 0 | 0 | 0 | 0 | 9 | 0 |

## Required Follow-Up

- Identity OIDC token backend config, signing key CRUD/rotate, role CRUD/list,
  signed token generation, token introspection, discovery metadata, default
  JWKS reads, OIDC provider/scope/client/assignment admin, named-provider
  discovery, named-provider JWKS, MFA method management, MFA TOTP
  generation/admin actions, and MFA login enforcement helpers are implemented
  in `0.10.0`.
- Named-provider OIDC browser protocol rows (`authorize`, `token`, `userinfo`) are classified as `external` because they belong to a dedicated OIDC client library.
- `sys/mfa/validate` is implemented in `0.10.0` because MFA-enforced login flows cannot complete without it.
- Transit wrapping-key, import/import-version, BYOK export, soft-delete/restore, cache/global config, CSR, and certificate install rows are planned for `0.11.0`; an optional pre-`1.0.0` `transit-import` wrapping helper is planned behind feature-gated `rsa` and `aes-gcm` dependencies.
- PKI Tier 1 multi-issuer/config/root/sign-verbatim/revoke-with-key and current-doc struct-field completion are planned for `0.12.0`; Tier 2 revocation/CEL/cross-sign/delta-CRL work is planned for `0.13.0`; unauthenticated public CA/CRL/cert and OCSP protocol reads are classified as `external`.
- System generate-root/recovery-token, decode-token, password policies, resultant ACL, legacy recovery-key rekey, and in-flight request inspection are planned for `0.14.0`; config-ui, monitor streaming, internal router inspection, request inspection, and internal counters are classified as `rejected`.
- `0.15.0` is the closure release where planned endpoint rows are implemented or intentionally reclassified before `1.0.0`.

Regenerate with:

```sh
python3 scripts/generate_openbao_endpoint_matrix.py
```
