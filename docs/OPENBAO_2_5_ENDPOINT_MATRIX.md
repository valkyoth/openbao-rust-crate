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
- `decision`: the row needs implementation, rejection, or movement to the optional `0.10.0` buffer before `1.0.0`.

## Summary

- Total documented endpoint rows: `626`
- Strict typed coverage: `457/626` (73.0%)
- Typed plus partial coverage: `458/626` (73.2%)
- Addressed by typed, partial, raw, or external policy: `473/626` (75.6%)
- Open decisions before `1.0.0`: `153`

| Status | Count |
| --- | ---: |
| `typed` | 413 |
| `typed-gated` | 44 |
| `partial` | 1 |
| `raw` | 9 |
| `external` | 6 |
| `decision` | 153 |

## Area Totals

| Area | Total | Typed | Typed gated | Partial | Raw | External | Decision | Strict % |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `auth` | 105 | 93 | 0 | 1 | 9 | 0 | 2 | 88.6% |
| `secret` | 329 | 211 | 0 | 0 | 0 | 6 | 112 | 64.1% |
| `system` | 192 | 109 | 44 | 0 | 0 | 0 | 39 | 79.7% |

## Pages With Non-Typed Rows

| Page | Typed | Typed gated | Partial | Raw | External | Decision |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| [/api-docs/auth/approle/](https://openbao.org/api-docs/auth/approle/) | 15 | 0 | 0 | 9 | 0 | 0 |
| [/api-docs/auth/token/](https://openbao.org/api-docs/auth/token/) | 16 | 0 | 1 | 0 | 0 | 2 |
| [/api-docs/secret/identity/mfa/duo/](https://openbao.org/api-docs/secret/identity/mfa/duo/) | 0 | 0 | 0 | 0 | 0 | 4 |
| [/api-docs/secret/identity/mfa/login-enforcement/](https://openbao.org/api-docs/secret/identity/mfa/login-enforcement/) | 0 | 0 | 0 | 0 | 0 | 4 |
| [/api-docs/secret/identity/mfa/okta/](https://openbao.org/api-docs/secret/identity/mfa/okta/) | 0 | 0 | 0 | 0 | 0 | 4 |
| [/api-docs/secret/identity/mfa/pingid/](https://openbao.org/api-docs/secret/identity/mfa/pingid/) | 0 | 0 | 0 | 0 | 0 | 4 |
| [/api-docs/secret/identity/mfa/totp/](https://openbao.org/api-docs/secret/identity/mfa/totp/) | 0 | 0 | 0 | 0 | 0 | 7 |
| [/api-docs/secret/identity/oidc-provider/](https://openbao.org/api-docs/secret/identity/oidc-provider/) | 0 | 0 | 0 | 0 | 0 | 17 |
| [/api-docs/secret/pki/](https://openbao.org/api-docs/secret/pki/) | 44 | 0 | 0 | 0 | 4 | 60 |
| [/api-docs/secret/ssh/](https://openbao.org/api-docs/secret/ssh/) | 22 | 0 | 0 | 0 | 2 | 0 |
| [/api-docs/secret/transit/](https://openbao.org/api-docs/secret/transit/) | 19 | 0 | 0 | 0 | 0 | 12 |
| [/api-docs/system/config-ui/](https://openbao.org/api-docs/system/config-ui/) | 0 | 0 | 0 | 0 | 0 | 4 |
| [/api-docs/system/generate-recovery-token/](https://openbao.org/api-docs/system/generate-recovery-token/) | 0 | 0 | 0 | 0 | 0 | 4 |
| [/api-docs/system/generate-root/](https://openbao.org/api-docs/system/generate-root/) | 0 | 0 | 0 | 0 | 0 | 4 |
| [/api-docs/system/in-flight-req/](https://openbao.org/api-docs/system/in-flight-req/) | 0 | 0 | 0 | 0 | 0 | 1 |
| [/api-docs/system/inspect/request/](https://openbao.org/api-docs/system/inspect/request/) | 0 | 0 | 0 | 0 | 0 | 1 |
| [/api-docs/system/inspect/router/](https://openbao.org/api-docs/system/inspect/router/) | 0 | 0 | 0 | 0 | 0 | 4 |
| [/api-docs/system/internal-counters/](https://openbao.org/api-docs/system/internal-counters/) | 0 | 0 | 0 | 0 | 0 | 2 |
| [/api-docs/system/internal-ui-resultant-acl/](https://openbao.org/api-docs/system/internal-ui-resultant-acl/) | 0 | 0 | 0 | 0 | 0 | 1 |
| [/api-docs/system/leases/](https://openbao.org/api-docs/system/leases/) | 8 | 0 | 0 | 0 | 0 | 1 |
| [/api-docs/system/mfa-validate/](https://openbao.org/api-docs/system/mfa-validate/) | 0 | 0 | 0 | 0 | 0 | 1 |
| [/api-docs/system/monitor/](https://openbao.org/api-docs/system/monitor/) | 0 | 0 | 0 | 0 | 0 | 1 |
| [/api-docs/system/policies-password/](https://openbao.org/api-docs/system/policies-password/) | 0 | 0 | 0 | 0 | 0 | 6 |
| [/api-docs/system/rekey-recovery-key/](https://openbao.org/api-docs/system/rekey-recovery-key/) | 0 | 0 | 0 | 0 | 0 | 9 |

## Required Follow-Up

- Token `create-orphan` and `renew-accessor` need dedicated helper decisions.
- AppRole delegated per-property endpoints need a final raw-vs-typed decision.
- Identity OIDC provider/token and MFA management needs a pre-`1.0.0` decision.
- Transit import/BYOK, wrapping-key, cache/config, CSR/certificate, and soft-delete rows need pre-`1.0.0` decisions.
- PKI advanced issuer/root/CEL/authority rows need implementation or explicit rejection.
- System generate-root/recovery-token, decode-token, password policies, monitor, internal inspection, resultant ACL, MFA validate, legacy recovery rekey, and lease tidy need decisions.

Regenerate with:

```sh
python3 scripts/generate_openbao_endpoint_matrix.py
```
