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
- `decision`: the row needs implementation, rejection, raw-wrapper policy, or external-client policy before `1.0.0`.

## Summary

- Total documented endpoint rows: `643`
- Strict typed coverage: `456/643` (70.9%)
- Typed plus partial coverage: `457/643` (71.1%)
- Addressed by typed, partial, raw, or external policy: `475/643` (73.9%)
- Open decisions before `1.0.0`: `168`

| Status | Count |
| --- | ---: |
| `typed` | 412 |
| `typed-gated` | 44 |
| `partial` | 1 |
| `raw` | 9 |
| `external` | 9 |
| `decision` | 168 |

## Area Totals

| Area | Total | Typed | Typed gated | Partial | Raw | External | Decision | Strict % |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `auth` | 105 | 93 | 0 | 1 | 9 | 0 | 2 | 88.6% |
| `secret` | 347 | 211 | 0 | 0 | 0 | 9 | 127 | 60.8% |
| `system` | 191 | 108 | 44 | 0 | 0 | 0 | 39 | 79.6% |

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
| [/api-docs/secret/identity/oidc-provider/](https://openbao.org/api-docs/secret/identity/oidc-provider/) | 0 | 0 | 0 | 0 | 3 | 18 |
| [/api-docs/secret/identity/tokens/](https://openbao.org/api-docs/secret/identity/tokens/) | 0 | 0 | 0 | 0 | 0 | 14 |
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
- Identity OIDC admin/discovery/token/introspection rows and MFA management are planned for `0.10.0`.
- Named-provider OIDC browser protocol rows (`authorize`, `token`, `userinfo`) are classified as `external` because they belong to a dedicated OIDC client library.
- `sys/mfa/validate` is planned for `0.10.0` because MFA-enforced login flows cannot complete without it.
- Transit import/BYOK, wrapping-key, cache/config, CSR/certificate, and soft-delete rows are planned for `0.11.0`.
- PKI advanced issuer/root/public-read rows are planned for `0.12.0`; PKI specialized CEL/sign-verbatim/OCSP/ACME-boundary rows are planned for `0.13.0`.
- System generate-root/recovery-token, decode-token, password policies, monitor, internal inspection, resultant ACL, legacy recovery rekey, and lease tidy are planned for `0.14.0`.
- `0.15.0` is the closure release where no endpoint row may remain `decision`.

Regenerate with:

```sh
python3 scripts/generate_openbao_endpoint_matrix.py
```
