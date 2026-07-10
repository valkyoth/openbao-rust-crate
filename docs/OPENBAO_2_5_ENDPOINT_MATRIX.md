# OpenBao 2.5.5 Exact Contract Matrix

Generated offline from the exact tagged OpenBao `v2.5.5` source commit
`028992583c693c4de6350b8aa52ff85e30375a99` and the normalized OpenAPI snapshot captured from the
locked `2.5.5` image. The machine-readable source of truth is
`docs/openbao-2.5-contract-matrix.json`; the CSV is a review index.

## Corrected Inventory

- Raw tagged documentation table rows: `651`.
- Unique documented rows: `644`.
- Expanded method/path operations: `663`.
- The prior 643-row report omitted `HEAD /sys/health`; 644 is the
  corrected tagged-source row count.

## Status Semantics

- `unverified`: an earlier typed claim exists, but no exact helper, field,
  security, transport, and test evidence has been linked yet.
- `confirmed-gap`: the row was previously non-strict, was proven falsely
  typed by the full-support audit, or was omitted from the old matrix.
- `typed` and `typed-gated`: final statuses accepted only after a public
  helper, complete field review, secret classification, and test evidence
  are present. No row receives either status in this baseline audit.

This is an implementation backlog, not a support percentage or a
compatibility certification.

## Review Summary

| Status | Rows |
| --- | ---: |
| `unverified` | 565 |
| `confirmed-gap` | 79 |
| `typed` | 0 |
| `typed-gated` | 0 |

## Area Summary

| Area | Rows | Unverified | Confirmed gap |
| --- | ---: | ---: | ---: |
| `auth` | 105 | 104 | 1 |
| `secret` | 347 | 307 | 40 |
| `system` | 192 | 154 | 38 |

## OpenAPI Reconciliation

| Match state | Expanded operations |
| --- | ---: |
| `absent` | 41 |
| `ambiguous` | 11 |
| `exact-pattern` | 611 |

An absent or ambiguous OpenAPI match is retained as an explicit review
item; it is never converted into typed coverage. Tagged documentation
remains authoritative for inventory identity.

## Verification

```sh
python3 scripts/generate_openbao_contract_matrix.py --verify
python3 scripts/generate_openbao_contract_matrix.py --self-test
```
