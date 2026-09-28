# OpenBao 2.7.0 Remaining Behavior Review

Checkpoint 09 is in progress, based on `e8d2402`. The checkpoint 08 pentest and
GitHub checks passed, including closure of the test-harness CodeQL findings.
No 2.7 profile is promoted, and neither workflow security block is lifted.

## Exact Source Review

The local source checkout reports tagged commit
`ca305a02daa68b203325daa1b25c18d7a252d4b3`. The staged adjacent API delta has 189
records; those records do not capture all behavior changes in the release.
This review supplements the checkpoint 02 inventory, not replaces it.

| Item | Finding / checkpoint 09 work |
| --- | --- |
| OCI digest and default command | Declarative server configuration changes, not optional SHA-256/command fields on catalog HTTP registration. `internal/vault/logical_system.go::handlePluginCatalogUpdate` still rejects missing SHA-256 and command, and requires a decoded 32-byte digest. Keep SDK registration validation. Server provisioning is not an SDK download/execution feature. |
| Plugin prune | `internal/command/plugin_prune.go` is local configuration/storage administration. Do not invent an HTTP route. |
| Latest plugin selection | `internal/vault/plugin_catalog.go` recognizes `latest`. Review existing mount/auth option serialization and version guards before claiming coverage. This is not verification of any external plugin artifact. |
| Sanitized configuration | Existing `sanitized_config_state_json` accommodates additive JSON fields. Verify the new server fields live; do not infer their presence from decoding success. |
| Envoy certificate decoder | `internal/http/handler.go` and `internal/http/util.go` implement listener-side XFCC decoding. This is not a cert-auth role/config field. Do not add an SDK header-spoofing path; server administrators own trusted proxy configuration. |
| Wrapping-token revoke-self | `internal/vault/request_handling.go` changes token handling for the existing route. Verify consumption and subsequent rejection live; do not add automatic retries. |
| Raw backup reads | Review protected storage paths and test only disposable backups, preserving operator gates and secret-aware results. No raw access privilege is widened by this review. |
| MFA TOTP | `internal/vault/login_mfa.go` returns `url` and `barcode`; existing `IdentityMfaTotpSecret` stores both as secrets. The staged documentation field delta adds the already-modeled admin-destroy method/entity IDs. Generation/destruction behavior still needs live verification. |
| Workflow CAS | Handler now passes the supplied CAS to the store. Require exact-version adversarial evidence before adding a version-scoped SDK exception. See below. |
| Workflow prefix listing | The tagged handler reads `data.Get("parent").(string)` although its route declares `path`, not `parent`. Source review does not justify lifting the independent prefix block. Keep the block; any live diagnostic is separate from CAS evidence. |
| Remaining inventory | Reconcile all staged operation/schema/documentation deltas and the six recovered historical route identities before checkpoint 10. No aggregate 100% coverage claim is made here. |

## 09a Workflow CAS Evidence

`internal/vault/logical_system_workflows.go::handleWorkflowsUpdate` uses
`GetOk("cas")`, which preserves an explicitly supplied zero in the tagged
`sdk/framework/field_data.go`. The store acquires its lock before reading the
existing entry and checking CAS. `-1` means create-only; a supplied nonnegative
version must match an existing entry. The existing or desired `cas_required`
flag requires CAS, preventing omission from clearing that requirement.

`scripts/openbao_2_7_workflow_cas.py` stages a constrained, disposable server
using the signed image and existing certificate-verified TLS 1.3 harness. It
checks absent-entry zero/positive rejection, create-only semantics, missing,
zero, stale and future CAS, full readback after rejection, matching updates,
required-to-optional transitions, two simultaneous writes with exactly one
winner, and delete/recreate. It does not execute the workflows. It rejects
unexpected errors instead of treating arbitrary failures as CAS enforcement.

The fixture emits a report only after successful checks and cleanup. Input
hashes include its implementation, shared transport/harness and `src/sys.rs`.
Credentials remain out of arguments, logs and reports; Python-managed copies
are not claimed to be sanitizing allocations. The report explicitly sets
`sdk_cas_enabled`, `prefix_listing_verified` and `routable` to false. A passing
Python fixture is not public SDK dispatch evidence.

Run as the repository operator:

```sh
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_2_7_workflow_cas.py
```

The live run passed. Its report is retained in
`compat/onboarding/2.7.0/workflow-cas-tls.json`, with an independent digest pin
and current-source validation in `scripts/verify_openbao_2_7_workflow_cas.py`.
Offline regression tests reject modified claims, missing or changed source
hashes, altered report bytes and noncanonical encoding. They also exercise ignored CAS,
mutation on rejection, multiple winners, strict response state and errors,
partial resource cleanup, redacted diagnostics and refusal to emit a report
after failure. Later 09 work can use this evidence when implementing a narrowly
version-gated CAS exception, with SDK request and historical-profile tests. Older server
profiles and prefix listing remain blocked regardless of this fixture result.
