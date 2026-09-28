# OpenBao 2.7.0 Onboarding For openbao 2.2.0

Status: checkpoints 01 through 08 passed pentest; checkpoint 08 follow-up `e8d2402` is green on GitHub with both CodeQL alerts closed. Checkpoint 09 pentest follow-up hardens grouped backup decoding; refreshed source-bound evidence is verified and follow-up review is pending;
remaining checkpoints are required before
release. The active supported server range remains 2.0.0 through 2.6.3.
Do not publish 2.2.0 or promote 2.7.0 routing from this checkpoint.

Checkpoint 03a records external-plugin availability and refreshes the local
development fixture. The approved checkpoint 03 scope now excludes LDAP
auth/secrets, Kerberos and RADIUS on 2.7 until separately verified artifacts
become available (target 2.2.1 or later). Older built-in profiles remain supported.
Staged 2.7 TLS fixture validation passed, including network/resource isolation,
negative TLS cases, initialization, built-in Transit and absent-plugin checks.
Checkpoint 03 is complete under the approved external-plugin exclusions.
See [the checkpoint 03 review](OPENBAO_2_7_0_PLUGIN_REVIEW.md).

## Source Baseline

- [Official release](https://github.com/openbao/openbao/releases/tag/v2.7.0),
  published 2026-09-23T17:39:54Z.
- Reviewed tag commit: `ca305a02daa68b203325daa1b25c18d7a252d4b3`.
- Predecessor: OpenBao 2.6.3, not the 2.7 beta.
- Tagged API root: `website/content/docs/api`.
- `compat/onboarding/2.7.0/source-inventory.json` locks all 122 API source
  files and the 14 added/modified files relative to the locked 2.6.3 snapshot.
  This is source evidence only, not image-signature or runtime evidence.
- Reproduce with `/usr/bin/python3 -E -s -S -B scripts/openbao_2_7_source_inventory.py --write
  --source-repository /path/to/openbao`; the repository must contain the exact
  official tag. The generator refuses output differing from its reviewed hash.
- Offline verification: `/usr/bin/python3 -E -s -S -B scripts/openbao_2_7_source_inventory.py
  --verify` and the corresponding `--self-test`.

The existing documentation extractor accepts slash-separated HTTP methods but
not the comma-separated method cells used by external-key config/key writes.
Those APIs also group multiple operations under a level-two heading. Checkpoint
02 adds a separately versioned extractor and rebaselines 2.6.3 in the staging
directory without regenerating historical evidence. Its capture scope and
discrepancies are in [OPENBAO_2_7_0_REVIEW.md](OPENBAO_2_7_0_REVIEW.md).

## Commit Checkpoints

Each checkpoint is a reviewable commit on main. Run its regression tests,
record its commit range for pentesting, and resolve findings before proceeding.
All checkpoints target the same 2.2.0 release, not intermediate releases.

| Commit | Goal | Required verification and stop condition |
| --- | --- | --- |
| 01 | Development baseline and source inventory | Version manifests/locks agree on 2.2.0; locked source inventory and tamper tests pass; all 25 active profiles remain unchanged and 2.7.0 remains rejected. |
| 02 | Signed artifacts and complete staged API evidence | Verify exact image signature identity, index/child/provenance relationships; capture bounded runtime OpenAPI; fix comma-separated method and nested operation parsing in a versioned extractor; diff all fields, methods, routes and responses against 2.6.3. Record source/runtime/doc discrepancies explicitly. No active routing promotion. |
| 03 | External-plugin exclusions and server-fixture compatibility | Retain older built-in LDAP auth/secrets, Kerberos and RADIUS profiles. Explicitly exclude those engines on 2.7 until separately verified plugin artifacts/contracts are available; distinguish server plugin-not-installed from SDK exclusion. Validate staged 2.7 fixtures with supported storage and TLS/container checks. The historical integration fixture already uses `inmem` and local development uses Raft. No silent mount skips or server-version-only plugin support claims. |
| 04 | External-key system administration | Typed config/key/grant CRUD, LIST and PATCH, built-in Transit provider and PKCS#11 schemas, and an explicitly bounded secret-aware path for custom provider options. Review grant privileges, verify=false, merge-patch deletion, endpoint validation, credentials, redaction, request limits and profile rejection. Live delegation tests must prove denied mounts cannot use keys. |
| 05 | Transit ML-DSA and external keys | Create/read/import/export/sign/verify for the three ML-DSA parameter sets; external-key create/rotation and provider-dependent operations; external-mu/prehashed validation, batch variants, import restrictions and response additions. Use additive options/details APIs where existing exhaustive enums or struct literals prevent compatible extension. Live positive and negative crypto tests plus old-profile rejection. |
| 06 | PKI ML-DSA, KMS and RSA-PSS changes | All affected root, rotate, intermediate, key, role, issue and sign paths, external_key_ref and kms mode, parameter-set checks, use_pss, and additive response types. Test PSS defaults, invalid trailing-dot names and unsupported ML-DSA OCSP behavior without weakening existing validation. Do not claim SDK TLS support for ML-DSA certificates merely because the server supports them. |
| 07 | Control groups and approval-aware wrapping | Typed authorize/status APIs with secret accessors and secret-aware bounded request_data; original request responses, authorization tokens and unwrap lifecycle; audit metadata redaction, namespace binding, denial, expiration, replay and cancellation. Review whether a narrowly typed ACL builder extension is safe; opaque PolicyWriteRequest remains available. Do not auto-approve or auto-replay requests. |
| 08 | Explicit consistency controls | Bounded typed X-Vault-Index response capture and X-Vault-Inconsistent request options, profile gating, namespace/cluster scoping, header validation, await-state timeout, forwarding and 429 handling. Preserve non-idempotent retry restrictions. Prove behavior with multi-node live tests, not single-node success alone. |
| 09 | Remaining behavior/field gaps and old security blocks | Catalog OCI digest/default command/latest version support, plugin prune, sanitized config additions, cert Envoy decoder, wrapping-token revoke-self, raw backup reads, MFA TOTP responses, and every other source/runtime delta. Re-review workflow CAS and prefix listing independently; retain blocks on older profiles and require exact 2.7 adversarial tests before lifting either. |
| 10 | Profile promotion and release assurance | Every inventory item has implemented/tested or explicitly justified unsupported/security-blocked disposition. Promote 2.7.0 only after routes, field rules, fixtures, explicit plugin exclusions and gates are wired. Regenerate registry/contracts/fixtures; test all historical versions against their own API and mixed-version intersections; update docs/migration/examples, audit dependencies, run full release gate and pentests, then await exact-commit GitHub checks before tagging. |

If a checkpoint needs multiple commits to keep review manageable, record the
subcommits and audit range here. No release capability is considered complete
merely because its planning row exists or its documentation was extracted.

Checkpoint 04 is split for review. Subcommit 04a adds validated, operator-gated
Transit and PKCS#11 provider schemas and their serialization, bounds and
redaction tests. Its pentest base is `61d88cf`. See the
[external-key review](OPENBAO_2_7_0_EXTERNAL_KEYS_REVIEW.md).
Subcommit 04b adds config/key/grant endpoint wrappers, bounded secret-aware
custom-provider options and responses, merge-patch deletion, verification
acknowledgements and old/fallback-profile rejection tests. Its pentest base is
`b4edeff`. Live TLS administration, grant denial/removal and encryption/decryption
passed; the retained result is hash-bound to its fixture inputs and checked in CI.
Checkpoint 04 and its follow-up fixes passed pentest review.
Successful public SDK dispatch also requires the checkpoint 10 generated-registry/
profile promotion; no staged wrapper bypasses that registry.

Checkpoint 05 is split for review. Subcommit 05a adds additive Transit ML-DSA
and external-reference request types and operations, detailed key reads, export
formats, mu/batch validation and old/fallback-profile rejection tests. Its pentest
base is `4394b8a`. Subcommit 05b (pentest base `16a1cde`) retains passing,
input-bound TLS cryptographic evidence for all three parameter sets and external
Transit-provider operations, plus offline failure and tamper regressions.
Checkpoint 05 and its follow-up fixes through `2361a98` passed pentest. Public SDK
positive dispatch remains a checkpoint 10 requirement, not a claim of this fixture.
See [the Transit review](OPENBAO_2_7_0_TRANSIT_REVIEW.md) for the explicit test scope.

Checkpoint 06 is split for review. Subcommit 06a (pentest base `2361a98`) adds
typed PKI ML-DSA selection and guards every existing generation/role path against
old or fallback profiles, including direct assignment to legacy public fields.
Subcommit 06b (pentest base `1942e7b`) adds six KMS generation paths, bounded
external-key references, conflicting-input rejection and additive key metadata.
Subcommit 06c (pentest base `21ad367`) adds role signature options/readback,
issuance key selection and CEL issue/sign inputs, preserving template gates.
Subcommit 06d (pentest base `a0d6bbf`) adds authority signature options, explicit
key-source selection and a corrected operator-gated cross-sign CSR API. It also
rejects key-exporting PEM bundles that duplicate private keys into public fields.
Subcommit 06e (pentest base `a08dbbd`) adds independent OpenSSL verification,
the constrained live PKI fixture and passing input-bound evidence. All three
ML-DSA parameter sets, RSA-PSS settings, OCSP behavior and Transit KMS grants
are checked. Checkpoint 06 implementation passed pentest; production SDK
positive dispatch remains required at checkpoint 10, with no profile promotion
from Python fixture results. See [the PKI review](OPENBAO_2_7_0_PKI_REVIEW.md).

Checkpoint 07 is split for review. Subcommit 07a (pentest base `7419d1b`)
adds the explicit control-group authorization call, validated secret accessors
and strict approval decoding, with incompatible-profile rejection tests.
Subcommit 07b (pentest base `8a85027`) adds bounded secret-aware request review,
including full requester metadata, duplicate rejection and decode-limit tests.
Subcommit 07c (pentest base `83133d5`) adds explicit deferred-execution ownership,
one-attempt state tracking, response-shape preservation and real-transport
cancellation/timeout/disconnection regression tests. Subcommit 07d (pentest base
`9f20076`) implements the narrow ACL builder extension and gated policy writer.
Live evidence, including generated-policy enforcement, remains required. See
[the control-group review](OPENBAO_2_7_0_CONTROL_GROUPS_REVIEW.md).
The 07e fixture and offline regression tests are prepared, with builder-matched
HCL. A live run confirmed repeated execution on approved unwrap. The maintainer
accepted API support with this known upstream limitation, separate from server
replay-security results. The strict replay test remains available; the default
fixture continues the other checks with an explicit limitation in its evidence.
The complete live compatibility report is retained and digest-pinned; checkpoint
07 passed pentest through `c6c4480` under this scope. Public SDK dispatch remains gated until
checkpoint 10. The report does not claim server replay protection.

The checkpoint 06 pipe-cleanup fix passed pentest and is committed as `7419d1b`.
Its four replacement 2.7 live evidence captures (TLS/plugin exclusions, external
keys, Transit and PKI) were rerun successfully and retained with updated digest
pins. Only the shared harness input hash differs from the earlier reports;
checks and scope are unchanged. Historical results were not relabeled as new
runs, and no active profile was changed.

The subsequent CI failure also identified stale harness provenance in the
25-version core-flow matrix. All 25 pinned 2.0.0 through 2.6.3 core integrations
were rerun successfully; their operation results are unchanged. The refreshed
matrix and dependent version-contract evidence hashes are anchored separately.
Stale-harness and stale-test-definition rejection remain enforced and tested.

Checkpoint 08 is split into 08a bounded header types and source-contract review,
08b scoped/profile-gated transport, and 08c multi-node live verification.
08a is committed as `4005c59` (pentest base `c6c4480`). 08b's pentest base is
`4005c59`; it adds context-bound metadata and advanced single-attempt transport,
with the public path blocked until profile promotion. 08c now has passing live evidence; its pentest base is `8662b26`. See
[the consistency review](OPENBAO_2_7_0_CONSISTENCY_REVIEW.md) for remaining work.

Checkpoint 09 starts with 09a's exact-source review and adversarial workflow CAS
fixture (base `e8d2402`). The live result passed and is retained with independent
digest/source verification and mutation tests; no workflow block is lifted.
Remaining fields and behaviors are tracked in
[the checkpoint 09 review](OPENBAO_2_7_0_REMAINING_REVIEW.md), including explicit
distinctions between server configuration, local CLI operations and HTTP APIs.
09a is committed as `2615d7e`. Checkpoint 09b adds the exact-verified-profile CAS
guard and before-dispatch rejection regressions, with `2615d7e` as its pentest
base. All active historical CAS blocks and prefix listing remain blocked; 2.7
still requires checkpoint 10 promotion. Refreshed source-bound CAS, control-group
and SDK consistency reports are retained; the known server replay failure remains
explicitly recorded. The remaining checkpoint 09 inventory is not yet complete.
09b is committed as `55015ec`. Checkpoint 09c adds a constrained sanitized-config
and wrapping-token revoke-self fixture with offline adversarial tests; its live
capture passed and is retained with an independent digest pin and strict
source/scope verification. The pentest base for 09c is `55015ec`.
09c is committed as `904abb4`. Checkpoint 09d adds the MFA TOTP enrollment
lifecycle fixture and adversarial offline tests, with passing source-bound live
evidence retained and independently digest-pinned.
Its pentest base is `904abb4`; it does not claim storage erasure, login
enforcement or public 2.7 dispatch.
09d is committed as `26a90ec`. Checkpoint 09e gates dynamic `latest` selection
for mount/auth enable and tune to the reviewed exact verified profile, preserving
explicit and omitted versions. Regression tests and refreshed source-bound live
evidence are retained with unchanged scope. Its pentest base is `26a90ec`.
09e is committed as `d324862`. Checkpoint 09f adds a disposable real
PGP-encrypted unseal backup fixture with raw/dedicated API comparison and
protected-path regressions. Passing source-bound live evidence is retained
with an independent digest pin; recovery and upgrade
coverage are not claimed. Its pentest base is `d324862`.
09f is committed as `683b176`. A separate recovery-backup fixture now retains
passing source-bound live evidence using disposable static auto-unseal, with
digest verification and adversarial cleanup/scope tests. A separate passing
single-node Raft fixture now retains recovery-backup preservation evidence from
2.6.3 to 2.7.0, including access controls and deletion, with independent digest
and source verification. This does not claim general upgrade compatibility or
unseal-backup migration. The [delta reconciliation](OPENBAO_2_7_0_DELTA_RECONCILIATION.md)
now accounts for all 189 changes and six recovered route identities. It found
a modern-rotation response-envelope and grouped-backup mismatch. Both now have
decoder fixes and regression coverage. The subsequent pentest identified missing
aggregate share limits and encoding validation. These are now enforced per map
with regression coverage. All nine affected source-bound reports have been
recaptured and verified, including both SDK consistency reports against the
rebuilt executable. Checkpoint 09 is ready for follow-up pentest review.
Checkpoint 10 profile promotion and release assurance have not started.

## Security And Compatibility Rules

- Preserve every released exact profile and immutable historical snapshot.
  Removing a built-in engine in 2.7 must not remove its 2.2 server support.
- No new operation or field becomes routable through an assumed profile,
  rolling interval or latest-version fallback before explicit promotion.
- The existing explicitly acknowledged unknown-newer mode still selects only
  the latest reviewed 2.6.3 profile. That is not verified 2.7.0 support; the
  strict, exact, assumed and range policies do not accept a 2.7.0 profile yet.
- Use semver-compatible additions: do not add mandatory fields to existing
  public struct literals or variants to exhaustive enums without an API review.
- External-key configuration can contain tokens, PINs and client keys. Keep
  it out of Debug, tracing, error messages and nonsanitizing intermediate maps.
- Control-group status may reveal the original request body. Treat it as
  sensitive even when a documentation example contains only public fields.
- Source-only, mock, single-node TLS, multi-node and provider-backed evidence
  must be labeled separately. PKCS#11/HSM guarantees require actual provider
  evidence; a Transit provider does not prove hardware memory properties.
- PQC signing support and TLS negotiation are distinct. Do not advertise pure
  PQC transport unless the SDK backend and tested server configuration support
  it; never disable certificate validation to make a new certificate work.
- The 2.7 release reports a workflow CAS fix. Source changes and adversarial
  live tests, not release prose alone, determine whether a security block lifts.

## First Review Findings

The tagged documentation changes include external keys, control groups, PKI,
Transit, Identity MFA TOTP, SSH, namespaces, policies, password policies and
workflows. Small documentation changes can be response-contract corrections,
so they must be reviewed rather than discarded as editorial changes.

The release also removes `file` server storage and built-in external engines.
Inspection in checkpoint 03a confirmed that neither our historical `inmem`
integration fixture nor our Raft local dev stack needs a `file`-storage migration.
The exact-version inventory and external plugins still prevent simply running
the historical harness unchanged on 2.7.
The source has moved under `internal/`, and plugin distribution identity is
now a separate compatibility input. These are fixture/evidence changes, not
reasons to weaken production dispatch or erase historical engine APIs.

Checkpoint 02's pentest follow-up hardens acquisition tool execution, adds
aggregate documentation expansion limits, and canonicalizes duplicate ACME
records while rejecting conflicts. The staged documentation and its lock were
corrected; active historical evidence and runtime captures were not rewritten.

The immutable checkpoint 01 source inventory intentionally asserts no endpoint
coverage count. Checkpoint 02 separately locks signed-image evidence, v2
documentation, built-in-only runtime OpenAPI and an adjacent diff. External
plugin capture is excluded from 2.2.0 by the approved checkpoint 03 decision;
request-field rules, typed APIs,
behavior tests and profile promotion remain pending later checkpoints. Neither
source inventory nor staged API evidence claims usable SDK 2.7.0 support.
