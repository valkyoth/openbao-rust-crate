# openbao 2.2.0

Version: 2.2.0
Status: unreleased development; OpenBao 2.7.0 is not yet supported

This release is being developed in pentestable commit checkpoints described in
[the OpenBao 2.7.0 plan](../docs/OPENBAO_2_7_0_PLAN.md).

## Completed

- Add a staged real unseal-backup fixture with raw/dedicated API comparison and
  adversarial offline tests. Passing source-bound live evidence is retained;
  recovery backup, upgrade
  and decryption verification are not claimed by this slice.

- Stage a guarded mount/auth `latest` plugin selector with historical-profile
  rejection and unchanged explicit/omitted payload tests. Refreshed source-bound
  evidence is retained; external plugin artifact support and 2.7 promotion are
  not claimed by this change.

- Add a staged MFA TOTP enrollment/removal fixture and offline regressions.
  Passing source-bound live evidence is retained with an independent digest pin.
  The source review distinguishes entity association
  removal from stored-key erasure; no production API or routing change is made.

- Add offline adversarial tests and a staged TLS fixture for sanitized-config
  additions and ordinary wrapping-token revoke-self. Passing source-bound live
  evidence is retained; this does not address the separate upstream control-group replay
  defect or enable the 2.7 profile.

- Stage a workflow CAS guard limited to exact verified OpenBao 2.7.0, with
  historical, assumed, fallback and range-profile rejection tests. Public 2.7
  dispatch remains disabled. Checkpoint 09b retains refreshed source-bound CAS,
  control-group and SDK consistency evidence, including the known server replay
  failure without claiming it is fixed.

- Checkpoint 09a adds exact-source behavior review and retained workflow CAS
  server evidence, including rejected-write integrity and concurrent updates.
  Evidence scope and provenance are checked in CI. This does not lift SDK CAS
  or prefix-listing blocks; the remaining checkpoint 09 work is still required.

- Verify a three-node Raft consistency protocol fixture with strict TLS and
  resource isolation, real index propagation and explicit synthetic-index checks.
  Its live capture is retained and digest-pinned; it does not claim controlled replication-lag or
  SDK live verification and does not complete checkpoint 08.

- Verify a staged SDK TLS test beneath the public consistency profile gate,
  with a bounded runner executing the compiled test as the non-root invoking
  user. Retained evidence binds the sources and executable digest.

- Verify coordinated SDK controlled lag, namespace-context rejection,
  cancellation and timeout after upstream TLS transmission, no retries, and
  recovery. The baseline was rerun with the same executable. A fourth independent
  cluster verifies preflight rejection at the same SDK endpoint before any
  authenticated operation is dispatched. Checkpoint 08c is ready for pentest;
  this does not protect against backend changes between preflight and dispatch.

- Verify controlled replication lag at the server-protocol level using a
  container-local Raft traffic filter, observed stale reads, real-index rejection,
  no write mutation, and bounded await recovery. Retained evidence does not claim
  SDK execution under controlled lag or complete checkpoint 08.

- Checkpoint 08b stages scoped consistency transport with explicit policy headers,
  cluster/context validation, redacted errors and no automatic retries. Mock
  regression coverage includes response capture, cancellation and sanitizing-body
  cleanup. This is not live replication proof: 08c and checkpoint 10 promotion
  remain required before the public 2.7 path is enabled.

- Checkpoint 08a adds the non-default `consistency` feature with bounded,
  secret-aware index parsing and explicit fail/forward/await-state policy values.
  This supplies the metadata foundation used by 08b and verified live in 08c;
  the 2.7 profile remains unpromoted.

- Reject empty, oversized and non-visible-ASCII explicit wrapping tokens before
  transport across lookup, rewrap and both unwrap interfaces. Explicit `None`
  on stateless unwrap still selects the authenticated client's token deliberately.

- Harden `WrappedResponse::try_unwrap`: once an attempt starts, that wrapper
  cannot send another unwrap, even after cancellation or an error. This changes
  explicit retry behavior without changing method signatures. `is_attempted()`
  exposes the local guard; conversion to control-group execution cannot reset it.
- Correct strict replay-security testing to accept rejection and derive later
  KV assertions from the observed outcome. Fresh live evidence still records
  the known OpenBao 2.7.0 server defect, not a successful replay-security check.

- Record the observed OpenBao 2.7.0 control-group replay limitation separately
  from API compatibility. The SDK one-attempt guard is local, not server-wide
  token consumption. The fixture retains a strict replay-security mode and
  marks the known server failure explicitly in retained live evidence.
- Complete the checkpoint 07e live control-group fixture with generated-policy,
  identity, approval, expiry, replay and cancellation checks. Offline tests do
  not establish live enforcement; the rootful TLS result is separately retained
  and digest-pinned with the known replay limitation. OpenBao 2.7 support remains unpromoted.

- Checkpoint 07d adds typed identity factors and TTL requirements to
  `AclPolicyBuilder`, with all rule operations controlled by every factor and
  self-approval disabled. `build_control_group_write_request` and
  `Sys::write_control_group_policy` preserve the unpromoted 2.7 compatibility gate.
  Live verification of the generated policy remains part of checkpoint 07.

- Checkpoint 07c adds `WrappedResponse::into_control_group_execution` and
  `ControlGroupExecution`. A handle preserves its original client/namespace and
  allows one execution attempt, with no automatic approval or retry. Cancellation
  and transport failures retain credentials with an unknown outcome; accepted
  responses clear credentials even if later typed decoding fails. Public dispatch
  still requires the unpromoted 2.7 profile.

- Checkpoint 07b adds `Sys::read_control_group_request` with bounded,
  duplicate-rejecting response decoding. Saved payload and full requester
  metadata use sanitizing JSON storage; operation, path and approver identities
  use secret strings. Debug and decode errors do not expose contents.

- Checkpoint 07a adds `ControlGroupAccessor`, `ControlGroupApproval` and
  `Sys::authorize_control_group`, using an explicit authenticated POST with no
  automatic approval, replay or unwrap. The 2.7 profile remains unpromoted;
  live lifecycle verification remains under development.

- Fix inherited subprocess stdout-pipe cleanup in the verification harness,
  with real-process tests for normal exit, failures, timeout, overflow,
  interruption and selector setup errors.

- Retain checkpoint 06e signed-image PKI TLS evidence with independent OpenSSL
  certificate, CSR and key-matching verification, local tamper/wrong-key controls
  and input-bound evidence validation. This is server-contract evidence, not SDK
  2.7 compatibility promotion; checkpoint 10 still requires positive SDK dispatch.

- Checkpoint 06d adds `PkiAuthorityKeySource`, authority signature-option
  helpers and operator-gated `cross_sign_intermediate_csr`, preserving existing
  APIs and requiring the unpromoted 2.7 contract. Live PKI evidence is retained in 06e.
- Security hardening: exported authority generation and ordinary issuance now
  reject `pem_bundle`, which puts private keys into public certificate/CSR
  fields. This also applies to existing helpers. Switch those requests to `pem`
  or `der`; public-only bundle output is unaffected.

- Checkpoint 06c adds `PkiSignatureOptions`, `PkiRoleSigningOptions`,
  `PkiRoleSigningDetails` and `PkiIssuanceKey`, with role write/PATCH/readback,
  ordinary/named-issuer issuance and CEL issue/sign helpers. Signature preferences
  preserve omitted/false/zero distinctions; identity-template overrides still
  require the acknowledgement feature and token. New writes require the reviewed
  2.7 contract, which remains unpromoted. Historical role reads remain available.

- Checkpoint 06b adds six PKI KMS generation methods, validated
  `PkiExternalKeyReference` and `PkiGeneratedKeyDetails`. Conflicting local key
  settings fail before compatibility probing; all active and fallback profiles
  reject KMS operations. Live Transit-provider PKI verification is retained in 06e.

- Checkpoint 06a adds `PkiMldsaParameterSet`, `with_mldsa` request builders and
  old/fallback-profile rejection on all existing PKI generation/role paths.
  [The PKI review](../docs/OPENBAO_2_7_0_PKI_REVIEW.md) records remaining PSS/issuance
  options and live evidence requirements. This is not completed 2.7 PKI support.

- Follow-up checkpoint 05 hardening removes message-sized constant-time Base64
  decoding from constructors, adds a separate 16 KiB BYOK budget and enforces a
  five-second combined budget for two maximum-size constructors in release tests.
  Fixed-size external-mu validation remains constant-time and sanitizing.

- Checkpoint 05 pentest hardening adds canonical Base64, BYOK size-layout and
  bounded public-key PEM envelope validation, including mutable version imports.
  Tests cover empty messages, malformed encodings, exact size limits, raw seeds,
  wrong PEM labels, duplicate envelopes and secret-free diagnostics.

- Checkpoint 05a adds additive Transit ML-DSA/external-reference APIs, detailed
  key metadata, export formats and bounded signing/verification controls with
  old-profile rejection. [The Transit review](../docs/OPENBAO_2_7_0_TRANSIT_REVIEW.md)
  records 05b's passing, hash-bound live TLS tests for all parameter sets,
  import/export, mu/batches and external-provider restrictions. Offline tests
  reject tampered evidence and failed fixture cleanup. OpenBao 2.7 remains
  unpromoted; successful SDK dispatch is still required at checkpoint 10.

- Checkpoint 04 pentest hardening: PKCS#11 OAEP SHA-1 requires the existing
  acknowledgement feature; external-key names match the server grammar;
  response objects permit at most 64 provider options plus `plugin` metadata.
  Regression tests cover the feature gate, rejected names and exact limits.

- Development manifests and maintained lockfiles identify 2.2.0.
- Hash-locked inventory of the exact 2.7.0 tagged API source files, with
  predecessor comparison and offline tamper checks.
- Existing 25 server profiles remain unchanged, through OpenBao 2.6.3.
- Staged signed-image/provenance evidence, bounded built-in-only runtime API
  capture, a versioned documentation extractor and like-for-like 2.6.3 delta.
  See the [checkpoint 02 review](../docs/OPENBAO_2_7_0_REVIEW.md) for scope and
  discrepancies. This is not profile promotion or application integration.
- Checkpoint 02 pentest hardening: controlled evidence-tool paths and
  environments, verified-signature claim checks, aggregate documentation
  expansion budgets and duplicate/conflict handling with regression tests.
- Isolated system-Python invocation prevents caller-provided import paths and
  startup customization from bypassing evidence verification.
- Checkpoint 03a records the missing external-plugin release artifacts and
  updates the local dev fixture without touching historical server profiles.
  The approved 2.2.0 scope explicitly excludes LDAP auth/secrets, Kerberos and
  RADIUS on 2.7 pending separately verified plugins (target 2.2.1 when available).
  Historical built-in support is unchanged. See the
  [plugin/fixture review](../docs/OPENBAO_2_7_0_PLUGIN_REVIEW.md).
- Checkpoint 03 completes the staged TLS fixture with verified network/resource
  restrictions, TLS rejection tests, initialization/unsealing, built-in Transit
  creation and explicit absent-plugin checks. Retained evidence is bound to its
  fixture inputs. This is server evidence, not SDK 2.7 profile promotion.
- Checkpoint 04a adds operator-gated Transit and PKCS#11 external-key provider
  schemas with validated private fields, secret-aware credentials, bounded
  inputs and serialization/redaction tests. See the
  [external-key review](../docs/OPENBAO_2_7_0_EXTERNAL_KEYS_REVIEW.md).
- Checkpoint 04b adds config/key/grant administration, bounded secret-aware custom
  options and provider reads, explicit custom/verification acknowledgements and
  JSON Merge Patch handling. Old and fallback profiles reject the new methods.
  Retained live TLS evidence proves administration, allowed encryption/decryption,
  denied mounts, denial after grant removal and preservation of remote key
  material after mapping deletion. CI verifies the input-bound evidence and its
  scope. No PKCS#11 hardware claim or 2.7 routing promotion is made.

## Dependency Assurance

Pentest follow-up: the security policy now explicitly records the lack of an
independent dependency audit chain as an accepted supply-chain assurance limit.
No dependency, runtime behavior or mandatory release gate changed for this note.

## Required Before Release

Built-in typed APIs and field rules,
security review, live regression coverage, profile
promotion, complete documentation and the final release gate remain pending.
Do not publish or tag this development checkpoint. The stable release is
2.1.9; its security and compatibility guarantees have not been extended to
OpenBao 2.7.0 by this preparation work.
