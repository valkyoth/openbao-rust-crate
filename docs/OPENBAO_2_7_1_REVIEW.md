# OpenBao 2.7.1 Review For openbao 2.2.1

Reviewed 2026-10-02. The development build now routes both reviewed patch
profiles. Normal-build live evidence is retained; release approval remains pending.

The final registry refresh replaced yanked `yoke-derive 0.8.3` with `0.8.4`
in all three lockfiles. Fresh normal-build SDK evidence below covers that
dependency graph. Earlier captures are preserved but rejected by current-input
checks. Server-only evidence is unaffected. Pentest and GitHub approval remain
required before tagging.

Subsequent mapping/OIDC auth hardening is covered by the new normal-build
capture below. Historical reports remain unchanged and cannot satisfy current
source gates. Security retesting and GitHub approval remain required.

## Identity

- [Official release](https://github.com/openbao/openbao/releases/tag/v2.7.1),
  published 2026-10-01T14:03:19Z.
- Source commit: `a5db72cef75c24b920ade02065b18dd8eb666bac`.
- [Changes since 2.7.0](https://github.com/openbao/openbao/compare/v2.7.0...v2.7.1).
- OCI index: `sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf`.
- Linux amd64: `sha256:a36ea8c27f0dcff5757664ad080425f96d3b6b2f33db3e76c4e2d3112fb17005`.
- Cosign verified the index with the exact certificate identity
  `https://github.com/openbao/openbao/.github/workflows/release-images.yml@refs/tags/v2.7.1`
  and issuer `https://token.actions.githubusercontent.com`. Certificate chain,
  signature claims and transparency-log inclusion checks passed.
- The retained index binds the exact amd64 manifest and attestation manifest
  `sha256:63e24eaaf1ed5cbc31cc45bacc6c26c38ce6f194d1502885e58d8b889858676f`.
  The latter binds provenance blob
  `sha256:c4077360974a8e99eeca4591ef48984fb17a7a61a63351dfe8a75d6ac04fa821`,
  whose subjects name the amd64 digest and whose source identifies the commit
  above. The signature bundle is retained alongside these artifacts.
  `scripts/verify_openbao_2_7_1_image.py` checks pinned bytes and their structural
  linkage offline; `--online` also repeats the Cosign verification. Offline
  hash checks are not a new cryptographic signature verification or an
  attestation of this Rust SDK's build.

## Patch Review

No files in the tagged API documentation tree changed. This is not proof
of runtime equivalence: capture and compare the actual built-in OpenAPI,
then test the public SDK against the exact signed server artifact.
All 122 extracted files and 711 documented operations match the `2.7.0`
extraction. The separate `2.7.1` extraction has SHA-256
`be731f6fe2db675a93e8c61852345b6ce6f640e3524ccdb8bf558dba20b4480c`.

| Upstream change | SDK assessment and required coverage |
| --- | --- |
| Sanitized configuration exposed `tls_acme_eab_mac_key` (GHSA-3237-j65r-m5rp) | Server-side sanitization fix. Test a configured disposable EAB key is absent from the returned configuration; do not log response contents. |
| Unauthenticated root generation/rekey returned results on audit failure (GHSA-q74w-hv5x-6hxf) | Preserve SDK operator acknowledgement gates; no client-side claim to fix older servers. Audit-failure behavior needs distinct server coverage. |
| Expired AppRole Secret IDs authenticated before tidy (GHSA-7m59-mp95-w6ph) | Test successful login before expiry and rejection after expiry without running tidy. |
| Form AppRole login and certificate role quota calculation (GHSA-5v22-543h-wg96) | Authentication/quota fixes are server-side. Keep the SDK's current request encoding and test applicable login behavior. |
| Kubernetes JWT validation on renewal (GHSA-gf3j-hm38-jhh5) | Server-side fix. A real Kubernetes review/renewal test requires its own backend fixture; generic auth tests do not prove it. |
| Key rotation `disabled` persistence | Test update/read and persistence across restart where feasible. |
| GRPC invalidation lifecycle, Raft auto-join ports, PostgreSQL replay index | Retest TLS and Raft consistency. Raft tests do not prove PostgreSQL replication behavior. |
| Go `LifetimeWatcher` retry backoff | Go SDK implementation change; not a Rust transport change. Preserve explicit no-replay behavior. |
| Packaged default storage changed to PebbleDB | Deployment change; disposable SDK fixtures already specify their own backend. |

The published patch notes list no control-group replay correction. Keep the
known upstream limitation and plugin exclusions until source and live checks
establish otherwise. OpenBao `2.6.4` is also in the `2.2.1` release scope, but
has a [separate source, image and compatibility review](OPENBAO_2_6_4_REVIEW.md).
Do not infer its support from this work, or infer support for unknown future
patches, external plugins, or external database/Kubernetes backends.

## Pending Verification

- The workflow CAS and latest-plugin guards now accept exact verified `2.7.0`
  and `2.7.1` only. Tests reject `2.6.4`, assumed, range-selected and unknown
  profiles. Their source-bound server reports have been refreshed; normal
  `2.7.1` routing is now enabled locally. Consistency binds each context to its exact
  reviewed patch and rechecks that version before dispatch.
- The extended public-SDK TLS test passed workflow CAS create/update, rejected
  omitted/create-only/zero/stale/future CAS writes, preserved state and deletion.
  Its fresh report is retained below; this is still a candidate build.
- Full-range pentest and exact-commit GitHub CI approval before tagging.

Local release-wide historical compatibility/evidence, Rust `1.99.0`, Rust
`1.90.0` MSRV, packaging, dependency audits and selected Kani checks have passed.

## Initial Live Capture

The first successful signed-image TLS capture is retained as
`compat/onboarding/2.7.1/initial-openapi.json` and
`initial-patch-tls.json`. The verifier pins both artifact hashes and checks
the exact current capture inputs. This is server-fixture evidence, not
public SDK evidence or profile promotion.

- Exact `2.7.1` health, TLS 1.3, rejection of untrusted certificates, wrong
  hostname and TLS 1.2, container limits, network isolation and cleanup passed.
- The fixture configures a disposable EAB key ID/MAC pair using static TLS
  certificates; it does not perform ACME issuance. The sanitized configuration
  retains the public key ID but omits the MAC-key field and its marker value.
- AppRole login succeeds with both JSON and form encoding before the Secret
  ID expires. Both fail with the expected invalid-credentials response after
  expiry, without the fixture invoking tidy.
- Captured 501 paths, 718 operations and 541 schemas. Raw-storage routes and
  four associated schemas are absent because this initial normal-mode server
  did not enable `raw_storage_endpoint`. This is not an upstream removal.
- The two changed GET projections are `/sys/namespaces` and
  `/sys/workflows/manage`: the server combines LIST/SCAN parameters and selects
  different operation IDs/response references. Do not silently discard these
  differences as annotation noise or infer distinct wire-method coverage from
  a GET projection alone.

`scripts/openbao_2_7_1_regressions.py` reuses the existing behavioral probes on
fresh exact-version TLS servers without mutating the historical harness's
version constants or relabeling `2.7.0` reports. Its API suite explicitly
enables raw storage to close the capture-scope gap. Other suites cover
external keys, Transit, PKI, workflow CAS, control groups, system behavior and
MFA. The runner preserves known replay-failure outcomes instead of marking
them as passed.

All eight server suites have now completed and their hash-pinned reports are
retained under `compat/onboarding/2.7.1/`. The control-group report records
`completed-with-known-upstream-replay-failure`, not a passing replay check.
The complete API capture contains 503 paths, 724 operations and 545 schemas.
Compared with 2.7.0, paths and component schemas match. The structural verifier
accepts only the two reviewed LIST/SCAN GET projections described above, with
matching response schemas and exact parameter definitions; any other change
fails verification.

The subsequent patch-guard edit in `src/sys.rs` required new captures of all
eight reports, the two server backup reports and the backup-upgrade report.
All eleven refreshed captures are now retained with `-tls-v2.json` filenames
and independently pinned digests. Their current source inputs and complete
report semantics are verified; the full OpenAPI bytes are unchanged. The
original capture bytes remain intact but are not current-source assurance.
Tests reject those stale captures even independently of the digest check,
changed or omitted provenance, altered checks and broader assurance claims.
The separate consistency server report has no changed inputs and remains
current. This refresh does not promote either patch profile.

The staged candidate adds exact 2.7.1 cells to all 707 registered operations,
preserving every historical cell and route variant. Only a disposable candidate
build could initially route that profile; normal-build integration followed
after the refreshed candidate SDK evidence passed.
`candidate-capability-registry-v2.json` binds the refreshed server reports;
its operation contracts are unchanged from the first candidate, which remains
retained under its original filename.
`scripts/openbao_2_7_1_sdk.py` builds that candidate with an allowlisted offline
build environment and runs its public SDK test unprivileged against an isolated
TLS server. It uses a sealed executable descriptor and retains the existing
build-provenance limitations.

## Retained SDK And Backup Evidence

The initial public-SDK candidate test passed against the signed 2.7.1 TLS server.
`sdk-candidate-tls.json` binds the exact source inputs, candidate registry,
generated Rust override and sealed executable digest. The verifier rejects
changed source inputs and any widening of its scope. Subsequent consistency and
backup test changes have made that report stale against current SDK sources;
it is not current release assurance. Its original bytes and source hashes remain
unchanged. Its explicit `--historical` mode verifies the archived artifact only;
the default still rejects stale source inputs. CI separately requires the
source-current normal-build advanced SDK evidence, retained separately below.
Tested behavior at the initial
captured source state includes:

- Exact profile selection and rejection of unknown `2.7.2`.
- Public AppRole login before Secret ID expiry and rejection afterward without
  running tidy.
- Transit encryption/decryption through secret-backed byte helpers, explicit
  version 1 selection after rotation to version 2, and wrong-AAD rejection.

This proves only the exercised public SDK paths in the disposable candidate,
not normal-build routing or all security fixes in the server's patch notes.

Separate exact-version unseal and recovery backup runs passed and are retained
as `unseal-backup-tls.json` and `recovery-backup-tls.json`. They create real
PGP-encrypted backups, compare raw and dedicated API representations, enforce
restricted-token and protected-path denial, delete the backups, and clean up
their isolated resources. The static recovery seal key file is wiped before
removal. These reports explicitly do not claim backup decryption, upgrade
behavior or public-SDK backup decoding.

`consistency-server-tls.json` now retains the passing three-node protocol and
controlled-lag run from `scripts/openbao_2_7_1_consistency.py`. It checks real
index propagation on both standbys, explicit policies, rejected-write side
effects, stale HTTPS reads while one standby's Raft port is isolated, and
recovery during an awaited read. The filter is restricted to the owned
container's network namespace. Historical fixture version constants are not
changed. Local regression tests reject wrong versions, foreign clusters,
accepted stale indices, failed awaited reads and cleanup failures. The evidence
explicitly remains server-protocol-only, not SDK integration.

The combined `scripts/openbao_2_7_1_sdk_advanced.py` run passed and is retained as
`sdk-advanced-candidate-tls.json`. It repeated AppRole and Transit checks, read
a real encrypted rotation backup through both public backup APIs, and exercised
the public consistency context and request methods across three Raft nodes.
The coordinated test covered cancellation and timeout after observed upstream
transmission, no retry, awaited recovery, namespace/context index isolation and
rejection before authenticated dispatch after switching to an independent
cluster. Never-observable indices used to hold cancellation/timeout requests
open are explicitly test-only synthetic metadata. Neither PGP decryption nor
normal routing is claimed. The report binds the source inputs at capture, the exact
candidate registry/generated override and sealed executable digest; the
verifier rejects changed or omitted inputs, altered test coverage and widened
assurance claims. This remains trusted-local-builder evidence, not an attested
source-to-binary build.

The subsequent `2.6.4` candidate renderer and shared AppRole/Transit test updates
made that original advanced SDK report stale. Its bytes and source hashes remain
preserved. A fresh signed-image run is now retained as
`sdk-advanced-candidate-tls-v2.json`, SHA-256
`ab0e3a80466da2e5fafaf04084a3c598812f7ab4670d3fc366c6175f3687215b`.
Its sealed executable SHA-256 is
`fb8de36a1d0bf386757d58e395d9b0b1501c6b427e7b76a76cc1c1a90695cdce`.
It repeated all four public SDK tests and additionally passed workflow CAS
create/update, rejection of omitted/create-only/zero/stale/future versions,
preserved state after rejection, and deletion. Current source inputs, checks,
registry, generated override, executable and scope are independently validated.
Mutation tests reject stale original captures, changed or omitted input hashes,
broader claims and integer substitution for boolean assurance fields. Normal
routing integration and final normal-build SDK evidence remain separate gates.
The report was validated against current sources before that integration.
The generated-registry, profile-test and README changes for normal routing now
make it pre-promotion evidence rather than final-source release assurance.

`scripts/generate_openbao_patch_registry.py` combines the independently verified
`2.6.4` and `2.7.1` candidates into `combined-capability-registry.json`. Tests
compare all 19,796 operation/version cells and every logical route or gap with
their own branch's verified candidate. The legacy engines remain available on
`2.6.4` and excluded on `2.7.1`. The candidate artifact remains non-routable and
unchanged. The normal generator now explicitly promotes only its exact pinned
digest, producing 28 routable profiles; altered contracts or a different version
inventory cannot pass that promotion path. Unknown future versions remain
rejected, and the default unselected client remains on the unverified 2.6.3
baseline. Candidate reports are not silently accepted as final normal-build
evidence: the separate final capture below is required instead.

## Final Normal-Build SDK Evidence

The public SDK run with `--normal` passed against the signed `2.7.1` image.
`compat/onboarding/2.7.1/sdk-normal-tls-v3.json` is independently pinned with
SHA-256 `a1a3ff1a5730485a3b30deb4187961e6567de75dfc22278dd6661a8cf398a2f7`.
The sealed executable SHA-256 is
`d5b1bb8c584f4e361327546b8b4d684c85ea45a3dca16dd0fc01cf214398c8df`.
The original `sdk-normal-tls.json` remains unchanged as pre-dependency-update
evidence; it cannot satisfy the current release gate. The pre-auth-fix
`sdk-normal-tls-v2.json` is also preserved and rejected as current evidence.

The build uses the checked-in generated registry without a candidate override.
It passed AppRole expiry, Transit version/AAD checks, workflow CAS, public
grouped/singleton backup decoding, three-node consistency, controlled lag,
post-transmission cancellation and timeout, no-retry checks, awaited recovery,
and independent-cluster rejection before authenticated dispatch. All resources
were cleaned up before success evidence was written. Backup decryption remains
unverified, and the test-only synthetic indices are explicitly identified.

`scripts/verify_openbao_patch_normal_sdk.py` requires this report and the
independent `2.6.4` normal-build report. It rejects candidate substitution,
changed or missing executable inputs, altered coverage and executable identities.
These reports prove the exercised paths with a trusted local builder, not
independent build provenance or release approval. The upstream control-group
replay failure remains unchanged.

The only accepted post-capture input change is an exact, separately hash-pinned
README correction: the pending auth-fix refresh status. The
captured README bytes are retained as `sdk-capture-readme-v3.md`; neither report nor
its recorded input hashes is rewritten. The verifier accepts no other README
revision or changed/missing input. Tests exercise every input with mutation and
omission after the correction. This is code-current live evidence plus a reviewed
documentation change, not byte identity of the entire current workspace with
the capture workspace. The README is not included in executable Rust or build
script code.

The passing `2.7.0` to `2.7.1` recovery-backup upgrade run is retained as
`recovery-backup-upgrade-tls.json`. The patch runner reuses the bounded historical backup probes
without changing their version constants. It requires both signed images,
exact source/target health versions, the same Raft storage and cluster identity,
preserved encrypted backup representations, access denial and successful cleanup.
Its local tests exercise startup, signature, stop, foreign-cluster, input-drift
and cleanup failures. The retained report is independently hash-pinned, and CI
rejects changed bytes, missing or changed source inputs, changed image/version
identity, or broadened assurance claims. This proves only the exercised
single-node Raft recovery-backup restart path. It does not establish unseal-backup
upgrade behavior, PGP decryption, public-SDK upgrade behavior or general
deployment-upgrade compatibility.

## Preparation Checks

Passed on Rust `1.99.0`: formatting, strict all-target/all-feature Clippy,
all-feature Rust tests and doctests. The all-target/all-feature check on
Rust `1.90.0`, release metadata, historical capability generation and
`cargo deny check` also passed. These are local SDK checks, not evidence of
a live `2.7.1` deployment. Environment-gated integration tests did not run
against a server during this preparation run.

Historical SDK reports still bind their original crate, toolchain and source
versions. Their hashes must not be rewritten to pretend the new build was
already exercised. The normal-build reports above supply new patch-specific
evidence. The twelve affected historical 2.7.0 reports have now been separately
recaptured and retained with `-tls-v2.json` filenames. Their original bytes are
unchanged, and tests reject their use as current-source evidence. The historical
core matrix, full contract checks, package checks, three-lockfile dependency
audits and every selected Kani harness passed as part of local release verification.
After the dependency update, five of those SDK reports were recaptured again
as `-tls-v3.json`: consistency baseline/controlled lag and the three backup
modes. The seven server-only `-tls-v2.json` reports still match current inputs.
Regression tests reject the pre-update SDK lockfile even if the original
artifact and executable hashes are explicitly allowed. The subsequent auth
fixes have fresh `-tls-v4.json` captures for all five SDK reports; tests also
reject pre-auth source inputs independently of the unchanged lockfile.
