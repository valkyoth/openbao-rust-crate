# OpenBao 2.7 Candidate Registry

Checkpoint 10c update: normal development builds now enable the reviewed 2.7
routing inventory. The candidate artifact below remains immutable pre-promotion
provenance. The disposable builder now produces the same routing table as the
normal build; it cannot enable additional versions. Earlier candidate TLS
evidence has been refreshed while preserving its original scope.
Release assurance is not complete. The sections below describe the candidate
verification that preceded this routing change.

Checkpoint 10b1 generates `compat/onboarding/2.7.0/candidate-capability-registry.json`
from the pinned active registry, staged v2 documentation/runtime OpenAPI and
reviewed delta. Its separate schema is intentionally rejected by the active
registry validator. Checkpoint 10b2 now compiles its metadata into the generated
Rust capability table, but keeps 2.7 out of the independent routable inventory.
Read-only profile inspection is available; public 2.7 policies and dispatch
remain rejected. The historical JSON registry remains byte-for-byte unchanged.

The candidate contains 707 identities: all 691 active identities, unchanged for
all 25 historical profiles, plus 16 candidate-only identities. These additions
are 13 external-key operations, two control-group operations and the corrected
internal request-inspection route. Every addition is unavailable on historical
profiles. Root-token logical endpoint metadata extends through 2.7 without
changing the path selected for any historical profile.

## Explicit Decisions

- LDAP auth/secrets, Kerberos and RADIUS remain unavailable on the 2.7 candidate,
  regardless of stale documentation. Their historical cells are preserved.
- External-key PUT aliases are represented by POST, matching runtime OpenAPI
  and SDK methods. External-key LIST entries require the runtime list query
  projection. Placeholders are normalized to existing registry semantics;
  grant mount paths use the existing multi-segment `:path` placeholder.
- `/sys/internal/inspect/request` is the runtime identity. The documented `/root`
  suffix remains in the historical inventory but is unavailable on the candidate.
  The SDK inspection method now uses a logical route variant. Its historical
  `/root` variant is available only on 2.5.5; the non-suffixed variant is staged
  for 2.7. Historical gaps remain rejected, with no fallback route attempt.
- SSH issuer PATCH is not invented from its combined documentation table.
  Runtime PATCH appearing later requires new review.
- Workflow LIST and SCAN remain separate identities despite their shared GET
  OpenAPI projection. No ordinary GET-list SDK identity is added. Both prefix
  variants remain security-blocked.
- OIDC public keys retain their reviewed runtime supplement.

Candidate availability is documentation/runtime contract evidence, not proof
that an operation succeeds on the live server. Inherited historical quirks are
not silently repaired. This artifact does not assert complete field coverage,
SDK method coverage, plugin availability, replay safety or strict 2.7 support.

## Verification

```bash
python3 -B scripts/generate_openbao_2_7_candidate.py
python3 -B scripts/test_openbao_2_7_candidate.py
```

Generation uses the existing bounded readers and atomic writer. Verification
requires byte-for-byte reproduction from anchored inputs plus an independent
output digest. Mutation tests reject changed evidence, new unreviewed identities,
lost runtime methods, changed projections, historical-cell changes, missing
exclusions and promotion flags. All checks run in CI without a new container run.
Rust tests cover candidate profile visibility without policy promotion, root
and inspection variant selection, historical inspection gaps and external-plugin
blocks. The existing HTTP test retains the real 2.5.5 `/root` wire assertion.

### Isolated Strict SDK Verification

`python3 -B scripts/check_openbao_2_7_candidate_sdk.py` builds a disposable source
copy using the locked dependencies offline. Only that copy's generated routable
inventory includes 2.7. No public feature, environment switch or production
configuration bypass is added. Repository sources are compared before and after
the run, and the normal generated-output verifier must still pass afterward.
The temporary source copy is removed; build artifacts use `target/candidate-sdk`.
Run this as the ordinary development user, never through sudo.

The eight explicitly inventoried, ignored integration tests exercise the public
SDK with exact-profile health probes and loopback HTTP mocks: distinct workflow
LIST/SCAN, legacy versus external-reference Transit rotation, versioned internal
inspection, all 13 external-key routes (including merge-patch content type and
multi-segment grants), both control-group routes, all 25 historical profiles,
PKI ML-DSA/KMS fields on a custom mount, and a rolling-range CAS rejection. An empty or incomplete test listing fails
the verifier. These are wire/decoder regressions, not live TLS, provider behavior
or server authorization evidence. They do not establish replay safety.

### Strict Backup Candidate Build

Build the separate ignored live test as the ordinary development user:

```bash
python3 -B scripts/check_openbao_2_7_candidate_sdk.py --build-backup-test
```

Then pass the printed binary path to the constrained server runner:

```bash
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_2_7_backup_sdk.py \
  --strict-candidate --test-binary /absolute/path/printed/by/the/builder
```

The test requires exact 2.7 selection and a verified health report before public
grouped/singleton backup reads. The runner retains the existing privilege drop,
single-test inventory check, private stdin, output suppression and resource cleanup.
Candidate executables are accepted only from the separate fixed build directory,
with the same owner, regular-file and permission checks as ordinary SDK binaries.
The strict report has a separate schema/scope, records the generated candidate
override digest, and cannot be relabelled as public promotion or PGP decryption.
The strict live capture passed and is retained unchanged in
`compat/onboarding/2.7.0/backup-sdk-strict-candidate-tls.json`. The report and
executable have independent digest pins in
`scripts/verify_openbao_2_7_backup_sdk_candidate.py`. Verification binds current
source inputs and the generated candidate override; tamper tests reject changed
or omitted inputs, binary/report pins and stronger scope claims. Both run in CI.

## Still Required

### Normal-Build Backup Acceptance

After promotion, build the live test without the disposable source override:

```bash
cargo test --locked --no-default-features \
  --features sys,operator-ops,operator-ops-acknowledged,rustls-tls --lib --no-run
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_2_7_backup_sdk.py \
  --strict --test-binary /absolute/path/to/the/printed/test/binary
```

The normal executable must be under `target/debug/deps`, not
`target/candidate-sdk`. `--strict` and `--strict-candidate` are mutually exclusive.
The normal result uses `openbao-backup-sdk-strict-tls/v1` and
`public-sdk-strict-normal-build`, with exact-profile verification performed by
the Rust test itself. It still does not claim PGP decryption. Scope, test name,
input hashes and binary changes are rejected by the report validator.
The strict normal-build run passed and is retained unchanged as
`compat/onboarding/2.7.0/backup-sdk-strict-tls.json`. Independent report and
executable digests are anchored by `verify_openbao_2_7_backup_sdk_strict.py`.
Its regression tests reject report/binary changes, omitted or changed source
inputs, current-source drift and unsupported scope or decryption claims.
Both the verifier and tests run in CI. All eleven other affected reports have
also been refreshed and validated against current inputs. This does not
complete the release gate by itself.

The [request-field review](OPENBAO_REQUEST_FIELD_COMPATIBILITY.md#staged-27-controls)
records the additive field gates and preserved defaults. Strict candidate live
backup evidence is now retained. The disposable checks cover the listed dispatch regressions;
historical exact profiles and mixed-profile behavior must continue to pass.
The dispatch regressions also require LDAP auth/secrets, Kerberos and RADIUS
operations to fail with an unsupported-capability error under both exact 2.7
selection and a rolling 2.6.3-to-2.7 policy detecting 2.7. Promotion must not
restore those excluded engines through custom routing or policy fallback.
The affected evidence set is now refreshed, including the normal-build SDK.
Release completion still requires the full release checks, documentation review,
checkpoint 10 pentest and exact-commit GitHub checks.

Any subsequent input change invalidates its source-bound live reports. Those
reports must be recaptured; older retained reports must not be re-anchored by
substituting source hashes.
