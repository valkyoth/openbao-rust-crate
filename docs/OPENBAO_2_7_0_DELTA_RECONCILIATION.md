# OpenBao 2.7.0 Delta Reconciliation

Checkpoint 09 accounting of the immutable, like-for-like 2.6.3-to-2.7.0
delta. This is not profile promotion, a 100% endpoint coverage claim, or proof
of public SDK dispatch. The exact 189 records and their reviewed group assignments
are retained in `compat/onboarding/2.7.0/delta-review.json`. Its independent
digest and exact correspondence to the staged delta are checked by
`scripts/verify_openbao_2_7_delta_review.py`. That validator detects changed
accounting; it does not prove the implementation or the review conclusions.

## Dispositions

| Group | Records | Reviewed disposition and evidence |
| --- | ---: | --- |
| External plugin exclusions | 71 | 52 removed runtime operations and 19 removed schemas belong to LDAP, Kerberos and RADIUS. Exclude these unverified external plugins from 2.7 support, not from historical profiles. See [plugin review](OPENBAO_2_7_0_PLUGIN_REVIEW.md). Availability requires separately verified plugin artifacts, not guessed routes. |
| External keys | 36 | Staged typed configuration, key and grant operations cover the new operations, schemas and documented aliases. SDK writes use POST rather than adding duplicate PUT methods; PATCH remains separate. Provider inputs are not fully described by generic OpenAPI. See [external-key review](OPENBAO_2_7_0_EXTERNAL_KEYS_REVIEW.md), its live Transit-provider evidence and provider exclusions. No PKCS#11/HSM assurance is inferred. |
| Control groups | 8 | Two runtime operations, four schemas and two documented routes map to staged approval/review APIs and secret-aware decoding. See [control-group review](OPENBAO_2_7_0_CONTROL_GROUPS_REVIEW.md). The known upstream replay defect remains explicit; compatibility is not replay-safety certification. |
| PKI | 50 | Request/response external-key references, ML-DSA/KMS key types and RSA-PSS controls map to the staged additive PKI APIs. See [PKI review](OPENBAO_2_7_0_PKI_REVIEW.md) for exact field semantics and retained certificate, CSR, grant and OCSP evidence. Do not infer ML-DSA OCSP support or PQC TLS support. |
| Transit | 18 | External-key creation/rotation and optional hash defaults map to staged Transit extensions and existing optional algorithm selection. See [Transit review](OPENBAO_2_7_0_TRANSIT_REVIEW.md) and the default-selection analysis below. The new rotate request body is represented by the external-reference rotation method, not forced onto legacy empty-body rotations. |
| Workflow list projection | 4 | GET OpenAPI operation ID, query parameter names and response schema reference changed. Tagged source still registers distinct LIST and SCAN operations. Existing `list_workflows` and `scan_workflows` preserve that distinction; this is not a new ordinary GET method. Public 2.7 LIST/SCAN dispatch is a checkpoint 10 test obligation. Prefix listing remains independently security-blocked. |
| MFA TOTP | 2 | Documented admin-destroy method/entity IDs were already represented. Checkpoint 09 live evidence verifies enrollment/removal behavior; removal is not stored-key erasure. See [remaining behavior review](OPENBAO_2_7_0_REMAINING_REVIEW.md). |

The groups sum to 189: 73 runtime operation records, 80 schema records and
36 documentation records. Records are field-level differences, not 189 distinct
endpoints or 189 separately live-tested contracts.

## Transit Defaults

At tagged commit `ca305a02daa68b203325daa1b25c18d7a252d4b3`,
`internal/builtin/logical/transit/path_sign_verify.go::getHashAlgorithm` resolves
URL algorithm, then `hash_algorithm`, then the legacy `algorithm` field. If all
are absent it calls the key type's `DefaultHashAlgorithm`. Removing the schema's
literal SHA-256 default must not be interpreted as disabling hashing.

The existing SDK `sign` and `verify` APIs already accept an optional URL
algorithm and do not inject a body hash default. New ML-DSA message APIs explicitly
select `none`; external-mu signing explicitly selects `mldsa-mu` with prehashed
input, and direct external-mu verification is rejected. These choices and input
bounds are covered by the extension tests and retained live Transit fixture.
`TransitKeyDetails` and its deserialization regression cover `imported_key`
and `imported_key_allow_rotation`; this response correction is also tracked in
the Transit review rather than misclassified as a newly added route.

## Recovered Historical Identities

The v2 documentation extractor recovered six identities from the predecessor.
They are not new 2.7 endpoints, and recovery alone does not authorize changing
an immutable historical profile.

| Recovered identity | Disposition |
| --- | --- |
| `GET /sys/internal/inspect/request/root` | Documentation/runtime discrepancy. The tagged table has `/root`, but its sample and registered handler use `internal/inspect/request`. Do not promote the suffixed identity based on that table. Existing historical behavior remains untouched; checkpoint 10 must resolve the 2.7 route against runtime evidence. |
| `GET /sys/rotate/(root\|recovery)/backup` | Existing operator-gated `operator_rotate_backup` uses the selected target. Modern authenticated backup handlers return data envelopes. Fresh unseal/recovery and recovery-backup upgrade evidence are retained; public 2.7 dispatch remains checkpoint 10 work. |
| `POST /sys/rotate/(root\|recovery)/update` | Existing operator-gated `operator_rotate_update` represents both targets. The backup fixtures exercise the server ceremony without enabling the disabled legacy unauthenticated rekey handlers. |
| `POST /sys/rotate/root` | Existing operator-gated `operator_rotate_root_key` represents this route. Do not confuse it with rotation initialization or key-share update. No new method is required by the extraction correction. |
| `POST /ssh/issuer/:issuer_ref` | Existing `Ssh::update_issuer` sends POST and models issuer metadata. The tagged handler registers the update operation. |
| `PATCH /ssh/issuer/:issuer_ref` | Documentation-only discrepancy: the combined POST/PATCH table is not matched by a registered PatchOperation in `internal/builtin/logical/ssh/path_issuers.go`. Do not invent a PATCH wrapper or mark it available from documentation alone. |

## Outside Structural Deltas

The [checkpoint 09 behavior review](OPENBAO_2_7_0_REMAINING_REVIEW.md) covers
OCI provisioning versus catalog HTTP fields, local plugin pruning, dynamic
`latest` selection, sanitized config, Envoy listener decoding, wrapping-token
revocation, backup storage changes and MFA lifecycle. The retained upgrade
fixture covers recovery backups on single-node Raft from 2.6.3 to 2.7.0 only;
it does not certify every storage backend, topology or unseal-backup migration.

The workflow CAS exception remains exact-verified-profile-only and cannot
bypass the unpromoted registry. Historical CAS blocks, workflow prefix blocks,
external-plugin exclusions and the known control-group replay limitation remain.

## Checkpoint 09 Decoder Fix And Evidence Refresh

Reconciliation found a production decoding mismatch in the modern rotation
helpers. `operator_rotate_status`, `operator_rotate_start`,
`operator_rotate_update`, verification helpers and `operator_rotate_backup`
previously requested their result structs directly. The modern logical handlers
return data envelopes, as the live backup fixtures already require. Several
HTTP mocks instead supply flat JSON. Defaulted fields can therefore conceal
the mismatch as an empty status or backup rather than an obvious error.

The seven data-returning methods now decode `ResponseEnvelope<T>`, consistent
with reviewed v2.4.0 and v2.7.0 logical handlers. Legacy rekey contracts and
no-content operations are unchanged. Both targets have HTTP regressions for
returned nonces and rejection of flat, null and duplicate-data responses.

Modern backup values are lists of shares per fingerprint, not single strings.
The additive `OperatorRotationBackup` and `operator_rotate_backup_grouped`
preserve all shares with bounded, duplicate-rejecting decoding and secret-aware
Debug. The existing return type is preserved: `operator_rotate_backup` accepts
singleton groups and errors on empty or multiple-share groups instead of silently
discarding shares. Tests cover multi-share preservation, malformed groups,
duplicate fingerprints, bounds and redaction. The checkpoint 09 pentest follow-up
adds a cumulative 4096-share budget per encoding map, at most 256 groups,
nonempty groups, lowercase 40-character hex fingerprints, and nonempty shares
of at most 16 KiB with valid hex or canonical standard Base64 encoding. Syntax
validation does not authenticate or decrypt the PGP payload. Whole-backup
validation additionally requires both maps to be nonempty with identical
recipients, share counts and ordered ciphertext.

The `src/sys.rs` change invalidated the retained control-group, workflow CAS,
system-behavior, MFA, raw-backup, recovery-backup, backup-upgrade and SDK
consistency reports. All nine reports have been recaptured against current
inputs after whole-backup validation, verified and independently pinned.
SDK reports match the rebuilt executable. No report source hashes were
substituted.
The control-group report still records the known upstream replay failure.
Checkpoint 09 awaits follow-up review; profile promotion is
still blocked.

## Checkpoint 10 Obligations

Create a real PGP-backed rotation backup and read it through the public SDK's
`operator_rotate_backup_grouped`, checking fingerprint acceptance and decoded
hex/Base64 equivalence. Include disposable-key share decryption where feasible.
Retained server-only backup evidence is not SDK integration evidence.

Before promotion, resolve the actual method/path identities and field rules in
the generated registry, including the documentation discrepancies above. Test
positive public SDK dispatch, LIST/SCAN projection, empty-body legacy versus
external-reference Transit rotation, all historical exact profiles and mixed
profile intersections. Retain all security gates and acknowledged exclusions.
The ledger is an input to those checks, never a replacement for them.
