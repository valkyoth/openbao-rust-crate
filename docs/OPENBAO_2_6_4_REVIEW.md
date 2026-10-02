# OpenBao 2.6.4 Review For openbao 2.2.1

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

- [Official release](https://github.com/openbao/openbao/releases/tag/v2.6.4),
  published 2026-10-01T13:59:14Z.
- Source commit: `8206bc114009a0e468bbdae143f292922e1dbe27`.
- [Changes since 2.6.3](https://github.com/openbao/openbao/compare/v2.6.3...v2.6.4).
- OCI index: `sha256:cf2340fc9a22cb9358ca0defd1f39b65673836bd23fe2bb8984a07e11fe13ef4`.
- Linux amd64: `sha256:bd3e8b6b67b5c4c3fc1064cd0f86eb8063d9ed92a7af608b6408d6748e6eef64`.
- Cosign verified the index with the exact certificate identity
  `https://github.com/openbao/openbao/.github/workflows/release-images.yml@refs/tags/v2.6.4`
  and issuer `https://token.actions.githubusercontent.com`, including signature
  claims and transparency-log verification. No verification bypass was used.
- The retained index binds the amd64 manifest and attestation manifest
  `sha256:b9f9c417f81c1f44e6a59b625f7e5b1780e044b3c62f27e5c0f960762196d172`.
  That manifest binds provenance blob
  `sha256:5042d06a394d3e1d216d3ac0363830b75cf1605e691f925ff7f46a3c90004e8d`,
  whose subject identifies the amd64 digest and whose source identifies the
  commit above. The signature bundle is retained with these artifacts.

`scripts/openbao_2_6_4.py --verify-image` verifies pinned bytes and structural
linkage offline. A live capture repeats online Cosign verification before
starting containers. Neither check attests the Rust SDK's build provenance.

## Patch Review

The tagged API documentation tree is unchanged from `2.6.3`: 117 files and
693 extracted operations match the pinned predecessor extraction. The separate
`2.6.4` extraction has SHA-256
`ee2284a895483dd93f4745e0b1e2ac2898cef17f04823d8af0464e3e22ad7576`.
Documentation equality is not a substitute for runtime API or public SDK tests.

The release backports the security fixes also reviewed for `2.7.1`:

| Upstream change | SDK assessment and evidence boundary |
| --- | --- |
| Sanitized configuration exposed the EAB MAC key (GHSA-3237-j65r-m5rp) | Stage a disposable configured MAC marker and verify the field and marker are absent from sanitized output over TLS. This does not test ACME issuance. |
| Unauthenticated root generation/rekey returned results on audit failure (GHSA-q74w-hv5x-6hxf) | Preserve operator acknowledgement gates. Generic rotation tests do not establish audit-failure behavior. |
| Expired AppRole Secret IDs authenticated before tidy (GHSA-7m59-mp95-w6ph) | Stage successful JSON/form logins followed by rejection after expiry, without invoking tidy. |
| AppRole form login and certificate-role quota calculation (GHSA-5v22-543h-wg96) | Exercise form authentication; do not claim certificate-specific quota coverage from it. |
| Kubernetes JWT validation on renewal (GHSA-gf3j-hm38-jhh5) | Real Kubernetes renewal requires its own backend fixture. Source now requires the saved JWT; tokens issued before the patch may need reissuance rather than renewal. |

The source diff also updates packaging and dependencies. It does not establish
support for new endpoints or 2.7-only features.

## Compatibility Boundary

The exact `2.6.4` profile is compared with `2.6.3`, independently of
the `2.7.1` profile. The TLS/API fixture mounts the full existing 2.6 engine set,
including LDAP auth/secrets, Kerberos and RADIUS, and requires their paths in
the captured API. Do not copy the 2.7 external-plugin exclusions into this line.
Conversely, do not grant 2.7-only consistency or workflow-CAS behavior to 2.6.4.

Unknown patches still fail closed. Existing profiles and the default unselected
client behavior are unchanged. Supporting a historical server does not repair
its upstream vulnerabilities or make it a recommended deployment version.

## Retained Capture And Candidate

The signed-image TLS capture passed and is retained as `openapi.json` and
`patch-tls.json` under `compat/onboarding/2.6.4/`. The exact source inputs match
the retained report. `scripts/verify_openbao_2_6_4.py` independently pins both
artifacts and the `2.6.3` predecessor, then verifies that the entire runtime
contract is identical except for `info.version`: 526 paths, 761 operations and
552 schemas. Mount lists, schemas, methods and parameters are not normalized
away during this comparison.

The run passed exact-version TLS 1.3 and certificate/protocol rejection checks,
container/network constraints, sanitized EAB MAC redaction, JSON/form AppRole
login before expiry, rejection after expiry without tidy, and cleanup. All
legacy 2.6 built-ins mounted successfully and their API paths were retained.
This does not prove authentication against external LDAP, Kerberos or RADIUS
servers.

`scripts/generate_openbao_2_6_4_candidate.py` stages the reviewed registry
extension without changing generated Rust or normal dispatch. All 707 operation
identities and historical cells are preserved. The new patch copies only the
`2.6.3` capability cells: 689 documented and 18 unavailable. Tests explicitly
preserve the legacy engine contracts, 2.7-only exclusions and the intentional
2.6 request-inspection route gap. Only the explicit disposable verification
build can route this standalone candidate. The later normal-build integration
uses a separately checked combined registry, not an implicit candidate promotion.

`scripts/openbao_2_6_4_sdk.py --build` builds the strict SDK candidate offline
with an allowlisted environment. Its ignored live test covers AppRole expiry,
Transit rotation/version selection and associated-data binding, KV v1/v2,
token lookup, single-use wrapping, LDAP/RADIUS user policy mappings, Kerberos
group policy mappings, and LDAP dynamic-role administration. KV payloads use
the existing secret-backed configuration type. Generic failure diagnostics
never interpolate server response bodies or secret values.

The live runner requires a constrained, signed-image TLS server and executes
the SDK binary after dropping root privileges. It seals and hashes the selected
executable using the existing memfd runner, and retains evidence only after
successful execution, cleanup and unchanged input hashes. This is not a
source-to-binary attestation. The live rerun passed every planned stage and is
retained as `compat/onboarding/2.6.4/sdk-candidate-tls.json`. Its SHA-256 is
`d4ee3ac59d296a96a4fcd9ed7e1fd649505b6aa35d3731bfeff8a04b3af670e7`;
the sealed executable SHA-256 is
`86b13d451cb50d0b1681242e419e4c678b621e633a84e832ef2e2be4cc7fee5b`.
`scripts/verify_openbao_2_6_4_sdk.py` pins the exact result and checks current
source inputs, image identity, candidate registry/generated Rust, feature set,
test selector, execution assurances and scope. It rejects changed or missing
inputs rather than silently treating an older run as current. This original
capture is strict candidate evidence, not normal-build evidence.

The later `2.7.1` guard and shared live-test changes have made this SDK report
stale against current sources. Its capture bytes and hashes remain unchanged,
and its current-source verifier intentionally rejects it. The subsequent
SDK rerun passed and was retained separately as
`sdk-candidate-tls-v2.json`, SHA-256
`1772b5be49dc02e3fe706a24c469cf846cae897da04ee6eb57ec162bc6319f57`,
with sealed executable SHA-256
`11416012204333139024a3b777e6e7583c986b994e4b1d91fcca97145ffe11c0`.
It was validated against current sources before normal-build integration.
The subsequent generated-registry and profile-test changes now require final
normal-build evidence; neither candidate capture is relabelled as that evidence.
The separate `2.6.4` server/API capture is unaffected.

The first SDK run failed and produced no success evidence. Reviewing the tagged
RADIUS implementation identified a response mismatch: `policies` is returned
as an array, while the SDK and its mock expected a string. The decoder now
accepts bounded arrays and legacy comma-separated strings while retaining the
public `String` field. Tests cover both forms, empty/null data, item and byte
ceilings, overflow rejection before parsing another item, ambiguous names and
constant validation errors. The subsequent live SDK run passed, including
RADIUS read-back and all remaining LDAP and cleanup steps.

The SDK runner now forwards only ordered, fixed stage labels from bounded
stdout; stderr and all other child text remain undisclosed. It preserves the
sealed executable, privilege drop, clean environment and timeout/cleanup
controls. Progress messages never constitute success evidence on their own.

## Pending Verification

- Full-range pentest and exact-commit GitHub CI approval before tagging.

Local release checks passed, including historical compatibility/evidence checks,
Rust `1.99.0` tests/Clippy/docs, Rust `1.90.0` MSRV, packaging, dependency audits
and all selected Kani harnesses. Passing local checks are not permission to tag
or publish.

## Final Normal-Build SDK Evidence

The public SDK run with `--normal` passed against the signed `2.6.4` image.
`compat/onboarding/2.6.4/sdk-normal-tls-v3.json` is independently pinned with
SHA-256 `bd5d855ff99869fcaecfced5872efd0ee3830b0aa0be0f9259ddded6603e3fb7`.
The sealed executable SHA-256 is
`5738f7805803d14e59c1e29ad2cc69df90de84ece20ad86c47b865340a62388f`.
All stages passed, including the legacy LDAP, Kerberos and RADIUS paths.
The original `sdk-normal-tls.json` remains unchanged as pre-dependency-update
evidence; it cannot satisfy the current release gate. The pre-auth-fix
`sdk-normal-tls-v2.json` is also preserved and rejected as current evidence.

This build copies the checked-in SDK sources without a generated candidate
override. `scripts/verify_openbao_patch_normal_sdk.py` requires both patches'
separate normal-build reports, exact current executable input hashes, normal registry
identity, executable identities and full report semantics. Candidate reports
cannot satisfy this gate; they retain their original bytes and historical scope.
The sealed descriptor binds the executable hash to execution, not an independently
attested source-to-binary build. External backend authentication and PGP share
decryption are not established by these checks.

After capture, the README's pending-refresh status was
corrected. This is not a claim that the new README was present during execution:
the original report and its README hash are unchanged. The exact captured README
is retained as `compat/onboarding/2.7.1/sdk-capture-readme-v3.md`. The verifier permits
only the independently pinned old/new README pair; it still rejects changes or
omissions to every other captured input and any unreviewed README revision.
No Rust or build-script input incorporates the README into executable code.

The capture command is:

```sh
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_2_6_4.py --capture
```

It uses a disposable constrained container and isolated network, verifies TLS
and exact server version, removes its resources, and only then writes a public
evidence report under a fresh temporary directory. Its scope is server-fixture
only, not public SDK integration or normal profile promotion.
