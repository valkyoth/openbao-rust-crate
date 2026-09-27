# OpenBao 2.7.0 Staged API Evidence

Checkpoint 02, reviewed 2026-09-27. This is API evidence, not promoted SDK
support or a successful application-level integration test. The active 25
profiles through 2.6.3 and all historical snapshots remain unchanged.

## Artifact Verification

- Official tag commit: `ca305a02daa68b203325daa1b25c18d7a252d4b3`.
- OCI index: `sha256:71156a1c6623a5fa3f5e61b0c6a8ead0faf0df29a778339188443551995d1315`.
- Linux amd64: `sha256:6d575d906d70d40b9d789149c8dc09897291c5a1707d4d0ba8a459eaaa94c8c4`.
- Cosign 3.1.2 verified the exact certificate identity
  `https://github.com/openbao/openbao/.github/workflows/release-images.yml@refs/tags/v2.7.0`
  with issuer `https://token.actions.githubusercontent.com`, signature claims,
  certificate trust and transparency-log inclusion. No verification bypasses.
- The child has no separately published signature. Its descriptor is bound by
  the signed index. The index also binds its attestation manifest, which binds
  the SLSA v1 provenance blob; provenance subjects match the amd64 digest and
  `externalParameters.request.root.request.args` names the reviewed source
  revision and official repository. This is an attested build claim, not an
  independently reproduced build.
- Raw index, attestation manifest, provenance and signature bundle bytes are
  retained under `compat/onboarding/2.7.0/`. The lock and script anchor their
  hashes and sizes. Offline checks verify unchanged evidence and bindings;
  they do not perform a fresh Sigstore trust verification.

Fresh online verification: `/usr/bin/python3 -E -s -S -B scripts/openbao_2_7_api.py --verify-image`.

Evidence acquisition executes only the system-installed `/usr/bin/cosign`,
`git`, `skopeo` and `podman`, checking root ownership and non-writable parents
and resolved targets. It does not search the caller's PATH. Each invocation
gets a private temporary home/config/cache and an allowlisted environment;
remote-container, proxy, custom trust-root, dynamic-loader and Git environment
overrides are not inherited. Cosign must return verified claims for the exact
index, not merely exit successfully. Install the tools through trusted host
administration; user-local installations are intentionally not accepted.

Run evidence Python scripts with `/usr/bin/python3 -E -s -S -B`, as shown
below and enforced in checks, release gates and compatibility CI. These flags
ignore Python environment overrides and disable user-site and automatic site
initialization before imports execute. Executable script shebangs use the
equivalent `-EsSB`. Plain `python3 -B` is not a trusted verification entry point:
it honors `PYTHONPATH` and startup customization. The repository's own scripts
directory remains importable and must be trusted. The host must provision a
trusted system interpreter and standard library; these flags do not protect
against a compromised interpreter, OS loader, root account or repository.
The historical integration harness retains its hash-bound source bytes but is
no longer executable directly. Run it through `scripts/openbao_integration.sh`
or the explicit isolated interpreter command; historical evidence is not
rewritten just to replace its old shebang.

This trusts the host OS, system tool packages, system configuration and Python
runtime. It is not a hermetic, binary-digest-pinned builder and does not defend
against a compromised root account or a process able to modify the verifier
itself. Root-owned files remapped to another UID by a sandbox fail closed;
run acquisition on the actual trusted host. Offline artifact checks need no
installed acquisition tools. Rootless capture is not established by these
checks; the verified capture used rootful Podman as described below.

## Capture Scope

The digest-pinned image reported exactly 2.7.0. Runtime OpenAPI was captured
inside a network-isolated, read-only, capability-dropped dev container with
memory, CPU, swap and task limits verified. Rootful Podman was required on
this host to enforce those limits; they were not relaxed. Communication was
local to that isolated container, not a live TLS application test.

The capture mounts nine secret engines and five auth engines. It contains
724 runtime operations, 503 paths and 545 schemas. The missing LDAP secret
engine and LDAP/Kerberos/RADIUS auth engines are explicitly listed as excluded
because their built-in distributions were removed. Their external-plugin
contracts and fixtures belong to checkpoint 03, not a successful skipped test.

`--capture-runtime` on the staged evidence script first verifies the frozen
evidence and image signature, then writes a fresh capture into a new temporary
directory. It never changes active profiles. Fresh evidence can be compared
with the locked capture; a new capture does not silently replace it.

## Parser And Delta

The v2 documentation extractor handles comma/slash method lists, nested
operation headings, fenced samples and the historical `Path -` header typo.
It keeps each operation's fields out of sibling operations, rejects malformed
or duplicate methods, and bounds source bytes, sections, operations and fields.
The v1 extractor and its historical output are preserved.

An aggregate budget permits at most 65,536 emitted field occurrences and 4,096
operations across the entire extraction, checked before deep copying. Snapshot
validation independently enforces the budget before serialization. Exact
duplicate records are canonicalized; conflicting records with the same method,
path, source and heading are rejected. The checkpoint 02 pentest corrections
remove two duplicate ACME rows from each staged document; historical active
snapshots and the raw runtime capture are unchanged.

The predecessor is re-extracted with v2 from the exact 2.6.3 source, with its
file identities checked against the immutable v1 snapshot. V2 finds 695
records before deduplication, or 693 canonical records, and 711 canonical
records in 2.7.0. All historical v1 route identities
must remain present. The six recovered predecessor identities are:

- `GET /sys/internal/inspect/request/root`
- `GET /sys/rotate/(root|recovery)/backup`
- `POST /sys/rotate/(root|recovery)/update`
- `POST /sys/rotate/root`
- `POST /ssh/issuer/:issuer_ref`
- `PATCH /ssh/issuer/:issuer_ref`

These are extraction corrections, not new 2.7 APIs. Checkpoints 09/10 must
reconcile their existing typed route identities and dispositions explicitly.

The like-for-like staged delta has 189 records: 36 tagged-documentation field
or route changes, 73 runtime operation changes and 80 schema changes. The
52 removed runtime operation identities all belong to the excluded engines.
Do not interpret their absence as removal of older SDK support or proof that
external plugins do not provide them. The 18 new documented method/path rows
cover external keys (16) and control groups (2).

## Reviewed Discrepancies And Follow-Up

| Evidence boundary | Finding and required treatment |
| --- | --- |
| External-key method aliases | Tagged tables document POST, PUT and PATCH. Runtime OpenAPI maps logical updates to POST; verify PUT behavior against HTTP dispatch when implementing. |
| External-key path names | Docs use `:name`, `:config_name`, `:key_name`, and `:mount-path`; runtime source uses `config`, `key`, and greedy `mount`. Canonicalize registry identities deliberately and preserve validated mount-path grants. |
| Provider-specific fields | `logical_system_external_keys.go` sets `TakesArbitraryInput`; generic OpenAPI fields cannot prove complete Transit/PKCS#11 provider schemas. Review tagged provider docs and pinned plugin source separately; credentials remain sensitive. |
| LIST/SCAN | OpenAPI standard-method projection can collapse these operations. In particular, the workflow list schema/operation metadata changed; inspect source and test both behaviors rather than equating GET metadata with every logical method. |
| Conditional workflows | The default capture does not enable unauthenticated workflows. Their docs/source remain relevant; preserve acknowledgements and test enabled/disabled configurations later. |
| Workflow CAS and prefix listing | The release reports a CAS fix and source now checks the supplied version against the existing entry under the store lock. That does not prove every zero/absent/create case or prefix behavior. Neither old security block is lifted at this checkpoint. |
| Transit external mu | Tagged sign source accepts `mldsa-mu` only for prehashed ML-DSA-compatible keys; verification explicitly rejects that mode. Do not add a symmetric sign/verify API on inference alone. |
| Transit imported key response | Tagged docs now show `imported_key`; source emits that field. Compare older sources and decoder aliases before classifying this as a new-only field. |
| Consistency and control groups | HTTP headers and conditional approval/wrapping behavior are not proven by OpenAPI shapes. Require shared-transport, secret-handling and multi-node/approval lifecycle tests. |
| Plugin prune | `internal/command/plugin_prune.go` operates on local server configuration and plugin storage, not a new documented system HTTP endpoint. Do not invent an SDK route. |
| PQC and PKI | ML-DSA values, signature defaults, `use_pss` and external-key semantics need source/behavior review beyond structural schema differences. Server TLS support does not establish SDK TLS support. |

The [official release](https://github.com/openbao/openbao/releases/tag/v2.7.0)
and rendered [external-key](https://openbao.org/docs/api/system/external-keys/)
and [control-group](https://openbao.org/docs/api/system/control-group/) pages
were also reviewed as secondary context. Rendered pages are not immutable
inputs or substitutes for the tagged documentation and runtime capture.

## Offline Checks

```sh
/usr/bin/python3 -E -s -S -B scripts/openbao_2_7_source_inventory.py --verify
/usr/bin/python3 -E -s -S -B scripts/openbao_2_7_api.py --verify
/usr/bin/python3 -E -s -S -B scripts/openbao_2_7_api.py --self-test
/usr/bin/python3 -E -s -S -B scripts/openbao_documentation_v2.py
/usr/bin/python3 -E -s -S -B scripts/test_openbao_evidence.py
```

Tests cover method expansion, sibling-field isolation, code fences, the
historical header typo, malformed/duplicate methods, section/field limits,
artifact tampering, provenance bindings, missing mounts, diff reconstruction,
lost historical routes, and rejection of implicit all-engine promotion. Shared
snapshot tests retain regular-file/no-follow/nonblocking reads, JSON bounds,
container limits and historical artifact verification.
Additional regressions exercise poisoned PATH/environment handling through
both process launchers, unsafe tool paths, empty/wrong Cosign claims, aggregate
field expansion before copying/serialization, shared cross-file budgets and
duplicate/conflicting operation identities.
Subprocess tests reproduce a false-green result with hostile `copy.py` and
`sitecustomize.py`, then prove the production isolated command verifies the
actual evidence without loading those modules. Entry-point checks prevent
dropping isolation flags from shell/CI commands or executable Python shebangs.
