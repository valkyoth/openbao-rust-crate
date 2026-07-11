# OpenBao Compatibility Evidence

This directory contains immutable inputs for the OpenBao multi-version
compatibility model. Artifact and API-evidence verification do not by
themselves certify live behavior or server security. Version-locked behavior
tests, capability profiles, and security support decisions land in later
checkpoints.

Application-facing selection guidance, including exact policies, rolling
ranges, mixed clusters, assumed mode, and future-release onboarding, is in
[`docs/OPENBAO_VERSION_SELECTION.md`](../docs/OPENBAO_VERSION_SELECTION.md).

## Release Lock

`releases.lock.json` records the 21 published OpenBao releases selected for the
initial compatibility range. Each record contains:

- the exact official Git tag ref object and peeled source commit;
- the published, non-draft, non-prerelease GitHub Release timestamp;
- the exact multi-platform OCI index and `linux/amd64` manifest digests;
- the exact official release-workflow identity used for Cosign verification;
- the source commit and path used for documentation evidence;
- the separate snapshot-lock path and explicit pending state retained as the
  immutable Commit 02 checkpoint record.

All selected stable tags are lightweight Git tags. Their tag ref object is
therefore the commit object itself, and the tag object and peeled commit IDs
are equal. Lightweight tags cannot carry an annotated-tag signature, so the
lock records `not_available_lightweight_tag`; it does not claim that source
tags were cryptographically signed.

Repository tags `v2.3.0` and `v2.4.2` are intentionally absent: the GitHub
Releases API has no published release for either tag. A repository tag alone
does not enter the supported stable-release inventory.

OpenBao's OCI indexes and `linux/amd64` manifests were verified with Cosign
`3.1.1`, built from module tag `v3.1.1` at peeled source commit
`7914231b348c4057891edeb321772aad3ed04fce`. Verification constrained the
Fulcio certificate to:

```text
https://github.com/openbao/openbao/.github/workflows/release.yml@refs/tags/v<exact-version>
```

and the issuer to `https://token.actions.githubusercontent.com`. Cosign
validated the image claims, certificate chain, and transparency-log inclusion.
`image-signatures.lock.json` records SHA-256 fingerprints of the downloaded
Sigstore bundle streams for both locked digests. The bundles are not copied
into this repository; their fingerprints make later registry-evidence changes
visible without adding roughly two MiB of duplicated certificate material.

No Cosign `.att` OCI tags were present for this repository, and the GitHub
attestations API returned no SLSA provenance attestation for the checked image
indexes on `2026-07-10`. The lock records `not_published`; it does not convert
the verified image signatures into a provenance-attestation claim.

## Offline Validation

Run:

```sh
python3 scripts/validate_openbao_release_lock.py
python3 scripts/validate_openbao_release_lock.py --self-test
python3 scripts/openbao_api_snapshots.py --verify
python3 scripts/openbao_api_snapshots.py --self-test
python3 -B scripts/generate_openbao_response_fixtures.py --verify
python3 -B scripts/generate_openbao_response_fixtures.py --self-test
python3 -B scripts/generate_openbao_version_contracts.py --verify
python3 -B scripts/generate_openbao_version_contracts.py --self-test
python3 scripts/openbao_test_harness.py --self-test
python3 scripts/openbao_core_matrix.py --verify
python3 scripts/openbao_core_matrix.py --self-test
python3 -B scripts/openbao_ci_matrix.py self-test
```

The validator uses only the Python standard library and performs no network
access. It opens inputs in no-follow, non-blocking mode, rejects non-regular
files before reading, and reads at most the configured byte limit plus one
byte. It rejects oversized or deeply nested JSON, duplicate keys, unknown or
missing fields, path traversal, mutable tags, malformed or duplicate hashes,
reordered records, changed historical identifiers, and verification-status
downgrades. The release and signature locks each have a sidecar SHA-256 plus a
hard-coded validator anchor, so changing historical evidence requires an
explicit multi-file review.

## API Snapshot Lock

`api-snapshots.lock.json` binds two deterministic artifacts for each locked
release:

- `api-snapshots/<version>/documentation.json` is derived only from MDX blobs
  under `website/content/api-docs` at the exact locked source commit. It keeps
  every source blob identity and hash, plus normalized method, path, heading,
  and documented-field evidence.
- `api-snapshots/<version>/openapi.json` is captured from the exact locked OCI
  index after independently verifying its `linux/amd64` child manifest. The
  server runs without a network, host port, writable root filesystem, Linux
  capabilities, or root privileges. One instance of every documented built-in
  auth method and secrets engine is mounted before requesting generic mount
  paths.

Descriptions, examples, summaries, external links, and tags are excluded from
the normalized OpenAPI contract. Paths, methods, operation identifiers,
parameters, request bodies, responses, defaults, extensions, and component
schemas remain. Canonical key ordering makes repeated captures byte-identical;
the committed `2.5.5` capture was reproduced independently before the lock was
finalized.

`api-diffs/` records path, method, documented field, OpenAPI operation, and
component-schema changes between adjacent published releases. A zero-change
diff is still retained and hashed. Existing artifacts are immutable: the
generator accepts an existing file only when its bytes are identical.

Rendered `2.3.x`, `2.4.x`, and current `2.5.x` pages are separately recorded
under `rendered-api-cross-checks/`. They are explicitly secondary observations
because a minor-line or current website can change and cannot prove an exact
patch release. They never replace or modify tagged-source evidence. No
equivalent rendered routes are published for `2.0.x` through `2.2.x`.

The snapshot validator uses a hard-coded lock digest, bounded pre-parse JSON
scanning, duplicate-key rejection, exact artifact paths, bounded descriptor
reads, and no-follow/non-blocking file opens. It verifies every source commit,
OCI digest, artifact size/hash, internal version, count, predecessor diff, and
rendered-observation identity against the release inventory.

`tests/fixtures/openbao_response_profiles.json` is generated from these locked
OpenAPI documents. It carries the exact source digest for each release and
provides serde fixtures for reviewed response-shape transitions. CI regenerates
the file in memory and rejects any stale or manually detached fixture.

`version-contract-matrix.json` joins the capability registry, exact tagged
contracts, request-field rules, response fixtures, and representative live
core-flow results into all 13,986 operation/profile cells. Its generated
summary and the user-facing `docs/OPENBAO_VERSION_SUPPORT_MATRIX.md` derive
coverage percentages mechanically. Live and fixture evidence remains labeled
as representative so a profile pass cannot be misreported as an endpoint-level
live test.

To reproduce all online evidence from an exact OpenBao source clone:

```sh
python3 scripts/openbao_api_snapshots.py \
  --generate \
  --source-repository /path/to/openbao
```

Generation requires `git`, `skopeo`, and rootless `podman`. Existing committed
artifacts are never overwritten with different bytes.

## Reproducing Online Evidence

Source object type and peeling can be checked after fetching an exact tag:

```sh
git cat-file -t refs/tags/v2.5.5
git rev-parse refs/tags/v2.5.5
git rev-parse 'refs/tags/v2.5.5^{}'
```

Resolve the registry index and architecture manifest with `skopeo inspect
--raw`, then verify each digest with the exact tag identity:

```sh
cosign verify \
  --certificate-identity \
  'https://github.com/openbao/openbao/.github/workflows/release.yml@refs/tags/v2.5.5' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  'docker.io/openbao/openbao@sha256:<locked-digest>'
```

The release and API snapshot locks are append-only after their respective
checkpoints. Commit 03 did not rewrite the Commit 02 source or image identities.

## Version-Locked Integration Harness

`scripts/openbao_test_harness.py` consumes the validated release inventory and
accepts only one exact listed version. It starts
`docker.io/openbao/openbao@sha256:<locked-linux-amd64-digest>` with Podman and
verifies the pulled digest, architecture, operating system, and exact
`/sys/health` version before initialization or test execution.

Runs use an internal per-run network, dynamic loopback API port, in-memory
storage, random ownership-labeled resources, ephemeral TLS, and an inherited
anonymous memory-backed credential descriptor. No caller-supplied image, port,
resource name, command, or environment-selected version enters the container
command. Proxy inheritance is disabled for loopback requests. Cleanup checks
the ownership label before removal and fails the run if a runtime resource or
private temporary directory survives.

Run one exact inventory release with:

```sh
scripts/openbao_integration.sh 2.5.5
```

The harness invokes the image's `bao` binary directly instead of trusting its
version-dependent entrypoint wrapper. This is required for the 2.0.x and 2.1.x
images, whose wrapper otherwise injects a second config path and loads the
listener twice.

## Historical Core-Flow Results

`core-flow-results.json` records a successful live run against every one of the
21 exact releases in `releases.lock.json`, from `2.0.0` through `2.5.5`. Each
run verifies the reported server version and executes the same core subset:

- health and seal status;
- secrets and auth mount management;
- KV v1 and KV v2 read/write/list behavior;
- ACL policy management;
- token lookup, creation, capability checks, and revocation;
- caller, token, and accessor capability checks;
- response wrapping, lookup, and unwrap.

The result is intentionally labeled `tested-subset`. It does not claim that
every typed helper or every documented OpenBao endpoint was exercised on every
historical server. The report records zero skipped operations and binds the
exact release inventory, harness source, Rust test definition, image digest,
and reported server version. Its canonical bytes are protected by
`core-flow-results.sha256` and a hard-coded validator anchor.

The Rust test writes a completion attestation only after the complete flow and
post-test resource verification succeed. Missing, reordered, duplicated,
zero-test, or all-skipped operation evidence fails validation. Reports permit
only fixed classifications and reason codes and reject control characters so
tokens or raw server errors cannot enter committed evidence.

## Capability Registry

`capability-registry.json` and
`src/generated/openbao_capabilities.rs` are deterministic outputs of
`scripts/generate_openbao_capability_registry.py`. The registry assigns 664
stable operation identifiers across the union of exact tagged documentation
and the corrected 2.5.5 contract. Every operation has a contiguous,
non-overlapping range partition covering all 21 locked releases.

Availability means only that an exact tagged route is documented. It is not a
live-behavior result or a typed-SDK support claim. The pre-2.0 matrix's typed
and typed-gated labels are retained as explicitly named legacy claims until
later migration commits link concrete helpers, fields, transports, and tests.
Security-blocked operations are maintained in generator code and cannot be
made available by changing generated documentation input alone.

Public Rust reporting exposes stable identifiers, methods, and route templates
only. Templates never contain concrete mount names, secret paths, lease IDs,
token accessors, namespaces, or query values. Unknown and unpublished version
numbers do not select a profile merely because they sort between two releases.

Verify the anchored JSON and Rust outputs plus adversarial range, duplicate,
policy-downgrade, injection, and determinism checks:

```sh
python3 -B scripts/generate_openbao_capability_registry.py --verify
python3 -B scripts/generate_openbao_capability_registry.py --self-test
```

## Compatibility CI Matrix

`.github/workflows/openbao-compatibility.yml` obtains every matrix value from
the validated release inventory through `scripts/openbao_ci_matrix.py`. Pull
requests run `2.0.0` plus the latest patch in each OpenBao minor line. Scheduled
nightly runs, manual pre-release gates, and version-tag runs cover all 21 exact
releases.

Compatibility jobs do not use a shared Cargo cache or repository secrets. They
checkout without persisted credentials, run on a fixed hosted-runner image,
and upload only `ci-artifacts/openbao-result.json`. That bounded report contains
fixed identifiers, classifications, and operation statuses; it cannot contain
raw errors, server bodies, tokens, TLS keys, or server data.

The aggregate job downloads exactly one result artifact for every expected
version and rejects missing, extra, malformed, symlinked, reordered, or
identity-mismatched evidence. A failed core flow is reported separately from a
runner, download, cleanup, or artifact infrastructure failure. The aggregate
job runs even after matrix failures and is the stable required status for
branch protection. Manual `workflow_dispatch` runs provide the pre-tag
all-release gate; tag-triggered runs are independent post-tag confirmation.
Because pull-request workflows execute pull-request code, branch protection
must require `OpenBao Compatibility / Aggregate results` and CODEOWNER review
for changes to the workflow, controller, release locks, or their validators.
