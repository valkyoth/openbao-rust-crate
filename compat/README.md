# OpenBao Compatibility Evidence

This directory contains immutable inputs for the OpenBao multi-version
compatibility model. Artifact and API-evidence verification do not by
themselves certify live behavior or server security. Version-locked behavior
tests, capability profiles, and security support decisions land in later
checkpoints.

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
python3 scripts/openbao_test_harness.py --self-test
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

Commit 04 establishes secure version selection and isolation. It does not by
itself claim that the current integration flow passes every historical
release; that classification and machine-readable evidence belong to Commit
05.
