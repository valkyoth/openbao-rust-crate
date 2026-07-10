# OpenBao Compatibility Evidence

This directory contains immutable inputs for the OpenBao multi-version
compatibility model. Artifact verification does not by itself certify API or
security compatibility. API snapshots, live behavior evidence, capability
profiles, and security support decisions land in later checkpoints.

## Release Lock

`releases.lock.json` records the 21 published OpenBao releases selected for the
initial compatibility range. Each record contains:

- the exact official Git tag ref object and peeled source commit;
- the published, non-draft, non-prerelease GitHub Release timestamp;
- the exact multi-platform OCI index and `linux/amd64` manifest digests;
- the exact official release-workflow identity used for Cosign verification;
- the source commit and path reserved for documentation evidence;
- explicit pending status for API snapshots and compatibility review.

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
```

The validator uses only the Python standard library and performs no network
access. It rejects oversized or deeply nested JSON, duplicate keys, unknown or
missing fields, path traversal, mutable tags, malformed or duplicate hashes,
reordered records, changed historical identifiers, and verification-status
downgrades. The release and signature locks each have a sidecar SHA-256 plus a
hard-coded validator anchor, so changing historical evidence requires an
explicit multi-file review.

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

The release lock is append-only after this checkpoint. Commit 03 adds a
separate API-snapshot lock rather than rewriting these source and image
identities.
