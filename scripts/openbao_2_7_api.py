#!/usr/bin/python3 -EsSB
"""Generate and verify staged 2.7.0 API evidence without promoting runtime support."""

from __future__ import annotations

import argparse
import copy
import sys
import tempfile
from pathlib import Path
from typing import Any

import openbao_api_snapshots as base
import openbao_documentation_v2 as documentation
import openbao_2_7_source_inventory as inventory

ROOT = Path(__file__).resolve().parents[1]
STAGED = ROOT / "compat/onboarding/2.7.0"
LOCK = STAGED / "api-evidence.lock.json"
EXPECTED_LOCK_SHA256 = "f0735addf3d20d4aeaca36f7c3a0a4cbbcd0874770381a8cb6cf6b6d6bb50cf8"
INDEX = "sha256:71156a1c6623a5fa3f5e61b0c6a8ead0faf0df29a778339188443551995d1315"
AMD64 = "sha256:6d575d906d70d40b9d789149c8dc09897291c5a1707d4d0ba8a459eaaa94c8c4"
ATTESTATION = "sha256:13771c09cd2f98950d1bfe21ce198d039cd41b071cc626e59f345b0c1f499897"
PROVENANCE = "sha256:d12155b3b8e6bb347da5b53e509822ef259b11bb1d377d8ca544a7ad6456b187"
BUNDLE_SHA256 = "01dfa2a5f173b8c3e7684c5243c0bfc7cd830724a6dbfab4259080e764241bb9"
IDENTITY = "https://github.com/openbao/openbao/.github/workflows/release-images.yml@refs/tags/v2.7.0"
ISSUER = "https://token.actions.githubusercontent.com"
MAX_ARTIFACT_BYTES = base.MAX_OPENAPI_BYTES
ARTIFACT_NAMES = frozenset({
    "release-evidence.json", "image-index.json", "image-attestation-manifest.json",
    "image-provenance.json", "signature-bundle.json", "documentation.json",
    "predecessor-2.6.3-documentation-v2.json", "openapi.json", "2.6.3--2.7.0.json",
})
RELEASE = {
    "version": "2.7.0",
    "source": {"peeled_commit_sha1": inventory.SOURCE_COMMIT},
    "documentation": {"source_path": "website/content/docs/api"},
    "image": {"index_digest": INDEX, "linux_amd64_digest": AMD64},
}
PREDECESSOR = {
    "version": "2.6.3",
    "source": {"peeled_commit_sha1": "63a65e6b907589dbb952c371a70260a065bf8bd7"},
    "documentation": {"source_path": "website/content/docs/api"},
}
EXCLUDED = [
    {"kind": "secret", "path": "ldap", "type": "ldap"},
    {"kind": "auth", "path": "kerberos", "type": "kerberos"},
    {"kind": "auth", "path": "ldap", "type": "ldap"},
    {"kind": "auth", "path": "radius", "type": "radius"},
]
PREDECESSOR_OPENAPI_SHA256 = "2e03c8864113c0f72c61735a72517c2a9b21e0e8b5b9a42a1dd0d0fc8262f67a"


def pinned(data: bytes, digest: str) -> bytes:
    if base.sha256(data) != digest.removeprefix("sha256:"):
        raise base.SnapshotError("staged artifact digest changed")
    return data


def parse(data: bytes) -> dict[str, Any]:
    return base.parse_json(data, MAX_ARTIFACT_BYTES)


def release_evidence() -> dict[str, Any]:
    return {
        "schema": "openbao-staged-release-evidence/v1",
        **copy.deepcopy(RELEASE),
        "release_url": "https://github.com/openbao/openbao/releases/tag/v2.7.0",
        "published_at": "2026-09-23T17:39:54Z",
        "observed_on": "2026-09-27",
        "source_tag_signature": "not_available_lightweight_tag",
        "cosign_version": "3.1.2",
        "certificate_identity": IDENTITY,
        "certificate_oidc_issuer": ISSUER,
        "index_signature": "verified_cosign_keyless",
        "amd64_signature": "not_published_bound_by_verified_index",
        "signature_bundle_sha256": BUNDLE_SHA256,
        "attestation_manifest_digest": ATTESTATION,
        "provenance_blob_digest": PROVENANCE,
        "provenance_source_revision": inventory.SOURCE_COMMIT,
        "runtime_scope": "built-in-only; external-plugin contracts require checkpoint 03",
        "excluded_mounts": EXCLUDED,
        "routable": False,
    }


def verify_image_signature() -> None:
    # No ignore-tlog, insecure-registry, or certificate-check bypass is permitted.
    _, output = base.run_bounded([
        "cosign", "verify", "--certificate-identity", IDENTITY,
        "--certificate-oidc-issuer", ISSUER, f"docker.io/openbao/openbao@{INDEX}",
    ], 1024 * 1024, timeout=180)
    validate_signature_output(output)


def validate_signature_output(output: bytes) -> None:
    signatures = base.parse_json(b'{"signatures":' + output + b'}', 1024 * 1024 + 32)["signatures"]
    if not isinstance(signatures, list) or not signatures or len(signatures) > 32:
        raise base.SnapshotError("Cosign did not return bounded verified signatures")
    for signature in signatures:
        if not isinstance(signature, dict) or not isinstance(signature.get("critical"), dict):
            raise base.SnapshotError("Cosign signature claims are malformed")
        critical = signature["critical"]
        if critical.get("image") != {"docker-manifest-digest": INDEX} or critical.get("type") != "https://sigstore.dev/cosign/sign/v1":
            raise base.SnapshotError("Cosign verified a different image or claim type")


def fetch_manifest(digest: str) -> bytes:
    _, data = base.run_bounded([
        "skopeo", "inspect", "--raw", f"docker://docker.io/openbao/openbao@{digest}",
    ], 2 * 1024 * 1024, timeout=120)
    return pinned(data, digest)


def validate_image_chain(artifacts: dict[str, bytes]) -> None:
    index = parse(pinned(artifacts["image-index.json"], INDEX))
    manifests = index.get("manifests", [])
    children = [m.get("digest") for m in manifests if m.get("platform") == {"architecture": "amd64", "os": "linux"}]
    if children != [AMD64]:
        raise base.SnapshotError("index does not bind the reviewed amd64 image")
    attestations = [m.get("digest") for m in manifests if m.get("annotations", {}).get("vnd.docker.reference.digest") == AMD64]
    if attestations != [ATTESTATION]:
        raise base.SnapshotError("index does not bind the reviewed provenance manifest")
    manifest = parse(pinned(artifacts["image-attestation-manifest.json"], ATTESTATION))
    if manifest.get("subject", {}).get("digest") != AMD64:
        raise base.SnapshotError("provenance manifest subject changed")
    layers = manifest.get("layers", [])
    if len(layers) != 1 or layers[0].get("digest") != PROVENANCE:
        raise base.SnapshotError("provenance layer identity changed")
    provenance = parse(pinned(artifacts["image-provenance.json"], PROVENANCE))
    if provenance.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise base.SnapshotError("provenance predicate type changed")
    subjects = provenance.get("subject", [])
    if not subjects or any(s.get("digest", {}).get("sha256") != AMD64.removeprefix("sha256:") for s in subjects):
        raise base.SnapshotError("provenance image subject changed")
    args = provenance["predicate"]["buildDefinition"]["externalParameters"]["request"]["root"]["request"]["args"]
    if args.get("vcs:revision") != inventory.SOURCE_COMMIT or args.get("vcs:source") != "https://github.com/openbao/openbao":
        raise base.SnapshotError("provenance source revision changed")
    pinned(artifacts["signature-bundle.json"], BUNDLE_SHA256)
    if artifacts["release-evidence.json"] != base.canonical_json(release_evidence()):
        raise base.SnapshotError("release evidence or capture scope changed")


def predecessor_bytes() -> tuple[bytes, bytes]:
    docs = base.read_regular_file(inventory.PREDECESSOR, base.MAX_SNAPSHOT_BYTES)
    api = base.read_regular_file(ROOT / "compat/api-snapshots/2.6.3/openapi.json", MAX_ARTIFACT_BYTES)
    return pinned(docs, inventory.PREDECESSOR_SHA256), pinned(api, PREDECESSOR_OPENAPI_SHA256)


def build_diff(before_docs: bytes, docs: bytes, api: bytes) -> bytes:
    _, before_api = predecessor_bytes()
    return base.canonical_json(base.build_diff(
        "2.6.3", parse(before_docs), parse(before_api), "2.7.0", parse(docs), parse(api),
        {"documentation": base.sha256(before_docs), "openapi": base.sha256(before_api)},
        {"documentation": base.sha256(docs), "openapi": base.sha256(api)},
    ))


def validate_artifacts(artifacts: dict[str, bytes]) -> None:
    if set(artifacts) != ARTIFACT_NAMES:
        raise base.SnapshotError("staged artifact set changed")
    source = inventory.verify()
    validate_image_chain(artifacts)
    docs = parse(artifacts["documentation.json"])
    before = parse(artifacts["predecessor-2.6.3-documentation-v2.json"])
    documentation.validate(docs, RELEASE)
    documentation.validate(before, PREDECESSOR)
    historical_docs, _ = predecessor_bytes()
    if docs["files"] != source["files"] or before["files"] != parse(historical_docs)["files"]:
        raise base.SnapshotError("v2 extraction rewrote tagged source identities")
    if not base.operation_index(parse(historical_docs)).keys() <= base.operation_index(before).keys():
        raise base.SnapshotError("v2 predecessor extraction lost a historical documented route")
    api_data = artifacts["openapi.json"]
    base.validate_openapi_snapshot(parse(api_data), api_data, {
        "version": "2.7.0", "image_index_digest": INDEX, "image_linux_amd64_digest": AMD64,
    }, expected_schema="openbao-normalized-openapi/v2", builtin_only_2_7=True)
    expected_diff = build_diff(artifacts["predecessor-2.6.3-documentation-v2.json"], artifacts["documentation.json"], api_data)
    if artifacts["2.6.3--2.7.0.json"] != expected_diff:
        raise base.SnapshotError("staged API diff does not match its inputs")


def build_artifacts(repository_text: str, runtime: Path, provenance: Path, bundle: Path) -> dict[str, bytes]:
    repository = base.validate_source_repository(repository_text)
    inventory.verify()
    docs = base.canonical_json(documentation.extract(repository, RELEASE))
    before = base.canonical_json(documentation.extract(repository, PREDECESSOR))
    api = base.read_regular_file(runtime, MAX_ARTIFACT_BYTES)
    artifacts = {
        "release-evidence.json": base.canonical_json(release_evidence()),
        "image-index.json": fetch_manifest(INDEX),
        "image-attestation-manifest.json": fetch_manifest(ATTESTATION),
        "image-provenance.json": base.read_regular_file(provenance, 2 * 1024 * 1024),
        "signature-bundle.json": base.read_regular_file(bundle, 1024 * 1024),
        "documentation.json": docs,
        "predecessor-2.6.3-documentation-v2.json": before,
        "openapi.json": api,
        "2.6.3--2.7.0.json": build_diff(before, docs, api),
    }
    validate_artifacts(artifacts)
    return artifacts


def lock_bytes(artifacts: dict[str, bytes]) -> bytes:
    return base.canonical_json({
        "schema": "openbao-staged-api-evidence/v1", "version": "2.7.0",
        "status": "evidence-only-not-routable", "runtime_scope": "built-in-only",
        "excluded_mounts": EXCLUDED, "source_inventory_sha256": inventory.EXPECTED_SHA256,
        "artifacts": {name: {"sha256": base.sha256(data), "bytes": len(data)} for name, data in sorted(artifacts.items())},
    })


def verify() -> dict[str, bytes]:
    lock_data = pinned(base.read_regular_file(LOCK, base.MAX_LOCK_BYTES), EXPECTED_LOCK_SHA256)
    locked = parse(lock_data)
    if set(locked["artifacts"]) != ARTIFACT_NAMES:
        raise base.SnapshotError("staged artifact names changed")
    artifacts = {}
    for name in sorted(ARTIFACT_NAMES):
        record = locked["artifacts"][name]
        data = pinned(base.read_regular_file(STAGED / name, MAX_ARTIFACT_BYTES), record["sha256"])
        if len(data) != record["bytes"]:
            raise base.SnapshotError("staged artifact length changed")
        artifacts[name] = data
    if lock_data != lock_bytes(artifacts):
        raise base.SnapshotError("staged lock metadata changed")
    checksum = base.read_regular_file(STAGED / "api-evidence.lock.sha256", 128)
    if checksum != f"{EXPECTED_LOCK_SHA256}  api-evidence.lock.json\n".encode():
        raise base.SnapshotError("staged lock checksum changed")
    validate_artifacts(artifacts)
    return artifacts


def self_test() -> None:
    artifacts = verify()
    documentation.self_test()
    for name in sorted(ARTIFACT_NAMES):
        data = artifacts[name]
        base.expect_rejected("altered artifact", lambda: pinned(data + b" ", base.sha256(data)))
    for name in ("image-index.json", "image-attestation-manifest.json", "image-provenance.json", "release-evidence.json"):
        altered = dict(artifacts)
        altered[name] = b"{}"
        base.expect_rejected("altered image chain", lambda: validate_image_chain(altered))
    altered = dict(artifacts)
    api = parse(altered["openapi.json"])
    base.expect_rejected("implicit all-engine promotion", lambda: base.validate_openapi_snapshot(
        api, artifacts["openapi.json"], {
            "version": "2.7.0", "image_index_digest": INDEX, "image_linux_amd64_digest": AMD64,
        }, expected_schema="openbao-normalized-openapi/v2",
    ))
    api["mounts"] = []
    altered["openapi.json"] = base.canonical_json(api)
    base.expect_rejected("missing built-in mounts", lambda: validate_artifacts(altered))
    altered = dict(artifacts)
    altered["2.6.3--2.7.0.json"] = b"{}"
    base.expect_rejected("unbound diff", lambda: validate_artifacts(altered))
    altered = dict(artifacts)
    before = parse(altered["predecessor-2.6.3-documentation-v2.json"])
    before["operations"] = [op for op in before["operations"] if op["path"] != "/sys/plugins/reload/backend"]
    altered["predecessor-2.6.3-documentation-v2.json"] = base.canonical_json(before)
    base.expect_rejected("lost predecessor route", lambda: validate_artifacts(altered))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    for name in ("verify", "self-test", "generate", "verify-image", "capture-runtime"):
        action.add_argument("--" + name, action="store_true")
    parser.add_argument("--source-repository")
    parser.add_argument("--runtime-capture", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--signature-bundle", type=Path)
    args = parser.parse_args()
    try:
        if args.generate:
            if not all((args.source_repository, args.runtime_capture, args.provenance, args.signature_bundle)):
                parser.error("generation requires source repository, runtime capture, provenance and signature bundle")
            verify_image_signature()
            artifacts = build_artifacts(args.source_repository, args.runtime_capture, args.provenance, args.signature_bundle)
            lock = pinned(lock_bytes(artifacts), EXPECTED_LOCK_SHA256)
            for name, data in artifacts.items():
                base.write_immutable(STAGED / name, data)
            base.write_immutable(LOCK, lock)
            base.write_immutable(STAGED / "api-evidence.lock.sha256", f"{EXPECTED_LOCK_SHA256}  api-evidence.lock.json\n".encode())
        elif args.self_test:
            self_test()
        elif args.verify_image:
            verify()
            verify_image_signature()
        elif args.capture_runtime:
            verify()
            verify_image_signature()
            output = Path(tempfile.mkdtemp(prefix="openbao-270-evidence-"))
            print(f"Output directory: {output}", flush=True)
            api = base.capture_openapi(RELEASE, builtin_only_2_7=True)
            base.write_immutable(output / "openapi.json", base.canonical_json(api))
            output.chmod(0o755)
        else:
            verify()
        print("OpenBao 2.7.0 staged API evidence: ok (built-in-only; not routable)")
        return 0
    except (base.SnapshotError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"OpenBao 2.7.0 staged evidence failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
