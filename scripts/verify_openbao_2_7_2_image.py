#!/usr/bin/python3 -EsSB
"""Retain the signed OCI index-to-image-to-source chain for exact 2.7.2."""

import argparse
import base64
from pathlib import Path
import tempfile

import openbao_2_7_2 as patch

ATTESTATION = "sha256:981ebfee5b2fadd491efa1d99b2ca5dd85de6feafbf83ba78f5103df5457d072"
PROVENANCE = "sha256:d0c693476cfc46de70692bf4c4582b94aeff5c304f0a64dbe46b16b059515534"
BUNDLE_SHA256 = "0449c315cef3786638fa6e0e0ffe8119944004225b94b859cad4e010c8274799"
ARTIFACTS = {"image-index.json": patch.INDEX, "image-attestation-manifest.json": ATTESTATION,
             "image-provenance.json": PROVENANCE, "signature-bundle.json": BUNDLE_SHA256}
LIMIT = 2 * 1024 * 1024
OUTPUT = patch.ROOT / "compat/onboarding/2.7.2"


def pinned(data, digest):
    patch.require(patch.base.sha256(data) == digest.removeprefix("sha256:"))
    return data


def validate(artifacts):
    patch.require(set(artifacts) == set(ARTIFACTS))
    data = {name: pinned(artifacts[name], digest) for name, digest in ARTIFACTS.items()}
    index = patch.base.parse_json(data["image-index.json"], LIMIT)
    manifests = index["manifests"]
    children = [entry["digest"] for entry in manifests
                if entry.get("platform") == {"architecture": "amd64", "os": "linux"}]
    patch.require(children == [patch.AMD64])
    attestations = [entry["digest"] for entry in manifests
                    if entry.get("annotations", {}).get("vnd.docker.reference.digest") == patch.AMD64]
    patch.require(attestations == [ATTESTATION])
    manifest = patch.base.parse_json(data["image-attestation-manifest.json"], LIMIT)
    patch.require(manifest["subject"]["digest"] == patch.AMD64)
    layers = manifest["layers"]
    patch.require(len(layers) == 1 and layers[0]["digest"] == PROVENANCE
                  and layers[0]["size"] == len(data["image-provenance.json"]))
    provenance = patch.base.parse_json(data["image-provenance.json"], LIMIT)
    patch.require(provenance.get("predicateType") == "https://slsa.dev/provenance/v1")
    subjects = provenance.get("subject")
    patch.require(isinstance(subjects, list) and bool(subjects)
                  and all(subject.get("digest") == {"sha256": patch.AMD64.removeprefix("sha256:")}
                          for subject in subjects))
    args = provenance["predicate"]["buildDefinition"]["externalParameters"]["request"]["root"]["request"]["args"]
    patch.require(args.get("vcs:revision") == patch.SOURCE
                  and args.get("vcs:source") == "https://github.com/openbao/openbao")
    # Offline checks pin the previously acquired bundle. Cryptographic identity,
    # certificate and transparency checks are performed by Cosign during capture.
    lines = data["signature-bundle.json"].splitlines()
    patch.require(0 < len(lines) <= 32)
    for line in lines:
        bundle = patch.base.parse_json(line, LIMIT)
        patch.require(bundle.get("mediaType") == "application/vnd.dev.sigstore.bundle.v0.3+json")
        envelope = bundle["dsseEnvelope"]
        payload = patch.base.parse_json(base64.b64decode(envelope["payload"], validate=True), LIMIT)
        patch.require(payload.get("_type") == "https://in-toto.io/Statement/v1"
                      and payload.get("predicateType") == "https://sigstore.dev/cosign/sign/v1")
        subjects = payload.get("subject")
        patch.require(isinstance(subjects, list) and len(subjects) == 1
                      and subjects[0].get("digest") == {"sha256": patch.INDEX.removeprefix("sha256:")})
    return provenance


def verify():
    return validate({name: patch.base.read_regular_file(OUTPUT / name, LIMIT) for name in ARTIFACTS})


def retain(directory):
    # The supplied blob is authenticated by the signed index's descriptor chain,
    # not by trusting its download directory or a mutable image tag.
    patch.verify_signature()
    with tempfile.TemporaryDirectory(prefix="openbao-272-registry-") as temporary:
        auth = Path(temporary) / "auth.json"
        patch.harness.write_private(auth, patch.base.canonical_json({"auths": {}}), 0o600)
        _, index = patch.base.run_bounded([
            "skopeo", "inspect", "--raw", "--authfile", str(auth), "--no-creds",
            f"docker://docker.io/openbao/openbao@{patch.INDEX}"], LIMIT, timeout=120)
    artifacts = {
        "image-index.json": index,
        "image-attestation-manifest.json": patch.base.read_regular_file(directory / "manifest.json", LIMIT),
        "image-provenance.json": patch.base.read_regular_file(directory / PROVENANCE.removeprefix("sha256:"), LIMIT),
        "signature-bundle.json": patch.base.read_regular_file(OUTPUT / "signature-bundle.json", LIMIT),
    }
    validate(artifacts)
    for name, data in artifacts.items():
        patch.base.write_immutable(OUTPUT / name, data)
    verify()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retain-provenance-directory", type=Path)
    parser.add_argument("--online", action="store_true", help="also reverify the registry signature with Cosign")
    args = parser.parse_args()
    try:
        if args.retain_provenance_directory:
            retain(args.retain_provenance_directory)
        else:
            verify()
            if args.online:
                patch.verify_signature()
    except (patch.harness.HarnessError, patch.base.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("2.7.2 image/source evidence failed verification; no compatibility promotion")
        return 1
    print("2.7.2 pinned image/source chain verified; signature acquisition and runtime coverage remain distinct")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
