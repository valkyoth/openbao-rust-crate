#!/usr/bin/python3 -EsSB
"""Validate retained artifact-only evidence; never enable plugin routing."""

from pathlib import Path

import openbao_api_snapshots as base
import openbao_plugin_artifacts as artifacts

EVIDENCE = artifacts.ROOT / "compat/plugins/artifact-review-v1.json"
EXPECTED_SHA256 = "20326b44fe331ce43b3a6174ef02e487244f769dee21be8dbf1fdf23464b55a6"
LICENSE_SHA256 = "3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04"


def expected():
    document = artifacts.lock()
    inputs = {str(path.relative_to(artifacts.ROOT)): base.sha256(base.read_regular_file(path, 1024 * 1024))
              for path in (artifacts.LOCK, artifacts.KEY, Path(artifacts.__file__),
                           artifacts.ROOT / "scripts/openbao_api_snapshots.py")}
    return {"schema": "openbao-plugin-artifact-review/v1", "inputs": inputs,
            "platform": document["platform"], "source_commit": document["source_commit"],
            "signing_primary_fingerprint": artifacts.PRIMARY,
            "plugins": [{"id": plugin["id"], "version": plugin["version"],
                         "binary_sha256": plugin["binary_sha256"],
                         "license_sha256": LICENSE_SHA256, "signature_verified": True}
                        for plugin in document["plugins"]],
            "scope": "artifact-signature-and-identity-only", "routable": False,
            "contracts_verified": False, "source_to_binary_provenance_verified": False}


def verify():
    data = base.read_regular_file(EVIDENCE, 32 * 1024)
    artifacts.require(base.sha256(data) == EXPECTED_SHA256)
    artifacts.require(data == base.canonical_json(expected()))
    return base.parse_json(data, 32 * 1024)


if __name__ == "__main__":
    verify()
    print("Retained plugin artifact evidence verified; compatibility remains excluded")
