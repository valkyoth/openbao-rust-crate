#!/usr/bin/python3 -EsSB
"""Exact normal-source builds and provenance for final patch SDK fixtures."""

import json
import os
from pathlib import Path
import tempfile

import check_openbao_2_7_candidate_sdk as builder
import generate_openbao_patch_registry as combined

registry = combined.registry


def verify():
    reviewed = combined.verify()
    expected = registry.rust_output(reviewed, promoted_patches=True)
    actual = registry.read_regular_file(registry.RUST_PATH, registry.MAX_OUTPUT_BYTES)
    combined.require(actual == expected and registry.sha256(actual) == registry.EXPECTED_RUST_SHA256)
    return {"combined_registry_sha256": combined.EXPECTED_SHA256,
            "generated_rust_sha256": registry.sha256(actual),
            "source_scope": "repository-normal-build-no-generated-override",
            "scope": "public-sdk-strict-normal-build", "routable": True}


def input_hashes():
    paths = ("scripts/openbao_patch_normal_sdk.py", "scripts/generate_openbao_patch_registry.py",
             "scripts/generate_openbao_2_6_4_candidate.py", "scripts/generate_openbao_2_7_1_candidate.py",
             "scripts/generate_openbao_capability_registry.py",
             "compat/onboarding/2.6.4/candidate-capability-registry.json",
             "compat/onboarding/2.7.1/candidate-capability-registry-v2.json",
             str(combined.OUTPUT.relative_to(registry.ROOT)))
    return {path: registry.sha256(registry.read_regular_file(registry.ROOT / path, registry.MAX_OUTPUT_BYTES))
            for path in paths}


def prepare(destination, inputs):
    # Unlike a candidate build, every source byte is copied without an override.
    for relative, value in inputs.items():
        path = Path(relative)
        combined.require(not path.is_absolute() and ".." not in path.parts)
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(value)


def build(features, hashes):
    combined.require(os.geteuid() != 0)
    before, provenance = hashes(), verify()
    inputs = builder.backup_inputs(builder.source_inputs())
    with tempfile.TemporaryDirectory(prefix="openbao-normal-sdk-build-") as temporary:
        root = Path(temporary)
        prepare(root, inputs)
        env = builder.build_environment(root)
        env["CARGO_TARGET_DIR"] = str(registry.ROOT / "target")
        messages = builder.run(["cargo", "test", "--locked", "--offline", "--no-default-features",
            "--features", features, "--lib", "--no-run", "--message-format=json-render-diagnostics"], root, env, capture=True)
        artifacts = [json.loads(line) for line in messages.splitlines() if line.strip()]
        binaries = [Path(item["executable"]) for item in artifacts if item.get("reason") == "compiler-artifact"
                    and item.get("executable") and item.get("target", {}).get("name") == "openbao"
                    and item.get("profile", {}).get("test") is True]
        combined.require(len(binaries) == 1)
    combined.require(before == hashes() and provenance == verify()
                     and inputs == builder.backup_inputs(builder.source_inputs()))
    print(f"Normal-build SDK binary: {binaries[0]}")
    print("Build only; final live verification remains pending")
