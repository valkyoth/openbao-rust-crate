#!/usr/bin/python3 -EsSB
"""Retain exact 2.7.2 advanced normal and candidate SDK evidence separately."""

import argparse
from pathlib import Path

import openbao_2_7_2_sdk_advanced as fixture
import verify_openbao_2_7_2 as initial

PINS = {
    "normal": ("1b8e424047bcec331fd891defbf0539d056b43e5f8e97c645e22902b350565f2",
               "ff2a02283d9caf85643a9edc22030ef2df67eaa590bfa766ebcfe2dba98d8726"),
    "candidate": ("be7022a34c3b18f043a40d70de4d11c9760819c92bf771a22c3436344e454b91",
                  "91dce38089177cc3851f230847953e312b532a844fce38661c08f190e9ffb5fe"),
}


def output(mode):
    fixture.patch.require(mode in PINS)
    return initial.OUTPUT / (f"sdk-advanced-{mode}-tls-v4.json")


def expected(mode, binary):
    normal = mode == "normal"
    report = {
        **fixture.execution.EXECUTION_ASSURANCE,
        "schema": "openbao-patch-sdk-advanced-tls/v1",
        "version": fixture.patch.VERSION,
        "inputs": fixture.input_hashes(normal=normal),
        "test_binary_sha256": binary,
        "tests": fixture.TESTS,
        "features": fixture.FEATURES,
        "checks": fixture.CHECKS,
        "scope": "public-sdk-strict-disposable-candidate-build",
        "image_linux_amd64_digest": fixture.patch.AMD64,
        "image_index_digest": fixture.patch.INDEX,
        "routable": False,
        "outcome": "passed",
        "backup_decryption_verified": False,
        "synthetic_indices": "test-only-never-observable-cancellation-and-timeout",
    }
    if normal:
        report.update(fixture.normal_sdk.verify())
    else:
        generated = fixture.base.sha256(fixture.candidate.registry.rust_output(
            fixture.candidate.verify(), verification_candidate=True))
        report.update(
            candidate_registry_sha256=fixture.candidate.EXPECTED_SHA256,
            candidate_generated_rust_sha256=generated,
            source_scope="repository-inputs-with-explicit-generated-candidate-override",
        )
    return report


def validate(mode, data):
    digest, binary = PINS[mode]
    report = initial.checked(data, digest, 128 * 1024)
    fixture.patch.require(data == fixture.base.canonical_json(report)
                          and report == expected(mode, binary))
    return report


def verify(mode):
    return validate(mode, fixture.base.read_regular_file(output(mode), 128 * 1024))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=PINS)
    parser.add_argument("--retain", type=Path)
    args = parser.parse_args()
    if args.retain and not args.mode:
        parser.error("--retain requires --mode")
    try:
        if args.retain:
            data = fixture.base.read_regular_file(args.retain, 128 * 1024)
            validate(args.mode, data)
            fixture.base.write_immutable(output(args.mode), data)
        for mode in ([args.mode] if args.mode else PINS):
            verify(mode)
    except (fixture.harness.HarnessError, fixture.base.SnapshotError,
            fixture.candidate.registry.RegistryError, OSError, ValueError, KeyError, TypeError):
        print("2.7.2 advanced SDK evidence failed verification; no compatibility promotion")
        return 1
    print("2.7.2 advanced normal and candidate SDK evidence verified with separate scopes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
