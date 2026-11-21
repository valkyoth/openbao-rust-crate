#!/usr/bin/python3 -EsSB
"""Retain exact 2.7.2 advanced normal and candidate SDK evidence separately."""

import argparse
from pathlib import Path

import openbao_2_7_2_sdk_advanced as fixture
import verify_openbao_2_7_2 as initial

PINS = {
    "normal": ("adb0f85f793d2ff0dd428808661156c3658119e97800ca4984b1c55bafa721ed",
               "2e0ef81986510b71736fb26f7283ba22a66a2da21394c6a2879200ba5467ba69"),
    "candidate": ("46e5936e5264a830cd34c280de2e6362705dba4717191f85c52907dc5193535f",
                  "b7eeb87cf920a24e05962285e99647bd2c6acb96af2d3d8f372db765d8a62fef"),
}


def output(mode):
    fixture.patch.require(mode in PINS)
    return initial.OUTPUT / (f"sdk-advanced-{mode}-tls-v6.json")


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
