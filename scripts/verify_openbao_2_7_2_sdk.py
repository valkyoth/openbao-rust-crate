#!/usr/bin/python3 -EsSB
"""Retain exact 2.7.2 normal and candidate public-SDK evidence separately."""

import argparse
from pathlib import Path

import openbao_2_7_2_sdk as fixture
import verify_openbao_2_7_2 as initial

PINS = {
    "normal": ("1bbbbf7a8a52284c32604455762803df1f8996121384691c9c3f8a3543febb25",
               "182f9f63233333c9f99098d6aa3170603bd39c00375eae93b05253cf2f9591dc"),
    "candidate": ("c4aed37f0f2a519d1534cb8d026a32325fd119d2d5792f0d4a520154e444320c",
                  "3930775b8174246e20ae1ad9567c47f2575a7b68becb7f2ba51e9332eae5b14d"),
}


def output(mode):
    fixture.patch.require(mode in PINS)
    return initial.OUTPUT / ("sdk-normal-tls-v3.json" if mode == "normal" else "sdk-candidate-tls-v3.json")


def expected(mode, binary):
    normal = mode == "normal"
    report = {**fixture.execution.EXECUTION_ASSURANCE,
              "schema": "openbao-patch-sdk-tls/v1", "version": fixture.patch.VERSION,
              "inputs": fixture.input_hashes(normal=normal), "test_binary_sha256": binary,
              "test": fixture.TEST, "features": fixture.FEATURES,
              "image_linux_amd64_digest": fixture.patch.AMD64,
              "image_index_digest": fixture.patch.INDEX, "outcome": "passed",
              "checks": fixture.CHECKS}
    if normal:
        report.update(fixture.normal_sdk.verify(), scope="public-sdk-strict-normal-build", routable=True)
    else:
        generated = fixture.base.sha256(fixture.candidate.registry.rust_output(
            fixture.candidate.verify(), verification_candidate=True))
        report.update(candidate_registry_sha256=fixture.candidate.EXPECTED_SHA256,
                      candidate_generated_rust_sha256=generated,
                      source_scope="repository-inputs-with-explicit-generated-candidate-override",
                      scope="public-sdk-strict-disposable-candidate-build", routable=False)
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
        print("2.7.2 SDK evidence failed verification; no compatibility promotion")
        return 1
    print("2.7.2 normal and candidate SDK evidence verified with separate scopes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
