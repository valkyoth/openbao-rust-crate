#!/usr/bin/python3 -EsSB
"""Retain exact 2.6.5 normal and candidate public-SDK evidence separately."""

import argparse
from pathlib import Path

import openbao_2_6_5_sdk as fixture
import verify_openbao_2_6_5 as initial

PINS = {
    "normal": ("d8d9c6e9861e61cf04b7b6f8dc0b25e7e9ae4755c82e1b74ae7a50236054405c",
               "aba77c147ccd8b881ade125e75dc257f89fcd10d636521694a6d44377116c502"),
    "candidate": ("8d841eb6516b64a4641094c7e7d03eb3124aac5e8071f9e05e5f5d812272443c",
                  "2aee95d698a3696f813772f67788463500cdc1f592e58fd68660e3c62bc3f5c3"),
}
CHECKS = ["exact-version", "tls13", "tls-rejections", "resource-limits", "network-isolation",
          "strict-sdk-profile", "approle-login", "expired-secret-id-denied-without-tidy",
          "transit-encrypt-decrypt", "transit-version-selection", "associated-data-binding",
          "kv1-roundtrip", "kv2-write-patch-read", "token-lookup", "wrapping-one-use",
          "ldap-auth-mapping", "kerberos-group-mapping", "radius-user-mapping",
          "ldap-dynamic-role-administration", "cleanup"]


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
              "checks": CHECKS}
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
        print("2.6.5 SDK evidence failed verification; no compatibility promotion")
        return 1
    print("2.6.5 normal and candidate SDK evidence verified with separate scopes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
