#!/usr/bin/python3 -EsSB
"""Retain exact 2.7.2 server protocol and controlled-lag evidence."""

import argparse
from pathlib import Path

import openbao_2_7_2_consistency as fixture
import verify_openbao_2_7_2 as initial

OUTPUT = initial.OUTPUT / "consistency-server-tls.json"
EXPECTED_SHA256 = "9faf8ad87b515b071c81241d57c3e00d354691accd0caa406bea8036e7cb8b2a"


def validate(data):
    report = initial.checked(data, EXPECTED_SHA256, 128 * 1024)
    expected = {"schema": "openbao-patch-consistency-tls/v1", "version": fixture.patch.VERSION,
                "inputs": fixture.input_hashes(), "image_linux_amd64_digest": fixture.patch.AMD64,
                "image_index_digest": fixture.patch.INDEX, "scope": "controlled-lag-server-protocol-only",
                "checks": fixture.CHECKS, "outcome": "passed", "nodes": 3, "routable": False,
                "sdk_live_verified": False, "expiry_listener_wait_ms": 250,
                "recovery_listener_wait_ms": 10000}
    fixture.patch.require(data == fixture.base.canonical_json(report)
                          and report == expected)
    return report


def verify():
    return validate(fixture.base.read_regular_file(OUTPUT, 128 * 1024))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retain", type=Path)
    args = parser.parse_args()
    try:
        if args.retain:
            data = fixture.base.read_regular_file(args.retain, 128 * 1024)
            validate(data)
            fixture.base.write_immutable(OUTPUT, data)
        verify()
    except (fixture.harness.HarnessError, fixture.base.SnapshotError,
            OSError, ValueError, KeyError, TypeError):
        print("2.7.2 consistency evidence failed; no compatibility promotion")
        return 1
    print("2.7.2 server protocol and controlled lag evidence verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
