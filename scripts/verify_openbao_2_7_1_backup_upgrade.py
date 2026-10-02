#!/usr/bin/python3 -EsSB
"""Retain the exact recovery-backup patch upgrade with its narrow scope."""

import argparse
from pathlib import Path

import openbao_2_7_1_backup_upgrade as fixture
import verify_openbao_2_7_1 as initial

OUTPUT = initial.OUTPUT / "recovery-backup-upgrade-tls-v2.json"
EXPECTED_SHA256 = "5a4464efe9e23157a9760b26ddeaf71bb350c787c9e1dc6d66d442052826a0a6"


def validate(data):
    report = initial.checked(data, EXPECTED_SHA256, 128 * 1024)
    expected = fixture.report_for(fixture.input_hashes())
    # Canonical bytes distinguish booleans from integers as well as extra keys.
    fixture.patch.require(fixture.base.canonical_json(report) == fixture.base.canonical_json(expected))
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
    except (fixture.harness.HarnessError, fixture.base.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("2.7.1 recovery-backup upgrade evidence failed; no compatibility promotion")
        return 1
    print("2.7.0 to 2.7.1 recovery-backup restart verified; no general upgrade or SDK claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
