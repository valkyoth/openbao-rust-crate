#!/usr/bin/python3 -EsSB
"""Retain the exact 2.7.1 to 2.7.2 recovery-backup upgrade evidence."""

import argparse
from pathlib import Path

import openbao_2_7_2_backup_upgrade as fixture
import verify_openbao_2_7_2 as initial

OUTPUT = initial.OUTPUT / "recovery-backup-upgrade-tls.json"
EXPECTED_SHA256 = "0d19778507ef4d4b88fe3a6bb2307ec29bfe042622986beec16252a300ed98ed"


def validate(data):
    report = initial.checked(data, EXPECTED_SHA256, 128 * 1024)
    expected = fixture.report_for(fixture.input_hashes())
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
        print("2.7.2 recovery-backup upgrade evidence failed; no compatibility promotion")
        return 1
    print("2.7.1 to 2.7.2 recovery-backup restart evidence verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
