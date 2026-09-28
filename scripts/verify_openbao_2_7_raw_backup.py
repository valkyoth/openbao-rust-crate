#!/usr/bin/python3 -EsSB
"""Verify unseal-backup evidence without claiming recovery, upgrade or promotion."""

import argparse

import openbao_2_7_raw_backup as fixture

snapshots = fixture.snapshots
RESULT = fixture.ROOT / "compat/onboarding/2.7.0/raw-backup-tls.json"
EXPECTED_SHA256 = "b99d139cfc44657a38b2c66b6479b50935105145f61266747b05727048f404dd"


def verify():
    data = snapshots.read_regular_file(RESULT, 64 * 1024)
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("raw backup evidence digest changed")
    report = snapshots.parse_json(data, 64 * 1024)
    if snapshots.canonical_json(report) != data:
        raise snapshots.SnapshotError("raw backup evidence is not canonical")
    fixture.validate_report(report)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (fixture.harness.HarnessError, snapshots.SnapshotError, OSError, ValueError):
        print("Raw backup evidence verification failed")
        return 1
    print("Unseal backup server evidence verified; recovery and upgrade not claimed; profile remains blocked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
