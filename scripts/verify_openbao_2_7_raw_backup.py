#!/usr/bin/python3 -EsSB
"""Verify unseal-backup evidence without claiming recovery, upgrade or promotion."""

import argparse

import openbao_2_7_raw_backup as fixture

snapshots = fixture.snapshots
RESULT = fixture.ROOT / "compat/onboarding/2.7.0/raw-backup-tls-v4.json"
EXPECTED_SHA256 = "25080f5b0b1859a18f2dc77cf80d6424a1fbbdc8f436241c5ff158910823179e"


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
    print("Unseal backup server evidence verified; no recovery, upgrade or release-approval claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
