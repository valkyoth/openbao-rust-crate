#!/usr/bin/python3 -EsSB
"""Verify recovery-backup evidence without claiming upgrade or promotion."""

import argparse

import openbao_2_7_recovery_backup as fixture

snapshots = fixture.snapshots
RESULT = fixture.ROOT / "compat/onboarding/2.7.0/recovery-backup-tls-v2.json"
EXPECTED_SHA256 = "009e30657a265f00fe539bc5d156451082ee18829906d9c127be4baa7b61e42a"


def verify():
    data = snapshots.read_regular_file(RESULT, 64 * 1024)
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("recovery backup evidence digest changed")
    report = snapshots.parse_json(data, 64 * 1024)
    if snapshots.canonical_json(report) != data:
        raise snapshots.SnapshotError("recovery backup evidence is not canonical")
    fixture.validate_report(report)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (fixture.harness.HarnessError, snapshots.SnapshotError, OSError, ValueError):
        print("Recovery backup evidence verification failed")
        return 1
    print("Recovery backup server evidence verified; no upgrade or release-approval claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
