#!/usr/bin/python3 -EsSB
"""Verify narrowly scoped recovery-backup upgrade evidence; no promotion."""

import argparse

import openbao_2_7_backup_upgrade as fixture

snapshots = fixture.snapshots
RESULT = fixture.ROOT / "compat/onboarding/2.7.0/backup-upgrade-tls-v4.json"
EXPECTED_SHA256 = "4afc2925955421ac29077b1668c098a09641c35bdfdf4242d8249d2da6651d5b"


def verify():
    data = snapshots.read_regular_file(RESULT, 64 * 1024)
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("backup upgrade evidence digest changed")
    report = snapshots.parse_json(data, 64 * 1024)
    if snapshots.canonical_json(report) != data:
        raise snapshots.SnapshotError("backup upgrade evidence is not canonical")
    fixture.validate_report(report)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (fixture.harness.HarnessError, snapshots.SnapshotError, fixture.releases.LockValidationError,
            OSError, ValueError):
        print("Backup upgrade evidence verification failed")
        return 1
    print("Recovery backup single-node Raft upgrade evidence verified; no general upgrade or release-approval claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
