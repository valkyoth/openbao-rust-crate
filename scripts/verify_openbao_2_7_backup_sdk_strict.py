#!/usr/bin/python3 -EsSB
"""Verify retained exact-profile backup evidence from the normal SDK build."""

import argparse

import openbao_2_7_backup_sdk as fixture

RESULT = fixture.ROOT / "compat/onboarding/2.7.0/backup-sdk-strict-tls-v4.json"
EXPECTED_SHA256 = "2c8bfffc4299e71a0d3cf5fb6df6e432d38c1c04ff65b362d8861e244c86ca26"
TEST_BINARY_SHA256 = "d5b1bb8c584f4e361327546b8b4d684c85ea45a3dca16dd0fc01cf214398c8df"


def verify():
    data = fixture.snapshots.read_regular_file(RESULT, 64 * 1024)
    if fixture.snapshots.sha256(data) != EXPECTED_SHA256:
        raise fixture.snapshots.SnapshotError("strict SDK backup evidence digest changed")
    report = fixture.snapshots.parse_json(data, 64 * 1024)
    if fixture.snapshots.canonical_json(report) != data:
        raise fixture.snapshots.SnapshotError("strict SDK backup evidence is not canonical")
    fixture.validate_report(report, TEST_BINARY_SHA256, strict=True)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (fixture.recovery.harness.HarnessError, fixture.snapshots.SnapshotError,
            OSError, ValueError):
        print("Strict normal-build SDK backup evidence verification failed")
        return 1
    print("Strict normal-build SDK backup TLS evidence verified; decryption not claimed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
