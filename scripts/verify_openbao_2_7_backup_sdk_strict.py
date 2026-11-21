#!/usr/bin/python3 -EsSB
"""Verify retained exact-profile backup evidence from the normal SDK build."""

import argparse

import openbao_2_7_backup_sdk as fixture

RESULT = fixture.ROOT / "compat/onboarding/2.7.0/backup-sdk-strict-tls-v13.json"
EXPECTED_SHA256 = "73d54d2fd2eb04112c0116a0daf62ab0ce2c9f017a61ab19568bfe3970d24f1c"
TEST_BINARY_SHA256 = "f975495d4087eb31008c4688e22e7e086a5e5def8a07b2a3fcb1c58a1c3f96fa"


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
