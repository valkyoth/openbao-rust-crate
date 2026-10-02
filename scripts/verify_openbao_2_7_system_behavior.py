#!/usr/bin/python3 -EsSB
"""Verify staged system behavior evidence without promoting SDK routing."""

import argparse

import openbao_2_7_system_behavior as fixture

snapshots = fixture.snapshots
RESULT = fixture.ROOT / "compat/onboarding/2.7.0/system-behavior-tls-v2.json"
EXPECTED_SHA256 = "b8ecbcef474e5d2f1678a95c101e9e2743a0fe75e139ca61f37d209e4c9de3f8"


def verify():
    data = snapshots.read_regular_file(RESULT, 64 * 1024)
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("system behavior evidence digest changed")
    report = snapshots.parse_json(data, 64 * 1024)
    if snapshots.canonical_json(report) != data:
        raise snapshots.SnapshotError("system behavior evidence is not canonical")
    fixture.validate_report(report)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (fixture.harness.HarnessError, snapshots.SnapshotError, OSError, ValueError):
        print("System behavior evidence verification failed")
        return 1
    print("System behavior server evidence verified; no SDK integration or release-approval claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
