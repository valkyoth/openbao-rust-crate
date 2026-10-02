#!/usr/bin/python3 -EsSB
"""Verify control-group compatibility evidence, including its known security failure."""

import argparse
from pathlib import Path

import openbao_2_7_control_groups as fixture
import openbao_api_snapshots as snapshots

ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "compat/onboarding/2.7.0/control-group-tls-v2.json"
EXPECTED_SHA256 = "544477e4f47b50855b98c278290cbcd990f7419427455a7a8287607fa1482cc4"


def verify():
    data = snapshots.read_regular_file(RESULT, 64 * 1024)
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("control-group evidence digest changed")
    report = snapshots.parse_json(data, 64 * 1024)
    if snapshots.canonical_json(report) != data:
        raise snapshots.SnapshotError("control-group evidence is not canonical")
    fixture.validate_report(report, fixture.input_hashes())
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (fixture.harness.HarnessError, snapshots.SnapshotError, OSError, ValueError):
        print("Control-group evidence verification failed")
        return 1
    print("Control-group compatibility evidence verified; known server replay failure remains; no release-approval claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
