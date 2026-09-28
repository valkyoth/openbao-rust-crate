#!/usr/bin/python3 -EsSB
"""Verify bounded server-protocol evidence without claiming SDK or lag verification."""

import argparse
from pathlib import Path

import openbao_2_7_consistency as fixture
import openbao_api_snapshots as snapshots

ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "compat/onboarding/2.7.0/consistency-protocol-tls.json"
EXPECTED_SHA256 = "c0a0f73800e8e804f3ec39c83d767d609b61806be11b25f324f3ebcf007a09d2"


def validate_report(report):
    expected = {"schema": "openbao-consistency-protocol-tls/v1", "version": fixture.fixture.VERSION,
                "image_linux_amd64_digest": fixture.staged.AMD64, "inputs": fixture.input_hashes(),
                "outcome": "passed", "scope": "multi-node-server-protocol-only", "nodes": 3,
                "tls": "TLSv1.3", "checks": fixture.CHECKS, "routable": False,
                "sdk_live_verified": False, "controlled_replication_lag_verified": False}
    # Canonical comparison also distinguishes booleans from integer lookalikes.
    fixture.require(snapshots.canonical_json(report) == snapshots.canonical_json(expected))


def verify():
    data = snapshots.read_regular_file(RESULT, 64 * 1024)
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("consistency evidence digest changed")
    report = snapshots.parse_json(data, 64 * 1024)
    if snapshots.canonical_json(report) != data:
        raise snapshots.SnapshotError("consistency evidence is not canonical")
    validate_report(report)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (fixture.harness.HarnessError, snapshots.SnapshotError, OSError, ValueError):
        print("Consistency evidence verification failed")
        return 1
    print("Consistency server-protocol evidence verified; SDK and controlled lag have separate reports; profile remains blocked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
