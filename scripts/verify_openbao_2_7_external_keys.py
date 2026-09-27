#!/usr/bin/python3 -EsSB
"""Verify retained staged external-key TLS evidence; never promote routing."""

import argparse
from pathlib import Path

import openbao_2_7_external_keys as fixture
import openbao_api_snapshots as snapshots

ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "compat/onboarding/2.7.0/external-key-tls.json"
EXPECTED_SHA256 = "2a24a872b40c795e11587c35fa65c7d99230d9f3693ff5f5bb1f4b908a511231"


def validate_report(report, inputs):
    expected = {"schema": "openbao-external-key-tls/v1", "version": "2.7.0",
                "image_linux_amd64_digest": fixture.staged.AMD64, "inputs": inputs,
                "outcome": "passed", "scope": "server-fixture-only-not-sdk-integration",
                "tls": "TLSv1.3", "checks": fixture.CHECKS,
                "pkcs11_verified": False, "routable": False}
    if (not isinstance(report, dict) or report != expected
        or report.get("pkcs11_verified") is not False or report.get("routable") is not False):
        raise snapshots.SnapshotError("external-key TLS evidence scope or inputs changed")


def verify():
    data = snapshots.read_regular_file(RESULT, 64 * 1024)
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("external-key TLS evidence digest changed")
    report = snapshots.parse_json(data, 64 * 1024)
    if snapshots.canonical_json(report) != data:
        raise snapshots.SnapshotError("external-key TLS evidence is not canonical")
    validate_report(report, fixture.input_hashes())
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (snapshots.SnapshotError, OSError, ValueError):
        print("External-key TLS evidence verification failed")
        return 1
    print("External-key TLS evidence verified (server contract only; SDK profile not promoted)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
