#!/usr/bin/python3 -EsSB
"""Verify retained Transit TLS evidence without promoting SDK routing."""

import argparse
from pathlib import Path

import openbao_2_7_transit as fixture
import openbao_api_snapshots as snapshots

ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "compat/onboarding/2.7.0/transit-tls.json"
EXPECTED_SHA256 = "6157f73c7d0f46aedc503f795b4f4aa62894c8d7fac1be0207aa687839694153"


def validate_report(report, inputs):
    expected = {"schema": "openbao-transit-tls/v1", "version": "2.7.0",
                "image_linux_amd64_digest": fixture.staged.AMD64, "inputs": inputs,
                "outcome": "passed", "scope": "server-fixture-only-not-sdk-integration",
                "tls": "TLSv1.3", "checks": fixture.CHECKS,
                "mldsa_parameters": [44, 65, 87],
                "pkcs11_verified": False, "routable": False}
    if (not isinstance(report, dict) or report != expected
        or report.get("pkcs11_verified") is not False or report.get("routable") is not False
        or any(type(value) is not int for value in report["mldsa_parameters"])):
        raise snapshots.SnapshotError("Transit TLS evidence scope or inputs changed")


def verify():
    data = snapshots.read_regular_file(RESULT, 64 * 1024)
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("Transit TLS evidence digest changed")
    report = snapshots.parse_json(data, 64 * 1024)
    if snapshots.canonical_json(report) != data:
        raise snapshots.SnapshotError("Transit TLS evidence is not canonical")
    validate_report(report, fixture.input_hashes())
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (snapshots.SnapshotError, OSError, ValueError):
        print("Transit TLS evidence verification failed")
        return 1
    print("Transit TLS evidence verified (server contract only; SDK profile not promoted)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
