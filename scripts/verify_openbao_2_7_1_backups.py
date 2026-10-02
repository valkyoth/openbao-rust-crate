#!/usr/bin/python3 -EsSB
"""Verify exact-version server backup reports without claiming SDK coverage."""

import argparse
from pathlib import Path

import openbao_2_7_1_backups as fixture
import verify_openbao_2_7_1 as initial

REPORTS = {
    "unseal": "089c4d4554d6f21b167184019019e445eb78a720c3699ccd79b90d0f76e66f75",
    "recovery": "d545aec1118b5a1d3a73344d5539cb2fecd3cc655da462fbf78e94da75388c0e",
}


def validate(suite, data):
    report = initial.checked(data, REPORTS[suite], 128 * 1024)
    module = fixture.unseal if suite == "unseal" else fixture.recovery
    expected = {
        "schema": "openbao-patch-backup-tls/v1", "version": fixture.patch.VERSION, "suite": suite,
        "inputs": fixture.input_hashes(), "image_linux_amd64_digest": fixture.patch.AMD64,
        "image_index_digest": fixture.patch.INDEX, "scope": "server-fixture-only-not-sdk-integration",
        "tls": "TLSv1.3", "checks": module.CHECKS, "outcome": "passed", "routable": False,
        "upgrade_verified": False, "backup_decryption_verified": False}
    fixture.patch.require(fixture.base.canonical_json(report) == fixture.base.canonical_json(expected))
    return report


def verify():
    return {suite: validate(suite, fixture.base.read_regular_file(
        initial.OUTPUT / (suite + "-backup-tls-v2.json"), 128 * 1024)) for suite in REPORTS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retain", choices=tuple(REPORTS))
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()
    try:
        if args.retain:
            if args.result is None:
                parser.error("--retain requires --result")
            data = fixture.base.read_regular_file(args.result, 128 * 1024)
            validate(args.retain, data)
            fixture.base.write_immutable(initial.OUTPUT / (args.retain + "-backup-tls-v2.json"), data)
        else:
            verify()
    except (fixture.harness.HarnessError, fixture.base.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("2.7.1 backup evidence failed verification; no compatibility promotion")
        return 1
    print("2.7.1 server backup evidence verified; no SDK, upgrade or decryption claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
