#!/usr/bin/python3 -EsSB
"""Retain exact 2.7.2 server backup reports without claiming SDK coverage."""

import argparse
from pathlib import Path

import openbao_2_7_2_backups as fixture
import verify_openbao_2_7_2 as initial

REPORTS = {
    "unseal": "f381a30454e47171a19815cdf7ed4de5b6c19627a24ca7e3caa2baa5208554f4",
    "recovery": "5dfa524a82c083389667ef69c2372631f02aa6d2ca477cd7b80f0fd4712a319b",
}


def output(suite):
    fixture.patch.require(suite in REPORTS)
    return initial.OUTPUT / (suite + "-backup-tls.json")


def validate(suite, data):
    report = initial.checked(data, REPORTS[suite], 128 * 1024)
    module = fixture.unseal if suite == "unseal" else fixture.recovery
    expected = {"schema": "openbao-patch-backup-tls/v1", "version": fixture.patch.VERSION,
                "suite": suite, "inputs": fixture.input_hashes(),
                "image_linux_amd64_digest": fixture.patch.AMD64,
                "image_index_digest": fixture.patch.INDEX,
                "scope": "server-fixture-only-not-sdk-integration", "tls": "TLSv1.3",
                "checks": module.CHECKS, "outcome": "passed", "routable": False,
                "upgrade_verified": False, "backup_decryption_verified": False}
    fixture.patch.require(data == fixture.base.canonical_json(report)
                          and report == expected)
    return report


def verify():
    return {suite: validate(suite, fixture.base.read_regular_file(output(suite), 128 * 1024))
            for suite in REPORTS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retain", choices=REPORTS)
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()
    if args.retain and not args.result:
        parser.error("--retain requires --result")
    try:
        if args.retain:
            data = fixture.base.read_regular_file(args.result, 128 * 1024)
            validate(args.retain, data)
            fixture.base.write_immutable(output(args.retain), data)
        else:
            verify()
    except (fixture.harness.HarnessError, fixture.base.SnapshotError,
            OSError, ValueError, KeyError, TypeError):
        print("2.7.2 backup evidence failed verification; no compatibility promotion")
        return 1
    print("2.7.2 server backup evidence verified; no SDK, upgrade or decryption claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
