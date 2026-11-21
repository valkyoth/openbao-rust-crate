#!/usr/bin/python3 -EsSB
"""Retain exact 2.7.2 server backup reports without claiming SDK coverage."""

import argparse
from pathlib import Path

import openbao_2_7_2_backups as fixture
import verify_openbao_2_7_2 as initial

REPORTS = {
    "unseal": "252fe40809072a68c75e4d6a7b19f1f271033a6c5f396a8c219b78263572ed96",
    "recovery": "2077f47072af337de61a3297bbdb08faf803f1e4649521657cb33d6c535feeea",
}


def output(suite):
    fixture.patch.require(suite in REPORTS)
    return initial.OUTPUT / (suite + "-backup-tls-v2.json")


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
