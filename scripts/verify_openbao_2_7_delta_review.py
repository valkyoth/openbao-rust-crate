#!/usr/bin/python3 -EsSB
"""Check exact delta accounting, not implementation correctness or promotion."""

import argparse
from collections import Counter

import openbao_2_7_api as staged

base = staged.base
RESULT = staged.STAGED / "delta-review.json"
EXPECTED_SHA256 = "e811c52d51cca19f928ed381e9c8495feb441139f01c6d621aa9e44610c00a27"
GROUPS = {"external-plugin-exclusion": 71, "external-keys": 36,
          "workflow-list-projection": 4, "control-groups": 8,
          "transit": 18, "pki": 50, "mfa-totp": 2}


def validate(document, delta):
    if (not isinstance(document, dict) or set(document) != {"schema", "scope", "changes"}
            or document["schema"] != "openbao-2.7-delta-review/v1"
            or document["scope"] != "record-reconciliation-not-profile-promotion"):
        raise base.SnapshotError("delta review scope changed")
    rows = document["changes"]
    if not isinstance(rows, list) or len(rows) != 189:
        raise base.SnapshotError("delta review count changed")
    reconstructed = []
    counts = Counter()
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {"change", "evidence", "field", "identity", "review_group"}
                or not isinstance(row["review_group"], str) or row["review_group"] not in GROUPS):
            raise base.SnapshotError("delta review record changed")
        counts[row["review_group"]] += 1
        reconstructed.append({key: value for key, value in row.items() if key != "review_group"})
    if counts != GROUPS or reconstructed != delta["changes"] or delta["change_count"] != 189:
        raise base.SnapshotError("delta review does not cover the exact staged delta")


def verify():
    artifacts = staged.verify()
    data = base.read_regular_file(RESULT, 128 * 1024)
    if base.sha256(data) != EXPECTED_SHA256:
        raise base.SnapshotError("reviewed delta assignments changed")
    document = base.parse_json(data, 128 * 1024)
    validate(document, staged.parse(artifacts["2.6.3--2.7.0.json"]))
    return document


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (base.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("Delta review verification failed")
        return 1
    print("189 exact delta records accounted for; no runtime or promotion claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
