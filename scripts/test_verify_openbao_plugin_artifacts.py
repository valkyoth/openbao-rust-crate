#!/usr/bin/python3 -EsSB
"""Reject stale inputs, artifact drift and inflated assurance claims."""

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import openbao_api_snapshots as base
import verify_openbao_plugin_artifacts as subject


class EvidenceTests(unittest.TestCase):
    def test_retained_scope(self):
        result = subject.verify()
        self.assertFalse(result["routable"])
        self.assertFalse(result["contracts_verified"])
        self.assertFalse(result["source_to_binary_provenance_verified"])

    def assert_rejected_even_if_repinned(self, document):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            data = base.canonical_json(document)
            path.write_bytes(data)
            with patch.object(subject, "EVIDENCE", path), \
                 patch.object(subject, "EXPECTED_SHA256", base.sha256(data)):
                with self.assertRaises(base.SnapshotError):
                    subject.verify()

    def test_each_input_mutation_and_omission(self):
        report = subject.verify()
        for path in report["inputs"]:
            changed = copy.deepcopy(report)
            changed["inputs"][path] = "0" * 64
            self.assert_rejected_even_if_repinned(changed)
            del changed["inputs"][path]
            self.assert_rejected_even_if_repinned(changed)

    def test_assurance_and_identity_cannot_be_promoted(self):
        report = subject.verify()
        for field, value in (("routable", True), ("contracts_verified", True),
                             ("source_to_binary_provenance_verified", True),
                             ("platform", "linux_arm64_v8"),
                             ("schema", "other"), ("scope", "sdk-integration"),
                             ("signing_primary_fingerprint", "0" * 40)):
            changed = copy.deepcopy(report)
            changed[field] = value
            self.assert_rejected_even_if_repinned(changed)
        for index in range(4):
            for field in report["plugins"][index]:
                changed = copy.deepcopy(report)
                changed["plugins"][index][field] = "changed"
                self.assert_rejected_even_if_repinned(changed)
        changed = copy.deepcopy(report)
        changed["plugins"].reverse()
        self.assert_rejected_even_if_repinned(changed)

    def test_checksum_and_noncanonical_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            data = base.canonical_json(subject.expected()) + b"\n"
            path.write_bytes(data)
            with patch.object(subject, "EVIDENCE", path):
                with self.assertRaises(base.SnapshotError):
                    subject.verify()
                with patch.object(subject, "EXPECTED_SHA256", base.sha256(data)):
                    with self.assertRaises(base.SnapshotError):
                        subject.verify()


if __name__ == "__main__":
    unittest.main()
