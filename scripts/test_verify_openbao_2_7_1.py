#!/usr/bin/python3 -EsSB
"""Regression tests for pinned patch capture provenance and scope."""

import unittest
from unittest.mock import patch

import verify_openbao_2_7_1 as evidence


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.artifacts = {name: evidence.base.read_regular_file(evidence.OUTPUT / name, limit)
                          for name, (_, _, limit) in evidence.ARTIFACTS.items()}

    def test_exact_capture(self):
        values = evidence.validate(self.artifacts)
        self.assertIs(values["initial-patch-tls.json"]["routable"], False)
        self.assertEqual(values["initial-openapi.json"]["path_count"], 501)

    def test_changed_source_fails(self):
        inputs = evidence.patch.input_hashes()
        for key in inputs:
            for omit in (False, True):
                changed = dict(inputs)
                if omit:
                    del changed[key]
                else:
                    changed[key] = "0" * 64
                with patch.object(evidence.patch, "input_hashes", return_value=changed), \
                     self.assertRaises(evidence.patch.harness.HarnessError):
                    evidence.validate(self.artifacts)

    def test_each_artifact_is_immutable(self):
        for name in self.artifacts:
            changed = dict(self.artifacts)
            changed[name] += b" "
            with self.assertRaises(evidence.patch.harness.HarnessError):
                evidence.validate(changed)

    def test_cannot_promote_or_relabel_scope(self):
        for key, value in (("routable", True), ("scope", "public-sdk"), ("version", "2.7.0"),
                           ("checks", []), ("inputs", {})):
            report = evidence.base.parse_json(self.artifacts["initial-patch-tls.json"], 65536)
            report[key] = value
            changed = dict(self.artifacts)
            changed["initial-patch-tls.json"] = evidence.base.canonical_json(report)
            with self.assertRaises(evidence.patch.harness.HarnessError):
                evidence.validate(changed)


if __name__ == "__main__":
    unittest.main()
