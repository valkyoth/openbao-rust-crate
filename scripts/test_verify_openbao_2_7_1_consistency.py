#!/usr/bin/python3 -EsSB
"""Prevent scope widening or stale inputs in retained patch lag evidence."""

import unittest
from unittest.mock import patch

import verify_openbao_2_7_1_consistency as evidence


class EvidenceTests(unittest.TestCase):
    def test_current_report(self):
        self.assertFalse(evidence.verify()["sdk_live_verified"])

    def test_changed_report_or_inputs_fail(self):
        data = evidence.fixture.base.read_regular_file(evidence.OUTPUT, 128 * 1024)
        with self.assertRaises(evidence.fixture.harness.HarnessError):
            evidence.validate(data + b" ")
        original = evidence.fixture.base.parse_json(data, 128 * 1024)
        for key, value in (("version", "2.7.0"), ("sdk_live_verified", True), ("routable", True),
                           ("scope", "public-sdk"), ("inputs", {}), ("checks", []), ("nodes", 1)):
            with self.subTest(key=key), patch.object(evidence.initial, "checked", return_value={**original, key: value}), \
                 self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(data)
        with patch.object(evidence.fixture, "input_hashes", return_value={}), \
             self.assertRaises(evidence.fixture.harness.HarnessError):
            evidence.validate(data)


if __name__ == "__main__":
    unittest.main()
