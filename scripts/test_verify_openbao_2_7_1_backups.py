#!/usr/bin/python3 -EsSB
"""Backup evidence mutations must not expand the tested guarantee."""

import copy
import unittest
from unittest.mock import patch

import verify_openbao_2_7_1_backups as evidence


class EvidenceTests(unittest.TestCase):
    def test_current_reports(self):
        self.assertEqual(set(evidence.verify()), {"unseal", "recovery"})

    def test_changed_or_mislabelled_report_rejected(self):
        for suite in evidence.REPORTS:
            data = evidence.fixture.base.read_regular_file(
                evidence.initial.OUTPUT / (suite + "-backup-tls-v2.json"), 128 * 1024)
            with self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(suite, data + b" ")
            original = evidence.fixture.base.parse_json(data, 128 * 1024)
            for key, value in (("version", "2.7.0"), ("routable", True), ("outcome", "failed"),
                               ("scope", "public-sdk"), ("inputs", {}), ("checks", []),
                               ("backup_decryption_verified", True), ("upgrade_verified", True),
                               ("routable", 0), ("backup_decryption_verified", 0)):
                report = copy.deepcopy(original)
                report[key] = value
                with self.subTest(suite=suite, key=key), \
                     patch.object(evidence.initial, "checked", return_value=report), \
                     self.assertRaises(evidence.fixture.harness.HarnessError):
                    evidence.validate(suite, data)

    def test_changed_source_rejected(self):
        with patch.object(evidence.fixture, "input_hashes", return_value={}), \
             self.assertRaises(evidence.fixture.harness.HarnessError):
            evidence.verify()

    def test_original_captures_are_stale_independently_of_digest(self):
        for suite in evidence.REPORTS:
            data = evidence.fixture.base.read_regular_file(
                evidence.initial.OUTPUT / (suite + "-backup-tls.json"), 128 * 1024)
            report = evidence.fixture.base.parse_json(data, 128 * 1024)
            with self.subTest(suite=suite), patch.object(evidence.initial, "checked", return_value=report), \
                 self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(suite, data)


if __name__ == "__main__":
    unittest.main()
