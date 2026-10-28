#!/usr/bin/python3 -EsSB
"""Reject stale, widened, or scope-confused 2.7.2 advanced SDK evidence."""

import copy
import unittest
from unittest.mock import patch

import verify_openbao_2_7_2_sdk_advanced as evidence


class EvidenceTests(unittest.TestCase):
    def test_modes_have_distinct_provenance_and_exact_scope(self):
        normal = evidence.verify("normal")
        candidate = evidence.verify("candidate")
        self.assertTrue(normal["routable"])
        self.assertEqual(normal["scope"], "public-sdk-strict-normal-build")
        self.assertNotIn("candidate_registry_sha256", normal)
        self.assertFalse(candidate["routable"])
        self.assertEqual(candidate["scope"], "public-sdk-strict-disposable-candidate-build")
        self.assertIn("candidate_registry_sha256", candidate)
        self.assertEqual(normal["tests"], evidence.fixture.TESTS)
        self.assertEqual(candidate["tests"], evidence.fixture.TESTS)

    def test_mutations_fail(self):
        for mode in evidence.PINS:
            data = evidence.fixture.base.read_regular_file(evidence.output(mode), 128 * 1024)
            report = evidence.fixture.base.parse_json(data, 128 * 1024)
            for key, value in (("inputs", {}), ("tests", []), ("checks", []),
                               ("test_binary_sha256", "0" * 64), ("routable", mode != "normal"),
                               ("backup_decryption_verified", True)):
                changed = copy.deepcopy(report)
                changed[key] = value
                with self.subTest(mode=mode, key=key), \
                     patch.object(evidence.initial, "checked", return_value=changed), \
                     self.assertRaises(evidence.fixture.harness.HarnessError):
                    evidence.validate(mode, data)


if __name__ == "__main__":
    unittest.main()
