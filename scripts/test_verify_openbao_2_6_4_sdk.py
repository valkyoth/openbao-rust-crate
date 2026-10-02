#!/usr/bin/python3 -EsSB
"""The live SDK result cannot be relabelled, widened or reused after source drift."""

import copy
import unittest
from unittest.mock import patch

import verify_openbao_2_6_4_sdk as evidence


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = evidence.fixture.base.read_regular_file(evidence.OUTPUT, 128 * 1024)
        cls.report = evidence.fixture.base.parse_json(cls.data, 128 * 1024)
        cls.candidate = evidence.fixture.candidate.verify()

    def test_retained_historical_evidence_is_candidate_only(self):
        report = evidence.verify(historical=True)
        self.assertIs(report["routable"], False)
        self.assertEqual(report["scope"], "public-sdk-strict-disposable-candidate-build")
        self.assertIn("radius-user-mapping", report["checks"])

    def test_archived_candidate_cannot_pass_as_current(self):
        with self.assertRaises(evidence.fixture.harness.HarnessError):
            evidence.verify()

    def test_changed_bytes_fail_digest(self):
        with self.assertRaises(evidence.fixture.harness.HarnessError):
            evidence.validate(self.data + b" ")

    def test_original_capture_is_stale_even_without_digest_check(self):
        data = evidence.fixture.base.read_regular_file(
            evidence.initial.OUTPUT / "sdk-candidate-tls.json", 128 * 1024)
        report = evidence.fixture.base.parse_json(data, 128 * 1024)
        with patch.object(evidence.initial, "checked", return_value=report), \
             self.assertRaises(evidence.fixture.harness.HarnessError):
            evidence.validate(data)

    def test_changed_or_missing_source_fails(self):
        for name in self.report["inputs"]:
            for omit in (False, True):
                inputs = dict(self.report["inputs"])
                if omit:
                    del inputs[name]
                else:
                    inputs[name] = "0" * 64
                with self.subTest(name=name, omit=omit), \
                     patch.object(evidence.fixture, "input_hashes", return_value=inputs), \
                     self.assertRaises(evidence.fixture.harness.HarnessError):
                    evidence.validate(self.data)

    def test_report_semantics_checked_independently_of_digest(self):
        for key, value in (("version", "2.7.1"), ("routable", True), ("routable", 0), ("outcome", "failed"),
                           ("test_binary_sha256", "0" * 64), ("scope", "public-sdk-strict-normal-build"),
                           ("candidate_registry_sha256", "0" * 64), ("checks", []), ("inputs", {}),
                           ("candidate_generated_rust_sha256", "0" * 64),
                           ("test", "other-test"), ("features", ""), ("image_index_digest", "sha256:" + "0" * 64),
                           ("executable_storage", "mutable-path"), ("build_provenance", "attested")):
            report = copy.deepcopy(self.report)
            report[key] = value
            checked = evidence.initial.checked

            def mutate_sdk_only(data, digest, limit):
                return report if data == self.data else checked(data, digest, limit)

            with self.subTest(key=key), patch.object(evidence.initial, "checked", side_effect=mutate_sdk_only), \
                 patch.object(evidence.fixture.candidate, "verify", return_value=self.candidate), \
                 self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(self.data, historical=True)


if __name__ == "__main__":
    unittest.main()
