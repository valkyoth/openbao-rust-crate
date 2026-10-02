#!/usr/bin/python3 -EsSB
"""Reject forged scope, missing inputs and changed patch SDK evidence."""

import copy
import unittest
from unittest.mock import patch

import verify_openbao_2_7_1_sdk as evidence


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = evidence.fixture.base.read_regular_file(evidence.OUTPUT, 128 * 1024)
        cls.report = evidence.fixture.base.parse_json(cls.data, 128 * 1024)

    def test_retained_historical_evidence_is_not_current(self):
        self.assertFalse(evidence.verify(historical=True)["routable"])
        with self.assertRaises(evidence.fixture.harness.HarnessError):
            evidence.verify()

    def test_changed_bytes_fail_digest(self):
        with self.assertRaises(evidence.fixture.harness.HarnessError):
            evidence.validate(self.data + b" ")

    def test_report_semantics_remain_checked_after_digest(self):
        for key, value in (("version", "2.7.0"), ("routable", True), ("outcome", "failed"),
                           ("test_binary_sha256", "0" * 64), ("scope", "public-sdk-strict-normal-build"),
                           ("candidate_registry_sha256", "0" * 64), ("checks", []), ("inputs", {}),
                           ("executable_storage", "mutable-path")):
            report = copy.deepcopy(self.report)
            report[key] = value
            checked = evidence.initial.checked
            def mutate_sdk_only(data, digest, limit):
                return report if data == self.data else checked(data, digest, limit)
            with self.subTest(key=key), patch.object(evidence.initial, "checked", side_effect=mutate_sdk_only), \
                 self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(self.data, historical=True)

    def test_historical_validation_does_not_claim_current_sources(self):
        with patch.object(evidence.fixture, "input_hashes", side_effect=AssertionError("current source comparison")), \
             patch.object(evidence.fixture.candidate, "verify", side_effect=AssertionError("current candidate comparison")):
            evidence.verify(historical=True)

    def test_changed_current_source_fails(self):
        inputs = dict(self.report["inputs"])
        for name in ("src/patch_271_live.rs", "src/client.rs", "Cargo.lock"):
            changed = {**inputs, name: "0" * 64}
            with self.subTest(name=name), patch.object(evidence.fixture, "input_hashes", return_value=changed), \
                 self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(self.data)


if __name__ == "__main__":
    unittest.main()
