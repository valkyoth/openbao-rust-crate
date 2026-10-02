#!/usr/bin/python3 -EsSB
"""Reject altered scope, executable identity or source inputs in SDK evidence."""

import copy
import unittest
from unittest.mock import patch

import verify_openbao_2_7_1_sdk_advanced as evidence


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = evidence.fixture.base.read_regular_file(evidence.OUTPUT, 128 * 1024)
        cls.report = evidence.fixture.base.parse_json(cls.data, 128 * 1024)
        cls.candidate = evidence.fixture.candidate.verify()

    def setUp(self):
        # Candidate integrity has its own tests; avoid repeating the full API
        # reconciliation for each independent report mutation below.
        mock = patch.object(evidence.fixture.candidate, "verify", return_value=self.candidate)
        mock.start()
        self.addCleanup(mock.stop)

    def test_retained_historical_evidence(self):
        report = evidence.verify(historical=True)
        self.assertFalse(report["routable"])
        self.assertFalse(report["backup_decryption_verified"])
        self.assertEqual(report["tests"], evidence.fixture.TESTS)
        self.assertIn("workflow-cas-create-update", report["checks"])
        self.assertIn("workflow-cas-rejected-write-preserves-state", report["checks"])

    def test_archived_candidate_cannot_pass_as_current(self):
        with self.assertRaises(evidence.fixture.harness.HarnessError):
            evidence.verify()

    def test_original_capture_is_not_current_independently_of_digest(self):
        data = evidence.fixture.base.read_regular_file(
            evidence.initial.OUTPUT / "sdk-advanced-candidate-tls.json", 128 * 1024)
        report = evidence.fixture.base.parse_json(data, 128 * 1024)
        with patch.object(evidence.initial, "checked", return_value=report), \
             self.assertRaises(evidence.fixture.harness.HarnessError):
            evidence.validate(data)

    def test_byte_changes_fail(self):
        for data in (self.data + b" ", self.data[:-1], b"{}\n"):
            with self.subTest(data_length=len(data)), self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(data)

    def test_semantics_are_checked_independently_of_digest(self):
        mutations = {
            "version": "2.7.0", "routable": True, "outcome": "failed",
            "scope": "public-sdk-strict-normal-build", "source_scope": "attested-build",
            "test_binary_sha256": "0" * 64, "candidate_registry_sha256": "0" * 64,
            "candidate_generated_rust_sha256": "0" * 64, "tests": [], "checks": [],
            "features": "sys,rustls-tls", "inputs": {}, "backup_decryption_verified": True,
            "synthetic_indices": "none", "executable_storage": "mutable-path",
            "build_provenance": "attested", "image_index_digest": "sha256:" + "0" * 64,
            "image_linux_amd64_digest": "sha256:" + "0" * 64,
        }
        for key, value in mutations.items():
            report = {**self.report, key: value}
            with self.subTest(key=key), patch.object(evidence.initial, "checked", return_value=report), \
                 self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(self.data, historical=True)
        for key in ("routable", "backup_decryption_verified"):
            with self.subTest(integer=key), \
                 patch.object(evidence.initial, "checked", return_value={**self.report, key: 0}), \
                 self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(self.data, historical=True)

    def test_missing_or_changed_current_inputs_fail(self):
        for name in self.report["inputs"]:
            for omit in (False, True):
                inputs = copy.deepcopy(self.report["inputs"])
                if omit:
                    inputs.pop(name)
                else:
                    inputs[name] = "0" * 64
                with self.subTest(name=name, omit=omit), \
                     patch.object(evidence.fixture, "input_hashes", return_value=inputs), \
                     self.assertRaises(evidence.fixture.harness.HarnessError):
                    evidence.validate(self.data)

    def test_failed_candidate_validation_blocks_evidence(self):
        with patch.object(evidence.fixture.candidate, "verify", side_effect=evidence.fixture.candidate.registry.RegistryError("invalid")), \
             patch.object(evidence.fixture, "input_hashes", return_value=self.report["inputs"]), \
             self.assertRaises(evidence.fixture.candidate.registry.RegistryError):
            evidence.verify()


if __name__ == "__main__":
    unittest.main()
