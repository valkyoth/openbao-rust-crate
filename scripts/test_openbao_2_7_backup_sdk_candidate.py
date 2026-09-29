#!/usr/bin/python3 -EsSB
"""Tamper regressions for retained strict candidate backup evidence."""

import copy
import unittest
from unittest.mock import patch

import generate_openbao_2_7_candidate as candidate
import verify_openbao_2_7_backup_sdk_candidate as subject


class StrictBackupEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = subject.verify()
        cls.candidate = candidate.verify()

    def test_independent_report_and_binary_pins(self):
        for field in ("EXPECTED_SHA256", "TEST_BINARY_SHA256"):
            with patch.object(subject, field, "0" * 64):
                with self.assertRaises((subject.fixture.snapshots.SnapshotError,
                                        subject.fixture.recovery.harness.HarnessError)):
                    subject.verify()

    def test_every_source_input_is_required_and_current(self):
        with patch.object(candidate, "verify", return_value=self.candidate):
            for path in self.report["inputs"]:
                for omit in (False, True):
                    changed = copy.deepcopy(self.report)
                    if omit:
                        del changed["inputs"][path]
                    else:
                        changed["inputs"][path] = "0" * 64
                    with self.assertRaises(subject.fixture.recovery.harness.HarnessError):
                        subject.fixture.validate_report(changed, subject.TEST_BINARY_SHA256, True)

    def test_scope_flags_checks_and_generated_override_cannot_change(self):
        with patch.object(candidate, "verify", return_value=self.candidate):
            for field, value in (("routable", True), ("routable", 0),
                                 ("strict_profile_verified", 1),
                                 ("backup_decryption_verified", True),
                                 ("scope", "public-sdk-promoted"), ("checks", []),
                                 ("test", subject.fixture.TEST),
                                 ("candidate_generated_rust_sha256", "0" * 64),
                                 ("candidate_registry_sha256", "0" * 64)):
                with self.assertRaises(subject.fixture.recovery.harness.HarnessError):
                    subject.fixture.validate_report(dict(self.report, **{field: value}),
                                                    subject.TEST_BINARY_SHA256, True)


if __name__ == "__main__":
    unittest.main()
