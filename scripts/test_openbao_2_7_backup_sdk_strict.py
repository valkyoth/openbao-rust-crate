#!/usr/bin/python3 -EsSB
"""Integrity and scope regressions for normal-build strict backup evidence."""

import copy
import unittest
from unittest.mock import patch

import verify_openbao_2_7_backup_sdk_strict as subject


class StrictBackupEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = subject.verify()

    def test_report_and_binary_are_independently_anchored(self):
        for field in ("EXPECTED_SHA256", "TEST_BINARY_SHA256"):
            with patch.object(subject, field, "0" * 64):
                with self.assertRaises((subject.fixture.snapshots.SnapshotError,
                                        subject.fixture.recovery.harness.HarnessError)):
                    subject.verify()

    def test_every_input_is_required_and_current(self):
        for path in self.report["inputs"]:
            for omit in (False, True):
                report = copy.deepcopy(self.report)
                if omit:
                    del report["inputs"][path]
                else:
                    report["inputs"][path] = "0" * 64
                with self.assertRaises(subject.fixture.recovery.harness.HarnessError):
                    subject.fixture.validate_report(report, subject.TEST_BINARY_SHA256, strict=True)
            inputs = dict(self.report["inputs"], **{path: "0" * 64})
            with patch.object(subject.fixture, "input_hashes", return_value=inputs):
                with self.assertRaises(subject.fixture.recovery.harness.HarnessError):
                    subject.verify()

    def test_scope_and_checks_cannot_be_changed(self):
        for field, value in (("strict_profile_verified", False), ("strict_profile_verified", 1),
                             ("routable", False), ("routable", 1),
                             ("backup_decryption_verified", True),
                             ("scope", "public-sdk-strict-disposable-candidate-build"),
                             ("source_scope", "candidate"), ("checks", []),
                             ("outcome", "failed"), ("test", subject.fixture.TEST)):
            with self.assertRaises(subject.fixture.recovery.harness.HarnessError):
                subject.fixture.validate_report(dict(self.report, **{field: value}),
                                                subject.TEST_BINARY_SHA256, strict=True)
        with self.assertRaises(subject.fixture.recovery.harness.HarnessError):
            subject.fixture.validate_report(self.report, subject.TEST_BINARY_SHA256)


if __name__ == "__main__":
    unittest.main()
