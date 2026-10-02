#!/usr/bin/python3 -EsSB
"""Reject changed patch-upgrade bytes, stale inputs and expanded assurances."""

import copy
from contextlib import redirect_stdout
import io
import unittest
from unittest.mock import patch

import verify_openbao_2_7_1_backup_upgrade as evidence


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = evidence.fixture.base.read_regular_file(evidence.OUTPUT, 128 * 1024)
        cls.report = evidence.fixture.base.parse_json(cls.data, 128 * 1024)

    def test_current_report_preserves_narrow_scope(self):
        report = evidence.verify()
        self.assertEqual(report["source_version"], "2.7.0")
        self.assertEqual(report["version"], "2.7.1")
        for name in ("sdk_live_verified", "general_upgrade_verified", "backup_decryption_verified",
                     "unseal_backup_upgrade_verified", "routable"):
            self.assertIs(report[name], False)

    def test_changed_bytes_fail(self):
        for data in (self.data + b" ", self.data[:-1], b"{}\n"):
            with self.subTest(length=len(data)), self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(data)

    def test_changed_or_missing_fields_fail_independently_of_digest(self):
        changes = {
            "source_version": "2.6.3", "version": "2.7.0", "inputs": {}, "checks": [],
            "source_image": "sha256:" + "0" * 64, "target_image": "sha256:" + "0" * 64,
            "source_image_index": "sha256:" + "0" * 64, "target_image_index": "sha256:" + "0" * 64,
            "scope": "general-upgrade", "tls": "TLSv1.2", "outcome": "failed",
        }
        for name in ("sdk_live_verified", "general_upgrade_verified", "backup_decryption_verified",
                     "unseal_backup_upgrade_verified", "routable"):
            changes[name] = True
        for name, value in changes.items():
            with self.subTest(name=name), patch.object(evidence.initial, "checked", return_value={**self.report, name: value}), \
                 self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(self.data)
        for name in self.report:
            report = dict(self.report)
            del report[name]
            with self.subTest(missing=name), patch.object(evidence.initial, "checked", return_value=report), \
                 self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(self.data)
        for name in ("routable", "sdk_live_verified", "general_upgrade_verified"):
            with self.subTest(integer=name), patch.object(evidence.initial, "checked", return_value={**self.report, name: 0}), \
                 self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(self.data)

    def test_every_current_input_is_required_and_unchanged(self):
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

    def test_invalid_capture_is_not_retained_or_reported_as_success(self):
        with patch("sys.argv", ["verifier", "--retain", "/capture"]), \
             patch.object(evidence.fixture.base, "read_regular_file", return_value=b"{}\n"), \
             patch.object(evidence.fixture.base, "write_immutable") as write, \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(evidence.main(), 1)
        write.assert_not_called()
        self.assertIn("failed", output.getvalue())


if __name__ == "__main__":
    unittest.main()
