#!/usr/bin/python3 -EsSB
"""Reject stale patch captures, altered provenance and overstated guarantees."""

import copy
from contextlib import redirect_stdout
import io
import unittest
from unittest.mock import patch

import verify_openbao_2_7_1_regressions as evidence


class EvidenceTests(unittest.TestCase):
    def test_current_reports_and_unchanged_openapi(self):
        self.assertEqual(evidence.verify()["document"]["info"]["version"], "2.7.1")

    def test_original_reports_are_not_current_even_without_digest_check(self):
        for suite in evidence.REPORTS:
            data = evidence.base.read_regular_file(evidence.OUTPUT / (suite + "-tls.json"), 131072)
            report = evidence.base.parse_json(data, 131072)
            with self.subTest(suite=suite), patch.object(evidence.initial, "checked", return_value=report), \
                 self.assertRaises(evidence.runner.harness.HarnessError):
                evidence.validate_report(suite, data)

    def test_all_source_inputs_and_report_fields_are_checked(self):
        for suite in evidence.REPORTS:
            data = evidence.base.read_regular_file(evidence.OUTPUT / (suite + "-tls-v2.json"), 131072)
            original = evidence.validate_report(suite, data)
            for name in original["inputs"]:
                for omit in (False, True):
                    report = copy.deepcopy(original)
                    if omit:
                        del report["inputs"][name]
                    else:
                        report["inputs"][name] = "0" * 64
                    with self.subTest(suite=suite, input=name, omit=omit), \
                         patch.object(evidence.initial, "checked", return_value=report), \
                         self.assertRaises(evidence.runner.harness.HarnessError):
                        evidence.validate_report(suite, data)
            changes = {"routable": 0, "scope": "public-sdk", "version": "2.7.0", "checks": [],
                       "tls": "TLSv1.2", "harness_checks": [], "extra": "unreviewed"}
            if suite == "control-groups":
                changes.update(server_replay_rejected=True, outcome="passed")
            else:
                changes["outcome"] = "failed"
            for name, value in changes.items():
                with self.subTest(suite=suite, field=name), \
                     patch.object(evidence.initial, "checked", return_value={**original, name: value}), \
                     self.assertRaises(evidence.runner.harness.HarnessError):
                    evidence.validate_report(suite, data)
            for name in original:
                report = dict(original)
                del report[name]
                with self.subTest(suite=suite, missing=name), \
                     patch.object(evidence.initial, "checked", return_value=report), \
                     self.assertRaises(evidence.runner.harness.HarnessError):
                    evidence.validate_report(suite, data)

    def test_changed_bytes_are_rejected(self):
        for suite in evidence.REPORTS:
            data = evidence.base.read_regular_file(evidence.OUTPUT / (suite + "-tls-v2.json"), 131072)
            with self.subTest(suite=suite), self.assertRaises(evidence.runner.harness.HarnessError):
                evidence.validate_report(suite, data + b" ")

    def test_invalid_report_is_never_retained(self):
        with patch("sys.argv", ["verifier", "--retain", "system", "--result", "/capture"]), \
             patch.object(evidence.base, "read_regular_file", return_value=b"{}\n"), \
             patch.object(evidence.base, "write_immutable") as write, redirect_stdout(io.StringIO()):
            self.assertEqual(evidence.main(), 1)
        write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
