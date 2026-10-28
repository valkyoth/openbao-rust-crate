#!/usr/bin/python3 -EsSB
"""Reject stale 2.7.2 captures, altered provenance and overstated guarantees."""

import copy
from contextlib import redirect_stdout
import io
import unittest
from unittest.mock import patch

import verify_openbao_2_7_2_regressions as evidence


class EvidenceTests(unittest.TestCase):
    def test_current_reports_and_reviewed_openapi(self):
        self.assertEqual(evidence.verify()["document"]["info"]["version"], "2.7.2")

    def test_all_source_inputs_and_report_fields_are_checked(self):
        for suite in evidence.REPORTS:
            data = evidence.base.read_regular_file(evidence.OUTPUT / (suite + "-tls.json"), 131072)
            original = evidence.validate_report(suite, data)
            for name in original["inputs"]:
                report = copy.deepcopy(original)
                report["inputs"][name] = "0" * 64
                with self.subTest(suite=suite, input=name), \
                     patch.object(evidence.initial, "checked", return_value=report), \
                     self.assertRaises(evidence.runner.harness.HarnessError):
                    evidence.validate_report(suite, data)
            changes = {"routable": True, "scope": "public-sdk", "version": "2.7.1",
                       "checks": [], "tls": "TLSv1.2", "harness_checks": [],
                       "extra": "unreviewed"}
            if suite == "control-groups":
                changes.update(server_replay_rejected=True, outcome="passed")
            else:
                changes["outcome"] = "failed"
            for name, value in changes.items():
                with self.subTest(suite=suite, field=name), \
                     patch.object(evidence.initial, "checked",
                                  return_value={**original, name: value}), \
                     self.assertRaises(evidence.runner.harness.HarnessError):
                    evidence.validate_report(suite, data)

    def test_changed_bytes_are_rejected(self):
        for suite in evidence.REPORTS:
            data = evidence.base.read_regular_file(evidence.OUTPUT / (suite + "-tls.json"), 131072)
            with self.subTest(suite=suite), self.assertRaises(evidence.runner.harness.HarnessError):
                evidence.validate_report(suite, data + b" ")

    def test_api_delta_rejects_unreviewed_change(self):
        api = evidence.validate_api(evidence.base.read_regular_file(
            evidence.OUTPUT / "openapi.json", evidence.base.MAX_OPENAPI_BYTES))
        changed = copy.deepcopy(api)
        changed["document"]["paths"].pop(next(iter(changed["document"]["paths"])))
        data = evidence.base.canonical_json(changed)
        with patch.object(evidence.initial, "checked", return_value=changed), \
             self.assertRaises(evidence.runner.harness.HarnessError):
            evidence.validate_api(data)

    def test_api_delta_accepts_only_reviewed_detailed_metadata_aliases(self):
        before = evidence.predecessor.initial.checked(
            evidence.base.read_regular_file(
                evidence.predecessor.OUTPUT / "openapi.json",
                evidence.base.MAX_OPENAPI_BYTES,
            ),
            evidence.predecessor.OPENAPI_SHA256,
            evidence.base.MAX_OPENAPI_BYTES,
        )
        after = evidence.validate_api(evidence.base.read_regular_file(
            evidence.OUTPUT / "openapi.json", evidence.base.MAX_OPENAPI_BYTES))
        changed = copy.deepcopy(before)
        operation = changed["document"]["paths"][
            "/{kv_v2_mount_path}/detailed-metadata/{path}"]["get"]
        operation["operationId"] = "kv-scan-detailed-metadata-path"
        operation["parameters"].reverse()
        evidence.compare_api(changed, after)
        changed["document"]["info"]["title"] = "unreviewed"
        with self.assertRaises(evidence.runner.harness.HarnessError):
            evidence.compare_api(changed, after)

    def test_invalid_report_is_never_retained(self):
        with patch("sys.argv", ["verifier", "--retain", "system", "--result", "/capture"]), \
             patch.object(evidence.base, "read_regular_file", return_value=b"{}\n"), \
             patch.object(evidence.base, "write_immutable") as write, redirect_stdout(io.StringIO()):
            self.assertEqual(evidence.main(), 1)
        write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
