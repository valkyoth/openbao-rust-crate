#!/usr/bin/python3 -EsSB
"""Patch evidence, projection equivalence and non-promotion regression tests."""

import copy
import unittest
from unittest.mock import patch

import generate_openbao_2_7_1_candidate as candidate

evidence = candidate.evidence


class CandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.after = evidence.verify()
        cls.before = candidate.previous.staged.parse(candidate.previous.staged.verify()["openapi.json"])
        cls.parent = candidate.previous.verify()
        cls.candidate = candidate.verify()

    def test_historical_cells_and_variants_are_unchanged(self):
        self.assertEqual(self.candidate["versions"][:-1], self.parent["versions"])
        for old, new in zip(self.parent["operations"], self.candidate["operations"], strict=True):
            stripped = copy.deepcopy(new)
            added = stripped["ranges"].pop()
            self.assertEqual(stripped, old)
            self.assertEqual(added, {**old["ranges"][-1], "minimum": "2.7.1", "maximum": "2.7.1"})
        for old, new in zip(self.parent["logical_endpoints"], self.candidate["logical_endpoints"], strict=True):
            self.assertEqual(old["variants"], new["variants"][:-1])

    def test_only_verification_build_can_route_patch(self):
        ordinary = candidate.registry.rust_output(self.candidate).decode()
        staged = candidate.registry.rust_output(self.candidate, verification_candidate=True).decode()
        section = "GENERATED_ROUTABLE_PROFILE_VERSIONS: &[OpenBaoVersion] = &["
        self.assertNotIn("OpenBaoVersion::new(2, 7, 1)", ordinary.split(section)[1].split("];")[0])
        self.assertIn("OpenBaoVersion::new(2, 7, 1)", staged.split(section)[1].split("];")[0])
        altered = copy.deepcopy(self.candidate)
        altered["versions"][-1] = "2.7.2"
        with self.assertRaises(candidate.registry.RegistryError):
            candidate.registry.rust_output(altered, verification_candidate=True)

    def test_api_equivalence_does_not_hide_contract_changes(self):
        evidence.compare_api(self.before, self.after)
        for mutation in ("path", "schema", "parameter", "alias"):
            changed = copy.deepcopy(self.after)
            doc = changed["document"]
            if mutation == "path":
                del doc["paths"]["/sys/raw"]
            elif mutation == "schema":
                doc["components"]["schemas"]["NamespacesScanNamespacesResponse"] = {"type": "string"}
            elif mutation == "parameter":
                doc["paths"]["/sys/namespaces"]["get"]["parameters"][0]["required"] = False
            else:
                doc["paths"]["/sys/namespaces"]["get"]["operationId"] = "arbitrary-replacement"
            with self.assertRaises(evidence.patch.harness.HarnessError):
                evidence.compare_api(self.before, changed)

    def test_reports_reject_changed_inputs_or_forged_success(self):
        inputs = evidence.runner.input_hashes()
        for suite in evidence.REPORTS:
            data = evidence.base.read_regular_file(evidence.OUTPUT / (suite + "-tls-v2.json"), 131072)
            with patch.object(evidence.runner, "input_hashes", return_value={}), \
                 self.assertRaises(evidence.patch.harness.HarnessError):
                evidence.validate_report(suite, data)
            with self.assertRaises(evidence.patch.harness.HarnessError):
                evidence.validate_report(suite, data + b" ")
        self.assertTrue(inputs)
        data = evidence.base.read_regular_file(evidence.OUTPUT / "control-groups-tls-v2.json", 131072)
        report = evidence.base.parse_json(data, 131072)
        self.assertIs(report["server_replay_rejected"], False)
        report["outcome"] = "passed"
        with self.assertRaises(evidence.patch.harness.HarnessError):
            evidence.validate_report("control-groups", evidence.base.canonical_json(report))


if __name__ == "__main__":
    unittest.main()
