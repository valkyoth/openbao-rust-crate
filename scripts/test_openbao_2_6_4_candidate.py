#!/usr/bin/python3 -EsSB
"""Prove the 2.6 patch cannot acquire 2.7 exclusions, routes or capabilities."""

import copy
import unittest
from unittest.mock import patch

import generate_openbao_2_6_4_candidate as candidate


class CandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parent = candidate.previous.verify()
        cls.value = candidate.verify()

    def test_every_historical_cell_is_identical(self):
        self.assertEqual([v for v in self.value["versions"] if v != "2.6.4"], self.parent["versions"])
        self.assertEqual(self.value["logical_endpoints"], self.parent["logical_endpoints"])
        for before, after in zip(self.parent["operations"], self.value["operations"], strict=True):
            stripped = copy.deepcopy(after)
            added = stripped["ranges"].pop(-2)
            self.assertEqual(stripped, before)
            predecessor = candidate.selected(before["ranges"], "2.6.3")
            self.assertEqual(added, {**predecessor, "minimum": "2.6.4", "maximum": "2.6.4"})
            for version in self.parent["versions"]:
                self.assertEqual(candidate.selected(after["ranges"], version),
                                 candidate.selected(before["ranges"], version))

    def test_legacy_engines_are_not_excluded(self):
        for route in ("/auth/ldap/config", "/auth/kerberos/config", "/auth/radius/config", "/ldap/config"):
            operations = [o for o in self.value["operations"] if o["path_template"] == route]
            self.assertTrue(operations)
            for operation in operations:
                self.assertEqual(candidate.selected(operation["ranges"], "2.6.4")["availability"], "documented")
                self.assertEqual(candidate.selected(operation["ranges"], "2.7.0")["availability"], "unavailable")

    def test_newer_only_operations_remain_unavailable(self):
        added = [o for o in self.value["operations"]
                 if candidate.selected(o["ranges"], "2.6.3")["availability"] == "unavailable"
                 and candidate.selected(o["ranges"], "2.7.0")["availability"] != "unavailable"]
        self.assertTrue(added)
        for operation in added:
            self.assertEqual(candidate.selected(operation["ranges"], "2.6.4")["availability"], "unavailable")
        endpoint = next(e for e in self.value["logical_endpoints"] if e["id"] == "sys.internal-request-inspection")
        self.assertIsNone(candidate.selected(endpoint["variants"], "2.6.4", optional=True))

    def test_only_explicit_candidate_build_can_dispatch(self):
        self.assertIs(self.value["routable"], False)
        self.assertNotIn("2.6.4", self.value["routable_versions"])
        section = "GENERATED_ROUTABLE_PROFILE_VERSIONS: &[OpenBaoVersion] = &["
        normal = candidate.registry.rust_output(self.value).decode().split(section)[1].split("];")[0]
        staged = candidate.registry.rust_output(self.value, verification_candidate=True).decode().split(section)[1].split("];")[0]
        self.assertNotIn("OpenBaoVersion::new(2, 6, 4)", normal)
        self.assertIn("OpenBaoVersion::new(2, 7, 0)", normal)
        self.assertIn("OpenBaoVersion::new(2, 6, 4)", staged)
        altered = copy.deepcopy(self.value)
        altered["versions"][-2] = "2.6.5"
        with self.assertRaises(candidate.registry.RegistryError):
            candidate.registry.rust_output(altered, verification_candidate=True)

    def test_evidence_failure_blocks_candidate(self):
        with patch.object(candidate.evidence, "verify", side_effect=candidate.evidence.patch.harness.HarnessError("rejected")), \
             self.assertRaises(candidate.evidence.patch.harness.HarnessError):
            candidate.build()

    def test_gaps_and_overlapping_ranges_fail_closed(self):
        span = {"minimum": "2.6.0", "maximum": "2.6.4"}
        for spans in ([], [span, span]):
            with self.assertRaises(candidate.evidence.patch.harness.HarnessError):
                candidate.selected(spans, "2.6.3")
        with self.assertRaises(candidate.evidence.patch.harness.HarnessError):
            candidate.selected([span, span], "2.6.3", optional=True)


if __name__ == "__main__":
    unittest.main()
