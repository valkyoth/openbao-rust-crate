#!/usr/bin/python3 -EsSB
"""Patch-candidate provenance and non-promotion regression tests."""

import unittest
from unittest.mock import patch

import generate_openbao_2_7_2_candidate as candidate


class CandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parent = candidate.load_parent()
        cls.value = candidate.verify()

    def test_parent_is_digest_anchored_without_revalidating_old_live_inputs(self):
        with patch.object(candidate.previous, "verify", side_effect=AssertionError("must not run")):
            self.assertEqual(candidate.load_parent(), self.parent)
            self.assertEqual(candidate.build()["versions"], self.value["versions"])

    def test_patch_remains_candidate_only(self):
        self.assertIs(self.value["routable"], False)
        self.assertNotIn("2.7.2", self.value["routable_versions"])
        self.assertEqual(self.value["versions"][-1], "2.7.2")
        self.assertEqual(self.value["versions"][:-1], self.parent["versions"])

    def test_evidence_failure_blocks_candidate(self):
        with patch.object(candidate.evidence, "verify",
                          side_effect=candidate.evidence.runner.harness.HarnessError("rejected")), \
             self.assertRaises(candidate.evidence.runner.harness.HarnessError):
            candidate.build()


if __name__ == "__main__":
    unittest.main()
