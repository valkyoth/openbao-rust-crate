#!/usr/bin/python3 -EsSB
"""Reject omissions, substitutions and expanded assurance in delta accounting."""

import copy
import unittest
from unittest.mock import patch

import verify_openbao_2_7_delta_review as subject


class DeltaReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = subject.verify()
        cls.delta = subject.staged.parse(subject.base.read_regular_file(
            subject.staged.STAGED / "2.6.3--2.7.0.json", 128 * 1024))

    def test_every_record_and_assignment_is_bound(self):
        for index in range(189):
            for mutation in ("omit", "duplicate", "field", "group"):
                document = copy.deepcopy(self.document)
                if mutation == "omit": del document["changes"][index]
                elif mutation == "duplicate": document["changes"][index] = document["changes"][(index + 1) % 189]
                elif mutation == "field": document["changes"][index]["field"] = "unreviewed"
                else: document["changes"][index]["review_group"] = "unreviewed"
                with self.assertRaises(subject.base.SnapshotError): subject.validate(document, self.delta)

    def test_scope_and_digest_cannot_be_widened(self):
        for value in ("profile-promoted", True, None):
            with self.assertRaises(subject.base.SnapshotError):
                subject.validate(dict(self.document, scope=value), self.delta)
        with patch.object(subject, "EXPECTED_SHA256", "0" * 64):
            with self.assertRaises(subject.base.SnapshotError): subject.verify()


if __name__ == "__main__":
    unittest.main()
