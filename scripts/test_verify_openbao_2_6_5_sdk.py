#!/usr/bin/python3 -EsSB
"""Reject stale inputs, scope widening and cross-mode 2.6.5 SDK evidence."""

import copy
import unittest
from unittest.mock import patch

import verify_openbao_2_6_5_sdk as evidence


class EvidenceTests(unittest.TestCase):
    def test_both_modes_are_current_and_separate(self):
        normal, candidate = evidence.verify("normal"), evidence.verify("candidate")
        self.assertIs(normal["routable"], True)
        self.assertIs(candidate["routable"], False)
        self.assertNotEqual(normal["test_binary_sha256"], candidate["test_binary_sha256"])

    def test_changed_bytes_and_cross_mode_reuse_fail(self):
        for mode in evidence.PINS:
            data = evidence.fixture.base.read_regular_file(evidence.output(mode), 128 * 1024)
            with self.subTest(mode=mode), self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(mode, data + b" ")
            other = "candidate" if mode == "normal" else "normal"
            with self.subTest(mode=mode, other=other), self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(other, data)

    def test_every_field_and_input_is_exact(self):
        for mode in evidence.PINS:
            data = evidence.fixture.base.read_regular_file(evidence.output(mode), 128 * 1024)
            report = evidence.fixture.base.parse_json(data, 128 * 1024)
            for key, value in (("version", "2.6.4"), ("routable", not report["routable"]),
                               ("scope", "widened"), ("outcome", "failed"), ("checks", []),
                               ("test_binary_sha256", "0" * 64), ("inputs", {})):
                changed = copy.deepcopy(report)
                changed[key] = value
                with self.subTest(mode=mode, key=key), \
                     patch.object(evidence.initial, "checked", return_value=changed), \
                     self.assertRaises(evidence.fixture.harness.HarnessError):
                    evidence.validate(mode, data)
            for name in report["inputs"]:
                changed = copy.deepcopy(report)
                changed["inputs"][name] = "0" * 64
                with self.subTest(mode=mode, input=name), \
                     patch.object(evidence.initial, "checked", return_value=changed), \
                     self.assertRaises(evidence.fixture.harness.HarnessError):
                    evidence.validate(mode, data)


if __name__ == "__main__":
    unittest.main()
