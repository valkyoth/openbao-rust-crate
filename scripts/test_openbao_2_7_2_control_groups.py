#!/usr/bin/python3 -EsSB
"""Offline controls for strict OpenBao 2.7.2 replay evidence."""

import contextlib
import io
import unittest

import openbao_2_7_2_control_groups as subject


class ControlGroupPatchTests(unittest.TestCase):
    def test_only_exact_replay_rejection_can_produce_evidence(self):
        inputs = subject.input_hashes()
        report = subject.report_for(inputs, True)
        subject.validate_report(report, inputs)
        self.assertEqual(report["version"], "2.7.2")
        self.assertEqual(report["outcome"], "passed")
        self.assertEqual(report["security_checks"], {"server-replay-rejection": "passed"})
        for value in (False, None, 1, "passed"):
            with self.assertRaises(subject.harness.HarnessError):
                subject.report_for(inputs, value)

    def test_successful_replay_never_uses_the_historical_exception(self):
        with contextlib.redirect_stdout(io.StringIO()):
            for strict in (False, True):
                with self.assertRaises(subject.harness.HarnessError):
                    subject.classify_known_replay(
                        200, {"data": {"version": 3}}, 3, strict
                    )

    def test_exact_denial_and_unchanged_state_pass(self):
        denial = {"errors": ["wrapping token is not valid or does not exist"]}
        for strict in (False, True):
            self.assertIs(subject.classify_known_replay(400, denial, 2, strict), True)
        for status, body, version in ((200, {}, 2), (400, {}, 2), (400, denial, 3)):
            with contextlib.redirect_stdout(io.StringIO()), \
                    self.assertRaises(subject.harness.HarnessError):
                subject.classify_known_replay(status, body, version, True)

    def test_report_rejects_mutation(self):
        inputs = subject.input_hashes()
        report = subject.report_for(inputs, True)
        for field in report:
            changed = dict(report)
            del changed[field]
            with self.assertRaises(subject.harness.HarnessError):
                subject.validate_report(changed, inputs)
        changed = dict(report)
        changed["security_checks"] = {"server-replay-rejection": "known-upstream-failure"}
        with self.assertRaises(subject.harness.HarnessError):
            subject.validate_report(changed, inputs)


if __name__ == "__main__":
    unittest.main()
