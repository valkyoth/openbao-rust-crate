import unittest

import maintenance_control_evidence as policy
import verify_openbao_2_7_control_groups as base
import verify_openbao_2_7_1_regressions as patch1
import verify_openbao_2_7_2_regressions as patch2


class HistoricalControlTests(unittest.TestCase):
    def test_review_is_limited_to_one_input_transition_and_report(self):
        current = {"src/sys.rs": policy.REVIEWED_SYS, "fixture": "new"}
        for version, digest in policy.HISTORICAL.items():
            self.assertEqual(policy.expected_inputs(version, digest, current),
                             {"src/sys.rs": policy.OLD_SYS, "fixture": "new"})
            for other_version, other_digest, inputs in (
                ("2.7.3", digest, current), (version, "0" * 64, current),
                (version, digest, {"src/sys.rs": "0" * 64}), (version, digest, {}),
            ):
                self.assertEqual(policy.expected_inputs(other_version, other_digest, inputs), inputs)
        self.assertEqual(current["src/sys.rs"], policy.REVIEWED_SYS)

    def test_archived_results_do_not_assert_server_fix(self):
        report = base.verify()
        self.assertEqual(report["security_checks"], {"server-replay-rejection": "known-upstream-failure"})
        for verifier in (patch1, patch2):
            raw = verifier.base.read_regular_file(verifier.report_path("control-groups"), 128 * 1024)
            report = verifier.validate_report("control-groups", raw)
            self.assertIs(report["server_replay_rejected"], False)
            self.assertIs(report["routable"], False)


if __name__ == "__main__":
    unittest.main()
