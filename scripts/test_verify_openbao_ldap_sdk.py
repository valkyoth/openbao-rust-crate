#!/usr/bin/python3 -EsSB
"""Normal-build LDAP evidence must fail closed on input, identity and scope drift."""

import copy
import unittest
from unittest.mock import patch

import verify_openbao_ldap_sdk as evidence


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        root = evidence.server.ROOT / "2.7.0/sdk-normal-v3"
        self.report = evidence.base.parse_json((root / "report.json").read_bytes(), 65536)
        self.schema = (root / "runtime-openapi.json").read_bytes()
        self.inputs = evidence.sdk.input_hashes()

    def test_exact_retained_pairs_pass(self):
        for version in evidence.ANCHORS:
            self.assertIs(evidence.verify(version)["routable"], False)

    def test_identity_scope_stages_execution_and_cleanup_are_exact(self):
        mutations = (("binary_sha256", "0" * 64), ("checks", []), ("scope", "production-sdk"),
                     ("schema", "openbao-ldap-plugin-server/v1"), ("routable", True),
                     ("routable", 0), ("cleanup", "failed"), ("execution", {}),
                     ("plugins", {}), ("server_version", "2.7.1"), ("outcome", "failed"))
        for field, value in mutations:
            report = {**self.report, field: value}
            with self.subTest(field=field), self.assertRaises(evidence.base.SnapshotError):
                evidence.validate_report(report, "2.7.0", self.inputs, self.schema)
        report = {**self.report, "library_verified": True}
        with self.assertRaises(evidence.base.SnapshotError):
            evidence.validate_report(report, "2.7.0", self.inputs, self.schema)

    def test_candidate_scope_cannot_replace_normal_build_acceptance(self):
        report = {**self.report, "scope": "public-sdk-candidate-only"}
        with self.assertRaises(evidence.base.SnapshotError):
            evidence.validate_report(report, "2.7.0", self.inputs, self.schema)

    def test_omitted_and_mutated_source_inputs_fail_closed(self):
        for path in self.inputs:
            inputs = dict(self.inputs)
            inputs[path] = "0" * 64
            with self.subTest(changed=path), self.assertRaises(evidence.base.SnapshotError):
                evidence.validate_report(self.report, "2.7.0", inputs, self.schema)
            del inputs[path]
            with self.subTest(missing=path), self.assertRaises(evidence.base.SnapshotError):
                evidence.validate_report(self.report, "2.7.0", inputs, self.schema)

    def test_altered_schema_and_wrong_version_fail_closed(self):
        with self.assertRaises(evidence.base.SnapshotError):
            evidence.validate_report(self.report, "2.7.0", self.inputs, self.schema + b" ")
        with self.assertRaises(evidence.base.SnapshotError):
            evidence.verify("2.7.2")

    def test_anchor_precedes_report_claim_validation(self):
        report = copy.deepcopy(self.report)
        report["routable"] = True
        raw = evidence.base.canonical_json(report)
        with patch.object(evidence.base, "read_regular_file", return_value=raw):
            with self.assertRaises(evidence.base.SnapshotError):
                evidence.verify("2.7.0")

    def test_all_33_operations_require_matching_schema_methods_and_list_flags(self):
        schema = evidence.base.parse_json(self.schema, 2 * 1024 * 1024)
        evidence.validate_operations(schema)
        for path in ("/{fixture_ldap_secrets_mount_path}/library/{name}/status",
                     "/{fixture_ldap_secrets_mount_path}/library/{name}/check-out"):
            changed = copy.deepcopy(schema)
            del changed["paths"][path]
            with self.subTest(path=path), self.assertRaises(evidence.base.SnapshotError):
                evidence.validate_operations(changed)
        changed = copy.deepcopy(schema)
        changed["paths"]["/{fixture_ldap_secrets_mount_path}/static-role"]["get"]["parameters"] = []
        with self.assertRaises(evidence.base.SnapshotError):
            evidence.validate_operations(changed)


if __name__ == "__main__":
    unittest.main()
