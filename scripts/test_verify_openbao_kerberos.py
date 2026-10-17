#!/usr/bin/python3 -EsSB
"""Kerberos evidence identity, input, schema and acceptance-scope regressions."""

import copy
import unittest
from unittest.mock import patch

import verify_openbao_kerberos_plugins as server
import verify_openbao_kerberos_sdk as sdk


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.root = server.ROOT / "2.7.0"
        self.report = server.base.parse_json((self.root / "report.json").read_bytes(), 65536)
        self.schema = (self.root / "runtime-openapi.json").read_bytes()
        self.inputs = server.fixture.input_hashes()

    def test_exact_server_pairs_and_candidate_history(self):
        for version in server.ANCHORS:
            self.assertIs(server.verify(version)["routable"], False)
            self.assertEqual(sdk.verify(version, candidate=True)["scope"], "public-sdk-candidate-only")
            self.assertEqual(sdk.verify(version)["scope"], "public-sdk-normal-build")

    def test_normal_evidence_rejects_every_omitted_or_mutated_input(self):
        report = sdk.verify("2.7.0")
        schema = (self.root / "sdk-normal-v3/runtime-openapi.json").read_bytes()
        for path in report["inputs"]:
            inputs = dict(report["inputs"])
            inputs[path] = "0" * 64
            with self.subTest(path=path), self.assertRaises(server.base.SnapshotError):
                sdk.validate_report(report, "2.7.0", inputs, schema)
            del inputs[path]
            with self.assertRaises(server.base.SnapshotError):
                sdk.validate_report(report, "2.7.0", inputs, schema)

    def test_normal_evidence_rejects_identity_scope_and_schema_drift(self):
        report = sdk.verify("2.7.0")
        schema = (self.root / "sdk-normal-v3/runtime-openapi.json").read_bytes()
        for key, value in (("binary_sha256", "0" * 64), ("checks", []), ("execution", {}),
                           ("scope", "public-sdk-candidate-only"), ("plugins", {}),
                           ("cleanup", "failed"), ("routable", True), ("extra", True)):
            with self.subTest(key=key), self.assertRaises(server.base.SnapshotError):
                sdk.validate_report({**report, key: value}, "2.7.0", report["inputs"], schema)
        with self.assertRaises(server.base.SnapshotError):
            sdk.validate_report(report, "2.7.0", report["inputs"], schema + b" ")
        with patch.object(sdk.base, "read_regular_file", return_value=sdk.base.canonical_json({**report, "checks": []})):
            with self.assertRaises(server.base.SnapshotError):
                sdk.verify("2.7.0")

    def test_server_identity_and_scope_are_exact(self):
        for key, value in (("checks", []), ("scope", "public-sdk-normal-build"), ("kdc", {}),
                           ("plugins", {}), ("cleanup", "failed"), ("routable", True),
                           ("routable", 0), ("server_version", "2.7.1"), ("extra", True)):
            with self.subTest(key=key), self.assertRaises(server.base.SnapshotError):
                server.validate_report({**self.report, key: value}, "2.7.0", self.inputs, self.schema)

    def test_every_server_input_is_required_and_hash_bound(self):
        for key in self.inputs:
            changed = dict(self.inputs)
            changed[key] = "0" * 64
            with self.subTest(key=key), self.assertRaises(server.base.SnapshotError):
                server.validate_report(self.report, "2.7.0", changed, self.schema)
            del changed[key]
            with self.assertRaises(server.base.SnapshotError):
                server.validate_report(self.report, "2.7.0", changed, self.schema)

    def test_candidate_cannot_satisfy_normal_acceptance(self):
        report = sdk.verify("2.7.0", candidate=True)
        schema = (self.root / "sdk-candidate/runtime-openapi.json").read_bytes()
        with self.assertRaises(server.base.SnapshotError):
            sdk.validate_report(report, "2.7.0", report["inputs"], schema)

    def test_sdk_identity_and_inputs_fail_closed(self):
        report = sdk.verify("2.7.0", candidate=True)
        schema = (self.root / "sdk-candidate/runtime-openapi.json").read_bytes()
        for key, value in (("binary_sha256", "0" * 64), ("checks", []), ("execution", {}), ("inputs", {})):
            with self.subTest(key=key), self.assertRaises(server.base.SnapshotError):
                sdk.validate_report({**report, key: value}, "2.7.0", report["inputs"], schema, candidate=True)

    def test_anchors_reject_modified_reports(self):
        raw = server.base.canonical_json({**self.report, "cleanup": "failed"})
        with patch.object(server.base, "read_regular_file", return_value=raw):
            with self.assertRaises(server.base.SnapshotError):
                server.verify("2.7.0")
            with self.assertRaises(server.base.SnapshotError):
                sdk.verify("2.7.0", candidate=True)

    def test_all_nine_schema_operations_and_list_flags_are_required(self):
        schema = server.base.parse_json(self.schema, 2 * 1024 * 1024)
        sdk.validate_operations(schema)
        for path in schema["paths"]:
            if "fixture_kerberos" in path:
                changed = copy.deepcopy(schema)
                del changed["paths"][path]
                with self.subTest(path=path), self.assertRaises(server.base.SnapshotError):
                    sdk.validate_operations(changed)
        changed = copy.deepcopy(schema)
        changed["paths"]["/auth/{fixture_kerberos_mount_path}/groups"]["get"]["parameters"] = []
        with self.assertRaises(server.base.SnapshotError):
            sdk.validate_operations(changed)
        with self.assertRaises(server.base.SnapshotError):
            server.validate_report(self.report, "2.7.0", self.inputs, self.schema + b" ")
        with self.assertRaises(server.base.SnapshotError):
            server.verify("2.7.2")


if __name__ == "__main__":
    unittest.main()
