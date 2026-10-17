#!/usr/bin/python3 -EsSB
"""RADIUS server evidence must reject altered provenance and stale inputs."""

import copy
import unittest
from unittest.mock import patch

import verify_openbao_radius_plugins as evidence
import verify_openbao_radius_sdk as sdk


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        root = evidence.ROOT / "2.7.0"
        self.report = evidence.base.parse_json((root / "report.json").read_bytes(), 65536)
        self.schema = (root / "runtime-openapi.json").read_bytes()
        self.inputs = evidence.fixture.input_hashes()

    def test_exact_pairs_pass(self):
        for version in evidence.ANCHORS:
            self.assertIs(evidence.verify(version)["routable"], False)
            self.assertEqual(sdk.verify(version)["scope"], "public-sdk-normal-build")

    def test_normal_sdk_requires_every_current_source_input(self):
        report = sdk.verify("2.7.0")
        schema = (evidence.ROOT / "2.7.0/sdk-normal-v4/runtime-openapi.json").read_bytes()
        for path in report["inputs"]:
            inputs = dict(report["inputs"])
            inputs[path] = "0" * 64
            with self.subTest(path=path), self.assertRaises(evidence.base.SnapshotError):
                sdk.validate_report(report, "2.7.0", inputs, schema)
            del inputs[path]
            with self.assertRaises(evidence.base.SnapshotError):
                sdk.validate_report(report, "2.7.0", inputs, schema)

    def test_normal_sdk_identity_scope_schema_and_anchor_are_exact(self):
        report = sdk.verify("2.7.0")
        schema = (evidence.ROOT / "2.7.0/sdk-normal-v4/runtime-openapi.json").read_bytes()
        for field, value in (("checks", []), ("execution", {}), ("binary_sha256", "0" * 64),
                             ("scope", "public-sdk-candidate-only"), ("cleanup", "failed"),
                             ("plugins", {}), ("routable", True), ("extra", True)):
            with self.subTest(field=field), self.assertRaises(evidence.base.SnapshotError):
                sdk.validate_report({**report, field: value}, "2.7.0", report["inputs"], schema)
        with self.assertRaises(evidence.base.SnapshotError):
            sdk.validate_report(report, "2.7.0", report["inputs"], schema + b" ")
        raw = evidence.base.canonical_json({**report, "checks": []})
        with patch.object(sdk.base, "read_regular_file", return_value=raw):
            with self.assertRaises(evidence.base.SnapshotError):
                sdk.verify("2.7.0")

    def test_candidate_history_is_not_normal_acceptance(self):
        for version in sdk.CANDIDATE_ANCHORS:
            report = sdk.verify(version, candidate=True)
            schema = (evidence.ROOT / version / "sdk-candidate/runtime-openapi.json").read_bytes()
            with self.assertRaises(evidence.base.SnapshotError):
                sdk.validate_report(report, version, report["inputs"], schema)

    def test_sdk_identity_inputs_and_execution_cannot_change(self):
        report = sdk.verify("2.7.0", candidate=True)
        schema = (evidence.ROOT / "2.7.0/sdk-candidate/runtime-openapi.json").read_bytes()
        for field, value in (("checks", []), ("execution", {}), ("binary_sha256", "0" * 64),
                             ("inputs", {}), ("scope", "public-sdk-normal-build"), ("extra", True)):
            with self.subTest(field=field), self.assertRaises(evidence.base.SnapshotError):
                sdk.validate_report({**report, field: value}, "2.7.0", report["inputs"], schema, candidate=True)
        for path in report["inputs"]:
            inputs = dict(report["inputs"])
            inputs[path] = "0" * 64
            with self.subTest(path=path), self.assertRaises(evidence.base.SnapshotError):
                sdk.validate_report(report, "2.7.0", inputs, schema, candidate=True)
            del inputs[path]
            with self.assertRaises(evidence.base.SnapshotError):
                sdk.validate_report(report, "2.7.0", inputs, schema, candidate=True)

    def test_six_sdk_contracts_require_exact_schema_methods(self):
        schema = evidence.base.parse_json(self.schema, 2 * 1024 * 1024)
        sdk.validate_operations(schema)
        for suffix, method in (("config", "post"), ("users", "get"), ("users/{name}", "post"),
                                ("users/{name}", "get"), ("users/{name}", "delete"), ("login/{urlusername}", "post")):
            changed = copy.deepcopy(schema)
            del changed["paths"]["/auth/{fixture_radius_mount_path}/" + suffix][method]
            with self.subTest(suffix=suffix, method=method), self.assertRaises(evidence.base.SnapshotError):
                sdk.validate_operations(changed)

    def test_identity_scope_and_cleanup_fail_closed(self):
        for field, value in (("checks", []), ("scope", "public-sdk-normal-build"), ("plugins", {}),
                             ("radius", {}), ("cleanup", "failed"), ("routable", True), ("routable", 0),
                             ("server_version", "2.7.1"), ("outcome", "failed"), ("extra", True)):
            with self.subTest(field=field), self.assertRaises(evidence.base.SnapshotError):
                evidence.validate_report({**self.report, field: value}, "2.7.0", self.inputs, self.schema)

    def test_unsigned_backend_and_protocol_limits_cannot_be_upgraded(self):
        for field, value in (("image", "unreviewed"), ("config", "0" * 64), ("publisher_signature", "verified"),
                             ("transport", "radsec"), ("message_authenticator_required", True),
                             ("message_authenticator_required", 0), ("trust", "production")):
            report = copy.deepcopy(self.report)
            report["radius"][field] = value
            with self.subTest(field=field), self.assertRaises(evidence.base.SnapshotError):
                evidence.validate_report(report, "2.7.0", self.inputs, self.schema)

    def test_every_input_is_required_and_hash_bound(self):
        for path in self.inputs:
            inputs = dict(self.inputs)
            inputs[path] = "0" * 64
            with self.subTest(path=path), self.assertRaises(evidence.base.SnapshotError):
                evidence.validate_report(self.report, "2.7.0", inputs, self.schema)
            del inputs[path]
            with self.assertRaises(evidence.base.SnapshotError):
                evidence.validate_report(self.report, "2.7.0", inputs, self.schema)

    def test_schema_methods_list_flag_and_digest_are_required(self):
        schema = evidence.base.parse_json(self.schema, 2 * 1024 * 1024)
        mutations = []
        for path in schema["paths"]:
            if "fixture_radius" in path:
                changed = copy.deepcopy(schema)
                del changed["paths"][path]
                mutations.append(changed)
        changed = copy.deepcopy(schema)
        changed["paths"]["/auth/{fixture_radius_mount_path}/users"]["get"]["parameters"] = []
        mutations.append(changed)
        for changed in mutations:
            raw = evidence.base.canonical_json(changed)
            report = {**self.report, "runtime_openapi_sha256": evidence.base.sha256(raw)}
            with self.assertRaises(evidence.base.SnapshotError):
                evidence.validate_report(report, "2.7.0", self.inputs, raw)
        with self.assertRaises(evidence.base.SnapshotError):
            evidence.validate_report(self.report, "2.7.0", self.inputs, self.schema + b" ")

    def test_anchor_and_exact_version_are_required(self):
        raw = evidence.base.canonical_json({**self.report, "cleanup": "failed"})
        with patch.object(evidence.base, "read_regular_file", return_value=raw):
            with self.assertRaises(evidence.base.SnapshotError):
                evidence.verify("2.7.0")
        with self.assertRaises(evidence.base.SnapshotError):
            evidence.verify("2.7.2")


if __name__ == "__main__":
    unittest.main()
