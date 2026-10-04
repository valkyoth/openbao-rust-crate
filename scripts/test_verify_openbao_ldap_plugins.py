#!/usr/bin/python3 -EsSB
"""Regressions for retained LDAP evidence identity and assurance boundaries."""

import copy
import unittest
from unittest.mock import patch

import verify_openbao_ldap_plugins as evidence


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.version = "2.7.0"
        root = evidence.ROOT / self.version
        self.schema = (root / "runtime-openapi.json").read_bytes()
        self.report = evidence.base.parse_json((root / "report.json").read_bytes(), 65536)
        self.inputs = evidence.fixture.input_hashes()

    def validate(self, report=None, inputs=None, schema=None, version=None):
        evidence.validate_report(self.report if report is None else report,
                                 self.version if version is None else version,
                                 self.inputs if inputs is None else inputs,
                                 self.schema if schema is None else schema)

    def test_retained_exact_versions_pass(self):
        for version in evidence.ANCHORS:
            self.assertIs(evidence.verify(version)["routable"], False)

    def test_checkpoint_reports_are_preserved_but_not_current(self):
        anchors = {
            "2.7.0": "1d2ca7f8942ac02b4c7fa41d406139446bf3b6a034d90a3ef66d33022152f28f",
            "2.7.1": "7316f7f37644db3ccb5853544017071ce3e37ca6f877d17c2745b9e8eb2489cc",
        }
        for version, digest in anchors.items():
            root = evidence.ROOT / version / "server-checkpoint"
            raw = evidence.base.read_regular_file(root / "report.json", 65536)
            self.assertEqual(evidence.base.sha256(raw), digest)
            report = evidence.base.parse_json(raw, 65536)
            schema = evidence.base.read_regular_file(root / "runtime-openapi.json", 2 * 1024 * 1024)
            evidence.validate_report(report, version, report["inputs"], schema)
            with self.assertRaises(evidence.base.SnapshotError):
                evidence.validate_report(report, version, self.inputs, schema)

    def test_scope_and_artifact_mutations_fail_closed(self):
        for key, value in (("scope", "sdk-integration"), ("outcome", "failed"),
                           ("routable", 0), ("routable", True), ("cleanup", "failed"),
                           ("server_version", "2.7.1"), ("checks", []), ("plugins", {}),
                           ("directory", {"publisher_signature": "verified"})):
            report = copy.deepcopy(self.report)
            report[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(evidence.base.SnapshotError):
                self.validate(report=report)
        report = {**self.report, "unreviewed_claim": True}
        with self.assertRaises(evidence.base.SnapshotError):
            self.validate(report=report)

    def test_missing_and_changed_inputs_fail_closed(self):
        for path in self.inputs:
            changed = dict(self.inputs)
            changed[path] = "0" * 64
            with self.subTest(path=path), self.assertRaises(evidence.base.SnapshotError):
                self.validate(inputs=changed)
            del changed[path]
            with self.subTest(missing=path), self.assertRaises(evidence.base.SnapshotError):
                self.validate(inputs=changed)

    def test_schema_digest_mutation_fails_closed(self):
        with self.assertRaises(evidence.base.SnapshotError):
            self.validate(schema=self.schema + b" ")

    def test_schema_structure_and_canonical_form_are_checked(self):
        schema = evidence.base.parse_json(self.schema, 2 * 1024 * 1024)
        for changed in ({**schema, "paths": {}}, {**schema, "openapi": "2.0"}):
            raw = evidence.base.canonical_json(changed)
            report = {**self.report, "runtime_openapi_sha256": evidence.base.sha256(raw)}
            with self.assertRaises(evidence.base.SnapshotError):
                self.validate(report=report, schema=raw)
        raw = self.schema + b" "
        report = {**self.report, "runtime_openapi_sha256": evidence.base.sha256(raw)}
        with self.assertRaises(evidence.base.SnapshotError):
            self.validate(report=report, schema=raw)

    def test_independent_report_anchor_is_required(self):
        raw = evidence.base.canonical_json({**self.report, "routable": True})
        with patch.object(evidence.base, "read_regular_file", return_value=raw):
            with self.assertRaises(evidence.base.SnapshotError):
                evidence.verify(self.version)

    def test_unknown_server_is_rejected(self):
        for version in ("2.7", "2.7.2", "2.6.4"):
            with self.subTest(version=version), self.assertRaises(evidence.base.SnapshotError):
                evidence.verify(version)


if __name__ == "__main__":
    unittest.main()
