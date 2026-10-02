#!/usr/bin/python3 -EsSB
"""Reject altered patch provenance, contracts, scope and legacy engine removal."""

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import verify_openbao_2_6_4 as evidence


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.artifacts = {name: evidence.base.read_regular_file(evidence.OUTPUT / name, limit)
                          for name, (_, _, limit) in evidence.ARTIFACTS.items()}

    def test_exact_capture(self):
        values = evidence.validate(self.artifacts)
        self.assertIs(values["patch-tls.json"]["routable"], False)
        self.assertEqual([values["openapi.json"][k] for k in
                          ("path_count", "operation_count", "schema_count")], [526, 761, 552])

    def test_changed_or_omitted_source_fails(self):
        inputs = evidence.patch.input_hashes()
        for key in inputs:
            for omit in (False, True):
                with self.subTest(key=key, omit=omit):
                    changed = dict(inputs)
                    if omit:
                        del changed[key]
                    else:
                        changed[key] = "0" * 64
                    with patch.object(evidence.patch, "input_hashes", return_value=changed), \
                         self.assertRaises(evidence.patch.harness.HarnessError):
                        evidence.validate(self.artifacts)

    def test_each_artifact_is_immutable(self):
        for name in self.artifacts:
            changed = dict(self.artifacts)
            changed[name] += b" "
            with self.assertRaises(evidence.patch.harness.HarnessError):
                evidence.validate(changed)
        with self.assertRaises(evidence.patch.harness.HarnessError):
            evidence.validate({})

    def test_scope_semantics_independent_of_hash(self):
        for key, value in (("routable", True), ("scope", "public-sdk"), ("version", "2.7.1"),
                           ("checks", []), ("inputs", {}), ("openapi_sha256", "0" * 64)):
            with self.subTest(key=key):
                report = evidence.base.parse_json(self.artifacts["patch-tls.json"], 65536)
                report[key] = value
                changed = dict(self.artifacts)
                changed["patch-tls.json"] = evidence.base.canonical_json(report)
                with patch.object(evidence.patch, "pinned", side_effect=lambda data, _: data), \
                     self.assertRaises(evidence.patch.harness.HarnessError):
                    evidence.validate(changed)

    def test_contract_changes_fail_even_without_artifact_hashes(self):
        before = evidence.base.parse_json(evidence.base.read_regular_file(evidence.PREDECESSOR,
                    evidence.base.MAX_OPENAPI_BYTES), evidence.base.MAX_OPENAPI_BYTES)
        api = evidence.base.parse_json(self.artifacts["openapi.json"], evidence.base.MAX_OPENAPI_BYTES)
        mutations = [lambda a: a.update(version="2.7.1"),
                     lambda a: a.update(mounts=[]),
                     lambda a: a.update(operation_count=0),
                     lambda a: a["document"]["components"].update(schemas={}),
                     lambda a: a["document"]["info"].update(title="changed"),
                     lambda a: a["document"]["paths"].update({"/unexpected": {}})]
        for route in evidence.patch.LEGACY_ROUTES:
            mutations.append(lambda a, route=route: a["document"]["paths"].pop(route))
        for mutation in mutations:
            changed = copy.deepcopy(api)
            mutation(changed)
            with self.assertRaises(evidence.patch.harness.HarnessError):
                evidence.compare_contracts(changed, before)

    def test_retain_validates_before_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, (source, _, _) in evidence.ARTIFACTS.items():
                (root / source).write_bytes(self.artifacts[name])
            (root / "report.json").write_bytes(b"{}")
            with patch.object(evidence.base, "write_immutable") as write, \
                 self.assertRaises(evidence.patch.harness.HarnessError):
                evidence.retain(root)
            write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
