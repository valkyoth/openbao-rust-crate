#!/usr/bin/python3 -EsSB
"""Candidate registry invariants; no live dispatch or profile promotion claims."""

import copy
import unittest
from unittest.mock import patch

import generate_openbao_2_7_candidate as subject


class CandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.active, cls.docs, cls.openapi = subject.inputs()
        cls.candidate = subject.build(cls.active, cls.docs, cls.openapi)

    def operation(self, method, path):
        return next(op for op in self.candidate["operations"]
                    if op["method"] == method and op["path_template"] == path)

    def test_every_historical_cell_and_identity_is_preserved(self):
        generated = {op["id"]: op for op in self.candidate["operations"]}
        for old in self.active["operations"]:
            candidate = generated[old["id"]]
            for field in ("id", "method", "path_template", "disposition"):
                self.assertEqual(old[field], candidate[field])
            self.assertEqual(old["ranges"], candidate["ranges"][:-1])
            for version in self.active["versions"]:
                self.assertEqual(subject.registry.state_for_version(old, version),
                                 subject.registry.state_for_version(candidate, version))
        self.assertEqual(len(generated), 707)
        self.assertEqual(len(generated) - len(self.active["operations"]), 16)
        self.assertEqual(self.candidate["routable_versions"], self.active["versions"])
        self.assertNotIn(subject.VERSION, self.candidate["routable_versions"])
        self.assertIs(self.candidate["routable"], False)
        with self.assertRaises(subject.registry.RegistryError):
            subject.registry.validate_registry(self.candidate)

    def test_new_identities_are_unavailable_on_every_historical_profile(self):
        for method, path in subject.NEW_RUNTIME:
            op = self.operation(method, path)
            self.assertEqual(op["disposition"], "typed-gated")
            for version in self.active["versions"]:
                self.assertEqual(subject.registry.state_for_version(op, version), ("unavailable", "none"))
            self.assertEqual(subject.registry.state_for_version(op, subject.VERSION), ("documented", "locked-openapi"))

    def test_externalized_plugins_and_security_blocks_remain_closed(self):
        excluded = 0
        for op in self.candidate["operations"]:
            if op["path_template"].startswith(subject.EXCLUDED_PREFIXES):
                self.assertEqual(op["ranges"][-1]["availability"], "unavailable")
                excluded += 1
            if op["disposition"] == "security-blocked":
                self.assertEqual(op["ranges"][-1]["availability"], "security-blocked")
        self.assertGreater(excluded, 0)

    def test_discrepancies_and_workflow_projection_are_explicit(self):
        self.assertEqual(self.operation("GET", "/sys/internal/inspect/request/root")["ranges"][-1]["availability"], "unavailable")
        identities = {(op["method"], op["path_template"]) for op in self.candidate["operations"]}
        self.assertNotIn(("PATCH", "/ssh/issuer/:issuer_ref"), identities)
        self.assertNotIn(("GET", "/sys/workflows/manage"), identities)
        for method in ("LIST", "SCAN"):
            self.assertEqual(self.operation(method, "/sys/workflows/manage")["ranges"][-1]["availability"], "documented")
        for op in self.candidate["operations"]:
            if op["path_template"].startswith("/sys/external-keys/"):
                self.assertNotEqual(op["method"], "PUT")
        for old, new in zip(self.active["logical_endpoints"], self.candidate["logical_endpoints"]):
            self.assertEqual(old["id"], new["id"])
            self.assertEqual(old["variants"][:-1], new["variants"][:-1])
            self.assertEqual(dict(old["variants"][-1], maximum=subject.VERSION), new["variants"][-1])
        inspection = self.candidate["logical_endpoints"][-1]
        self.assertEqual(inspection["id"], "sys.internal-request-inspection")
        self.assertEqual(len(inspection["variants"]), 2)
        for variant, path in zip(inspection["variants"],
                                 ("/sys/internal/inspect/request/root", "/sys/internal/inspect/request")):
            self.assertEqual(variant["operation_id"], self.operation("GET", path)["id"])
        self.assertEqual(inspection["variants"][0]["minimum"], "2.5.5")
        self.assertEqual(inspection["variants"][0]["maximum"], "2.5.5")
        self.assertEqual(inspection["variants"][1]["minimum"], "2.7.0")

    def test_generated_rust_promotes_only_reviewed_candidate_inventory(self):
        output = subject.registry.rust_output(self.candidate).decode()
        profiles, rest = output.split("GENERATED_ROUTABLE_PROFILE_VERSIONS", 1)
        routable, operations = rest.split("GENERATED_OPERATIONS", 1)
        self.assertIn("OpenBaoVersion::new(2, 7, 0)", profiles)
        self.assertIn("OpenBaoVersion::new(2, 7, 0)", routable)
        self.assertEqual(routable.count("OpenBaoVersion::new("), 26)
        self.assertEqual(operations.count("OpenBaoOperation::generated("), 707)
        for method, path in subject.NEW_RUNTIME:
            self.assertIn(subject.registry.stable_id(method, path), operations)

    def test_runtime_disappearance_or_discrepancy_changes_fail_closed(self):
        for method, path in set(subject.NEW_RUNTIME.values()):
            changed = copy.deepcopy(self.openapi)
            del changed["document"]["paths"][path][method]
            with self.assertRaises(subject.registry.RegistryError): subject.build(self.active, self.docs, changed)
        for change in ("ssh", "inspect", "workflow", "list"):
            changed = copy.deepcopy(self.openapi)
            paths = changed["document"]["paths"]
            if change == "ssh": paths["/{ssh_mount_path}/issuer/{issuer_ref}"]["patch"] = {}
            if change == "inspect": paths["/sys/internal/inspect/request/root"] = {"get": {}}
            if change == "workflow": paths["/sys/workflows/manage"]["get"]["parameters"] = []
            if change == "list": paths["/sys/external-keys/configs"]["get"]["parameters"] = []
            with self.assertRaises(subject.registry.RegistryError): subject.build(self.active, self.docs, changed)
        docs = copy.deepcopy(self.docs)
        docs["operations"].append({"method": "GET", "path": "/sys/unreviewed"})
        with self.assertRaises(subject.registry.RegistryError): subject.build(self.active, docs, self.openapi)

    def test_retained_candidate_rejects_tampering(self):
        with patch.object(subject, "inputs", return_value=(self.active, self.docs, self.openapi)):
            subject.verify()
            for field, value in (("routable", True), ("routable", 0), ("routable_versions", [subject.VERSION]),
                                 ("operations", []), ("active_registry_sha256", "0" * 64),
                                 ("logical_endpoints", []), ("excluded_prefixes", [])):
                changed = dict(self.candidate, **{field: value})
                with patch.object(subject.registry, "read_regular_file", return_value=subject.registry.canonical_json(changed)):
                    with self.assertRaises(subject.registry.RegistryError): subject.verify()
            changed = copy.deepcopy(self.candidate)
            changed["operations"][0]["ranges"][0]["availability"] = "documented"
            if changed == self.candidate:
                changed["operations"][0]["ranges"][0]["availability"] = "unavailable"
            with patch.object(subject.registry, "read_regular_file", return_value=subject.registry.canonical_json(changed)):
                with self.assertRaises(subject.registry.RegistryError): subject.verify()


if __name__ == "__main__":
    unittest.main()
