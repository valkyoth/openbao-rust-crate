#!/usr/bin/python3 -EsSB
"""Check both patch lines together without weakening historical contracts."""

import copy
import unittest
from unittest.mock import patch

import generate_openbao_patch_registry as combined


class RegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.legacy = combined.legacy.verify()
        cls.modern = combined.modern.verify()
        cls.value = combined.combine(cls.legacy, cls.modern)

    def test_every_operation_cell_preserves_its_own_line(self):
        self.assertEqual(len(self.value["versions"]), 28)
        self.assertEqual(self.value["versions"], sorted(set(self.value["versions"]),
                                                     key=combined.registry.version_tuple))
        for target, legacy, modern in zip(self.value["operations"], self.legacy["operations"],
                                          self.modern["operations"], strict=True):
            for version in self.value["versions"]:
                source = modern if version == "2.7.1" else legacy
                self.assertEqual(combined.legacy.selected(target["ranges"], version),
                                 combined.legacy.selected(source["ranges"], version))
        self.assertEqual(len(self.value["operations"]) * len(self.value["versions"]), 19796)

    def test_legacy_engines_remain_available_only_on_the_older_line(self):
        for route in ("/auth/ldap/config", "/auth/kerberos/config", "/auth/radius/config", "/ldap/config"):
            operations = [op for op in self.value["operations"] if op["path_template"] == route]
            self.assertTrue(operations)
            for op in operations:
                self.assertEqual(combined.legacy.selected(op["ranges"], "2.6.4")["availability"], "documented")
                self.assertEqual(combined.legacy.selected(op["ranges"], "2.7.1")["availability"], "unavailable")

    def test_every_logical_route_and_gap_is_preserved(self):
        for target, legacy, modern in zip(self.value["logical_endpoints"], self.legacy["logical_endpoints"],
                                          self.modern["logical_endpoints"], strict=True):
            for version in self.value["versions"]:
                source = modern if version == "2.7.1" else legacy
                self.assertEqual(combined.legacy.selected(target["variants"], version, optional=True),
                                 combined.legacy.selected(source["variants"], version, optional=True))
        inspection = next(e for e in self.value["logical_endpoints"] if e["id"] == "sys.internal-request-inspection")
        self.assertIsNone(combined.legacy.selected(inspection["variants"], "2.6.4", optional=True))
        self.assertIsNotNone(combined.legacy.selected(inspection["variants"], "2.7.1", optional=True))

    def test_no_promotion_or_future_version_is_implied(self):
        self.assertIs(self.value["routable"], False)
        self.assertEqual(self.value["scope"], "candidate-contracts-not-public-dispatch")
        self.assertEqual(self.value["routable_versions"], [*combined.registry.EXPECTED_VERSIONS, "2.7.0"])
        for version in ("2.6.4", "2.7.1"):
            self.assertNotIn(version, self.value["routable_versions"])
        for version in ("2.6.5", "2.7.2", "2.8.0"):
            self.assertNotIn(version, self.value["versions"])

    def test_normal_promotion_requires_exact_combined_registry(self):
        marker = "GENERATED_ROUTABLE_PROFILE_VERSIONS: &[OpenBaoVersion] = &["
        ordinary = combined.registry.rust_output(self.value).decode().split(marker)[1].split("];")[0]
        promoted = combined.registry.rust_output(self.value, promoted_patches=True).decode().split(marker)[1].split("];")[0]
        for version in ("OpenBaoVersion::new(2, 6, 4)", "OpenBaoVersion::new(2, 7, 1)"):
            self.assertNotIn(version, ordinary)
            self.assertIn(version, promoted)
        altered = copy.deepcopy(self.value)
        altered["operations"][0]["disposition"] = "typed"
        altered["scope"] = "altered"
        for value in (altered, self.legacy, self.modern):
            with self.assertRaises(combined.registry.RegistryError):
                combined.registry.rust_output(value, promoted_patches=True)
        with self.assertRaises(combined.registry.RegistryError):
            combined.registry.rust_output(self.value, promoted_patches=True, verification_candidate=True)

    def test_changed_candidate_cannot_be_combined(self):
        for line in ("legacy", "modern"):
            for mutation in ("version", "operation", "route", "promotion", "scope"):
                left, right = copy.deepcopy(self.legacy), copy.deepcopy(self.modern)
                altered = left if line == "legacy" else right
                if mutation == "version": altered["versions"].append("2.8.0")
                elif mutation == "operation": altered["operations"].pop()
                elif mutation == "route": altered["logical_endpoints"].pop()
                elif mutation == "promotion": altered["routable"] = True
                else: altered["scope"] = "public-dispatch"
                with self.subTest(line=line, mutation=mutation), \
                     self.assertRaises(combined.legacy.evidence.patch.harness.HarnessError):
                    combined.combine(left, right)

    def test_both_source_evidence_gates_are_required(self):
        for module in (combined.legacy, combined.modern):
            with patch.object(module, "verify", side_effect=combined.registry.RegistryError("invalid")), \
                 self.assertRaises(combined.registry.RegistryError):
                combined.build()

    def test_output_matches_pin_and_rejects_modified_bytes(self):
        with patch.object(combined, "build", return_value=self.value):
            self.assertEqual(combined.verify(), self.value)
            for data in (b"{}\n", combined.registry.canonical_json(self.value) + b" "):
                with patch.object(combined.registry, "read_regular_file", return_value=data), \
                     self.assertRaises(combined.legacy.evidence.patch.harness.HarnessError):
                    combined.verify()


if __name__ == "__main__":
    unittest.main()
