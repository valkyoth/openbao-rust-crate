#!/usr/bin/python3 -EsSB
"""Historical reports cannot satisfy current tooling and dependency inputs."""

import importlib
import unittest
from unittest.mock import patch

import verify_openbao_current_ci as ci
import verify_openbao_patch_normal_sdk as sdk

HISTORICAL_CI = ci.fixture.ROOT / "compat/ci/2.2.3"


class ToolingRefreshTests(unittest.TestCase):
    def test_previous_release_ci_reports_cannot_be_repinned_as_current(self):
        pins = {
            "2.6.4": "5e247a39e4bba3735740c5f7f8540eaeaeb76c7fe00b51ad5d15b92c39725daa",
            "2.7.0": "7d2acf79092d2b0408182684121995a0be6e5f06977ff2529c19aff2d0a29e1a",
            "2.7.1": "24fd7f902b692248c4b0d75b4e63ac9b83564b498f47ee01c4c9a6f7397a6424",
        }
        for version, digest in pins.items():
            with self.subTest(version=version):
                raw = ci.fixture.base.read_regular_file(HISTORICAL_CI / f"{version}-v4.json", 131072)
                self.assertEqual(ci.fixture.base.sha256(raw), digest)
                report = ci.fixture.base.parse_json(raw, 131072)
                current = ci.verify(version)
                changed = {name for name in report["inputs"]
                           if report["inputs"][name] != current["inputs"].get(name)}
                self.assertTrue({"Cargo.toml", "Cargo.lock", "README.md"} <= changed)
                with patch.object(ci, "PINS", pins), \
                     patch.object(ci, "BINARY_SHA256", report["test_binary_sha256"]), \
                     self.assertRaises(ci.fixture.harness.HarnessError):
                    ci.validate(version, raw)

    def test_pre_inout_ci_reports_rejected_even_with_restored_pins(self):
        for version in ci.PINS:
            with self.subTest(version=version):
                raw = ci.fixture.base.read_regular_file(HISTORICAL_CI / f"{version}-v3.json", 131072)
                report = ci.fixture.base.parse_json(raw, 131072)
                current = ci.fixture.base.parse_json(ci.fixture.base.read_regular_file(
                    HISTORICAL_CI / f"{version}-v4.json", 131072), 131072)
                self.assertEqual(
                    {name for name in set(report["inputs"]) | set(current["inputs"])
                     if report["inputs"].get(name) != current["inputs"].get(name)},
                    {"Cargo.lock"},
                )
                with patch.object(ci, "PINS", {version: ci.fixture.base.sha256(raw)}), \
                     patch.object(ci, "BINARY_SHA256", report["test_binary_sha256"]), \
                     self.assertRaises(ci.fixture.harness.HarnessError):
                    ci.validate(version, raw)

    def test_previous_ci_reports_cannot_be_repinned_as_current(self):
        pins = {
            "2.6.4": "444298ae06bd5efaa295f27f1c69f8758c3068b425b33e33a51315260070c9a9",
            "2.7.0": "de40e0163c9fa6375d4fb8fbd1e642d74a86f0aa74d4d7dffde8ce72f2254a06",
            "2.7.1": "5ca2da380615b81af0e7802db5862e0557aefa28fa088ad08801be93f9da22f8",
        }
        for version, digest in pins.items():
            with self.subTest(version=version):
                raw = ci.fixture.base.read_regular_file(HISTORICAL_CI / f"{version}-v2.json", 131072)
                self.assertEqual(ci.fixture.base.sha256(raw), digest)
                report = ci.fixture.base.parse_json(raw, 131072)
                with patch.object(ci, "PINS", pins), \
                     patch.object(ci, "BINARY_SHA256", report["test_binary_sha256"]), \
                     self.assertRaises(ci.fixture.harness.HarnessError):
                    ci.validate(version, raw)

    def test_previous_patch_sdk_reports_cannot_be_repinned_as_current(self):
        pins = {
            "2.6.4": "9809d823fb7cede6c4c77aea5bd6c7eb85182f7c3b19e3242691abe253a98b3f",
            "2.7.1": "ee74bb54f069d708ebfb25586fcf068487b487c0660e09a9f5af68506412e6a3",
        }
        for version, digest in pins.items():
            with self.subTest(version=version):
                raw = sdk.base.read_regular_file(sdk.output(version).with_name("sdk-normal-tls-v6.json"), 131072)
                self.assertEqual(sdk.base.sha256(raw), digest)
                report = sdk.base.parse_json(raw, 131072)
                with patch.object(sdk, "PINS", {version: (digest, report["test_binary_sha256"])}), \
                     self.assertRaises(sdk.harness.HarnessError):
                    sdk.validate(version, raw)

    def test_previous_270_reports_cannot_be_repinned_as_current(self):
        pins = {
            "consistency_sdk": "bc65c91e25500dd437516dab0159e4e046c19b20181f97d8e306d94870d6d837",
            "consistency_sdk_lag": "269da022dc17036a8cd161b2302be684511d1c0f0b7b8541d5ea93cd854cecad",
            "backup_sdk": "9a5e0863db47da5a297ccb9afa6cb99f983011033eac57a981d06321c2953c82",
            "backup_sdk_strict": "f4a29a77d8fb8152b7a4ef6bac76842caf213d19b72d6f28f482cd05f4e68448",
            "backup_sdk_candidate": "d920db41e6a160de79ef8f4c3d72c7af27b29232ff428531767a0271385ce021",
        }
        for name, digest in pins.items():
            module = importlib.import_module("verify_openbao_2_7_" + name)
            previous = module.RESULT.with_name(module.RESULT.name.replace("-v10.json", "-v7.json"))
            with self.subTest(name=name):
                raw = sdk.base.read_regular_file(previous, 131072)
                self.assertEqual(sdk.base.sha256(raw), digest)
                report = sdk.base.parse_json(raw, 131072)
                with patch.object(module, "RESULT", previous), \
                     patch.object(module, "EXPECTED_SHA256", digest), \
                     patch.object(module, "TEST_BINARY_SHA256", report["test_binary_sha256"]), \
                     self.assertRaises((sdk.harness.HarnessError, sdk.base.SnapshotError)):
                    module.verify()


if __name__ == "__main__":
    unittest.main()
