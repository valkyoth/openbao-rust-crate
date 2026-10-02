#!/usr/bin/python3 -EsSB
"""Keep original 2.7.0 captures immutable and reject them as current evidence."""

import importlib
import unittest
from unittest.mock import patch

import openbao_api_snapshots as base
import openbao_test_harness as harness

ORIGINAL_DIGESTS = {
    "workflow_cas": "e12e882c699c731db7a6399dc87684f226ffd1c710ab13f7afbcb3f60f4ecdb4",
    "control_groups": "9c574f074bdf0fbe2305987259163454ed31bb53b02a7bd73cd26f9b23c78f65",
    "system_behavior": "9a3d79db484494ed3fa80f78a702f29c075325b9ee716e7646d935181cd7123a",
    "mfa_totp": "006b5ed1ac04b30772f0623b13fdbe0a67f29c3bae28c0f9f0aa2d3990285a05",
    "raw_backup": "701d68f5cb45e746440c3fd547e73a11a0923adba4007b7ec6a13dbd79045009",
    "recovery_backup": "129635bf28b46923f1ba9b1c22b8828386214135838ab22b124f76ce8ce752b1",
    "backup_upgrade": "9e546a79dba5b1e2ae4ffa1bfc4741f66fbe28ea466f3749c9414b5985363b8b",
    "consistency_sdk": "08ef991fd034a39aa55c06f0df592198afdbb017703b1c35283859e6cd508e04",
    "consistency_sdk_lag": "a69b0247f2a20b4d72c814265888c7d8a114e79b03846ff92ba7cb33e628d0ae",
    "backup_sdk": "edc04a4cdb268578524a1592531e4309d7c829fba3634165d64aba4d23c4213d",
    "backup_sdk_strict": "1a945bba0bc835b285f653cc16cbd556aa04d2e5ee33df870165012c5030eef5",
    "backup_sdk_candidate": "460400a18b63fccc17a1502f368ad433c90897704b58f96b6faa5e1566b7937d",
}
PRE_DEPENDENCY_DIGESTS = {
    "consistency_sdk": "ef0eb9a47dd7fcd7754e74742a5bd4f2dd78e8148fc1dd9937d478f5eda09ecf",
    "consistency_sdk_lag": "3d5b9b3be2a3c20f14e016fc2cce942fd9bd346e4f187b6afe0bfb4dc96154ce",
    "backup_sdk": "de1d4a1c5928d67ec69f65ee947e704143e4371327978f87cd7272f00f70c156",
    "backup_sdk_strict": "dc0b4bb0649170b9d0260151312368ea1204cb7cdb1c138f97036bdbfc39cc09",
    "backup_sdk_candidate": "a9f5a6ca91b7340486221dbff20de954467ae5eaba2fd4570a01e012b3feca1e",
}
PRE_AUTH_DIGESTS = {
    "consistency_sdk": "f412e929749e1c51b4f3e105d22bfa534a566b3189810295fd1970c90db81c2f",
    "consistency_sdk_lag": "c24a6a5cbe8a677489440b14e0a5b8c96c9f333652b4e5ea7dcacd7e392f994e",
    "backup_sdk": "fec010fc8c88f4dc2d32d2fb8010f7f36954db534536c934bd6ff637ae90d513",
    "backup_sdk_strict": "e75ba74bdee5f49d1b85e2afc1ead177235987171500bbd304038ca40b99fbe0",
    "backup_sdk_candidate": "b89a7f70e18cf2d3b73042131e9e21b0c422741ea0c140e1fc82610db13be0e9",
}


class RefreshTests(unittest.TestCase):
    def test_current_reports_and_original_integrity(self):
        for name, digest in ORIGINAL_DIGESTS.items():
            with self.subTest(name=name):
                verifier = importlib.import_module("verify_openbao_2_7_" + name)
                report = verifier.verify()
                original = verifier.RESULT.with_name(verifier.RESULT.name.split("-tls-v")[0] + "-tls.json")
                data = base.read_regular_file(original, 65536)
                self.assertEqual(base.sha256(data), digest)
                old_report = base.parse_json(data, 65536)
                self.assertNotEqual(old_report["inputs"], report["inputs"])
                if name == "control_groups":
                    self.assertEqual(report["security_checks"], {"server-replay-rejection": "known-upstream-failure"})
                    self.assertEqual(report["outcome"], "compatible-with-known-upstream-limitation")
                # Even allowing the original artifact/binary hashes cannot
                # satisfy the current-source check.
                with patch.object(verifier, "RESULT", original), \
                     patch.object(verifier, "EXPECTED_SHA256", digest):
                    if hasattr(verifier, "TEST_BINARY_SHA256"):
                        with patch.object(verifier, "TEST_BINARY_SHA256", old_report["test_binary_sha256"]), \
                             self.assertRaises((base.SnapshotError, harness.HarnessError)):
                            verifier.verify()
                    else:
                        with self.assertRaises((base.SnapshotError, harness.HarnessError)):
                            verifier.verify()

    def test_pre_dependency_sdk_captures_cannot_satisfy_current_lockfile(self):
        for name, digest in PRE_DEPENDENCY_DIGESTS.items():
            with self.subTest(name=name):
                verifier = importlib.import_module("verify_openbao_2_7_" + name)
                verifier.verify()
                stem = verifier.RESULT.name.split("-tls-v")[0]
                dependency_capture = verifier.RESULT.with_name(stem + "-tls-v3.json")
                captured = base.read_regular_file(dependency_capture, 65536)
                self.assertEqual(base.sha256(captured), PRE_AUTH_DIGESTS[name])
                current = base.parse_json(captured, 65536)
                previous = verifier.RESULT.with_name(stem + "-tls-v2.json")
                data = base.read_regular_file(previous, 65536)
                self.assertEqual(base.sha256(data), digest)
                report = base.parse_json(data, 65536)
                self.assertEqual(set(report["inputs"]), set(current["inputs"]))
                self.assertEqual({key for key in report["inputs"]
                                  if report["inputs"][key] != current["inputs"][key]}, {"Cargo.lock"})
                with patch.object(verifier, "RESULT", previous), \
                     patch.object(verifier, "EXPECTED_SHA256", digest), \
                     patch.object(verifier, "TEST_BINARY_SHA256", report["test_binary_sha256"]), \
                     self.assertRaises((base.SnapshotError, harness.HarnessError)):
                    verifier.verify()

    def test_pre_auth_sdk_captures_cannot_satisfy_current_sources(self):
        for name, digest in PRE_AUTH_DIGESTS.items():
            with self.subTest(name=name):
                verifier = importlib.import_module("verify_openbao_2_7_" + name)
                current = verifier.verify()
                previous = verifier.RESULT.with_name(verifier.RESULT.name.split("-tls-v")[0] + "-tls-v3.json")
                data = base.read_regular_file(previous, 65536)
                self.assertEqual(base.sha256(data), digest)
                old = base.parse_json(data, 65536)
                self.assertEqual(old["inputs"]["Cargo.lock"], current["inputs"]["Cargo.lock"])
                self.assertNotIn("src/auth/mapping.rs", old["inputs"])
                self.assertIn("src/auth/mapping.rs", current["inputs"])
                for auth in ("jwt", "kerberos", "ldap", "mod", "radius"):
                    key = "src/auth/" + auth + ".rs"
                    self.assertNotEqual(old["inputs"][key], current["inputs"][key])
                with patch.object(verifier, "RESULT", previous), \
                     patch.object(verifier, "EXPECTED_SHA256", digest), \
                     patch.object(verifier, "TEST_BINARY_SHA256", old["test_binary_sha256"]), \
                     self.assertRaises((base.SnapshotError, harness.HarnessError)):
                    verifier.verify()


if __name__ == "__main__":
    unittest.main()
