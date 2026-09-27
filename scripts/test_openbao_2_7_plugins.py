#!/usr/bin/python3 -EsSB
"""Plugin-observation and local fixture boundary regressions."""

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import openbao_api_snapshots as base
import openbao_2_7_plugins as plugins
import openbao_dev_config as dev
from validate_openbao_release_lock import validate_lock_files


class PluginTests(unittest.TestCase):
    def test_retained_tls_result_is_bound_to_fixture_and_not_promotion(self):
        result = plugins.verify_tls_result()
        self.assertFalse(result["routable"])
        self.assertFalse(result["plugin_contracts_verified"])
        import openbao_2_7_tls as fixture
        with patch.object(fixture, "input_hashes", return_value={}):
            with self.assertRaises(base.SnapshotError):
                plugins.verify_tls_result()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tls.json"
            path.write_bytes(base.canonical_json(result) + b" ")
            with patch.object(plugins, "TLS_RESULT", path), self.assertRaises(base.SnapshotError):
                plugins.verify_tls_result()

    def test_observation_is_not_artifact_or_contract_verification(self):
        document = plugins.verify()
        self.assertEqual(len(document["plugins"]), 4)
        with self.assertRaisesRegex(base.SnapshotError, "excluded from 2.7 support"):
            plugins.require_verified_plugins(document)
        for item in document["plugins"]:
            self.assertFalse(item["artifact_verified"])
            self.assertFalse(item["contract_verified"])
        altered = copy.deepcopy(document)
        altered["promotion_allowed"] = True
        with self.assertRaises(base.SnapshotError):
            plugins.validate(altered)

    def test_source_or_tag_never_implies_verified_plugin(self):
        candidates = plugins.classify(["auth-ldap-v1.0.0"], ["auth/ldap"])
        ldap = next(item for item in candidates if item["id"] == "auth/ldap")
        self.assertEqual(ldap["status"], "requires-artifact-review")
        self.assertTrue(ldap["source_present"])
        self.assertFalse(ldap["artifact_verified"])
        self.assertFalse(ldap["contract_verified"])

    def test_observation_rejects_tampering_and_conflicting_status(self):
        document = plugins.verify()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "observation.json"
            path.write_bytes(base.canonical_json(document) + b" ")
            with patch.object(plugins, "EVIDENCE", path), self.assertRaises(base.SnapshotError):
                plugins.verify()
        for field in ("artifact_verified", "contract_verified", "source_present", "server_version_alone_proves_support"):
            altered = copy.deepcopy(document)
            altered["plugins"][0][field] = not altered["plugins"][0][field]
            with self.assertRaises(base.SnapshotError):
                plugins.validate(altered)

    def test_observation_bounds_and_duplicates(self):
        for entries in ([], ["x"] * 4097, ["x", "x"], ["z", "a"], ["x" * 513], [True]):
            document = copy.deepcopy(plugins.verify())
            document["git_tags"] = entries
            with self.assertRaises(base.SnapshotError):
                plugins.validate(document)
        for date in (None, "20260927", "2026-99-99"):
            document = copy.deepcopy(plugins.verify())
            document["observed_on"] = date
            with self.assertRaises(base.SnapshotError):
                plugins.validate(document)

    def test_remote_observation_is_bounded_and_requires_complete_tree(self):
        with patch.object(plugins, "fetch", return_value=[{"tag_name": "x"}] * 100) as fetch:
            with self.assertRaisesRegex(base.SnapshotError, "pagination"):
                plugins.observe()
            self.assertEqual(fetch.call_count, 4)
        with patch.object(plugins, "fetch", side_effect=[[], [], {"truncated": True}]):
            with self.assertRaisesRegex(base.SnapshotError, "incomplete"):
                plugins.observe()
        for malformed in ({}, [None], [{"tag_name": 1}], [{"tag_name": "x" * 513}]):
            with patch.object(plugins, "fetch", return_value=malformed), self.assertRaises(base.SnapshotError):
                plugins.observe()
        with patch.object(plugins, "fetch", side_effect=[[], [{"ref": "refs/heads/main"}], {"truncated": False, "tree": []}]):
            with self.assertRaisesRegex(base.SnapshotError, "non-tag"):
                plugins.observe()

    def test_promotion_command_returns_failure(self):
        result = subprocess.run(["/usr/bin/python3", "-E", "-s", "-S", "-B", str(plugins.ROOT / "scripts/openbao_2_7_plugins.py"), "--require-verified"],
                                capture_output=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"excluded from 2.7 support", result.stdout)

    def test_dev_profile_rejects_unknown_and_staged_versions(self):
        inventory = validate_lock_files()
        for version in ("latest", "2.7.0", "2.6", "../../tmp", "2.6.3;true", None):
            with self.assertRaises(base.SnapshotError):
                dev.resolve({"schema": "openbao-local-dev/v1", "server_version": version}, inventory)
        with self.assertRaises(base.SnapshotError):
            dev.resolve({"schema": "openbao-local-dev/v1", "server_version": "2.6.3", "image": "untrusted"}, inventory)

    def test_dev_image_is_pinned_and_storage_is_version_specific(self):
        profile = dev.load()
        self.assertEqual(profile["version"], "2.6.3")
        self.assertEqual(profile["project"], "openbao-rust-crate-2-6-3")
        self.assertIn("@sha256:", profile["image"])
        inventory = validate_lock_files()
        old = dev.resolve({"schema": "openbao-local-dev/v1", "server_version": "2.5.5"}, inventory)
        self.assertNotEqual(profile["project"], old["project"])
        compose = (dev.ROOT / "deploy/podman/compose.dev.yml").read_text()
        self.assertIn("image: ${OPENBAO_IMAGE:?", compose)
        self.assertNotIn("docker.io/openbao/openbao:", compose)
        self.assertIn("./dev-state/${OPENBAO_DEV_VERSION:?", compose)
        config = (dev.ROOT / "deploy/podman/openbao.hcl").read_text()
        self.assertIn('storage "raft"', config)
        self.assertIn('tls_min_version = "tls13"', config)

    def test_dev_wrapper_ignores_inherited_image_and_project(self):
        with tempfile.TemporaryDirectory() as directory:
            podman = Path(directory) / "podman"
            podman.write_text('#!/usr/bin/python3 -EsSB\nimport json, os, sys\nprint(json.dumps({"args": sys.argv[1:], "image": os.environ["OPENBAO_IMAGE"], "project": os.environ["OPENBAO_DEV_PROJECT"]}))\n')
            podman.chmod(0o755)
            environment = {**os.environ, "PATH": directory + ":/usr/bin:/bin", "OPENBAO_IMAGE": "untrusted:latest", "OPENBAO_DEV_PROJECT": "openbao-rust-crate"}
            for operation in ("status", "down"):
                output = subprocess.run([str(dev.ROOT / "scripts/openbao_dev.sh"), operation],
                                        env=environment, capture_output=True, check=True, timeout=30)
                invocation = json.loads(output.stdout)
                self.assertEqual(invocation["image"], dev.load()["image"])
                self.assertEqual(invocation["project"], dev.load()["project"])
                if operation == "status":
                    self.assertEqual(invocation["args"][1], "openbao-rust-crate-2-6-3_dev")
                else:
                    self.assertEqual(invocation["args"][:3], ["compose", "-p", "openbao-rust-crate-2-6-3"])


if __name__ == "__main__":
    unittest.main()
