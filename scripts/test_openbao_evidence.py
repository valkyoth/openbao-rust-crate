#!/usr/bin/env python3
"""Regression tests for evidence tool isolation and documentation expansion."""

import copy
import json
import os
import stat
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import evidence_tools as tools
import openbao_api_snapshots as base
import openbao_documentation_v2 as docs
import openbao_2_7_api as staged


SAMPLE = "## Write\n| Method | Path |\n| --- | --- |\n| POST | `/x` |\n- `x` `(string: required)`\n"


class EvidenceTests(unittest.TestCase):
    def test_environment_and_path_are_not_inherited(self):
        poisoned = {"PATH": "/tmp/evil", "CONTAINER_HOST": "ssh://evil", "LD_PRELOAD": "evil",
                    "GIT_CONFIG_COUNT": "1", "SSL_CERT_FILE": "/tmp/evil", "HOME": "/tmp/evil"}
        with patch.dict(os.environ, poisoned), patch.object(tools, "protected_path", return_value=Path("/usr/bin/cosign")) as checked:
            with tools.invocation(["cosign", "verify"]) as (command, environment):
                checked.assert_called_once_with(Path("/usr/bin/cosign"))
                self.assertEqual(command, ["/usr/bin/cosign", "verify"])
                self.assertEqual(environment["PATH"], "/usr/bin:/bin")
                self.assertTrue(Path(environment["HOME"]).is_dir())
                self.assertEqual(Path(environment["HOME"]).stat().st_mode & 0o777, 0o700)
                for key in poisoned.keys() - {"PATH", "HOME"}:
                    self.assertNotIn(key, environment)
                self.assertNotEqual(environment["HOME"], poisoned["HOME"])
                home = environment["HOME"]
            self.assertFalse(Path(home).exists())

    def test_reject_unknown_tool_and_environment(self):
        with self.assertRaises(ValueError), tools.invocation(["/tmp/cosign"]):
            pass
        with patch.object(tools, "protected_path", return_value=Path("/usr/bin/podman")):
            with self.assertRaises(ValueError), tools.invocation(["podman"], {"CONTAINER_HOST": "ssh://evil"}):
                pass
        self.assertEqual(set(base.podman_environment("test-only")), tools.BAO_ENV)

    def test_production_launchers_ignore_poisoned_path(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "git").symlink_to("/usr/bin/false")
            with patch.dict(os.environ, {"PATH": directory}), \
                 patch.object(tools, "protected_path", return_value=Path("/usr/bin/git")):
                _, output = base.run_bounded(["git", "--version"], 1024, timeout=10)
                self.assertTrue(output.startswith(b"git version "))
                base.run_quiet(["git", "--version"], timeout=10)

    def test_untrusted_binary_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "cosign"
            binary.write_bytes(b"not an executable verifier")
            binary.chmod(0o755)
            with self.assertRaises(ValueError):
                tools.protected_path(binary)
            binary.unlink()
            binary.symlink_to("/usr/bin/true")
            with self.assertRaises(ValueError):
                tools.protected_path(binary)

    def test_tool_metadata_checks(self):
        path = Path("/usr/bin/cosign")
        good = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)
        with patch.object(Path, "resolve", return_value=path), \
             patch.object(Path, "lstat", return_value=good), \
             patch.object(Path, "stat", return_value=good):
            self.assertEqual(tools.protected_path(path), path)
            for uid, mode in ((1000, 0o755), (0, 0o775), (0, 0o757)):
                with patch.object(Path, "lstat", return_value=SimpleNamespace(st_uid=uid, st_mode=stat.S_IFREG | mode)):
                    with self.assertRaises(ValueError):
                        tools.protected_path(path)
            for mode in (stat.S_IFREG | 0o644, stat.S_IFDIR | 0o755, stat.S_IFIFO | 0o755):
                with patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=0, st_mode=mode)):
                    with self.assertRaises(ValueError):
                        tools.protected_path(path)

    def test_success_exit_without_verified_claims_rejected(self):
        with patch.object(base, "run_bounded", return_value=(0, b"")):
            with self.assertRaises(base.SnapshotError):
                staged.verify_image_signature()
        valid = {"critical": {"image": {"docker-manifest-digest": staged.INDEX},
                              "type": "https://sigstore.dev/cosign/sign/v1"}}
        staged.validate_signature_output(json.dumps([valid]).encode())
        for value in ([], {}, [None], [valid] * 33):
            with self.assertRaises(base.SnapshotError):
                staged.validate_signature_output(json.dumps(value).encode())
        valid["critical"]["image"]["docker-manifest-digest"] = "sha256:" + "0" * 64
        with self.assertRaises(base.SnapshotError):
            staged.validate_signature_output(json.dumps([valid]).encode())

    def test_expansion_rejected_before_copying(self):
        text = "## Write\n| Method | Path |\n| --- | --- |\n"
        text += "| POST | `/x` |\n" * base.MAX_OPERATIONS
        text += '- `x` `(string: required)`\n' * base.MAX_FIELDS_PER_SECTION
        with patch.object(docs.copy, "deepcopy", side_effect=AssertionError("copied before limit")):
            with self.assertRaisesRegex(base.SnapshotError, "expansion"):
                docs.parse("fixture.mdx", text)

    def test_shared_budget_and_exact_boundary(self):
        full = docs.ExpansionBudget()
        full.take(base.MAX_OPERATIONS, docs.MAX_TOTAL_FIELD_OCCURRENCES)
        self.assertEqual((full.operations, full.fields), (0, 0))
        for operations, fields in ((1, 0), (0, 1)):
            with self.assertRaises(base.SnapshotError):
                full.take(operations, fields)
        budget = docs.ExpansionBudget(operations=2, fields=2)
        docs.parse("first.mdx", SAMPLE, budget)
        docs.parse("second.mdx", SAMPLE, budget)
        self.assertEqual((budget.operations, budget.fields), (0, 0))
        with self.assertRaisesRegex(base.SnapshotError, "expansion"):
            docs.parse("third.mdx", SAMPLE, budget)

    def test_extraction_uses_shared_budget_without_legacy_expansion(self):
        raw = SAMPLE.encode()
        files = [{"path": name, "bytes": len(raw), "sha256": base.sha256(raw), "blob_sha1": "0" * 40}
                 for name in ("a.mdx", "b.mdx")]
        budget = docs.ExpansionBudget(operations=2, fields=1)
        with patch.object(base, "extract_documentation", return_value={"files": files}) as legacy, \
             patch.object(base, "git_output", return_value=raw), \
             patch.object(docs, "ExpansionBudget", return_value=budget):
            with self.assertRaisesRegex(base.SnapshotError, "expansion"):
                docs.extract(Path("/unused"), {})
            legacy.assert_called_once_with(Path("/unused"), {}, files_only=True)

    def test_duplicate_canonicalization_and_conflicts(self):
        operation = docs.parse("fixture.mdx", SAMPLE)[0]
        self.assertEqual(docs.canonical_operations([operation, copy.deepcopy(operation)]), [operation])
        conflict = copy.deepcopy(operation)
        conflict["fields"][0]["signature"] = "(string: optional)"
        with self.assertRaisesRegex(base.SnapshotError, "conflicting"):
            docs.canonical_operations([operation, conflict])
        with self.assertRaisesRegex(base.SnapshotError, "duplicated"):
            docs.validate({"operations": [operation, operation]}, {})

    def test_snapshot_budget_before_serialization(self):
        operation = docs.parse("fixture.mdx", SAMPLE)[0]
        operation["fields"] *= base.MAX_FIELDS_PER_SECTION
        with patch.object(base, "canonical_json", side_effect=AssertionError("serialized before limit")):
            with self.assertRaisesRegex(base.SnapshotError, "expansion"):
                docs.validate({"operations": [operation] * 65}, {})


if __name__ == "__main__":
    unittest.main()
