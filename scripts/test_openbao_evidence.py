#!/usr/bin/python3 -EsSB
"""Regression tests for evidence tool isolation and documentation expansion."""

import copy
import json
import os
import stat
import shlex
import subprocess
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
    def test_python_startup_ignores_injected_modules(self):
        root = Path(__file__).resolve().parents[1]
        checks = (root / "scripts/checks.sh").read_text()
        command = next(line for line in checks.splitlines()
                       if line.endswith("scripts/openbao_2_7_api.py --verify"))
        arguments = shlex.split(command)
        self.assertEqual(arguments[:5], ["/usr/bin/python3", "-E", "-s", "-S", "-B"])
        with tempfile.TemporaryDirectory() as directory:
            poison = Path(directory)
            (poison / "copy.py").write_text('print("IMPORT_POISON_EXECUTED")\nraise SystemExit(0)\n')
            (poison / "sitecustomize.py").write_text('print("SITE_POISON_EXECUTED")\n')
            (poison / "usercustomize.py").write_text('print("USER_SITE_POISON_EXECUTED")\n')
            (poison / "python3").symlink_to("/usr/bin/true")
            environment = {**os.environ, "PYTHONPATH": directory, "PYTHONUSERBASE": directory, "PATH": directory}
            # Confirm the fixture reproduces a false-green verification without isolation.
            control = subprocess.run(["/usr/bin/python3", "-B", *arguments[5:]], cwd=root,
                                     env=environment, capture_output=True, timeout=30, check=False)
            self.assertEqual(control.returncode, 0)
            self.assertIn(b"IMPORT_POISON_EXECUTED", control.stdout)
            self.assertIn(b"SITE_POISON_EXECUTED", control.stdout)
            environment["PYTHONHOME"] = str(poison / "invalid-python-home")
            verified = subprocess.run(arguments, cwd=root, env=environment,
                                      capture_output=True, timeout=30, check=False)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn(b"staged API evidence: ok", verified.stdout)
            self.assertNotIn(b"POISON_EXECUTED", verified.stdout + verified.stderr)
            probe = subprocess.run([*arguments[:5], "-c", "import sys; print(sys.flags.ignore_environment, sys.flags.no_user_site, sys.flags.no_site, sys.flags.dont_write_bytecode)"],
                                   env=environment, capture_output=True, timeout=10, check=False)
            self.assertEqual(probe.returncode, 0, probe.stderr)
            self.assertEqual(probe.stdout.strip(), b"1 1 1 1")
            direct = subprocess.run([str(root / "scripts/openbao_api_snapshots.py"), "--help"],
                                    cwd=root, env=environment, capture_output=True, timeout=30, check=False)
            self.assertEqual(direct.returncode, 0, direct.stderr)
            self.assertIn(b"Generate and verify immutable", direct.stdout)
            self.assertNotIn(b"POISON_EXECUTED", direct.stdout + direct.stderr)

    def test_evidence_entry_points_use_isolated_python(self):
        root = Path(__file__).resolve().parents[1]
        files = list((root / "scripts").glob("*.sh")) + list((root / ".github/workflows").glob("*.yml"))
        for path in files:
            for line in path.read_text().splitlines():
                if "python3" in line and "scripts/" in line:
                    self.assertIn("/usr/bin/python3 -E -s -S -B ", line, str(path))
        for path in (root / "scripts").glob("*.py"):
            first = path.read_text().splitlines()[0]
            if path.name == "openbao_test_harness.py":
                # Historical live evidence hashes these exact bytes. Its old
                # shebang must not remain an executable verification entry point.
                self.assertEqual(path.stat().st_mode & 0o111, 0)
                continue
            if first.startswith("#!"):
                self.assertEqual(first, "#!/usr/bin/python3 -EsSB", str(path))

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
