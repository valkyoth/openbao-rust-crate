#!/usr/bin/python3 -EsSB
"""Final SDK evidence must use exact normal sources and explicit execution mode."""

from contextlib import ExitStack, redirect_stdout
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import openbao_patch_normal_sdk as normal
import openbao_2_7_1_sdk_advanced as advanced


class NormalTests(unittest.TestCase):
    def test_normal_registry_is_exact_and_mutation_rejected(self):
        proof = normal.verify()
        self.assertIs(proof["routable"], True)
        self.assertEqual(proof["generated_rust_sha256"], normal.registry.EXPECTED_RUST_SHA256)
        read = normal.registry.read_regular_file
        def altered(path, maximum):
            value = read(path, maximum)
            return value + b"\n" if path == normal.registry.RUST_PATH else value
        with patch.object(normal.registry, "read_regular_file", side_effect=altered), \
             self.assertRaises(advanced.harness.HarnessError):
            normal.verify()

    def test_prepare_preserves_every_byte_without_rendering(self):
        inputs = {"Cargo.toml": b"package", "src/generated/openbao_capabilities.rs": b"normal bytes"}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(normal.registry, "rust_output") as render:
            root = Path(directory)
            normal.prepare(root, inputs)
            for path, value in inputs.items():
                self.assertEqual((root / path).read_bytes(), value)
            render.assert_not_called()
            with self.assertRaises(FileExistsError):
                normal.prepare(root, inputs)
            for path in ("../outside", "/absolute"):
                with self.assertRaises(advanced.harness.HarnessError):
                    normal.prepare(root, {path: b"invalid"})

    def test_build_refuses_root(self):
        with patch.object(normal.os, "geteuid", return_value=0), \
             self.assertRaises(advanced.harness.HarnessError):
            normal.build("sys", lambda: {})

    def test_all_normal_provenance_inputs_are_bound(self):
        inputs = normal.input_hashes()
        for runner in (advanced, __import__("openbao_2_6_4_sdk")):
            hashes = runner.input_hashes(normal=True)
            for path, digest in inputs.items():
                self.assertEqual(hashes[path], digest)
            self.assertEqual(hashes["src/generated/openbao_capabilities.rs"], normal.registry.EXPECTED_RUST_SHA256)

    def test_advanced_normal_mode_preserves_all_phases_and_rejects_drift(self):
        for failure in (None, "backup", "cluster", "source", "binary", "registry"):
            with self.subTest(failure=failure), ExitStack() as stack:
                stack.enter_context(redirect_stdout(io.StringIO()))
                def mock(obj, name, **kwargs):
                    return stack.enter_context(patch.object(obj, name, **kwargs))
                stack.enter_context(patch.dict(advanced.os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}))
                mock(advanced.pwd, "getpwuid", return_value=SimpleNamespace(pw_gid=1000))
                hashes = mock(advanced, "input_hashes", side_effect=[{"a": "b"}, {"a": "c" if failure == "source" else "b"}])
                binary = mock(advanced.execution, "binary_hash", side_effect=["a" * 64, ("b" if failure == "binary" else "a") * 64])
                mock(normal, "verify", side_effect=[{"scope": "public-sdk-strict-normal-build", "routable": True},
                     {"scope": "changed" if failure == "registry" else "public-sdk-strict-normal-build", "routable": True}])
                candidate = mock(advanced.candidate, "verify")
                def backup(suite, backup_observer):
                    self.assertEqual(suite, "recovery")
                    backup_observer("https://127.0.0.1:1", Path("/ca"), "disposable")
                    if failure == "backup": raise advanced.harness.HarnessError("failed")
                mock(advanced.backups, "run", side_effect=backup)
                tests = mock(advanced.execution, "run_test")
                cluster = mock(advanced, "run_cluster", side_effect=advanced.harness.HarnessError("failed") if failure == "cluster" else None)
                if failure:
                    with self.assertRaises(advanced.harness.HarnessError):
                        advanced.run.__wrapped__(object(), normal=True)
                else:
                    report = advanced.run.__wrapped__(object(), normal=True)
                    self.assertIs(report["routable"], True)
                    self.assertEqual(report["scope"], "public-sdk-strict-normal-build")
                    self.assertNotIn("candidate_registry_sha256", report)
                    self.assertNotIn("candidate_generated_rust_sha256", report)
                    self.assertEqual([call.kwargs["test"] for call in tests.call_args_list],
                                     [advanced.basic.TEST, advanced.BACKUP_TEST])
                    cluster.assert_called_once()
                candidate.assert_not_called()
                self.assertTrue(all(call.kwargs == {"candidate": False} for call in binary.call_args_list))
                self.assertTrue(all(call.kwargs == {"normal": True} for call in hashes.call_args_list))

    def test_ambiguous_advanced_modes_are_rejected(self):
        for normal_mode, candidate in ((False, False), (True, True), (1, False), (False, 1)):
            with self.assertRaises(advanced.harness.HarnessError):
                advanced.run.__wrapped__(object(), normal=normal_mode, strict_candidate=candidate)


if __name__ == "__main__":
    unittest.main()
