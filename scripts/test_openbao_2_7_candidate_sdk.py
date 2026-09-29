#!/usr/bin/python3 -EsSB
"""Regression tests for disposable candidate compilation and cleanup."""

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import check_openbao_2_7_candidate_sdk as subject


class CandidateSdkTests(unittest.TestCase):
    def test_ancestor_cargo_configuration_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".cargo").mkdir()
            (root / ".cargo/config.toml").write_text('[build]\nrustc-wrapper="untrusted"\n')
            destination = root / "build"
            destination.mkdir()
            with self.assertRaises(subject.registry.RegistryError):
                subject.build_environment(destination)

    def test_build_environment_excludes_ambient_wrappers_flags_and_config(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            tools = home / "toolchain/bin"
            tools.mkdir(parents=True)
            (tools / "cargo").touch()
            (tools / "rustc").touch()
            destination = Path(directory) / "build"
            destination.mkdir()
            with patch.object(Path, "home", return_value=home), \
                 patch.object(subject.shutil, "which", return_value=str(home / ".cargo/bin/rustup")) as locate, \
                 patch.object(subject.subprocess, "check_output", return_value=str(tools / "cargo")), \
                 patch.dict(os.environ, {"RUSTC_WRAPPER": "/untrusted", "RUSTFLAGS": "injected", "LD_PRELOAD": "injected", "CARGO_HOME": "/untrusted"}):
                env = subject.build_environment(destination)
            locate.assert_called_once_with("rustup", path=f"{home / '.cargo/bin'}:/usr/bin:/bin")
            for key in ("RUSTC_WRAPPER", "RUSTFLAGS", "LD_PRELOAD"):
                self.assertNotIn(key, env)
            self.assertEqual(env["CARGO_HOME"], str(destination / "cargo-home"))
            self.assertFalse((destination / "cargo-home/config.toml").exists())
            self.assertEqual(env["RUSTC"], str(tools / "rustc"))

    def test_missing_rustup_fails_closed_before_execution(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(subject.shutil, "which", return_value=None), \
             patch.object(subject.subprocess, "check_output") as execute:
            with self.assertRaises(subject.registry.RegistryError):
                subject.build_environment(Path(directory))
            execute.assert_not_called()

    @classmethod
    def setUpClass(cls):
        cls.candidate = subject.candidate.verify()

    def test_disposable_build_matches_promoted_routing_without_source_mutation(self):
        registry = subject.registry
        normal = registry.rust_output(self.candidate)
        promoted = registry.rust_output(self.candidate, verification_candidate=True)
        self.assertEqual(promoted, normal)
        original = registry.read_regular_file(registry.RUST_PATH, registry.MAX_OUTPUT_BYTES)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            inputs = {"Cargo.toml": b"manifest", "src/generated/openbao_capabilities.rs": normal}
            subject.prepare(destination, inputs, self.candidate)
            self.assertEqual((destination / "Cargo.toml").read_bytes(), b"manifest")
            self.assertEqual((destination / "src/generated/openbao_capabilities.rs").read_bytes(), promoted)
        self.assertEqual(registry.read_regular_file(registry.RUST_PATH, registry.MAX_OUTPUT_BYTES), original)
        self.assertEqual(original, normal)

    def test_verification_inventory_is_exact(self):
        for versions in ([], list(subject.registry.EXPECTED_VERSIONS), [*self.candidate["versions"], "2.7.1"]):
            with self.assertRaises(subject.registry.RegistryError):
                subject.registry.rust_output(dict(self.candidate, versions=versions), verification_candidate=True)

    def test_root_is_rejected_before_reading_or_running(self):
        with patch.object(subject.os, "geteuid", return_value=0), \
             patch.object(subject.registry, "verify_outputs") as verify:
            self.assertEqual(subject.main(), 1)
            verify.assert_not_called()

    def test_timeout_kills_owned_process_group_and_reaps(self):
        process = Mock(pid=12345, returncode=-9)
        process.communicate.side_effect = subprocess.TimeoutExpired("cargo", 900)
        with patch.object(subject.subprocess, "Popen", return_value=process) as popen, \
             patch.object(subject.os, "killpg") as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                subject.run(["cargo"], Path("/tmp"), {})
            self.assertIs(popen.call_args.kwargs["start_new_session"], True)
            kill.assert_called_once_with(12345, subject.signal.SIGKILL)
            process.wait.assert_called_once()

    def test_empty_or_incomplete_test_listing_fails(self):
        for listing in ("", "0 tests", "strict_inspection_routes_are_version_specific: test\n"):
            with patch.object(subject.os, "geteuid", return_value=1000), \
                 patch.object(subject.registry, "verify_outputs"), \
                 patch.object(subject.candidate, "verify", return_value=self.candidate), \
                 patch.object(subject, "source_inputs", return_value={}), \
                 patch.object(subject, "prepare"), \
                 patch.object(subject, "build_environment", return_value={}), \
                 patch.object(subject, "run", return_value=listing) as run:
                self.assertEqual(subject.main(), 1)
                self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
