#!/usr/bin/python3 -EsSB
"""Coverage, sealed execution and fail-closed attestation regressions."""

import fcntl
import hashlib
import io
import os
from contextlib import redirect_stderr
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import openbao_current_ci as ci


class CurrentCiTests(unittest.TestCase):
    def test_real_input_collection_covers_both_patch_fixtures_and_sdk(self):
        inputs = ci.input_hashes()
        self.assertGreater(len(inputs), 20)
        for fixture in (ci.legacy, ci.modern):
            for path, digest in fixture.input_hashes().items():
                self.assertEqual(inputs[path], digest)
        for path in ("Cargo.toml", "Cargo.lock", "README.md", "src/lib.rs",
                     "scripts/openbao_current_ci.py", "tests/openbao_integration.rs",
                     ".github/workflows/openbao-current-compatibility.yml"):
            self.assertEqual(inputs[path], ci.base.sha256(ci.base.read_regular_file(ci.ROOT / path, 2 * 1024 * 1024)))
        original_read = ci.base.read_regular_file
        def changed_read(path, maximum):
            value = original_read(path, maximum)
            return value + b"\n" if path == ci.ROOT / "scripts/openbao_current_ci.py" else value
        with patch.object(ci.base, "read_regular_file", side_effect=changed_read):
            changed = ci.input_hashes()
        self.assertEqual({path for path in inputs if inputs[path] != changed[path]},
                         {"scripts/openbao_current_ci.py"})

    def test_supported_profile_coverage(self):
        ci.coverage(["2.6.3"], ["2.6.3", *ci.VERSIONS])
        for historical, supported, supplemental in (
            (["2.6.3"], ["2.6.3", "2.6.4"], ci.VERSIONS),
            (["2.6.3"], ["2.6.3", *ci.VERSIONS, "2.7.2"], ci.VERSIONS),
            (["2.6.3", "2.6.4"], ["2.6.3", *ci.VERSIONS], ci.VERSIONS),
            (["2.6.3"], ["2.6.3", *ci.VERSIONS], ["2.6.4", "2.7.0"]),
            (["2.6.3", "2.6.3"], ["2.6.3", *ci.VERSIONS], ci.VERSIONS),
            (["2.6.3"], ["2.6.3", *ci.VERSIONS, "2.7.1"], ci.VERSIONS),
        ):
            with self.assertRaises(ci.harness.HarnessError):
                ci.coverage(historical, supported, supplemental)

    def test_binary_hash_and_execution_share_sealed_bytes(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(ci, "ROOT", Path(directory)):
            binary = Path(directory) / "target/debug/deps/openbao_integration-1234567890abcdef"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"original executable bytes")
            binary.chmod(0o700)
            descriptor, digest = ci.freeze_binary(binary, os.getuid())
            try:
                binary.write_bytes(b"replacement executable bytes")
                self.assertEqual(digest, hashlib.sha256(b"original executable bytes").hexdigest())
                self.assertEqual(os.read(descriptor, 100), b"original executable bytes")
                self.assertEqual(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & ci.SEALS, ci.SEALS)
                with self.assertRaises(OSError):
                    os.write(descriptor, b"changed")
            finally:
                os.close(descriptor)

    def test_binary_rejects_symlink_unsafe_permissions_owner_and_path(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(ci, "ROOT", Path(directory)):
            binary = Path(directory) / "target/debug/deps/openbao_integration-1234567890abcdef"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"fixture")
            binary.chmod(0o777)
            with self.assertRaises(ci.harness.HarnessError):
                ci.freeze_binary(binary, os.getuid())
            binary.chmod(0o700)
            with self.assertRaises(ci.harness.HarnessError):
                ci.freeze_binary(binary, os.getuid() + 1)
            with self.assertRaises(ci.harness.HarnessError):
                ci.freeze_binary(binary.with_name("other-name"), os.getuid())
            link = binary.with_name("openbao_integration-0000000000000000")
            link.symlink_to(binary)
            with self.assertRaises(OSError):
                ci.freeze_binary(link, os.getuid())

    def test_sdk_attestation_and_privilege_boundary(self):
        expected = {"schema": "openbao-core-flow-attestation/v1", "version": "2.7.1",
                    "executed": list(ci.OPERATIONS), "skipped": list(ci.harness.OPENBAO_2_6_OPERATION_IDS)}
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca.pem"
            ca.write_text("disposable CA fixture")
            child = Mock()
            child.wait.return_value = 0
            child.poll.return_value = 0
            with patch.object(ci.subprocess, "Popen", return_value=child) as start, \
                 patch.object(ci.tls.evidence_tools, "protected_path", return_value=Path("/usr/bin/setpriv")), \
                 patch.object(ci.harness, "read_descriptor", return_value=ci.base.canonical_json(expected)):
                self.assertEqual(ci.run_sdk(123, os.getuid(), os.getgid(), "https://127.0.0.1:12345",
                                           ca, "disposable-secret-marker", "2.7.1"), expected)
                arguments, options = start.call_args
                self.assertIn("--no-new-privs", arguments[0])
                self.assertIn("--bounding-set=-all", arguments[0])
                self.assertEqual(options["pass_fds"][0], 123)
                self.assertNotIn("disposable-secret-marker", str(arguments) + str(options))
                self.assertNotIn("LD_PRELOAD", options["env"])
                for descriptor in options["pass_fds"][1:]:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
            for invalid in ({**expected, "version": "2.7.0"}, {**expected, "executed": []},
                            {**expected, "extra": True}):
                with patch.object(ci.subprocess, "Popen", return_value=child), \
                     patch.object(ci.tls.evidence_tools, "protected_path", return_value=Path("/usr/bin/setpriv")), \
                     patch.object(ci.harness, "read_descriptor", return_value=ci.base.canonical_json(invalid)), \
                     self.assertRaises(ci.harness.HarnessError):
                    ci.run_sdk(123, os.getuid(), os.getgid(), "https://127.0.0.1:12345", ca, "fixture", "2.7.1")

    def test_unknown_version_fails_before_starting_resources(self):
        with patch.object(ci.os, "geteuid", return_value=0), \
             patch.object(ci, "freeze_binary") as freeze, self.assertRaises(ci.harness.HarnessError):
            ci.run("2.7.2", Path("/not-used"))
        freeze.assert_not_called()

    def test_setup_failure_reports_safe_stage_not_exception_contents(self):
        diagnostic = io.StringIO()
        descriptor = os.memfd_create("openbao-ci-diagnostic-test", os.MFD_CLOEXEC)
        with patch.object(ci.os, "geteuid", return_value=0), \
             patch.dict(ci.os.environ, {"SUDO_UID": str(os.getuid()), "SUDO_GID": str(os.getgid())}), \
             patch.object(ci, "input_hashes", return_value={}), \
             patch.object(ci, "freeze_binary", return_value=(descriptor, "0" * 64)), \
             patch.object(ci.tls.evidence_tools, "protected_path", side_effect=lambda path: path), \
             patch.object(ci.modern, "verify_signature"), \
             patch.object(ci.harness, "generate_tls", side_effect=ci.harness.HarnessError("sensitive-marker")), \
             patch.object(ci.sys, "argv", ["fixture", "--version", "2.7.1", "--test-binary", "/not-used"]), \
             redirect_stderr(diagnostic):
            self.assertEqual(ci.main(), 1)
        self.assertIn("Current-profile CI: preparing TLS certificates", diagnostic.getvalue())
        self.assertIn("Current-profile CI: cleaning owned resources", diagnostic.getvalue())
        self.assertIn("no compatibility success recorded", diagnostic.getvalue())
        self.assertNotIn("sensitive-marker", diagnostic.getvalue())
        self.assertNotIn("preparing pinned image", diagnostic.getvalue())
        with self.assertRaises(OSError):
            os.fstat(descriptor)


if __name__ == "__main__":
    unittest.main()
