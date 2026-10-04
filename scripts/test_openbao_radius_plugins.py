#!/usr/bin/python3 -EsSB
"""RADIUS fixture trust, configuration and negative-control regressions."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import openbao_radius_plugins as fixture


class RadiusTests(unittest.TestCase):
    def values(self):
        return {key: char * 64 for key, char in zip(("shared", "alice", "bob", "wrong"), "abcd")}

    def test_explicit_radius_image_acknowledgement_precedes_any_execution(self):
        for value in (False, None, 1, "yes"):
            with patch.object(fixture.ldap, "run") as run, self.assertRaises(fixture.harness.HarnessError):
                fixture.run("2.7.0", True, value)
            run.assert_not_called()
            with patch.object(fixture.image.harness, "run_bounded") as run, self.assertRaises(fixture.harness.HarnessError):
                fixture.image.verify({}, value)
            run.assert_not_called()

    def test_image_bytes_config_binding_and_platform_are_required(self):
        base, image = fixture.base, fixture.image
        config = base.canonical_json({"architecture": "amd64", "os": "linux"})
        digest = "sha256:" + base.sha256(config)
        manifest = base.canonical_json({"schemaVersion": 2, "config": {"digest": digest}})
        with patch.object(image, "CONFIG", digest), patch.object(image, "DIGEST", "sha256:" + base.sha256(manifest)):
            self.assertEqual(image.validate(manifest, config)["publisher_signature"], "not-established")
            for first, second in ((manifest + b" ", config), (manifest, config + b" ")):
                with self.assertRaises(fixture.harness.HarnessError):
                    image.validate(first, second)
        bad = base.canonical_json({"architecture": "arm64", "os": "linux"})
        digest = "sha256:" + base.sha256(bad)
        manifest = base.canonical_json({"schemaVersion": 2, "config": {"digest": digest}})
        with patch.object(image, "CONFIG", digest), patch.object(image, "DIGEST", "sha256:" + base.sha256(manifest)):
            with self.assertRaises(fixture.harness.HarnessError):
                image.validate(manifest, bad)

    def test_configuration_is_loopback_only_without_password_logging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fixture.configuration(Path(tmp), self.values())
            config = (root / "radiusd.conf").read_text()
            self.assertIn("ipaddr = 127.0.0.1", config)
            self.assertIn("port = 11812", config)
            self.assertIn("require_message_authenticator = no", config)
            self.assertIn("limit_proxy_state = yes", config)
            self.assertIn("auth_badpass = no", config)
            self.assertIn("auth_goodpass = no", config)
            self.assertIn("file = /dev/null", config)
            for path in root.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertNotIn("Auth-Type := Accept", (root / "users").read_text())

    def test_configuration_rejects_injection_and_reused_secrets(self):
        for bad in ('a"\nexec attacker', "", "a" * 65, "b" * 64):
            with tempfile.TemporaryDirectory() as tmp, self.assertRaises(fixture.harness.HarnessError):
                fixture.configuration(Path(tmp), {**self.values(), "shared": bad})

    def test_container_has_no_published_ports_and_retains_constraints(self):
        command = fixture.container_command("podman", "name", "owned-server", "owner", Path("/fixture"))
        for flag, value in (("--network", "container:owned-server"), ("--user", "65532:0"),
                            ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges"),
                            ("--log-driver", "none"), ("--pull", "never")):
            self.assertEqual(command[command.index(flag) + 1], value)
        self.assertIn("--read-only", command)
        self.assertNotIn("-p", command)
        self.assertNotIn("--publish", command)
        self.assertNotIn("-X", command)
        self.assertIn(fixture.image.REFERENCE, command)
        for option in fixture.base.CONTAINER_RESOURCE_OPTIONS:
            self.assertIn(option, command)

    def test_rejection_requires_a_received_reject_not_timeout(self):
        for label in ("positive", "negative", "unknown"):
            expected = b"Received Access-Accept" if label == "positive" else b"Received Access-Reject"
            with patch.object(fixture.harness, "run_bounded", return_value=expected) as run:
                fixture.probe("podman", "name", {}, label)
                self.assertEqual(run.call_args.kwargs["accepted_codes"], (0,) if label == "positive" else (0, 1))
                self.assertNotIn(self.values()["shared"], run.call_args.args[0])
            for raw in (b"", b"No reply", b"Sent Access-Reject", b"Received Access-Reject\nReceived Access-Accept"):
                with patch.object(fixture.harness, "run_bounded", return_value=raw), self.assertRaises(fixture.harness.HarnessError):
                    fixture.probe("podman", "name", {}, label)

    def test_policy_and_identity_checks_are_exact(self):
        auth = {"client_token": "disposable", "policies": ["base", "mapped"], "metadata": {"username": "alice"}}
        self.assertEqual(fixture.check_auth({"auth": auth}, "alice", ["mapped", "base"]), "disposable")
        for changed in ({**auth, "policies": ["root"]}, {**auth, "metadata": {}}, {**auth, "client_token": ""}):
            with self.assertRaises(fixture.harness.HarnessError):
                fixture.check_auth({"auth": changed}, "alice", ["base", "mapped"])


if __name__ == "__main__":
    unittest.main()
