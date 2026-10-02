#!/usr/bin/python3 -EsSB
"""Exact 2.6 patch identity, legacy scope and fail-closed TLS capture checks."""

import copy
from contextlib import ExitStack, redirect_stdout
import io
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

import openbao_2_6_4 as fixture


class PatchTests(unittest.TestCase):
    def document(self):
        paths = {path: {"get": {"responses": {"200": {"description": "ok"}}}}
                 for path in fixture.LEGACY_ROUTES | {"/sys/raw", "/sys/raw/{path}"}}
        return {"openapi": "3.0.2", "info": {"version": "2.6.4"}, "paths": paths, "components": {"schemas": {}}}

    def mounts(self):
        return ([{"kind": "secret", "path": path, "type": kind} for path, kind, _ in fixture.base.SECRET_MOUNTS]
                + [{"kind": "auth", "path": path, "type": kind} for path, kind in fixture.base.AUTH_MOUNTS])

    def test_source_and_image_are_pinned(self):
        self.assertEqual(len(fixture.verify_source()["operations"]), 693)
        fixture.verify_image()
        docs = fixture.base.read_regular_file(fixture.OUTPUT / "documentation.json", fixture.LIMIT)
        with self.assertRaises(fixture.harness.HarnessError): fixture.validate_documentation(docs + b" ")
        artifacts = {name: fixture.base.read_regular_file(fixture.OUTPUT / name, fixture.LIMIT) for name in fixture.IMAGE_ARTIFACTS}
        for name in artifacts:
            with self.subTest(name=name), self.assertRaises(fixture.harness.HarnessError):
                fixture.validate_image({**artifacts, name: artifacts[name] + b" "})

    def test_image_semantics_are_checked_beyond_pins(self):
        original = {name: fixture.base.read_regular_file(fixture.OUTPUT / name, fixture.LIMIT) for name in fixture.IMAGE_ARTIFACTS}
        for mutation in ("child", "subject", "layer", "length", "revision", "repository", "predicate"):
            artifacts = dict(original)
            if mutation == "child":
                name = "image-index.json"
                value = fixture.base.parse_json(artifacts[name], fixture.LIMIT)
                value["manifests"][0]["digest"] = "sha256:" + "0" * 64
            elif mutation in ("subject", "layer", "length"):
                name = "image-attestation-manifest.json"
                value = fixture.base.parse_json(artifacts[name], fixture.LIMIT)
                if mutation == "subject": value["subject"]["digest"] = "sha256:" + "0" * 64
                elif mutation == "layer": value["layers"][0]["digest"] = "sha256:" + "0" * 64
                else: value["layers"][0]["size"] += 1
            else:
                name = "image-provenance.json"
                value = fixture.base.parse_json(artifacts[name], fixture.LIMIT)
                args = value["predicate"]["buildDefinition"]["externalParameters"]["request"]["root"]["request"]["args"]
                if mutation == "revision": args["vcs:revision"] = "0" * 40
                elif mutation == "repository": args["vcs:source"] = "https://example.invalid/source"
                else: value["predicateType"] = "unreviewed"
            artifacts[name] = fixture.base.canonical_json(value)
            if name == "image-provenance.json":
                manifest = fixture.base.parse_json(artifacts["image-attestation-manifest.json"], fixture.LIMIT)
                manifest["layers"][0]["size"] = len(artifacts[name])
                artifacts["image-attestation-manifest.json"] = fixture.base.canonical_json(manifest)
            with self.subTest(mutation=mutation), patch.object(fixture, "pinned", side_effect=lambda data, _: data), \
                 self.assertRaises(fixture.harness.HarnessError):
                fixture.validate_image(artifacts)

    def test_signature_requires_exact_release_and_no_bypass(self):
        good = [{"critical": {"image": {"docker-manifest-digest": fixture.INDEX}, "type": "https://sigstore.dev/cosign/sign/v1"}}]
        with patch.object(fixture.base, "run_bounded", return_value=(0, fixture.base.canonical_json(good))) as run:
            fixture.verify_signature()
        self.assertEqual(run.call_args.args[0], ["cosign", "verify", "--certificate-identity", fixture.IDENTITY,
                         "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
                         "docker.io/openbao/openbao@" + fixture.INDEX])
        wrong = copy.deepcopy(good)
        wrong[0]["critical"]["image"]["docker-manifest-digest"] = fixture.wire.INDEX
        for value in ([], [{}], [None], good * 33, wrong):
            with self.assertRaises(fixture.harness.HarnessError): fixture.validate_signature(fixture.base.canonical_json(value))

    def test_all_legacy_engines_remain_in_capture(self):
        count = len(self.mounts())
        with patch.object(fixture, "call", side_effect=[{}] * count + [self.document()]) as call:
            result = fixture.capture_api("https://127.0.0.1", Path("ca"), "disposable")
        self.assertEqual(result["mounts"], self.mounts())
        self.assertEqual(result["version"], "2.6.4")
        posted = [item.args[4] for item in call.call_args_list]
        for path in ("/v1/sys/auth/ldap", "/v1/sys/auth/kerberos", "/v1/sys/auth/radius", "/v1/sys/mounts/ldap"):
            self.assertIn(path, posted)
        self.assertEqual(call.call_args.args[4], "/v1/sys/internal/specs/openapi")
        self.assertEqual(call.call_args.kwargs, {"openapi": True})

    def test_wrong_version_missing_raw_or_legacy_scope_rejected(self):
        for version in ("2.6.3", "2.6.5", "2.7.1", "2.6.4+unreviewed", None):
            document = self.document()
            document["info"]["version"] = version
            with self.assertRaises(fixture.harness.HarnessError): fixture.normalize_api(document, self.mounts())
        for path in self.document()["paths"]:
            document = self.document()
            del document["paths"][path]
            with self.assertRaises(fixture.harness.HarnessError): fixture.normalize_api(document, self.mounts())
        for mounts in ([], self.mounts()[1:]):
            with self.assertRaises(fixture.harness.HarnessError): fixture.normalize_api(self.document(), mounts)

    def test_config_keeps_tls_and_does_not_contact_acme(self):
        with tempfile.TemporaryDirectory() as directory:
            config, marker = fixture.prepare_config(Path(directory))
            text = config.read_text()
            self.assertIn('tls_min_version = "tls13"', text)
            self.assertIn('tls_acme_eab_mac_key = "' + marker + '"', text)
            self.assertIn("raw_storage_endpoint = true", text)
            self.assertNotIn("tls_acme_enable", text)
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o640)

    def test_both_form_and_json_expire_without_tidy(self):
        valid = {"data": {"listeners": [{"config": {"tls_acme_eab_key_id": fixture.wire.EAB_KEY_ID}}]}}
        replies = [valid, {}, {}, {"data": {"role_id": "role"}}, {"data": {"secret_id": "id"}},
                   {"auth": {"client_token": "disposable"}}, {"auth": {"client_token": "disposable"}}, {}]
        for bad in (None, (200, {"auth": {"client_token": "disposable"}}), (403, {"errors": ["permission denied"]}),
                    (500, {"errors": ["invalid role or secret ID"]})):
            with patch.object(fixture, "call", side_effect=copy.deepcopy(replies)) as call, \
                 patch.object(fixture.wire, "request", return_value=bad or (400, {"errors": ["invalid role or secret ID"]})) as request, \
                 patch.object(fixture.time, "sleep"), redirect_stdout(io.StringIO()):
                if bad:
                    with self.assertRaises(fixture.harness.HarnessError): fixture.patch_probes("address", Path("ca"), "disposable", "marker")
                else:
                    fixture.patch_probes("address", Path("ca"), "disposable", "marker")
                    self.assertEqual([c.kwargs["form"] for c in request.call_args_list], [False, True])
                    self.assertEqual([c.kwargs["form"] for c in call.call_args_list if "form" in c.kwargs], [False, True])
                self.assertFalse(any("tidy" in str(c.args) for c in call.call_args_list + request.call_args_list))

    def test_nonroot_and_signature_fail_before_resources(self):
        with patch.object(fixture.os, "geteuid", return_value=1000), patch.object(fixture.tempfile, "mkdtemp") as create:
            with self.assertRaises(fixture.harness.HarnessError): fixture.capture()
            create.assert_not_called()
        with patch.object(fixture.os, "geteuid", return_value=0), \
             patch.object(fixture, "verify_signature", side_effect=fixture.harness.HarnessError("failed")), \
             patch.object(fixture.tempfile, "mkdtemp") as create, redirect_stdout(io.StringIO()):
            with self.assertRaises(fixture.harness.HarnessError): fixture.capture()
            create.assert_not_called()

    def test_capture_gates_cleanup_and_source_stability(self):
        for failure in (None, "limits", "network", "version", "tls", "probe", "api", "cleanup", "inputs"):
            with self.subTest(failure=failure), ExitStack() as stack:
                stack.enter_context(redirect_stdout(io.StringIO()))
                def mock(obj, name, **kwargs): return stack.enter_context(patch.object(obj, name, **kwargs))
                mock(fixture.os, "geteuid", return_value=0)
                mock(fixture, "input_hashes", side_effect=[{"a": "b"}, {"a": "c" if failure == "inputs" else "b"}])
                mock(fixture, "verify_source")
                mock(fixture, "verify_image")
                mock(fixture, "verify_signature")
                mock(fixture.tls.evidence_tools, "protected_path", side_effect=lambda p: p)
                mock(fixture.harness, "generate_tls", side_effect=lambda root, *_: (root / "tls", root / "ca"))
                mock(fixture, "prepare_config", side_effect=lambda root: (root / "config", "marker"))
                mock(fixture.harness, "inspect_image", return_value="digest")
                mock(fixture.harness, "run_bounded", return_value=b"{}")
                mock(fixture.harness, "parse_port", return_value=1234)
                for obj, name, stage in ((fixture.base, "validate_container_resource_config", "limits"),
                                         (fixture.tls, "verify_network", "network"),
                                         (fixture.harness, "wait_for_exact_version", "version"),
                                         (fixture.tls, "probe_tls", "tls"), (fixture, "patch_probes", "probe"),
                                         (fixture, "capture_api", "api")):
                    mock(obj, name, side_effect=fixture.harness.HarnessError("failed") if failure == stage else None, return_value={})
                mock(fixture.harness, "initialize_and_unseal", return_value="disposable")
                removed = mock(fixture.harness, "remove_owned_resource")
                mock(fixture.harness, "cleanup_private_files", return_value=failure != "cleanup")
                output = mock(fixture, "write_capture_output", return_value=Path("/result"))
                if failure:
                    with self.assertRaises(fixture.harness.HarnessError): fixture.capture()
                    output.assert_not_called()
                else:
                    fixture.capture()
                    self.assertEqual(output.call_args.args[1]["version"], "2.6.4")
                    self.assertFalse(output.call_args.args[1]["routable"])
                self.assertEqual([c.args[1] for c in removed.call_args_list], ["container", "network"])

    def test_output_permissions_and_failure_cleanup(self):
        output = fixture.write_capture_output(b"{}\n", {"routable": False})
        try:
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((output / "report.json").stat().st_mode), 0o644)
        finally:
            shutil.rmtree(output)
        output = Path(tempfile.mkdtemp())
        with patch.object(fixture.tempfile, "mkdtemp", return_value=str(output)), \
             patch.object(fixture.os, "fsync", side_effect=OSError), self.assertRaises(OSError):
            fixture.write_capture_output(b"{}\n", {})
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
