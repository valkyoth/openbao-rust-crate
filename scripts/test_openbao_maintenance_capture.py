import json
import unittest
from unittest.mock import patch

import openbao_maintenance_capture as capture
import openbao_maintenance_sdk as sdk
import openbao_2_7_3_backup_upgrade as upgrade
import openbao_2_7_3_backups as backups
import openbao_2_7_3_consistency as consistency
import openbao_2_7_3_regressions as regressions
import openbao_2_7_3_plugin_sdk as plugin_sdk
import openbao_2_7_3_sdk_advanced as advanced


class MaintenanceCaptureTests(unittest.TestCase):
    def test_retained_normal_reports_match_current_sources(self):
        sdk.profiles.verify_normal_reports()

    def test_normal_registry_exact_pin_and_missing_release_evidence(self):
        import verify_openbao_maintenance_normal as release
        normal = sdk.profiles.normal_registry()
        self.assertEqual(normal["routable_versions"], normal["versions"])
        self.assertTrue(set(sdk.TESTS).issubset(normal["versions"]))
        self.assertEqual(sdk.base.sha256(sdk.registry.maintenance_rust(normal)),
                         sdk.registry.EXPECTED_RUST_SHA256)
        normal["versions"].append("2.7.4")
        with self.assertRaises(sdk.registry.RegistryError):
            sdk.registry.maintenance_rust(normal)
        with patch.object(release, "REPORT_SHA256", {}), self.assertRaises(sdk.registry.RegistryError):
            release.verify()

    def test_normal_preflight_requires_both_patches_without_using_candidate_override(self):
        proof = {"source_scope": "repository-normal-build-no-generated-override"}
        with patch.object(sdk.normal_sdk, "verify_build", return_value=proof), \
             patch.object(sdk, "candidate", side_effect=AssertionError("candidate override")), \
             patch.object(sdk.profiles, "normal_registry") as reviewed:
            for versions in ([], ["2.6.6"], ["2.7.3"]):
                with self.subTest(versions=versions):
                    reviewed.return_value = {"versions": versions}
                    with self.assertRaises(sdk.MissingNormalProfiles) as err:
                        sdk.normal_provenance()
                    for missing in set(sdk.TESTS) - set(versions):
                        self.assertIn(missing, str(err.exception))
            reviewed.return_value = {"versions": list(sdk.TESTS)}
            self.assertEqual(sdk.normal_provenance(), proof)

    def test_release_rejects_candidate_or_stale_normal_reports_even_when_pinned(self):
        import verify_openbao_maintenance_normal as release
        inputs = {"Cargo.lock": "1" * 64}
        proof = {"scope": "public-sdk-strict-normal-build", "routable": True}
        for changes in ({}, {"scope": "strict-candidate-only"}, {"inputs": {}},
                        {"explicit_case_sensitive_alias_verified": 1}):
            documents = {}
            pins = {}
            for version, test in sdk.TESTS.items():
                index, platform = sdk.capture.PINS[version]
                raw = sdk.base.canonical_json({
                    **sdk.execution.EXECUTION_ASSURANCE, **proof,
                    "test_binary_sha256": "2" * 64, "new_auth_mount_reported_case_sensitive_alias": None,
                    "inputs": inputs, "version": version, "schema": "openbao-maintenance-normal-sdk/v1",
                    "test": test, "features": sdk.FEATURES, "stages": list(sdk.STAGES[version]),
                    "image_index_digest": index, "image_linux_amd64_digest": platform,
                    "explicit_case_sensitive_alias_verified": True, "outcome": "passed", **changes})
                documents[version] = raw
                pins[version] = sdk.base.sha256(raw)
            with self.subTest(changes=changes), patch.object(sdk, "normal_provenance", return_value=proof), \
                 patch.object(sdk, "normal_hashes", return_value=inputs), patch.object(release, "REPORT_SHA256", pins), \
                 patch.object(sdk.base, "read_regular_file", side_effect=lambda path, _: documents[path.parent.name]):
                if changes:
                    with self.assertRaises(sdk.registry.RegistryError):
                        release.verify()
                else:
                    release.verify()

    def test_retained_advanced_candidate_report(self):
        path = sdk.patch.ROOT / "compat/onboarding/2.7.3/sdk-advanced-candidate-tls.json"
        raw = sdk.base.read_regular_file(path, 65536)
        self.assertEqual(sdk.base.sha256(raw), "8209d06d4d73da4139c636f28a47f1a581bdb6202cd8d5cf9ecf26c71245359a")
        report = sdk.base.parse_json(raw, 65536)
        self.assertEqual((report["version"], report["scope"], report["outcome"]),
                         ("2.7.3", "public-sdk-strict-disposable-candidate-build", "passed"))
        self.assertIs(report["routable"], False)
        self.assertIs(report["backup_decryption_verified"], False)
        self.assertEqual(report["checks"], advanced.CHECKS)
        self.assertEqual(report["tests"], advanced.TESTS)

    def test_advanced_candidate_is_exact_and_not_a_normal_build(self):
        inputs = {path: sdk.base.read_regular_file(sdk.patch.ROOT / path, 65536) for path in
                  (advanced.SOURCE, "src/sys/backup_live.rs", "src/client/consistency/patch_live.rs")}
        staged = advanced.candidate_inputs(inputs)
        addition = b"    OpenBaoVersion::new(2, 7, 3),\n"
        lines = staged[advanced.SOURCE].splitlines(keepends=True)
        self.assertEqual(lines.count(addition), 1)
        lines.remove(addition)
        self.assertEqual(b"".join(lines), inputs[advanced.SOURCE])
        for test in advanced.TESTS[1:]:
            name = test.split("::")[-1].encode()
            self.assertEqual(sum(source.count(b"fn " + name + b"()") for source in staged.values()), 1)
        with self.assertRaises(sdk.harness.HarnessError):
            advanced.candidate_inputs(staged)
        with self.assertRaises(sdk.harness.HarnessError):
            advanced.run.__wrapped__(None, strict_candidate=False)

    def test_candidate_plugin_extension_only_adds_exact_patch(self):
        path = plugin_sdk.SOURCE
        source = sdk.base.read_regular_file(sdk.patch.ROOT / path, 65536)
        inputs = {path: source}
        staged = plugin_sdk.candidate_inputs(inputs)[path]
        extra = b"OpenBaoVersion::new(2, 7, 3),"
        self.assertEqual(inputs[path], source)
        self.assertEqual(sum(line.strip() == extra for line in staged.splitlines()), 2)
        self.assertEqual(b"".join(line for line in staged.splitlines(keepends=True)
                                  if line.strip() != extra), source)
        with self.assertRaises(sdk.harness.HarnessError):
            plugin_sdk.candidate_inputs({path: staged})

    def test_candidate_plugin_run_rejects_missing_acknowledgements(self):
        for directory, radius in ((False, False), (True, False), (False, True)):
            with self.assertRaises(sdk.harness.HarnessError):
                plugin_sdk.run.__wrapped__(None, strict_candidate=True, directory_ack=directory, radius_ack=radius)

    def test_retained_plugin_contracts_match_predecessor(self):
        import verify_openbao_kerberos_plugins as kerberos
        import verify_openbao_ldap_plugins as ldap
        import verify_openbao_radius_plugins as radius

        for verifier in (ldap, kerberos, radius):
            with self.subTest(plugin=verifier.ROOT.name):
                self.assertIs(verifier.verify("2.7.3")["routable"], False)
                def mounted_paths(version):
                    path = verifier.ROOT / version / "runtime-openapi.json"
                    raw = verifier.base.read_regular_file(path, 2 * 1024 * 1024)
                    schema = verifier.base.parse_json(raw, 2 * 1024 * 1024)
                    return {p: ops for p, ops in schema["paths"].items() if "fixture_" in p}
                self.assertEqual(mounted_paths("2.7.2"), mounted_paths("2.7.3"))

    def test_retained_server_regressions(self):
        hashes = {
            "external-keys": "1abe0da7f7e14fb83d5f0bc4e8fb8e1bcec268dd12601baecb883628bc0a292a",
            "transit": "a0efabc2fa9a4db95de6ba2bf095ecc7cf4e842dfff60d70df62aa98cafa53b5",
            "pki": "b3b5dc756d74f52189917652c8c703725736faf1d4e1695e2f9faa502b18fb94",
            "workflow-cas": "6d4de11a9f7f485c334c5226672e59cb21aacae089806a516fc08cfe495dc1ff",
            "system": "3634a9516d85efbaaab7dd73b0f5b4b50162c1fcf9ebd5833d33e76e03504dfd",
            "mfa-totp": "eab99c108149fda70c5940431fa3b39098d86782ad0df78838bd7ef7018d51b3",
        }
        self.assertEqual(set(hashes), set(regressions.SUITES))
        for suite, digest in hashes.items():
            raw = sdk.base.read_regular_file(sdk.patch.ROOT / f"compat/onboarding/2.7.3/{suite}-tls.json", 65536)
            self.assertEqual(sdk.base.sha256(raw), digest)
            report = sdk.base.parse_json(raw, 65536)
            self.assertEqual((report["version"], report["suite"], report["outcome"]), ("2.7.3", suite, "passed"))
            self.assertEqual(report["checks"], regressions.MODULES[suite].CHECKS)
            self.assertEqual(report["inputs"], regressions.input_hashes())
            self.assertIs(report["routable"], False)

    def test_external_key_private_export_requires_the_reviewed_denial(self):
        client = regressions.TransitProbe(None, None, None)
        expected = {"errors": ['unsupported key type "external-key" for export type "encryption-key"']}
        args = ("GET", "fixture-delegated/export/encryption-key/forbidden-export", None, "unknown key type")
        with patch.object(client, "request", return_value=(500, expected)):
            client.error(*args)
        for reply in [(200, expected), (500, {"errors": ["unrelated failure"]}),
                      (500, {**expected, "data": {"keys": {}}})]:
            with patch.object(client, "request", return_value=reply):
                with self.assertRaises(regressions.harness.HarnessError):
                    client.error(*args)

    def test_retained_raft_evidence_is_server_only(self):
        path = sdk.patch.ROOT / "compat/onboarding/2.7.3/consistency-server-tls.json"
        raw = sdk.base.read_regular_file(path, 65536)
        self.assertEqual(sdk.base.sha256(raw), "f430e1b6ea91fa5ae229c8705b1426396eb8dc5f9aa53b128de825c0cd605056")
        report = sdk.base.parse_json(raw, 65536)
        self.assertEqual((report["version"], report["nodes"], report["checks"]), ("2.7.3", 3, consistency.CHECKS))
        self.assertEqual(report["scope"], "controlled-lag-server-protocol-only")
        self.assertIs(report["sdk_live_verified"], False)
        self.assertIs(report["routable"], False)

    def test_regression_suites_require_verified_image(self):
        self.assertEqual(set(regressions.SUITES), {"external-keys", "transit", "pki", "workflow-cas", "system", "mfa-totp"})
        with patch.object(regressions.os, "geteuid", return_value=0), patch.object(
                capture, "verify_signature", side_effect=regressions.harness.HarnessError("signature")) as verify, patch.object(
                regressions.harness, "inspect_image") as inspect:
            for suite in regressions.SUITES:
                with self.assertRaises(regressions.harness.HarnessError):
                    regressions.run(suite)
                verify.assert_called_with("2.7.3")
            self.assertEqual(verify.call_count, len(regressions.SUITES))
            inspect.assert_not_called()

    def test_retained_fresh_backup_reports(self):
        for suite, module, digest in (
            ("unseal", backups.unseal, "52d0e1732fd2fa9f80e2ca21a4b234181da3226bf03cd220cf935cbbd610f82e"),
            ("recovery", backups.recovery, "c298784a7bd0905438b4c8dfaf3910bdc58dd85712e360081ccd4137b1de9a44"),
        ):
            path = sdk.patch.ROOT / f"compat/onboarding/2.7.3/{suite}-backup-tls.json"
            raw = sdk.base.read_regular_file(path, 65536)
            self.assertEqual(sdk.base.sha256(raw), digest)
            report = sdk.base.parse_json(raw, 65536)
            self.assertEqual((report["version"], report["suite"], report["checks"]), ("2.7.3", suite, module.CHECKS))
            self.assertFalse(report["routable"] or report["backup_decryption_verified"] or report["upgrade_verified"])

    def test_consistency_refuses_wrong_version_on_one_standby(self):
        nodes = ["leader", "standby1", "standby2"]
        def health(address, *_):
            return (200 if address == "leader" else 429,
                    {"version": "2.7.2" if address == "standby2" else "2.7.3", "initialized": True,
                     "sealed": False, "standby": address != "leader", "cluster_id": "shared"}, None, None)
        with patch.object(consistency.protocol, "request", side_effect=health):
            with self.assertRaises(consistency.harness.HarnessError):
                consistency.ready_cluster(nodes, None)

    def test_retained_backup_upgrade(self):
        path = sdk.patch.ROOT / "compat/onboarding/2.7.3/recovery-backup-upgrade-tls.json"
        raw = sdk.base.read_regular_file(path, 1024 * 1024)
        self.assertEqual(sdk.base.sha256(raw), "60de2b76c9a6209c76f878dbd2e3745adaf752b421e18806c4fd5c8b2838e20e")
        report = sdk.base.parse_json(raw, 1024 * 1024)
        self.assertEqual(report, upgrade.report_for(report["inputs"]))

    def test_fresh_backups_require_target_signature_before_start(self):
        self.assertIn("scripts/openbao_2_7_3_backups.py", backups.input_hashes())
        for suite in backups.SUITES:
            with patch.object(backups.os, "geteuid", return_value=0), patch.object(
                    capture, "verify_signature", side_effect=backups.harness.HarnessError("signature")) as verify, patch.object(
                    backups.harness, "inspect_image") as inspect:
                with self.assertRaises(backups.harness.HarnessError):
                    backups.run(suite)
                verify.assert_called_once_with("2.7.3")
                inspect.assert_not_called()

    def test_retained_candidate_reports(self):
        for version, digest in (
            ("2.6.6", "c9f4ab2ad630289ee3bd5c23049151b76df39b4f530a0020a7595c58c55e536b"),
            ("2.7.3", "30b696c87ae0504d13adcd2627d2d76032130e94504ab2c41e264450da28c617"),
        ):
            with self.subTest(version=version):
                raw = sdk.base.read_regular_file(sdk.patch.ROOT / "compat/onboarding" / version
                                                 / "sdk-candidate-tls.json", 1024 * 1024)
                self.assertEqual(sdk.base.sha256(raw), digest)
                report = sdk.base.parse_json(raw, 1024 * 1024)
                self.assertEqual(report["version"], version)
                self.assertEqual(report["test"], sdk.TESTS[version])
                self.assertEqual(report["inputs"], sdk.input_hashes())
                self.assertEqual(report["stages"], list(sdk.STAGES[version]))
                self.assertEqual(report["scope"], "strict-candidate-only")
                self.assertEqual(report["outcome"], "passed")
                self.assertIs(report["routable"], False)
                self.assertIsNone(report["new_auth_mount_reported_case_sensitive_alias"])
                self.assertIs(report["explicit_case_sensitive_alias_verified"], True)

    def test_backup_upgrade_pins_and_fail_closed_on_signature_failure(self):
        report = upgrade.report_for(upgrade.input_hashes())
        self.assertEqual((report["source_version"], report["version"]), ("2.7.2", "2.7.3"))
        self.assertEqual((report["target_image_index"], report["target_image"]), capture.PINS["2.7.3"])
        self.assertIs(report["general_upgrade_verified"], False)
        with patch.object(upgrade.os, "geteuid", return_value=0), patch.object(
                upgrade.source_image_evidence, "verify"), patch.object(upgrade.source, "verify_signature"), patch.object(
                capture, "verify_signature", side_effect=upgrade.harness.HarnessError("invalid signature")), patch.object(
                upgrade.harness, "inspect_image") as inspect:
            with self.assertRaises(upgrade.harness.HarnessError):
                upgrade.run()
            inspect.assert_not_called()

    def test_candidate_extends_only_the_two_reviewed_profiles(self):
        candidate = sdk.candidate()
        original = sdk.registry.parse_json(sdk.registry.read_regular_file(
            sdk.parent.OUTPUT, sdk.registry.MAX_OUTPUT_BYTES), sdk.registry.MAX_OUTPUT_BYTES)
        self.assertEqual(candidate["routable_versions"], original["versions"])
        self.assertFalse(candidate["routable"])
        for group, field in (("operations", "ranges"), ("logical_endpoints", "variants")):
            for new, old in zip(candidate[group], original[group], strict=True):
                self.assertEqual([cell for cell in new[field] if cell["minimum"] not in sdk.TESTS], old[field])
                for version, predecessor in (("2.6.6", "2.6.5"), ("2.7.3", "2.7.2")):
                    a = sdk.parent.selected(new[field], version, optional=True)
                    b = sdk.parent.selected(old[field], predecessor, optional=True)
                    def meaning(cell):
                        return None if cell is None else {k: v for k, v in cell.items()
                                                          if k not in ("minimum", "maximum")}
                    self.assertEqual(meaning(a), meaning(b))
        with self.assertRaises(sdk.registry.RegistryError):
            sdk.registry.rust_output(candidate, promoted_patches=True)

    def test_retained_combined_plugin_sdk_candidate(self):
        root = capture.previous.ROOT / "compat"
        directory = root / "onboarding/2.7.3/plugin-sdk-candidate"
        limit = 2 * 1024 * 1024
        raw = capture.base.read_regular_file(directory / "report.json", limit)
        self.assertEqual(capture.base.sha256(raw),
                         "79ec07411a0391ac6a58a38bb589f59c241119b26ddc67f3ae98e622fc00b930")
        report = capture.base.parse_json(raw, limit)
        self.assertEqual((report["server_version"], report["scope"], report["outcome"]),
                         ("2.7.3", "public-sdk-candidate-only", "passed"))
        self.assertIs(report["routable"], False)
        raw = capture.base.read_regular_file(directory / "runtime-openapi.json", limit)
        self.assertEqual(capture.base.sha256(raw), report["runtime_openapi_sha256"])
        paths = capture.base.parse_json(raw, limit)["paths"]
        expected = set()
        for plugin in ("ldap", "kerberos", "radius"):
            raw = capture.base.read_regular_file(root / "plugins" / plugin / "2.7.3/runtime-openapi.json", limit)
            server_paths = capture.base.parse_json(raw, limit)["paths"]
            expected.update(server_paths)
            for route, schema in server_paths.items():
                if "{fixture_" in route:
                    self.assertEqual(paths[route], schema, route)
        self.assertEqual(set(paths), expected)

    def test_retained_server_contract_deltas(self):
        def load(version, name, digest):
            path = capture.previous.ROOT / "compat/onboarding" / version / name
            raw = capture.base.read_regular_file(path, 2 * 1024 * 1024)
            self.assertEqual(capture.base.sha256(raw), digest)
            return capture.base.parse_json(raw, 2 * 1024 * 1024)

        pairs = [
            ("2.6.5", "2.6.6", "a1a656ea3bfd46116fe3dbc83a0409c0f7a11d991998b02779a641c1186d8929",
             "acada321180b214f2810bf8ede4ced3cd88008b98c49bc3394989b5f3773a60a",
             "839bce14393dc4a4a7816befcfce96971ce79581ee411741e04172ee0121023c"),
            ("2.7.2", "2.7.3", "eb4ebb0fea1bcfd682ee7f44d1962150a224cf2744a0ea2ee6f6de3535528fd5",
             "b94f171efed6d6de10362673eb372cda6c660cecb143aef92b8e4b3c7c9b849c",
             "a0f7133be739eb0dc8dff76244f5c527e960321ef1bd780d710549c9e340c95f"),
        ]
        for parent, version, old_hash, new_hash, report_hash in pairs:
            with self.subTest(version=version):
                expected = load(parent, "openapi.json", old_hash)
                actual = load(version, "openapi.json", new_hash)
                report = load(version, "report.json", report_hash)
                self.assertEqual(report["openapi_sha256"], new_hash)
                self.assertEqual(report["version"], version)
                self.assertIs(report["routable"], False)
                index, platform = capture.PINS[version]
                self.assertEqual((report["image_index_digest"], report["image_linux_amd64_digest"]),
                                 (index, platform))
                expected.update(version=version, image_index_digest=index, image_linux_amd64_digest=platform)
                expected["document"]["info"]["version"] = version
                schemas = expected["document"]["components"]["schemas"]
                for prefix in ("Auth", "Mounts"):
                    for suffix in ("ReadTuningInformationResponse", "TuneConfigurationParametersRequest"):
                        properties = schemas[prefix + suffix]["properties"]
                        self.assertNotIn("case_sensitive_alias", properties)
                        properties["case_sensitive_alias"] = {"type": "boolean"}
                self.assertEqual(actual, expected)

    def test_contract_is_bound_to_exact_version_and_platform(self):
        for version, (index, platform) in capture.PINS.items():
            document = {"openapi": "3.0.0", "info": {"version": version},
                        "paths": {"/fixture": {"get": {}}}, "components": {"schemas": {}}}
            result = capture.normalize_api(document, [], version)
            self.assertEqual((result["image_index_digest"], result["image_linux_amd64_digest"]),
                             (index, platform))
            self.assertEqual(result["operation_count"], 1)
            document["info"]["version"] = "2.7.2"
            with self.assertRaises(capture.harness.HarnessError):
                capture.normalize_api(document, [], version)

    def test_platform_binding_checked_before_signature(self):
        version = "2.7.3"
        raw = json.dumps({"manifests": [{"digest": "other", "platform": {
            "os": "linux", "architecture": "amd64"}}]}).encode()
        index = "sha256:" + capture.base.sha256(raw)
        with patch.dict(capture.PINS, {version: (index, "expected")}), patch.object(
                capture.base, "run_bounded", return_value=(0, raw)) as run:
            with self.assertRaises(capture.harness.HarnessError):
                capture.verify_signature(version)
            self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
