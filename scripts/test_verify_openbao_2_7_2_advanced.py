#!/usr/bin/python3 -EsSB
"""Reject stale or widened 2.7.2 consistency and backup evidence."""

import copy
import unittest
from unittest.mock import patch

import verify_openbao_2_7_2_backup_upgrade as upgrade
import verify_openbao_2_7_2_backups as backups
import verify_openbao_2_7_2_consistency as consistency


class EvidenceTests(unittest.TestCase):
    def test_current_narrow_scopes(self):
        self.assertIs(consistency.verify()["sdk_live_verified"], False)
        self.assertEqual(set(backups.verify()), {"unseal", "recovery"})
        report = upgrade.verify()
        self.assertEqual((report["source_version"], report["version"]), ("2.7.1", "2.7.2"))
        for key in ("routable", "sdk_live_verified", "general_upgrade_verified",
                    "backup_decryption_verified", "unseal_backup_upgrade_verified"):
            self.assertIs(report[key], False)

    def test_consistency_mutations_fail(self):
        data = consistency.fixture.base.read_regular_file(consistency.OUTPUT, 128 * 1024)
        report = consistency.fixture.base.parse_json(data, 128 * 1024)
        with self.assertRaises(consistency.fixture.harness.HarnessError):
            consistency.validate(data + b" ")
        for key, value in (("version", "2.7.1"), ("scope", "public-sdk"),
                           ("routable", True), ("sdk_live_verified", True),
                           ("inputs", {}), ("checks", []), ("nodes", 1)):
            with self.subTest(key=key), patch.object(consistency.initial, "checked",
                                                     return_value={**report, key: value}), \
                 self.assertRaises(consistency.fixture.harness.HarnessError):
                consistency.validate(data)

    def test_backup_mutations_fail(self):
        for suite in backups.REPORTS:
            data = backups.fixture.base.read_regular_file(backups.output(suite), 128 * 1024)
            report = backups.fixture.base.parse_json(data, 128 * 1024)
            with self.assertRaises(backups.fixture.harness.HarnessError):
                backups.validate(suite, data + b" ")
            for key, value in (("scope", "public-sdk"), ("routable", True),
                               ("upgrade_verified", True), ("backup_decryption_verified", True),
                               ("inputs", {}), ("checks", [])):
                changed = copy.deepcopy(report)
                changed[key] = value
                with self.subTest(suite=suite, key=key), \
                     patch.object(backups.initial, "checked", return_value=changed), \
                     self.assertRaises(backups.fixture.harness.HarnessError):
                    backups.validate(suite, data)

    def test_upgrade_mutations_fail(self):
        data = upgrade.fixture.base.read_regular_file(upgrade.OUTPUT, 128 * 1024)
        report = upgrade.fixture.base.parse_json(data, 128 * 1024)
        with self.assertRaises(upgrade.fixture.harness.HarnessError):
            upgrade.validate(data + b" ")
        changes = {"source_version": "2.7.0", "version": "2.7.1", "scope": "general-upgrade",
                   "routable": True, "sdk_live_verified": True,
                   "general_upgrade_verified": True, "backup_decryption_verified": True,
                   "unseal_backup_upgrade_verified": True, "inputs": {}, "checks": []}
        for key, value in changes.items():
            with self.subTest(key=key), patch.object(upgrade.initial, "checked",
                                                     return_value={**report, key: value}), \
                 self.assertRaises(upgrade.fixture.harness.HarnessError):
                upgrade.validate(data)


if __name__ == "__main__":
    unittest.main()
