"""Exercise batch continuation without building an SDK or elevating privileges."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import openbao_current_ci as ci


@unittest.skipIf(os.geteuid() == 0, "batch requires an unprivileged caller")
class MaintenanceBatchTests(unittest.TestCase):
    def test_release_refresh_keeps_seven_ci_results_after_other_builds_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts = root / "scripts"
            scripts.mkdir()
            batch = scripts / "maintenance_batch.sh"
            shutil.copyfile(ci.ROOT / "scripts" / batch.name, batch)
            (scripts / "openbao_current_ci.py").write_text(
                'from pathlib import Path\nprint("Current-profile CI test binary:", '
                'Path.cwd() / "target/debug/deps/openbao_integration-0123456789abcdef")\n')
            for name, body in {
                "sudo": 'printf \'{"simulated":true}\\n\'',
                "git": "exit 0",
                "mktemp": 'mkdir "$FAKE_RESULTS" && printf "%s\\n" "$FAKE_RESULTS"',
            }.items():
                path = root / name
                path.write_text("#!/bin/sh\n" + body + "\n")
                path.chmod(0o700)
            results = root / "results"
            run = subprocess.run(["bash", str(batch), "--release-refresh"], timeout=60,
                                 capture_output=True, env={**os.environ, "PATH": f"{root}:/usr/bin:/bin",
                                                           "FAKE_RESULTS": str(results)})
            self.assertEqual(run.returncode, 1)
            summary = (results / "summary.tsv").read_text().splitlines()
            for version in ci.VERSIONS:
                self.assertIn(f"PASS\tci-{version}\t0", summary)
                self.assertEqual(json.loads((results / f"ci-{version}.json").read_bytes()), {"simulated": True})
            self.assertIn("BLOCKED\t2.6.6-normal-live\t-", summary)
            self.assertIn("PASS\tdiff-check\t0", summary)
            sdk = root / "sdk"
            run = subprocess.run(["bash", str(batch), "--sdk-refresh"], timeout=60,
                                 capture_output=True, env={**os.environ, "PATH": f"{root}:/usr/bin:/bin",
                                                           "FAKE_RESULTS": str(sdk)})
            self.assertEqual(run.returncode, 1)
            labels = {row.split("\t")[1] for row in (sdk / "summary.tsv").read_text().splitlines()[1:]}
            self.assertTrue({f"ci-{v}" for v in ci.VERSIONS} <= labels)
            self.assertTrue({"273-plugin-candidate-live", "270-backup_sdk-strict",
                             "2.7.1-kerberos-sdk", "2.6.6-candidate-live"} <= labels)
            self.assertFalse({"273-transit", "273-backup-upgrade", "270-raw_backup", "271-api"} & labels)
            prior = root / "prior"
            run = subprocess.run(["bash", str(batch), "--prior-patch-sdk"], timeout=60,
                                 capture_output=True, env={**os.environ, "PATH": f"{root}:/usr/bin:/bin",
                                                           "FAKE_RESULTS": str(prior)})
            self.assertEqual(run.returncode, 1)
            rows = (prior / "summary.tsv").read_text().splitlines()[1:]
            self.assertEqual(set(rows), {"PASS\tdiff-check\t0"} | {
                f"{status}\t{suite}-{mode}-{step}\t{code}"
                for suite in ("2_7_2_sdk", "2_7_1_sdk_advanced", "2_7_2_sdk_advanced")
                for mode in ("normal", "candidate")
                for status, step, code in (("FAIL", "build", "2"), ("BLOCKED", "live", "-"))
            })
