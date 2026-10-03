#!/usr/bin/python3 -EsSB
"""Execute the release gates against mutated current-profile workflows."""

from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/openbao-current-compatibility.yml"
ACTIONS = {
    "actions/checkout": ("7", "v7.0.1", "3d3c42e5aac5ba805825da76410c181273ba90b1"),
    "sigstore/cosign-installer": ("4", "v4.1.2", "6f9f17788090df1f26f669e9d70d6ae9567deba6"),
    "actions/upload-artifact": ("7", "v7.0.1", "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"),
}


def action_gate():
    script = (ROOT / "scripts/check_latest_crates.sh").read_text()
    function = script.split("check_github_action_pin() {", 1)[1].split("\n}\n", 1)[0]
    calls = [line for line in script.splitlines()
             if line.startswith("check_github_action_pin ") and line.endswith(" " + WORKFLOW)]
    expected = {f"check_github_action_pin {action} https://github.com/{action}.git {major} {WORKFLOW}"
                for action, (major, _, _) in ACTIONS.items()}
    if len(calls) != len(expected) or set(calls) != expected:
        raise AssertionError("all current-profile actions must be enrolled exactly once")
    # Fixed official-tag fixtures keep mutation tests deterministic and offline.
    cases = "\n".join(
        f"*https://github.com/{action}.git*) printf '%s\\t%s\\n' {shlex.quote(sha)} "
        f"{shlex.quote('refs/tags/' + tag)} ;;"
        for action, (_, tag, sha) in ACTIONS.items()
    )
    return ("set -eu\ngit() { case \"$*\" in\n" + cases
            + "\n*) return 1 ;;\nesac; }\ncheck_github_action_pin() {"
            + function + "\n}\n" + "\n".join(calls))


def metadata_gate():
    script = (ROOT / "scripts/validate-release-metadata.sh").read_text()
    functions = script.split("\ncheck_file Cargo.toml", 1)[0]
    calls = [line for line in script.splitlines()
             if line.startswith(("check_file ", "check_grep ")) and line.endswith(" " + WORKFLOW)]
    expected = {f"check_file {WORKFLOW}",
                f"check_grep 'permissions:' {WORKFLOW}",
                f"check_grep 'contents: read' {WORKFLOW}",
                f"check_grep 'persist-credentials: false' {WORKFLOW}"}
    if len(calls) != len(expected) or set(calls) != expected:
        raise AssertionError("current-profile workflow metadata must be enrolled")
    return functions + "\n" + "\n".join(calls)


def run_gate(gate, workflow):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / WORKFLOW
        path.parent.mkdir(parents=True)
        if workflow is not None:
            path.write_text(workflow)
        return subprocess.run(["/bin/sh", "-c", gate], cwd=directory,
                              capture_output=True, text=True, timeout=10)


class CurrentCiReleaseControlsTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / WORKFLOW).read_text()

    def test_current_workflow_and_gate_enrollment(self):
        for gate in (action_gate(), metadata_gate()):
            result = run_gate(gate, self.workflow)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("scripts/test_current_ci_release_controls.py",
                      (ROOT / "scripts/checks.sh").read_text())

    def test_each_action_rejects_missing_unpinned_stale_and_wrong_label(self):
        gate = action_gate()
        for action, (major, tag, sha) in ACTIONS.items():
            mutations = {
                "missing": self.workflow.replace(f"uses: {action}@{sha}", "run: true"),
                "unpinned": self.workflow.replace(f"{action}@{sha}", f"{action}@v{major}"),
                "stale": self.workflow.replace(f"{action}@{sha}", f"{action}@{'0' * 40}"),
                "wrong-label": self.workflow.replace(f"# {action} {tag}", f"# {action} v0.0.0"),
                "missing-label": self.workflow.replace(f"# {action} {tag}", "# omitted"),
            }
            for name, workflow in mutations.items():
                with self.subTest(action=action, mutation=name):
                    self.assertNotEqual(workflow, self.workflow)
                    self.assertNotEqual(run_gate(gate, workflow).returncode, 0)

    def test_metadata_rejects_missing_workflow_and_controls(self):
        gate = metadata_gate()
        self.assertNotEqual(run_gate(gate, None).returncode, 0)
        for control in ("permissions:", "contents: read", "persist-credentials: false"):
            with self.subTest(control=control):
                self.assertNotEqual(run_gate(gate, self.workflow.replace(control, "omitted")).returncode, 0)
        for old, new in (("contents: read", "contents: write"),
                         ("persist-credentials: false", "persist-credentials: true")):
            with self.subTest(control=new):
                self.assertNotEqual(run_gate(gate, self.workflow.replace(old, new)).returncode, 0)


if __name__ == "__main__":
    unittest.main()
