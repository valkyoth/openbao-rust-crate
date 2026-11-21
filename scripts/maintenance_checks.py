"""Select local maintenance checks relative to the last release tag."""

import argparse
import copy
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PY = ("/usr/bin/python3", "-EsSB")
CONTROL = "sys::control_groups::execution::tests::execution_preserves_response_shape_and_blocks_replay"
FEATURES = {"aes-kw": ("transit,transit-import,rustls-tls", "transit_import_helper_"),
            "time": ("time,rustls-tls", "timestamp::tests::"), "tokio": None}
LOCAL = {"src/timestamp.rs": "time"}
MANIFESTS = {"Cargo.toml", "fuzz/Cargo.toml", "tests/fixtures/reqwest-native-unification/Cargo.toml"}
LOCKS = {p.replace("Cargo.toml", "Cargo.lock") for p in MANIFESTS}


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def manifest_shape(data):
    shape = copy.deepcopy(data)
    versions = {}
    for section in ("dependencies", "dev-dependencies"):
        for name, value in shape.get(section, {}).items():
            if name not in {*FEATURES, "openbao"}:
                continue
            if isinstance(value, str):
                versions[section, name] = value
                shape[section][name] = "*"
            elif "version" in value:
                versions[section, name] = value.pop("version")
    return shape, versions


def lock_changes(before, after):
    def packages(data):
        result = {}
        for row in data["package"]:
            result.setdefault(row["name"], []).append(row)
        return result
    if {k: v for k, v in before.items() if k != "package"} != {
            k: v for k, v in after.items() if k != "package"}:
        return {"unknown lockfile format"}
    left, right = packages(before), packages(after)
    changed = {k for k in left.keys() | right.keys() if left.get(k) != right.get(k)}
    for name in changed & FEATURES.keys():
        a, b = left.get(name, []), right.get(name, [])
        if len(a) != 1 or len(b) != 1:
            return {"dependency graph change"}
        old, new = a[0], b[0]
        if (version(old["version"])[:2] != version(new["version"])[:2]
                or version(new["version"]) <= version(old["version"])
                or {k:v for k,v in old.items() if k not in ("version", "checksum")}
                != {k:v for k,v in new.items() if k not in ("version", "checksum")}):
            return {"dependency graph change"}
    return changed


def select(paths, baseline, current, documents):
    # Unknown paths, shared dependencies, or feature/source changes fail broad.
    if current[:2] != baseline[:2] or current < baseline or not paths:
        return "full", set()
    affected = set()
    for path in paths:
        if path in LOCAL:
            affected.add(LOCAL[path])
        elif path == "SECURITY.md":
            before, after = documents(path)
            prefix = lambda v: "/blob/v" + ".".join(map(str, v)) + "/"
            if before.replace(prefix(baseline), prefix(current)) != after:
                return "full", set()
        elif path in MANIFESTS | LOCKS:
            before, after = documents(path)
            if path in LOCKS:
                changes = lock_changes(before, after)
                # Ignore only the crate's own version, not changes to its dependencies.
                if "openbao" in changes:
                    rows = [[{k:v for k,v in r.items() if k != "version"} for r in d["package"]
                             if r["name"] == "openbao"] for d in (before, after)]
                    if rows[0] != rows[1]:
                        return "full", set()
                    changes.remove("openbao")
                affected.update(changes)
            else:
                left, a = manifest_shape(before)
                right, b = manifest_shape(after)
                if path == "Cargo.toml":
                    left["package"].pop("version")
                    right["package"].pop("version")
                if left != right:
                    return "full", set()
                for key in a.keys() | b.keys():
                    if a.get(key) == b.get(key) or key[1] == "openbao":
                        continue
                    if key not in a or key not in b or version(a[key])[:2] != version(b[key])[:2]:
                        return "full", set()
                    affected.add(key[1])
        elif path not in {"README.md", "CHANGELOG.md"} and not (
                path.startswith(("docs/", "release-notes/")) and path.endswith(".md")):
            return "full", set()
    if affected - FEATURES.keys():
        return "full", set()
    return ("targeted" if affected else "metadata"), affected


def version(s):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", s):
        raise ValueError("expected a stable release version")
    return tuple(map(int, s.split(".")))


def plan():
    tag = git("describe", "--tags", "--abbrev=0", "--match", "v[0-9]*", "HEAD").decode().strip()
    baseline = version(tag[1:])
    paths = set(os.fsdecode(p) for listing in (
        git("diff", "--no-renames", "--name-only", "-z", tag, "--"),
        git("ls-files", "--others", "--exclude-standard", "-z")) for p in listing.split(b"\0") if p)
    def documents(path):
        texts = (git("show", f"{tag}:{path}").decode(), (ROOT / path).read_text())
        return texts if path == "SECURITY.md" else tuple(tomllib.loads(text) for text in texts)
    try:
        old, current = documents("Cargo.toml")
        if version(old["package"]["version"]) != baseline:
            raise ValueError("release tag and manifest disagree")
        mode, areas = select(paths, baseline, version(current["package"]["version"]), documents)
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError):
        mode, areas = "full", set()
    return tag, mode, areas, len(paths)


def steps(mode, areas):
    if mode == "full":
        return [("full-local", ["sh", "scripts/checks.sh"], False)]
    checks = [
        ("metadata", ["bash", "scripts/validate-release-metadata.sh"], False),
        ("evidence-integrity", [*PY, "scripts/check_released_evidence.py"], False),
        ("diff", ["git", "diff", "--check"], False),
        ("control-history", [*PY, "scripts/test_maintenance_control_evidence.py"], False),
        ("control-sdk", ["cargo", "test", "--locked", "--all-features", "--lib", CONTROL, "--", "--exact"], True),
    ]
    if mode != "control":
        checks.append(("package-smoke", ["cargo", "test", "--locked", "--all-features", "--test", "package_smoke"], True))
    for name in sorted(areas):
        if name == "tokio":
            checks.append(("tokio-consumers", ["cargo", "test", "--locked", "--all-features"], True))
            continue
        features, test = FEATURES[name]
        checks.append((name, ["cargo", "test", "--locked", "--no-default-features", "--features", features,
                              "--lib", test], True))
    if areas:
        checks.extend([("dependency-policy", ["cargo", "deny", "check"], False),
                       ("msrv", ["cargo", "+1.90.0", "check", "--locked", "--all-targets", "--all-features"], False)])
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--full", action="store_true")
    modes.add_argument("--control-groups", action="store_true", help="only the historical evidence and defensive SDK checks")
    args = parser.parse_args()
    if args.full or args.control_groups:
        tag, mode, areas, count = "explicit", ("full" if args.full else "control"), set(), "n/a"
    else:
        try:
            tag, mode, areas, count = plan()
        except (ValueError, subprocess.CalledProcessError):
            tag, mode, areas, count = "no usable release tag", "full", set(), "unknown"
    checks = steps(mode, areas)
    print(f"Base: {tag}; changed paths: {count}; scope: {mode}; checks: " + ", ".join(s[0] for s in checks), flush=True)
    if args.plan:
        return 0
    out = Path(tempfile.mkdtemp(prefix="openbao-maintenance-checks-", dir="/tmp"))
    print(f"Results: {out}", flush=True)
    for label, cmd, require_tests in checks:
        log = out / (label + ".log")
        with log.open("xb") as handle:
            result = subprocess.run(cmd, cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT)
        passed = result.returncode == 0 and (not require_tests or
                 re.search(rb"(?m)^test result: ok\. [1-9][0-9]* passed;", log.read_bytes()))
        status = "PASS" if passed else "FAIL"
        print(status, label, flush=True)
        with (out / "summary.tsv").open("a") as handle:
            print(status, label, sep="\t", file=handle)
        if not passed:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
