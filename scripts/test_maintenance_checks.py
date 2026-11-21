import unittest

import maintenance_checks as checks


class SelectionTests(unittest.TestCase):
    def mode(self, paths, pair=({}, {}), current=(2, 2, 6)):
        return checks.select(paths, (2, 2, 5), current, lambda _: pair)

    def test_patch_docs_and_local_source(self):
        self.assertEqual(self.mode(["README.md"]), ("metadata", set()))
        self.assertEqual(self.mode(["src/timestamp.rs"]), ("targeted", {"time"}))
        self.assertEqual(self.mode(["SECURITY.md"], ("/blob/v2.2.5/docs", "/blob/v2.2.6/docs"))[0], "metadata")
        self.assertEqual(self.mode(["SECURITY.md"], ("policy", "another policy"))[0], "full")

    def test_major_minor_shared_and_unknown_changes_are_full(self):
        for paths, current in ((["README.md"], (2, 3, 0)), (["README.md"], (3, 0, 0)),
                               (["src/client.rs"], (2, 2, 6)), (["build.rs"], (2, 2, 6)),
                               (["src/timestamp.rs", ".github/workflows/ci.yml"], (2, 2, 6))):
            self.assertEqual(self.mode(paths, current=current)[0], "full")

    def test_patch_dependency_uses_its_own_tests(self):
        def lock(name, version, **fields):
            return {"package": [{"name": name, "version": version, **fields}]}
        for name in ("tokio", "aes-kw", "time"):
            mode, areas = self.mode(["Cargo.lock"], (lock(name, "1.0.1"), lock(name, "1.0.2")))
            self.assertEqual((mode, areas), ("targeted", {name}))
            self.assertTrue(any(test for _, _, test in checks.steps(mode, areas)))
        for after in (lock("time", "2.0.0"), lock("time", "1.0.2", dependencies=["extra"]),
                      lock("different", "1.0.2")):
            self.assertEqual(self.mode(["Cargo.lock"], (lock("time", "1.0.1"), after))[0], "full")

    def test_manifest_features_do_not_get_mistaken_for_a_patch_bump(self):
        def manifest(v, features):
            return {"package": {"version": "2.2.6"}, "dependencies": {"time": {"version": v, "features": features}}}
        self.assertEqual(self.mode(["Cargo.toml"], (manifest("1.1.0", []), manifest("1.1.1", []))),
                         ("targeted", {"time"}))
        self.assertEqual(self.mode(["Cargo.toml"], (manifest("1.1.0", []), manifest("1.1.1", ["new"])))[0], "full")


if __name__ == "__main__":
    unittest.main()
