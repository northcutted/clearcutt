#!/usr/bin/env python3
"""Teeth tests for the runtime-patch completeness gate (closure-cve-check.py).

Runnable the way the repo runs its python tests:

    cd core && python3 -m unittest tests/test_closure_cve_check.py

Exercises both the in-process matcher/version logic and the subprocess CLI
exit codes over synthetic ``--store-paths`` files, so the gate's default-deny
behavior and artifact-skip anchoring are pinned against regression.
"""

import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest


TESTS_DIR = pathlib.Path(__file__).resolve().parent
CHECKER = TESTS_DIR / "closure-cve-check.py"
FLOOR = TESTS_DIR / "runtime-dep-floor.json"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cve = load_module("closure_cve_check", CHECKER)


def run_cli(lines):
    """Run the checker over a synthetic store-paths file; return exit code."""
    with tempfile.NamedTemporaryFile("w", suffix=".paths", delete=False) as handle:
        handle.write("\n".join(lines) + "\n")
        paths_file = handle.name
    proc = subprocess.run(
        [sys.executable, str(CHECKER), "--store-paths", paths_file, "--floor", str(FLOOR)],
        capture_output=True,
        text=True,
    )
    pathlib.Path(paths_file).unlink()
    return proc.returncode, proc.stdout, proc.stderr


class VersionLogicTests(unittest.TestCase):
    def test_parse_version_dotted_numeric(self):
        self.assertEqual(cve.parse_version("3.6.3"), (3, 6, 3))
        self.assertEqual(cve.parse_version("3.53.2"), (3, 53, 2))

    def test_parse_version_rejects_non_numeric(self):
        self.assertIsNone(cve.parse_version("3.6.3a"))
        self.assertIsNone(cve.parse_version("3.6.3-rc1"))
        self.assertIsNone(cve.parse_version(""))

    def test_version_ge_is_tuple_not_string_compare(self):
        # 3.6.10 > 3.6.3 numerically, even though "3.6.10" < "3.6.3" as strings.
        self.assertTrue(cve.version_ge((3, 6, 10), (3, 6, 3)))
        self.assertTrue(cve.version_ge((3, 6, 3), (3, 6, 3)))
        self.assertFalse(cve.version_ge((3, 6, 2), (3, 6, 3)))
        # Padding: 3.6 == 3.6.0 < 3.6.3.
        self.assertFalse(cve.version_ge((3, 6), (3, 6, 3)))


class MatcherTests(unittest.TestCase):
    def setUp(self):
        self.floor = cve.load_floor(str(FLOOR))
        self.dep_re = cve.build_dep_re(self.floor)

    def evaluate(self, name):
        return cve.evaluate_component(name, self.floor, self.dep_re)

    def test_all_six_openssl_outputs_match_by_version(self):
        for output in ("", "-bin", "-dev", "-out", "-man", "-doc", "-debug"):
            self.assertIsNone(self.evaluate(f"openssl-3.6.3{output}"))

    def test_stock_openssl_3_6_2_fails(self):
        self.assertIn("floor 3.6.3", self.evaluate("openssl-3.6.2-bin"))

    def test_old_majors_fail(self):
        self.assertIsNotNone(self.evaluate("openssl-3.5.6"))
        self.assertIsNotNone(self.evaluate("openssl-3.0.20"))

    def test_stock_sqlite_fails_patched_passes(self):
        self.assertIsNotNone(self.evaluate("sqlite-3.51.2"))
        self.assertIsNone(self.evaluate("sqlite-3.53.2"))

    def test_artifacts_are_skipped_not_flagged(self):
        # .drv / .tar.gz / .zip / source / patch must NOT match — the version
        # group is dotted-numeric only, so an extension is not an output suffix.
        for artifact in (
            "openssl-3.6.3.drv",
            "openssl-3.6.3.tar.gz",
            "openssl-3.6.3-bin.drv",
            "sqlite-src-3530200.zip",
            "openssl-disable-kernel-detection.patch",
        ):
            self.assertIsNone(self.evaluate(artifact), artifact)

    def test_below_floor_short_versions_default_deny(self):
        # A bare older version still anchors and is denied as below-floor.
        self.assertIsNotNone(self.evaluate("openssl-3"))    # 3 < 3.6.3
        self.assertIsNotNone(self.evaluate("openssl-3.6"))  # 3.6.0 < 3.6.3

    def test_unparseable_matched_version_default_denies(self):
        # If a name anchors as dep-<numeric...> but parse_version still can't
        # produce a clean tuple, the gate denies rather than guessing. We drive
        # parse_version directly through evaluate by constructing a match whose
        # version the regex admits but the parser rejects is impossible here
        # (the regex is dotted-numeric); assert the parser contract instead.
        self.assertIsNone(cve.parse_version("3.6.3rc1"))


class CliExitCodeTests(unittest.TestCase):
    H = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-"

    def test_clean_closure_passes(self):
        rc, out, _ = run_cli([
            self.H + "openssl-3.6.3",
            self.H + "openssl-3.6.3-dev",
            self.H + "sqlite-3.53.2",
            self.H + "openssl-3.6.3.tar.gz",  # artifact, skipped
        ])
        self.assertEqual(rc, 0, out)
        self.assertIn("clean", out)

    def test_stock_openssl_fails(self):
        rc, _, err = run_cli([self.H + "openssl-3.6.2-bin"])
        self.assertEqual(rc, 1)
        self.assertIn("openssl-3.6.2 (floor 3.6.3)", err)

    def test_stock_sqlite_fails(self):
        rc, _, err = run_cli([self.H + "sqlite-3.51.2"])
        self.assertEqual(rc, 1)
        self.assertIn("sqlite-3.51.2 (floor 3.53.2)", err)

    def test_old_major_fails(self):
        rc, _, err = run_cli([self.H + "openssl-3.5.6"])
        self.assertEqual(rc, 1)
        self.assertIn("openssl-3.5.6", err)

    def test_higher_patch_passes_numeric_not_string(self):
        rc, out, _ = run_cli([self.H + "openssl-3.6.10"])
        self.assertEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main()
