#!/usr/bin/env python3
"""Teeth tests for the runtime-patch completeness gate (closure-cve-check.py).

Runnable the way the repo runs its python tests:

    cd core && python3 -m unittest tests/test_closure_cve_check.py

Exercises both the in-process identity matcher and the subprocess CLI exit
codes over synthetic ``--store-paths`` files, so the gate's default-deny
behavior, artifact-skip anchoring, and identity (not version) semantics are
pinned against regression.
"""

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


TESTS_DIR = pathlib.Path(__file__).resolve().parent
CHECKER = TESTS_DIR / "closure-cve-check.py"
COMMITTED_FLOOR = TESTS_DIR / "runtime-dep-floor.json"

# Synthetic known-good identities. openssl's known-good build reads version
# 3.6.2 — a patched-not-bumped build — to prove the gate passes by IDENTITY,
# not version.
KG_OPENSSL_OUT = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-openssl-3.6.2"
KG_OPENSSL_BIN = "cccccccccccccccccccccccccccccccc-openssl-3.6.2-bin"
KG_SQLITE_OUT = "dddddddddddddddddddddddddddddddd-sqlite-3.53.2"
# An off-allowlist openssl at a HIGHER version — must still be rejected.
OFF_OPENSSL = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-openssl-3.6.9"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cve = load_module("closure_cve_check", CHECKER)


def write_allowlist(deps):
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump({"deps": deps}, handle)
    handle.close()
    return handle.name


def sample_allowlist():
    return write_allowlist([
        {"name": "openssl", "cve": "CVE-2026-34182", "knownGood": [
            {"storePath": KG_OPENSSL_OUT},
            {"storePath": "/nix/store/" + KG_OPENSSL_BIN + "/bin/openssl"},
        ]},
        {"name": "sqlite", "cve": "CVE-2026-11822", "knownGood": [
            {"storePath": KG_SQLITE_OUT},
        ]},
    ])


def run_cli(lines, floor):
    """Run the checker over a synthetic store-paths file; return exit code."""
    with tempfile.NamedTemporaryFile("w", suffix=".paths", delete=False) as handle:
        handle.write("\n".join(lines) + "\n")
        paths_file = handle.name
    proc = subprocess.run(
        [sys.executable, str(CHECKER), "--store-paths", paths_file, "--floor", str(floor)],
        capture_output=True,
        text=True,
    )
    pathlib.Path(paths_file).unlink()
    return proc.returncode, proc.stdout, proc.stderr


class IdentityMatcherTests(unittest.TestCase):
    def setUp(self):
        self.floor_path = sample_allowlist()
        self.allowlist = cve.load_floor(self.floor_path)
        self.dep_re = cve.build_dep_re(self.allowlist)

    def tearDown(self):
        pathlib.Path(self.floor_path).unlink()

    def evaluate(self, component):
        return cve.evaluate_component(component, self.allowlist, self.dep_re)

    def test_known_good_identities_pass(self):
        # Including the patched-not-bumped openssl-3.6.2 and the bin output that
        # was given as a full /nix/store/.../bin/openssl path.
        for comp in (KG_OPENSSL_OUT, KG_OPENSSL_BIN, KG_SQLITE_OUT):
            self.assertIsNone(self.evaluate(comp), comp)

    def test_off_allowlist_fails_regardless_of_version(self):
        msg = self.evaluate(OFF_OPENSSL)
        self.assertIsNotNone(msg)
        self.assertIn("off-allowlist openssl", msg)
        # A stock-vulnerable lower version with an unknown identity also fails.
        self.assertIsNotNone(self.evaluate("ffffffffffffffffffffffffffffffff-openssl-3.6.0"))

    def test_non_crypto_paths_ignored(self):
        self.assertIsNone(self.evaluate("11111111111111111111111111111111-zlib-1.3.1"))

    def test_artifacts_are_skipped_not_flagged(self):
        for artifact in (
            "22222222222222222222222222222222-openssl-3.6.3.drv",
            "33333333333333333333333333333333-openssl-3.6.3.tar.gz",
            "44444444444444444444444444444444-openssl-3.6.3-bin.drv",
            "55555555555555555555555555555555-sqlite-src-3530200.zip",
            "66666666666666666666666666666666-openssl-disable-kernel-detection.patch",
        ):
            self.assertIsNone(self.evaluate(artifact), artifact)

    def test_normalize_store_component(self):
        self.assertEqual(
            cve.normalize_store_component("/nix/store/" + KG_OPENSSL_OUT + "/lib/x"),
            KG_OPENSSL_OUT,
        )
        self.assertEqual(cve.normalize_store_component("nohyphen"), "")
        self.assertEqual(cve.normalize_store_component(""), "")


class LoadErrorTests(unittest.TestCase):
    def expect_systemexit(self, deps):
        path = write_allowlist(deps)
        try:
            with self.assertRaises(SystemExit):
                cve.load_floor(path)
        finally:
            pathlib.Path(path).unlink()

    def test_empty_deps(self):
        self.expect_systemexit([])

    def test_legacy_min_version_rejected(self):
        path = write_allowlist([{"name": "openssl", "minVersion": "3.6.3"}])
        try:
            with self.assertRaises(SystemExit) as ctx:
                cve.load_floor(path)
            self.assertIn("generate-crypto-allowlist", str(ctx.exception))
        finally:
            pathlib.Path(path).unlink()

    def test_empty_known_good(self):
        self.expect_systemexit([{"name": "openssl", "knownGood": []}])

    def test_cross_dep_identity_rejected(self):
        self.expect_systemexit([
            {"name": "openssl", "knownGood": [{"storePath": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-sqlite-3.53.2"}]},
        ])

    def test_invalid_store_path(self):
        self.expect_systemexit([{"name": "openssl", "knownGood": [{"storePath": "openssl"}]}])


class CliExitCodeTests(unittest.TestCase):
    def setUp(self):
        self.floor_path = sample_allowlist()

    def tearDown(self):
        pathlib.Path(self.floor_path).unlink()

    def test_clean_closure_passes(self):
        rc, out, _ = run_cli([
            "/nix/store/" + KG_OPENSSL_OUT,
            "/nix/store/" + KG_OPENSSL_BIN,
            "/nix/store/" + KG_SQLITE_OUT,
            "/nix/store/77777777777777777777777777777777-openssl-3.6.3.tar.gz",  # artifact, skipped
        ], self.floor_path)
        self.assertEqual(rc, 0, out)
        self.assertIn("clean", out)

    def test_off_allowlist_openssl_fails(self):
        rc, _, err = run_cli(["/nix/store/" + OFF_OPENSSL], self.floor_path)
        self.assertEqual(rc, 1)
        self.assertIn("off-allowlist openssl", err)


class CommittedFloorTests(unittest.TestCase):
    """The committed allowlist must be well-formed (loadable, non-vacuous) so a
    malformed regenerate can't silently disable the gate."""

    def test_committed_floor_loads_with_known_good_identities(self):
        allowlist = cve.load_floor(str(COMMITTED_FLOOR))
        self.assertIn("openssl", allowlist)
        self.assertIn("sqlite", allowlist)
        self.assertTrue(allowlist["openssl"], "openssl allowlist must be non-empty")
        self.assertTrue(allowlist["sqlite"], "sqlite allowlist must be non-empty")
        # A committed openssl identity passes; a fabricated one default-denies.
        dep_re = cve.build_dep_re(allowlist)
        one_openssl = next(iter(allowlist["openssl"]))
        self.assertIsNone(cve.evaluate_component(one_openssl, allowlist, dep_re))
        self.assertIsNotNone(
            cve.evaluate_component("00000000000000000000000000000000-openssl-3.6.3", allowlist, dep_re)
        )


if __name__ == "__main__":
    unittest.main()
