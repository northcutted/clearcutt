#!/usr/bin/env python3
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


draft_agent = load_module("cve_draft_agent", ROOT / "scripts" / "cve-draft-agent.py")
broker = load_module("remediation_broker", ROOT / "scripts" / "remediation-broker.py")


class RemediationPipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = pathlib.Path(self.tmp.name)
        self.old_overlay_dir = draft_agent.OVERLAY_DIR
        self.old_patch_cache_path = draft_agent.PATCH_CACHE_PATH
        draft_agent.OVERLAY_DIR = str(self.tmp_path / "overlays" / "cve")
        draft_agent.PATCH_CACHE_PATH = str(self.tmp_path / "patch-cache.json")

    def tearDown(self):
        draft_agent.OVERLAY_DIR = self.old_overlay_dir
        draft_agent.PATCH_CACHE_PATH = self.old_patch_cache_path
        self.tmp.cleanup()

    def test_overlay_write_remove_uses_cve_then_package_identity(self):
        expr = 'zlib = prev.zlib.overrideAttrs (old: { version = "1.3.2"; });'
        path = draft_agent.write_cve_overlay("CVE-2026-12345", "zlib", expr)

        self.assertTrue(path.endswith("cve-2026-12345-zlib.nix"))
        self.assertTrue(os.path.exists(path))

        draft_agent.remove_cve_overlay("CVE-2026-12345", "zlib")
        self.assertFalse(os.path.exists(path))

    def test_postinstall_comment_remediation_recipe_is_rejected(self):
        recipe = {
            "route": "version_bump",
            "package_attribute": "zlib",
            "fixed_version": "1.3.2",
            "overlay_expression": (
                'zlib = prev.zlib.overrideAttrs (old: { '
                'postInstall = (old.postInstall or "") + "\\n# CVE-2026-12345 verified\\n"; '
                "});"
            ),
        }

        with self.assertRaisesRegex(ValueError, "postInstall"):
            draft_agent.validate_recipe(recipe, "zlib", "CVE-2026-12345")

    def test_recipe_can_target_nix_attribute_that_differs_from_scanned_package(self):
        recipe = {
            "route": "version_bump",
            "package_attribute": "python313",
            "fixed_version": "3.13.2",
            "overlay_expression": (
                'python313 = prev.python313.overrideAttrs (old: { version = "3.13.2"; });'
            ),
        }

        expr = draft_agent.validate_recipe(recipe, "python", "CVE-2026-12345")

        self.assertIn("python313 =", expr)

    def test_agent_nix_invocations_accept_repo_flake_cache_config(self):
        setup_action = (ROOT / ".github" / "actions" / "setup-nix" / "action.yml").read_text()
        release_workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()

        self.assertIn("--accept-flake-config", draft_agent.NIX_FLAKE_FLAGS)
        self.assertIn("accept-flake-config = true", setup_action)
        self.assertIn("https://nix-cache.clearcutt.dev", setup_action)
        self.assertIn("clearcutt-cache-1:0O2A23T11EBggh2Uz+LJcaRMBpuS9eUjeWmXKP0QoDE=", setup_action)
        self.assertIn("nix store sign --recursive --key-file secret-key.pem", release_workflow)
        self.assertIn('s3 rm "s3://clearcutt-nix-cache/${NARINFO_KEY}"', release_workflow)
        self.assertIn('s3 cp "s3://clearcutt-nix-cache/${NARINFO_KEY}" -', release_workflow)
        self.assertIn("purge_cache", release_workflow)
        self.assertIn("R2 origin narinfo is signed", release_workflow)
        self.assertIn("secret-key=$PWD/secret-key.pem", release_workflow)
        self.assertIn("^Sig: clearcutt-cache-1:", release_workflow)

    def test_broker_prioritizes_fixed_runtime_production_campaigns(self):
        vuln_dir = self.tmp_path / "vulnerabilities" / "v1.0.0"
        vuln_dir.mkdir(parents=True)
        finding = {
            "id": "CVE-2026-12345",
            "severity": "High",
            "packageName": "python",
            "packageVersion": "3.13.1",
            "layer": "runtime",
            "fixedIn": "3.13.2",
            "fixState": "fixed",
            "cvssScore": 8.1,
            "epssScore": 0.42,
            "riskScore": 17.5,
        }
        with open(vuln_dir / "python3.13-slim-amd64.json", "w", encoding="utf-8") as handle:
            json.dump({"findings": [finding]}, handle)
        with open(vuln_dir / "python3.13-dev-amd64.json", "w", encoding="utf-8") as handle:
            json.dump({"findings": [finding]}, handle)

        plan = broker.build_plan(str(vuln_dir))

        self.assertEqual(len(plan["campaigns"]), 1)
        campaign = plan["campaigns"][0]
        self.assertEqual(campaign["package"], "python")
        self.assertEqual(campaign["fixedVersion"], "3.13.2")
        self.assertEqual(campaign["productionTargetCount"], 1)
        self.assertEqual(campaign["affectedTargets"][0]["target"], "python3.13-slim")

    def test_broker_defers_dev_only_campaigns_by_default(self):
        vuln_dir = self.tmp_path / "vulnerabilities" / "v1.0.0"
        vuln_dir.mkdir(parents=True)
        finding = {
            "id": "CVE-2026-67890",
            "severity": "Critical",
            "packageName": "gradle",
            "packageVersion": "9.2.0",
            "layer": "runtime",
            "fixedIn": "9.3.0",
            "fixState": "fixed",
        }
        with open(vuln_dir / "java21-dev-amd64.json", "w", encoding="utf-8") as handle:
            json.dump({"findings": [finding]}, handle)

        default_plan = broker.build_plan(str(vuln_dir))
        opt_in_plan = broker.build_plan(str(vuln_dir), include_dev_only=True)

        self.assertEqual(default_plan["campaigns"], [])
        self.assertEqual(default_plan["summary"]["candidateCampaignCount"], 1)
        self.assertEqual(default_plan["summary"]["devOnlyCampaignCount"], 1)
        self.assertEqual(len(opt_in_plan["campaigns"]), 1)
        self.assertEqual(opt_in_plan["campaigns"][0]["package"], "gradle")

    def test_remediation_scan_mode_fails_closed_when_grype_missing(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")

        env = os.environ.copy()
        env["GRYPE_BIN"] = "/definitely/missing/grype"
        env["SCAN_MODE"] = "remediation"
        env["SBOM_CACHE_DIR"] = str(self.tmp_path / "missing-sboms")

        res = subprocess.run(
            [node, str(ROOT / "scripts" / "scan-vulnerabilities.mjs"), "--mode", "remediation"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(res.returncode, 0)
        self.assertIn("not on PATH", res.stderr)

    def test_python_generic_cpe_is_runtime_owned_in_python_images(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")

        sbom_dir = self.tmp_path / "sboms" / "v1.0.0"
        sbom_dir.mkdir(parents=True)
        (sbom_dir / "python3.13-slim-amd64.sbom.json").write_text("{}", encoding="utf-8")

        fake_grype = self.tmp_path / "fake-grype"
        fake_grype.write_text(
            """#!/usr/bin/env bash
if [[ "$1" == "version" ]]; then
  echo '{"version":"test-grype","db":{"built":"2026-05-28T00:00:00Z"}}'
  exit 0
fi
cat <<'JSON'
{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2026-6100",
        "severity": "Critical",
        "fix": {"state": "unknown", "versions": []},
        "namespace": "nvd:cpe",
        "description": "CPython runtime advisory"
      },
      "artifact": {
        "name": "python",
        "version": "3.13.13",
        "purl": "pkg:generic/python@3.13.13"
      }
    }
  ]
}
JSON
""",
            encoding="utf-8",
        )
        fake_grype.chmod(0o755)

        out_dir = self.tmp_path / "vulns"
        env = os.environ.copy()
        env["GRYPE_BIN"] = str(fake_grype)
        env["SCAN_MODE"] = "remediation"
        env["SBOM_CACHE_DIR"] = str(self.tmp_path / "sboms")
        env["VULN_DIR"] = str(out_dir)

        res = subprocess.run(
            [node, str(ROOT / "scripts" / "scan-vulnerabilities.mjs"), "--mode", "remediation"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )

        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads((out_dir / "v1.0.0" / "python3.13-slim-amd64.json").read_text())
        finding = data["findings"][0]
        self.assertEqual(finding["layer"], "runtime")
        self.assertEqual(finding["remediation"]["reason"], "no_fixed_version")
        self.assertEqual(finding["inclusion"]["category"], "primary_runtime")
        self.assertIn("Primary Python 3.13 runtime", finding["inclusion"]["summary"])

    def test_release_wording_matches_fixable_cve_policy(self):
        flake = (ROOT / "flake.nix").read_text()
        release_workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        latest_notes = (ROOT / "docs" / "releases" / "v0.11.1.md").read_text()

        self.assertNotIn("Zero-CVE", flake)
        self.assertNotIn("Zero-CVE", release_workflow)
        self.assertNotIn("Zero-CVE", latest_notes)
        self.assertIn("CVE-aware", flake)
        self.assertIn("no fixable Critical/High CVEs", release_workflow)
        self.assertIn("no fixable Critical/High CVEs", latest_notes)

    def test_catalog_verifier_fails_when_signature_is_inferred_from_provenance(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")

        catalog = self.tmp_path / "catalog"
        images = catalog / "images"
        images.mkdir(parents=True)
        index = {
            "latestTag": "v1.0.0",
            "images": [
                {
                    "id": "coreLTS-slim",
                    "latestTag": "v1.0.0",
                    "signed": True,
                    "provenance": True,
                    "evidence": {
                        "signature": False,
                        "provenance": True,
                        "sbom": True,
                        "tests": True,
                        "vulnerabilities": True,
                    },
                }
            ],
        }
        release = {
            "tag": "v1.0.0",
            "signature": None,
            "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
            "evidence": {
                "signature": False,
                "provenance": True,
                "sbom": True,
                "tests": True,
                "vulnerabilities": True,
                "archCount": 1,
                "sbomArchCount": 1,
                "testArchCount": 1,
                "passedTestArchCount": 1,
                "vulnerabilityArchCount": 1,
            },
            "architectures": [],
        }
        (catalog / "index.json").write_text(json.dumps(index), encoding="utf-8")
        (images / "coreLTS-slim.json").write_text(
            json.dumps({"releases": [release]}),
            encoding="utf-8",
        )

        env = os.environ.copy()
        env["CATALOG_DIR"] = str(catalog)
        res = subprocess.run(
            [node, str(ROOT / "scripts" / "verify-catalog-data.mjs")],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(res.returncode, 0)
        self.assertIn("index signed=true", res.stderr)

    def test_catalog_verifier_accepts_complete_latest_evidence(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")

        catalog = self.tmp_path / "catalog-ok"
        images = catalog / "images"
        images.mkdir(parents=True)
        evidence = {
            "signature": True,
            "provenance": True,
            "sbom": True,
            "tests": True,
            "vulnerabilities": True,
            "archCount": 1,
            "sbomArchCount": 1,
            "testArchCount": 1,
            "passedTestArchCount": 1,
            "vulnerabilityArchCount": 1,
        }
        index = {
            "latestTag": "v1.0.0",
            "images": [
                {
                    "id": "coreLTS-slim",
                    "latestTag": "v1.0.0",
                    "signed": True,
                    "provenance": True,
                    "evidence": evidence,
                }
            ],
        }
        release = {
            "tag": "v1.0.0",
            "signature": {"cosignBundlePresent": True},
            "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
            "evidence": evidence,
            "architectures": [],
        }
        (catalog / "index.json").write_text(json.dumps(index), encoding="utf-8")
        (images / "coreLTS-slim.json").write_text(
            json.dumps({"releases": [release]}),
            encoding="utf-8",
        )

        env = os.environ.copy()
        env["CATALOG_DIR"] = str(catalog)
        res = subprocess.run(
            [node, str(ROOT / "scripts" / "verify-catalog-data.mjs")],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )

        self.assertEqual(res.returncode, 0, res.stderr)


if __name__ == "__main__":
    unittest.main()
