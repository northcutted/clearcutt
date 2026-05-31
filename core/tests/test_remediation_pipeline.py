#!/usr/bin/env python3
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


CORE_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = CORE_ROOT.parent


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


draft_agent = load_module("cve_draft_agent", CORE_ROOT / "scripts" / "cve-draft-agent.py")
broker = load_module("remediation_broker", CORE_ROOT / "scripts" / "remediation-broker.py")


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

    def test_phase_hook_remediation_recipe_is_rejected(self):
        recipe = {
            "route": "fetchpatch",
            "package_attribute": "openssl",
            "patch_url": "https://github.com/openssl/openssl/commit/abc.patch",
            "overlay_expression": (
                'openssl = prev.openssl.overrideAttrs (old: { '
                'postPatch = (old.postPatch or "") + "\\ntrue\\n"; '
                "});"
            ),
        }

        with self.assertRaisesRegex(ValueError, "postPatch"):
            draft_agent.validate_recipe(recipe, "openssl", "CVE-2026-12345")

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

    def test_deterministic_resolver_uses_explicit_source_evidence(self):
        campaign = {
            "package": "zlib",
            "cve": "CVE-2026-12345",
            "fixedVersion": "1.3.2",
            "remediationEvidence": {
                "package_attribute": "zlib",
                "source_url": "https://zlib.net/zlib-1.3.2.tar.gz",
                "sha256": "sha256-deadbeef",
            },
        }

        recipe = draft_agent.resolve_deterministic_recipe(
            campaign,
            "zlib",
            "CVE-2026-12345",
            "1.3.2",
            env={},
            evidence_entries=[],
        )

        self.assertIsNotNone(recipe)
        self.assertEqual(recipe["route"], "version_bump")
        self.assertEqual(recipe["fixed_version"], "1.3.2")
        self.assertIn("zlib = prev.zlib.overrideAttrs", recipe["overlay_expression"])
        self.assertIn("sha256-deadbeef", recipe["overlay_expression"])

    def test_deterministic_resolver_uses_explicit_patch_evidence(self):
        campaign = {
            "package": "openssl",
            "cve": "CVE-2026-12345",
            "fixedVersion": "3.4.1",
            "remediationEvidence": {
                "patch_url": "https://github.com/openssl/openssl/commit/abc.patch",
                "patch_sha256": "sha256-feedface",
            },
        }

        recipe = draft_agent.resolve_deterministic_recipe(
            campaign,
            "openssl",
            "CVE-2026-12345",
            "3.4.1",
            env={},
            evidence_entries=[],
        )

        self.assertIsNotNone(recipe)
        self.assertEqual(recipe["route"], "fetchpatch")
        self.assertIn("prev.fetchpatch", recipe["overlay_expression"])
        self.assertIn("sha256-feedface", recipe["overlay_expression"])

    def test_deterministic_resolver_uses_external_evidence_provider(self):
        campaign = {
            "package": "zlib",
            "cve": "CVE-2026-12345",
            "installedVersion": "1.3.1",
            "fixedVersion": "1.3.2",
        }

        recipe = draft_agent.resolve_deterministic_recipe(
            campaign,
            "zlib",
            "CVE-2026-12345",
            "1.3.2",
            env={},
            evidence_entries=[
                {
                    "package": "zlib",
                    "cve": "CVE-2026-12345",
                    "installedVersion": "1.3.1",
                    "fixedVersion": "1.3.2",
                    "packageAttribute": "zlib",
                    "sourceUrl": "https://zlib.net/zlib-1.3.2.tar.gz",
                    "sourceSha256": "sha256-provider",
                }
            ],
        )

        self.assertIsNotNone(recipe)
        self.assertEqual(recipe["route"], "version_bump")
        self.assertIn("sha256-provider", recipe["overlay_expression"])

    def test_deterministic_resolver_refuses_scanner_fixed_version_alone(self):
        campaign = {
            "package": "gradle",
            "cve": "CVE-2026-22816",
            "installedVersion": "8.14.4",
            "fixedVersion": "9.3.0",
        }

        recipe = draft_agent.resolve_deterministic_recipe(
            campaign,
            "gradle",
            "CVE-2026-22816",
            "9.3.0",
            env={},
            evidence_entries=[],
        )

        self.assertIsNone(recipe)

    def test_package_name_matching_avoids_substring_false_positives(self):
        self.assertTrue(draft_agent.package_name_matches("openssl", {"openssl", ""}))
        self.assertTrue(draft_agent.package_name_matches("openssl", {"openssl-3.4.1", ""}))
        self.assertFalse(draft_agent.package_name_matches("ssl", {"openssl", ""}))
        self.assertFalse(draft_agent.package_name_matches("ssl", {"ssl-cert", ""}))

    def test_verify_remediation_removed_requires_at_least_one_passed_scan(self):
        old_scan = draft_agent.scan_artifact_for_finding
        try:
            draft_agent.scan_artifact_for_finding = lambda artifact, cve, package: {
                "target": artifact["target"],
                "status": "skipped",
                "reason": "native target has no OCI archive",
                "remainingFindings": [],
            }
            ok, validation = draft_agent.verify_remediation_removed(
                [{"target": "java21-native"}],
                "CVE-2026-12345",
                "zlib",
            )
            self.assertFalse(ok)
            self.assertEqual(validation[0]["status"], "skipped")

            draft_agent.scan_artifact_for_finding = lambda artifact, cve, package: {
                "target": artifact["target"],
                "status": "passed",
                "reason": "original CVE/package pair removed",
                "remainingFindings": [],
            }
            ok, _ = draft_agent.verify_remediation_removed(
                [{"target": "java21-slim", "tarPath": "unused"}],
                "CVE-2026-12345",
                "zlib",
            )
            self.assertTrue(ok)
        finally:
            draft_agent.scan_artifact_for_finding = old_scan

    def test_agent_sandbox_uses_ephemeral_home(self):
        res = subprocess.run(
            ["./scripts/agent-sandbox.sh", "bash", "-lc", 'printf "%s" "$HOME"'],
            cwd=CORE_ROOT,
            capture_output=True,
            text=True,
        )

        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotEqual(res.stdout, os.environ.get("HOME", ""))
        self.assertIn("clearcutt-agent-home", res.stdout)

    def test_agent_nix_invocations_accept_repo_flake_cache_config(self):
        setup_action = (REPO_ROOT / ".github" / "actions" / "setup-nix" / "action.yml").read_text()
        release_workflow = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text()
        scheduled_scan = (REPO_ROOT / ".github" / "workflows" / "scheduled-scan.yml").read_text()
        patch_agent = (REPO_ROOT / ".github" / "workflows" / "cve-patch-agent.yml").read_text()

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
        self.assertIn("OPENROUTER_FREE_MODEL: \"openrouter/free\"", scheduled_scan)
        self.assertIn("OPENROUTER_PAID_MODEL: \"openrouter/free\"", scheduled_scan)
        self.assertIn("OPENROUTER_FALLBACK_MODEL: \"openrouter/free\"", scheduled_scan)
        self.assertIn("OPENROUTER_FREE_MODEL: \"openrouter/free\"", patch_agent)
        self.assertIn("OPENROUTER_PAID_MODEL: \"openrouter/free\"", patch_agent)
        self.assertIn("OPENROUTER_FALLBACK_MODEL: \"openrouter/free\"", patch_agent)

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

    def test_auto_patch_dispatcher_forwards_explicit_vuln_root_from_core_cwd(self):
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

        env = os.environ.copy()
        env["VULN_ROOT"] = str(self.tmp_path / "vulnerabilities")
        env["MAX_FINDINGS_PER_RUN"] = "1"
        env["MAX_PATCH_FAILURES_PER_RUN"] = "1"
        env.pop("INCLUDE_DEV_ONLY_REMEDIATION", None)

        res = subprocess.run(
            [str(CORE_ROOT / "scripts" / "auto-patch-triage.py")],
            cwd=CORE_ROOT,
            env=env,
            capture_output=True,
            text=True,
        )

        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("source=", res.stdout)
        self.assertIn(str(vuln_dir), res.stdout)
        self.assertIn("dev-tier-only", res.stdout)

    def test_remediation_scan_mode_fails_closed_when_grype_missing(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")

        env = os.environ.copy()
        env["GRYPE_BIN"] = "/definitely/missing/grype"
        env["SCAN_MODE"] = "remediation"
        env["SBOM_CACHE_DIR"] = str(self.tmp_path / "missing-sboms")

        res = subprocess.run(
            [node, str(CORE_ROOT / "scripts" / "scan-vulnerabilities.mjs"), "--mode", "remediation"],
            cwd=CORE_ROOT,
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
            [node, str(CORE_ROOT / "scripts" / "scan-vulnerabilities.mjs"), "--mode", "remediation"],
            cwd=CORE_ROOT,
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
        flake = (CORE_ROOT / "flake.nix").read_text()
        release_workflow = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text()
        latest_notes = (REPO_ROOT / "docs" / "releases" / "v0.11.1.md").read_text()

        self.assertNotIn("Zero-CVE", flake)
        self.assertNotIn("Zero-CVE", release_workflow)
        self.assertNotIn("Zero-CVE", latest_notes)
        self.assertIn("CVE-aware", flake)
        self.assertIn("no fixable Critical/High CVEs", release_workflow)
        self.assertIn("no fixable Critical/High CVEs", latest_notes)

    def test_release_evidence_verifier_discards_large_attestation_stdout(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")

        bin_dir = self.tmp_path / "bin"
        bin_dir.mkdir()

        fake_cosign = bin_dir / "cosign"
        fake_cosign.write_text(
            """#!/usr/bin/env python3
import sys

if "verify-attestation" in sys.argv and "spdxjson" in sys.argv:
    chunk = b"x" * 262144
    for _ in range(8):
        sys.stdout.buffer.write(chunk)
else:
    print("ok")
""",
            encoding="utf-8",
        )
        fake_cosign.chmod(0o755)

        for name, body in {
            "crane": 'print("sha256:abc123")\n',
            "slsa-verifier": 'print("ok")\n',
            "gh": 'print("ok")\n',
        }.items():
            fake_tool = bin_dir / name
            fake_tool.write_text(f"#!/usr/bin/env python3\n{body}", encoding="utf-8")
            fake_tool.chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
        env["EVIDENCE_COMMAND_MAX_BUFFER_BYTES"] = str(1024 * 1024)

        res = subprocess.run(
            [
                node,
                str(CORE_ROOT / "scripts" / "verify-release-evidence.mjs"),
                "--ref",
                "ghcr.io/example/clearcutt-dotnet8:v1-dev",
                "--digest",
                "sha256:abc123",
                "--repo",
                "example/clearcutt",
                "--workflow-identity",
                "https://github.com/example/clearcutt/.github/workflows/release.yml@refs/heads/main",
                "--source-ref",
                "refs/heads/main",
                "--source-branch",
                "main",
            ],
            cwd=CORE_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )

        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("[evidence] ok: SPDX SBOM attestation", res.stdout)
        self.assertIn("[evidence] complete: ghcr.io/example/clearcutt-dotnet8@sha256:abc123", res.stdout)
        self.assertLess(len(res.stdout), 5000)

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
                    "lifecycle": {
                        "status": "active",
                        "support": "lts",
                        "productionAllowed": True,
                    },
                    "runtimeContract": {
                        "shellPresent": True,
                        "packageManagerPresent": False,
                        "productionTier": True,
                    },
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
            "lifecycle": {
                "status": "active",
                "support": "lts",
                "productionAllowed": True,
            },
            "runtimeContract": {
                "shellPresent": True,
                "packageManagerPresent": False,
                "productionTier": True,
            },
            "exceptions": {
                "total": 0,
                "expired": 0,
                "active": 0,
                "acceptedRisk": 0,
                "noFixAvailable": 0,
                "falsePositive": 0,
                "inheritedFromBase": 0,
            },
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
            json.dumps({
                "id": "coreLTS-slim",
                "lifecycle": release["lifecycle"],
                "runtimeContract": release["runtimeContract"],
                "releases": [release],
            }),
            encoding="utf-8",
        )

        env = os.environ.copy()
        env["CATALOG_DIR"] = str(catalog)
        res = subprocess.run(
            [node, str(CORE_ROOT / "scripts" / "verify-catalog-data.mjs")],
            cwd=CORE_ROOT,
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
                    "lifecycle": {
                        "status": "active",
                        "support": "lts",
                        "productionAllowed": True,
                    },
                    "runtimeContract": {
                        "shellPresent": True,
                        "packageManagerPresent": False,
                        "productionTier": True,
                    },
                    "evidence": evidence,
                }
            ],
        }
        release = {
            "tag": "v1.0.0",
            "signature": {"cosignBundlePresent": True},
            "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
            "lifecycle": {
                "status": "active",
                "support": "lts",
                "productionAllowed": True,
            },
            "runtimeContract": {
                "shellPresent": True,
                "packageManagerPresent": False,
                "productionTier": True,
            },
            "exceptions": {
                "total": 0,
                "expired": 0,
                "active": 0,
                "acceptedRisk": 0,
                "noFixAvailable": 0,
                "falsePositive": 0,
                "inheritedFromBase": 0,
            },
            "evidence": evidence,
            "architectures": [],
        }
        (catalog / "index.json").write_text(json.dumps(index), encoding="utf-8")
        (images / "coreLTS-slim.json").write_text(
            json.dumps({
                "id": "coreLTS-slim",
                "lifecycle": release["lifecycle"],
                "runtimeContract": release["runtimeContract"],
                "releases": [release],
            }),
            encoding="utf-8",
        )

        env = os.environ.copy()
        env["CATALOG_DIR"] = str(catalog)
        res = subprocess.run(
            [node, str(CORE_ROOT / "scripts" / "verify-catalog-data.mjs")],
            cwd=CORE_ROOT,
            env=env,
            capture_output=True,
            text=True,
        )

        self.assertEqual(res.returncode, 0, res.stderr)


if __name__ == "__main__":
    unittest.main()
