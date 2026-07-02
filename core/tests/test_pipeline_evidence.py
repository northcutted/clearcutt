#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest


CORE_ROOT = pathlib.Path(__file__).resolve().parents[1]
PIPELINE = CORE_ROOT / "pipeline" / "pipeline.sh"
CREDENTIAL_BROKER = CORE_ROOT / "lib" / "credential-broker.sh"
BUILD_FLEET_NIX = CORE_ROOT / "lib" / "build-fleet.nix"
VERIFY_SH = CORE_ROOT / "tests" / "verify.sh"


class PipelineEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = pathlib.Path(self.tmp.name)
        self.bin_dir = self.tmp_path / "bin"
        self.bin_dir.mkdir()
        self.clearcutt_log = self.tmp_path / "clearcutt-invocations.log"
        self.write_fake_tools()

    def tearDown(self):
        self.tmp.cleanup()

    def write_executable(self, name, body):
        path = self.bin_dir / name
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        path.chmod(0o755)
        return path

    def write_fake_tools(self):
        self.write_executable(
            "nix",
            r"""
            #!/usr/bin/env bash
            set -euo pipefail
            out_link=""
            while [[ $# -gt 0 ]]; do
              if [[ "$1" == "--out-link" ]]; then
                out_link="$2"
                shift 2
              else
                shift
              fi
            done
            if [[ -z "$out_link" ]]; then
              echo "missing --out-link" >&2
              exit 2
            fi
            tmp_dir="$(mktemp -d)"
            tar -czf "$out_link" -C "$tmp_dir" .
            rm -rf "$tmp_dir"
            """,
        )
        self.write_executable(
            "syft",
            r"""
            #!/usr/bin/env bash
            set -euo pipefail
            printf '{"spdxVersion":"SPDX-2.3","packages":[]}\n'
            """,
        )
        self.write_executable(
            "grype",
            r"""
            #!/usr/bin/env bash
            set -euo pipefail
            printf '{"matches":[{"vulnerability":{"id":"CVE-2026-0001","severity":"High","fix":{"versions":["1.2.3"]}}}]}\n'
            exit "${FAKE_GRYPE_EXIT:-1}"
            """,
        )
        self.write_executable(
            "clearcutt",
            r"""
            #!/usr/bin/env bash
            set -euo pipefail
            if [[ -n "${FAKE_CLEARCUTT_LOG:-}" ]]; then
              printf '%s\n' "$*" >> "$FAKE_CLEARCUTT_LOG"
            fi
            exit "${FAKE_CLEARCUTT_EXIT:-0}"
            """,
        )

    def run_pipeline(self, target, *args, extra_env=None):
        env = os.environ.copy()
        env.update({
            "PATH": f"{self.bin_dir}{os.pathsep}{env.get('PATH', '')}",
            "CLEARCUTT_SKIP_NIX_ENV_LOAD": "true",
            "FAKE_GRYPE_EXIT": "1",
            "FAKE_CLEARCUTT_LOG": str(self.clearcutt_log),
        })
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [
                str(PIPELINE),
                "--system",
                "x86_64-linux",
                "--skip-local-signing",
                *args,
                target,
            ],
            cwd=self.tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

    def read_result(self, target):
        path = self.tmp_path / "build-outputs" / f"{target}.test-results.json"
        self.assertTrue(path.exists(), f"missing test results predicate at {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def assert_scan_evidence(self, target):
        scan_path = self.tmp_path / "build-outputs" / f"{target}.grype.json"
        self.assertTrue(scan_path.exists(), f"missing raw Grype evidence at {scan_path}")
        scan = json.loads(scan_path.read_text(encoding="utf-8"))
        self.assertEqual(scan["matches"][0]["vulnerability"]["id"], "CVE-2026-0001")

    def clearcutt_invocations(self):
        if not self.clearcutt_log.exists():
            return ""
        return self.clearcutt_log.read_text(encoding="utf-8")

    def test_runtime_slim_grype_failure_writes_failed_predicate_and_scan(self):
        result = self.run_pipeline("coreLTS-slim")

        self.assertNotEqual(result.returncode, 0, result.stderr + result.stdout)
        evidence = self.read_result("coreLTS-slim")
        self.assertEqual(evidence["status"], "failed")
        self.assertTrue(evidence["policy"]["blocking"])
        self.assertEqual(evidence["assertions"][2]["status"], "failed")
        invocations = self.clearcutt_invocations()
        self.assertIn("verify runtime-cve", invocations)
        self.assertNotIn("closure-cve-check.py", PIPELINE.read_text(encoding="utf-8"))
        self.assert_scan_evidence("coreLTS-slim")

    def test_runtime_dev_grype_failure_records_warning(self):
        result = self.run_pipeline("coreLTS-dev")

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        evidence = self.read_result("coreLTS-dev")
        self.assertEqual(evidence["status"], "warning")
        self.assertFalse(evidence["policy"]["blocking"])
        self.assertEqual(evidence["assertions"][2]["status"], "warning")
        self.assert_scan_evidence("coreLTS-dev")

    def test_runtime_distroless_uses_clearcutt_boundary_gates(self):
        result = self.run_pipeline("coreLTS-distroless")

        self.assertNotEqual(result.returncode, 0, result.stderr + result.stdout)
        evidence = self.read_result("coreLTS-distroless")
        self.assertEqual(evidence["status"], "failed")
        self.assertTrue(evidence["closurePurity"])
        self.assertTrue(evidence["runtimePatchComplete"])
        invocations = self.clearcutt_invocations()
        self.assertIn("verify closure-purity", invocations)
        self.assertIn("verify runtime-cve", invocations)

    def test_pipeline_boundary_gates_are_cli_owned(self):
        source = PIPELINE.read_text(encoding="utf-8")

        self.assertIn("run_clearcutt_verify_gate closure-purity", source)
        self.assertIn("run_clearcutt_verify_gate runtime-cve", source)
        self.assertNotIn("python3 \"$pipeline_dir/../tests/closure-purity-check.py\"", source)
        self.assertNotIn("python3 \"$pipeline_dir/../tests/closure-cve-check.py\"", source)

    def test_preview_service_grype_failure_records_warning(self):
        result = self.run_pipeline("postgres16", "--kind", "service")

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        evidence = self.read_result("postgres16")
        self.assertEqual(evidence["status"], "warning")
        self.assertFalse(evidence["policy"]["blocking"])
        self.assertEqual(evidence["policy"]["lifecycleStatus"], "preview")
        self.assertEqual(evidence["assertions"][2]["status"], "warning")
        self.assert_scan_evidence("postgres16")

    def test_active_production_service_grype_failure_records_failure(self):
        result = self.run_pipeline(
            "postgres16",
            "--kind",
            "service",
            extra_env={
                "CLEARCUTT_SERVICE_PRODUCTION_ALLOWED": "true",
                "CLEARCUTT_SERVICE_LIFECYCLE_STATUS": "active",
            },
        )

        self.assertNotEqual(result.returncode, 0, result.stderr + result.stdout)
        evidence = self.read_result("postgres16")
        self.assertEqual(evidence["status"], "failed")
        self.assertTrue(evidence["policy"]["blocking"])
        self.assertTrue(evidence["policy"]["productionAllowed"])
        self.assertEqual(evidence["policy"]["lifecycleStatus"], "active")
        self.assertEqual(evidence["assertions"][2]["status"], "failed")
        self.assert_scan_evidence("postgres16")


class CredentialBrokerTests(unittest.TestCase):
    def broker_env(self):
        env = os.environ.copy()
        env.update({
            "ENTERPRISE_MIRROR_URL": "https://mirror.example.internal/repository/npm-group",
            "ENTERPRISE_MIRROR_USER": "clearcutt",
            "ENTERPRISE_MIRROR_TOKEN": "test-token",
        })
        return env

    def run_broker_shell(self, script):
        with tempfile.TemporaryDirectory() as tmp:
            return subprocess.run(
                ["bash", "-c", textwrap.dedent(script), "bash", str(CREDENTIAL_BROKER)],
                cwd=tmp,
                env=self.broker_env(),
                capture_output=True,
                text=True,
            )

    def test_sourcing_broker_does_not_install_exit_trap(self):
        result = self.run_broker_shell(
            r"""
            set -euo pipefail
            source "$1" >/dev/null
            trap -p EXIT
            test -d .nix-enterprise-auth-cache
            cleanup_credential_broker >/dev/null
            """
        )

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(result.stdout.strip(), "")

    def test_broker_trap_install_is_explicit(self):
        result = self.run_broker_shell(
            r"""
            set -euo pipefail
            source "$1" >/dev/null
            install_credential_broker_trap
            trap -p EXIT
            """
        )

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("__clearcutt_run_chained_trap", result.stdout)

    def test_broker_trap_chains_existing_exit_handler(self):
        result = self.run_broker_shell(
            r"""
            set -euo pipefail
            marker="$PWD/marker.txt"
            (
              set -euo pipefail
              trap 'echo previous-exit > "$marker"' EXIT
              source "$1" >/dev/null
              install_credential_broker_trap
            ) >/dev/null
            test "$(cat "$marker")" = "previous-exit"
            test ! -d .nix-enterprise-auth-cache
            """
        )

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)


class DockerToolsAssemblyTests(unittest.TestCase):
    def test_rootless_ownership_uses_fakeroot_commands(self):
        source = BUILD_FLEET_NIX.read_text(encoding="utf-8")
        base_contents = source.split("baseContents = [", 1)[1].split("];", 1)[0]

        self.assertNotIn("cc-app-dir", source)
        self.assertNotIn("appDir", base_contents)
        self.assertRegex(
            source,
            r"prepareAppWorkspace = ''\n"
            r"\s+mkdir -p app\n"
            r"\s+chmod 0755 app\n"
            r"\s+'';",
        )
        self.assertRegex(
            source,
            r"ownAppWorkspace = ''\n"
            r"\s+chown \$\{uid\}:\$\{gid\} app\n"
            r"\s+'';",
        )
        self.assertEqual(source.count("fakeRootCommands"), 2)
        self.assertIn("fakeRootCommands = ownAppWorkspace;", source)
        self.assertIn("${ownDataDirs dataDirs}", source)


class GatingSuiteTests(unittest.TestCase):
    def test_g4_smoke_targets_resolve_fleet_config_from_core_cwd(self):
        source = VERIFY_SH.read_text(encoding="utf-8")

        self.assertIn("find_fleet_config()", source)
        self.assertIn('"../clearcutt.fleet.yaml"', source)
        self.assertIn('--fleet-config "$fleet_config"', source)
        self.assertIn('fleet_config="$(find_fleet_config || true)"', source)


if __name__ == "__main__":
    unittest.main()
