package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
)

func TestWorkflowDefaultExpressionValue(t *testing.T) {
	root := t.TempDir()
	workflow := ".github/workflows/release.yml"
	path := filepath.Join(root, workflow)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "version: ${{ vars.CLEARCUTT_CLI_VERSION || 'v9.9.9' }}\nempty: ${{ vars.EMPTY_VAR || '' }}\nbroken: ${{ vars.BROKEN || 'unterminated\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := workflowDefaultExpressionValue(root, workflow, "vars.CLEARCUTT_CLI_VERSION", "fallback"); got != "v9.9.9" {
		t.Fatalf("expected parsed default v9.9.9, got %q", got)
	}
	if got := workflowDefaultExpressionValue(root, workflow, "vars.MISSING", "fallback"); got != "fallback" {
		t.Fatalf("missing var should fall back, got %q", got)
	}
	if got := workflowDefaultExpressionValue(root, workflow, "vars.EMPTY_VAR", "fallback"); got != "fallback" {
		t.Fatalf("empty default should fall back, got %q", got)
	}
	if got := workflowDefaultExpressionValue(root, "missing.yml", "vars.X", "fallback"); got != "fallback" {
		t.Fatalf("missing workflow file should fall back, got %q", got)
	}
}

func TestRemediationPolicyFromJSON(t *testing.T) {
	if got := remediationPolicyFromJSON(""); got.MinimumSeverity != fleet.DefaultRemediationPolicy().MinimumSeverity {
		t.Fatalf("empty JSON should return the default policy, got %#v", got)
	}
	if got := remediationPolicyFromJSON("null"); got.MinimumSeverity != fleet.DefaultRemediationPolicy().MinimumSeverity {
		t.Fatalf("null JSON should return the default policy, got %#v", got)
	}
	if got := remediationPolicyFromJSON("{invalid"); got.MinimumSeverity != fleet.DefaultRemediationPolicy().MinimumSeverity {
		t.Fatalf("invalid JSON should return the default policy, got %#v", got)
	}
	got := remediationPolicyFromJSON(`{"minimumSeverity":"critical"}`)
	if got.MinimumSeverity != "critical" {
		t.Fatalf("explicit policy JSON should win, got %#v", got)
	}
}

func TestPlatformRegistryEnvCommand(t *testing.T) {
	dir := t.TempDir()
	cfg := fleet.DefaultConfig("acme", "fleet")
	cfg.Registry.Host = "registry.example.com"
	writeFleetConfigStruct(t, filepath.Join(dir, "clearcutt.fleet.yaml"), cfg)

	t.Setenv("CLEARCUTT_REGISTRY_USER", "svc-publisher")
	githubOutput := filepath.Join(dir, "github-output.txt")
	stdout, err := runCLI(t,
		"platform", "registry-env",
		"--fleet-config", filepath.Join(dir, "clearcutt.fleet.yaml"),
		"--github-output", githubOutput,
	)
	if err != nil {
		t.Fatalf("platform registry-env failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "registry.example.com") || !strings.Contains(stdout, "generic-token") {
		t.Fatalf("table output missing host/auth mode:\n%s", stdout)
	}
	raw, err := os.ReadFile(githubOutput)
	if err != nil {
		t.Fatalf("read github output: %v", err)
	}
	for _, want := range []string{"auth_mode=generic-token", "host=registry.example.com", "username=svc-publisher"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("github output missing %q:\n%s", want, raw)
		}
	}

	stdout, err = runCLI(t, "--format", "json", "platform", "registry-env", "--fleet-config", filepath.Join(dir, "clearcutt.fleet.yaml"))
	if err != nil {
		t.Fatalf("registry-env json failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, `"authMode"`) {
		t.Fatalf("json output missing authMode:\n%s", stdout)
	}
}

func TestCatalogWorkflowParamsCommand(t *testing.T) {
	dir := t.TempDir()
	configPath := writeFleetConfig(t, dir)

	oldOpts := catalogWorkflowOpts
	t.Cleanup(func() { catalogWorkflowOpts = oldOpts })

	githubOutput := filepath.Join(dir, "github-output.txt")
	stdout, err := runCLI(t,
		"catalog", "workflow-params",
		"--fleet-config", configPath,
		"--release-limit", "7",
		"--github-output", githubOutput,
	)
	if err != nil {
		t.Fatalf("catalog workflow-params failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "releaseLimit") || !strings.Contains(stdout, "7") {
		t.Fatalf("table output missing overridden release limit:\n%s", stdout)
	}
	raw, err := os.ReadFile(githubOutput)
	if err != nil {
		t.Fatalf("read github output: %v", err)
	}
	for _, want := range []string{"limit=7", "scan_depth="} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("github output missing %q:\n%s", want, raw)
		}
	}

	stdout, err = runCLI(t, "--format", "json", "catalog", "workflow-params", "--fleet-config", configPath)
	if err != nil {
		t.Fatalf("workflow-params json failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, `"releaseLimit"`) {
		t.Fatalf("json output missing releaseLimit:\n%s", stdout)
	}

	if _, err := runCLI(t, "catalog", "workflow-params", "--fleet-config", configPath, "--release-limit", "zero"); err == nil {
		t.Fatal("non-integer release limit should error")
	}
}

func TestCatalogVexAllCommand(t *testing.T) {
	oldOpts := catalogWorkflowOpts
	t.Cleanup(func() { catalogWorkflowOpts = oldOpts })

	outputDir := filepath.Join(t.TempDir(), "vex")
	stdout, err := runCLI(t,
		"--catalog", fixtureCatalog(),
		"catalog", "vex-all",
		"--output-dir", outputDir,
	)
	if err != nil {
		t.Fatalf("catalog vex-all failed: %v\n%s", err, stdout)
	}
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("read vex output dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one OpenVEX document for the fixture catalog")
	}
	if !strings.Contains(stdout, "images") {
		t.Fatalf("table output missing image count:\n%s", stdout)
	}

	if _, err := runCLI(t, "--catalog", fixtureCatalog(), "catalog", "vex-all", "--output-dir", ""); err == nil {
		t.Fatal("empty --output-dir should error")
	}
}

func TestPlatformStatusTableOutput(t *testing.T) {
	dir := t.TempDir()
	writeFleetConfig(t, dir)
	writePlatformStatusFixture(t, dir, "ghcr.io/acme/platform/clearcutt-*")

	stdout, err := runCLI(t, "platform", "status", "--output", dir)
	if err != nil {
		t.Fatalf("platform status table failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "CHECK") || !strings.Contains(stdout, "STATUS") {
		t.Fatalf("expected table-rendered status output:\n%s", stdout)
	}
}
