package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRemediationScan(t *testing.T, root, version, file string, findings []map[string]any) string {
	t.Helper()
	dir := filepath.Join(root, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, file)
	payload := map[string]any{"findings": findings}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRemediationPlanProductionOnlyDefault(t *testing.T) {
	root := t.TempDir()
	prodFix := map[string]any{
		"id":             "CVE-2026-12345",
		"severity":       "High",
		"packageName":    "python",
		"packageVersion": "3.13.1",
		"layer":          "runtime",
		"fixedIn":        "3.13.2",
		"fixState":       "fixed",
	}
	devFix := map[string]any{
		"id":             "CVE-2026-67890",
		"severity":       "Critical",
		"packageName":    "gradle",
		"packageVersion": "9.2.0",
		"layer":          "runtime",
		"fixedIn":        "9.3.0",
		"fixState":       "fixed",
	}
	writeRemediationScan(t, root, "v1.0.0", "python3.13-slim-amd64.json", []map[string]any{prodFix})
	writeRemediationScan(t, root, "v1.0.0", "java21-dev-amd64.json", []map[string]any{devFix})

	stdout, err := runCLI(t, "--format", "json", "remediation", "plan", "--vuln-root", root)
	if err != nil {
		t.Fatalf("remediation plan failed: %v\n%s", err, stdout)
	}

	var plan RemediationPlan
	if err := json.Unmarshal([]byte(stdout), &plan); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if plan.Summary.CampaignCount != 1 {
		t.Fatalf("expected one selected production campaign, got %+v", plan.Summary)
	}
	if plan.Summary.CandidateCampaignCount != 2 || plan.Summary.DevOnlyCampaignCount != 1 {
		t.Fatalf("unexpected candidate/dev summary: %+v", plan.Summary)
	}
	if plan.Campaigns[0].Package != "python" || plan.Campaigns[0].ProductionTargetCount != 1 {
		t.Fatalf("unexpected campaign: %+v", plan.Campaigns[0])
	}
}

func TestRemediationPlanIncludesDevOnlyWhenRequested(t *testing.T) {
	root := t.TempDir()
	devFix := map[string]any{
		"id":             "CVE-2026-67890",
		"severity":       "Critical",
		"packageName":    "gradle",
		"packageVersion": "9.2.0",
		"layer":          "runtime",
		"fixedIn":        "9.3.0",
		"fixState":       "fixed",
	}
	writeRemediationScan(t, root, "v1.0.0", "java21-dev-amd64.json", []map[string]any{devFix})

	stdout, err := runCLI(t, "--format", "json", "remediation", "plan", "--vuln-root", root, "--include-dev-only")
	if err != nil {
		t.Fatalf("remediation plan failed: %v\n%s", err, stdout)
	}

	var plan RemediationPlan
	if err := json.Unmarshal([]byte(stdout), &plan); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if plan.Summary.CampaignCount != 1 || !plan.Summary.IncludeDevOnly {
		t.Fatalf("unexpected summary: %+v", plan.Summary)
	}
	if plan.Campaigns[0].Package != "gradle" || plan.Campaigns[0].ProductionTargetCount != 0 {
		t.Fatalf("unexpected dev campaign: %+v", plan.Campaigns[0])
	}
}

func TestRemediationPlanTableOutput(t *testing.T) {
	root := t.TempDir()
	devFix := map[string]any{
		"id":             "CVE-2026-67890",
		"severity":       "Critical",
		"packageName":    "gradle",
		"packageVersion": "9.2.0",
		"layer":          "runtime",
		"fixedIn":        "9.3.0",
		"fixState":       "fixed",
	}
	writeRemediationScan(t, root, "v1.0.0", "java21-dev-amd64.json", []map[string]any{devFix})

	stdout, err := runCLI(t, "remediation", "plan", "--vuln-root", root, "--include-dev-only")
	if err != nil {
		t.Fatalf("remediation plan failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "Remediation Plan") || !strings.Contains(stdout, "gradle") {
		t.Fatalf("unexpected table output:\n%s", stdout)
	}
}

// The auto-patch dispatcher invokes `clearcutt remediation plan` and trusts it
// to select the same "latest" scan directory the scanner most recently wrote.
// A non-numeric patch segment (v1.2.x) must therefore not be ranked above a
// clean release (v1.0.0), or the dispatcher would plan against stale findings.
func TestRemediationPlanSelectsLatestVersionDir(t *testing.T) {
	root := t.TempDir()
	finding := map[string]any{
		"id":             "CVE-2026-67890",
		"severity":       "Critical",
		"packageName":    "gradle",
		"packageVersion": "9.2.0",
		"layer":          "runtime",
		"fixedIn":        "9.3.0",
		"fixState":       "fixed",
		"riskScore":      12.5,
		"epssScore":      0.25,
	}
	writeRemediationScan(t, root, "v1.2.x", "ignored-dev-amd64.json", []map[string]any{finding})
	latest := writeRemediationScan(t, root, "v1.0.0", "java21-dev-amd64.json", []map[string]any{finding})

	stdout, err := runCLI(t, "--format", "json", "remediation", "plan", "--vuln-root", root, "--include-dev-only")
	if err != nil {
		t.Fatalf("remediation plan failed: %v\n%s", err, stdout)
	}
	var plan RemediationPlan
	if err := json.Unmarshal([]byte(stdout), &plan); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}

	if plan.SourceDir != latest {
		t.Fatalf("expected latest dir %s, got %s", latest, plan.SourceDir)
	}
	if len(plan.Campaigns) != 1 {
		t.Fatalf("expected one campaign, got %d: %+v", len(plan.Campaigns), plan.Summary)
	}
	c := plan.Campaigns[0]
	if c.Package != "gradle" || c.CVE != "CVE-2026-67890" || c.FixedVersion != "9.3.0" || c.TargetCount != 1 {
		t.Fatalf("unexpected campaign: %+v", c)
	}
}

func TestRemediationRunDefersDevOnlyCampaignsWithoutAgent(t *testing.T) {
	root := t.TempDir()
	coreDir := t.TempDir()
	finding := map[string]any{
		"id":             "CVE-2026-67890",
		"severity":       "Critical",
		"packageName":    "gradle",
		"packageVersion": "9.2.0",
		"layer":          "runtime",
		"fixedIn":        "9.3.0",
		"fixState":       "fixed",
	}
	latest := writeRemediationScan(t, root, "v1.0.0", "java21-dev-amd64.json", []map[string]any{finding})
	planPath := filepath.Join(t.TempDir(), "plan.json")

	stdout, err := runCLI(t,
		"remediation", "run",
		"--vuln-root", root,
		"--core-dir", coreDir,
		"--plan-out", planPath,
		"--limit", "1",
	)
	if err != nil {
		t.Fatalf("remediation run failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "dev-tier-only") {
		t.Fatalf("expected dev-only deferral in output, got:\n%s", stdout)
	}
	raw, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	var plan RemediationPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.SourceDir != latest || plan.Summary.CampaignCount != 0 || plan.Summary.DevOnlyCampaignCount != 1 {
		t.Fatalf("unexpected plan: source=%s summary=%+v", plan.SourceDir, plan.Summary)
	}
}

func TestRemediationOpenPRDryRunRendersSummary(t *testing.T) {
	summaryPath := filepath.Join(t.TempDir(), "summary.json")
	summary := map[string]any{
		"fixed_version":     "1.3.2",
		"remediation_route": "tier1_pin_bump",
		"recipe": map[string]any{
			"route":             "version_bump",
			"package_attribute": "zlib",
		},
		"affected_targets": []map[string]any{
			{"target": "python3.13-slim", "tier": "slim", "arch": "amd64"},
			{"target": "python3.13-dev", "tier": "dev", "arch": "amd64"},
		},
		"validation": []map[string]any{
			{"target": "python3.13-slim", "status": "passed", "reason": "original CVE/package pair removed", "scanPath": "build-outputs/scan.json"},
		},
	}
	writeCatalogJSON(t, summaryPath, summary)

	stdout, err := runCLI(t,
		"remediation", "open-pr",
		"--branch", "cve-remediation/cve-2026-12345-zlib",
		"--package", "zlib",
		"--cve", "CVE-2026-12345",
		"--installed-version", "1.3.1",
		"--summary", summaryPath,
		"--dry-run",
	)
	if err != nil {
		t.Fatalf("open-pr dry run failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"Title: chore: automated CVE patch remediation for zlib (CVE-2026-12345)",
		"### Planner campaign",
		"`version_bump`",
		"`zlib`",
		"`python3.13-slim:amd64, python3.13-dev:amd64`",
		"`build-outputs/scan.json`",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %q in dry-run output:\n%s", want, stdout)
		}
	}
}
