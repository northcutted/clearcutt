package commands

import (
	"encoding/json"
	"os"
	"os/exec"
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

func TestRemediationPlanMatchesPythonBrokerSummary(t *testing.T) {
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
	writeRemediationScan(t, root, "v1.0.0", "java21-dev-amd64.json", []map[string]any{finding})

	stdout, err := runCLI(t, "--format", "json", "remediation", "plan", "--vuln-root", root, "--include-dev-only")
	if err != nil {
		t.Fatalf("Go remediation plan failed: %v\n%s", err, stdout)
	}
	var goPlan RemediationPlan
	if err := json.Unmarshal([]byte(stdout), &goPlan); err != nil {
		t.Fatalf("invalid Go JSON: %v\n%s", err, stdout)
	}

	repoRoot := filepath.Join("..", "..", "..")
	cmd := exec.Command(
		"python3",
		"core/scripts/remediation-broker.py",
		"--vuln-root",
		root,
		"--include-dev-only",
	)
	cmd.Dir = repoRoot
	pyRaw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Python broker failed: %v\n%s", err, string(pyRaw))
	}
	var pyPlan RemediationPlan
	if err := json.Unmarshal(pyRaw, &pyPlan); err != nil {
		t.Fatalf("invalid Python JSON: %v\n%s", err, string(pyRaw))
	}

	if goPlan.SourceDir != pyPlan.SourceDir {
		t.Fatalf("source dir drift: go=%s python=%s", goPlan.SourceDir, pyPlan.SourceDir)
	}
	if goPlan.Summary.CampaignCount != pyPlan.Summary.CampaignCount ||
		goPlan.Summary.CandidateCampaignCount != pyPlan.Summary.CandidateCampaignCount ||
		goPlan.Summary.DevOnlyCampaignCount != pyPlan.Summary.DevOnlyCampaignCount ||
		goPlan.Summary.DeferredCount != pyPlan.Summary.DeferredCount {
		t.Fatalf("summary drift:\ngo=%+v\npython=%+v", goPlan.Summary, pyPlan.Summary)
	}
	if len(goPlan.Campaigns) != 1 || len(pyPlan.Campaigns) != 1 {
		t.Fatalf("unexpected campaign counts: go=%d python=%d", len(goPlan.Campaigns), len(pyPlan.Campaigns))
	}
	if goPlan.Campaigns[0].Package != pyPlan.Campaigns[0].Package ||
		goPlan.Campaigns[0].CVE != pyPlan.Campaigns[0].CVE ||
		goPlan.Campaigns[0].FixedVersion != pyPlan.Campaigns[0].FixedVersion ||
		goPlan.Campaigns[0].TargetCount != pyPlan.Campaigns[0].TargetCount {
		t.Fatalf("campaign drift:\ngo=%+v\npython=%+v", goPlan.Campaigns[0], pyPlan.Campaigns[0])
	}
}
