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

func TestRemediationPlanQuietOutExplicitDirAndDiagnostics(t *testing.T) {
	root := t.TempDir()
	prodFix := map[string]any{
		"id":             "CVE-2026-12345",
		"severity":       "Critical",
		"packageName":    "openssl",
		"packageVersion": "3.0.0",
		"layer":          "runtime",
		"fixedIn":        "3.0.1, 3.1.0",
		"fixState":       "fixed",
		"riskScore":      37.5,
		"epssScore":      0.42,
	}
	baseLayer := map[string]any{
		"id":             "CVE-2026-20001",
		"severity":       "High",
		"packageName":    "glibc",
		"packageVersion": "2.39",
		"layer":          "base",
		"fixedIn":        "2.40",
		"fixState":       "fixed",
	}
	lowSeverity := map[string]any{
		"id":             "CVE-2026-20002",
		"severity":       "Medium",
		"packageName":    "curl",
		"packageVersion": "8.0.0",
		"layer":          "runtime",
		"fixedIn":        "8.0.1",
		"fixState":       "fixed",
	}
	noFix := map[string]any{
		"id":             "CVE-2026-20003",
		"severity":       "High",
		"packageName":    "zlib",
		"packageVersion": "1.3.0",
		"layer":          "runtime",
		"fixState":       "not-fixed",
	}
	latest := writeRemediationScan(t, root, "v1.0.0", "python3.13-slim-amd64.json", []map[string]any{
		prodFix, baseLayer, lowSeverity, noFix,
	})
	writeCatalogJSON(t, filepath.Join(latest, "ignored-name.json"), map[string]any{"findings": []any{prodFix}})

	planPath := filepath.Join(t.TempDir(), "nested", "plan.json")
	stdout, err := runCLI(t,
		"--quiet",
		"remediation", "plan",
		"--vuln-root", root,
		"--vuln-dir", latest,
		"--out", planPath,
		"--limit", "1",
	)
	if err != nil {
		t.Fatalf("quiet remediation plan failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "[remediation] campaigns=1") || strings.Contains(stdout, "{") {
		t.Fatalf("expected compact quiet summary, got:\n%s", stdout)
	}
	raw, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatalf("expected plan file: %v", err)
	}
	var plan RemediationPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatalf("parse plan file: %v\n%s", err, raw)
	}
	if plan.Campaigns[0].FixedVersion != "3.0.1" {
		t.Fatalf("expected fixed version to use first comma-delimited candidate, got %+v", plan.Campaigns[0])
	}
	for _, reason := range []string{"base_layer", "below_priority_threshold", "no_fixed_version"} {
		if plan.Summary.DeferredReasonCounts[reason] != 1 {
			t.Fatalf("expected one deferred %s finding, got summary %+v", reason, plan.Summary)
		}
	}

	_, err = runCLI(t, "remediation", "plan", "--vuln-root", root, "--vuln-dir", filepath.Join(root, "missing"))
	if err == nil || !strings.Contains(err.Error(), "checked_vuln_root=") {
		t.Fatalf("expected explicit vuln-dir diagnostic, got %v", err)
	}

	emptyRoot := t.TempDir()
	_, err = runCLI(t, "remediation", "plan", "--vuln-root", emptyRoot)
	if err == nil || !strings.Contains(err.Error(), "version_dir_count=0") {
		t.Fatalf("expected empty root diagnostic, got %v", err)
	}
}

func TestRemediationPlanClustersMultiCVERootCauseAndRiskContext(t *testing.T) {
	root := t.TempDir()
	fixedIn := "3.13.14"
	epssPercentile := 0.95
	prodScan := map[string]any{
		"scannedAt":         "2026-06-07T00:00:00Z",
		"scanner":           "grype-test",
		"dbBuiltAt":         "2026-06-06T00:00:00Z",
		"kevStatus":         "available",
		"kevCatalogVersion": "2026.06.07",
		"findings": []map[string]any{
			{
				"id":             "CVE-2026-10001",
				"severity":       "High",
				"packageName":    "python",
				"packageVersion": "3.13.13",
				"layer":          "runtime",
				"fixedIn":        fixedIn,
				"fixState":       "fixed",
				"epssPercentile": epssPercentile,
				"kev":            map[string]any{"knownExploited": true},
			},
			{
				"id":             "CVE-2026-10002",
				"severity":       "High",
				"packageName":    "python",
				"packageVersion": "3.13.13",
				"layer":          "runtime",
				"fixedIn":        fixedIn,
				"fixState":       "fixed",
			},
			{
				"id":             "CVE-2026-10003",
				"severity":       "High",
				"packageName":    "glibc",
				"packageVersion": "2.39",
				"layer":          "base",
				"fixedIn":        "2.40",
				"fixState":       "fixed",
			},
		},
	}
	devFinding := map[string]any{
		"id":             "CVE-2026-20001",
		"severity":       "Critical",
		"packageName":    "gradle",
		"packageVersion": "9.2.0",
		"layer":          "runtime",
		"fixedIn":        "9.3.0",
		"fixState":       "fixed",
	}
	dir := filepath.Join(root, "v1.0.0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCatalogJSON(t, filepath.Join(dir, "python3.13-slim-amd64.json"), prodScan)
	writeCatalogJSON(t, filepath.Join(dir, "java21-dev-amd64.json"), map[string]any{"findings": []map[string]any{devFinding}})

	stdout, err := runCLI(t, "--format", "json", "remediation", "plan", "--vuln-root", root)
	if err != nil {
		t.Fatalf("remediation plan failed: %v\n%s", err, stdout)
	}

	var plan RemediationPlan
	if err := json.Unmarshal([]byte(stdout), &plan); err != nil {
		t.Fatalf("parse plan: %v\n%s", err, stdout)
	}
	if plan.ScanSource.KEVStatus != "available" || plan.ScanSource.KEVCatalogVersion == nil || *plan.ScanSource.KEVCatalogVersion != "2026.06.07" {
		t.Fatalf("unexpected scan source: %+v", plan.ScanSource)
	}
	if plan.Summary.CampaignCount != 1 || plan.Summary.CandidateCampaignCount != 2 || plan.Summary.DevOnlyCampaignCount != 1 {
		t.Fatalf("unexpected summary: %+v", plan.Summary)
	}
	campaign := plan.Campaigns[0]
	if campaign.Package != "python" || campaign.PrimaryCVE != "CVE-2026-10001" || campaign.CVE != campaign.PrimaryCVE {
		t.Fatalf("unexpected primary campaign identity: %+v", campaign)
	}
	if got := strings.Join(campaign.CVEs, ","); got != "CVE-2026-10001,CVE-2026-10002" {
		t.Fatalf("expected clustered CVEs, got %q", got)
	}
	if len(campaign.ExpectedRemoved) != 2 || !campaign.RiskFactors.KnownExploited || campaign.RiskFactors.ProductionTargetCount != 1 {
		t.Fatalf("expected clustered validation and risk factors, got %+v", campaign)
	}
	if len(plan.Clusters) != 1 || plan.Clusters[0].Package != "python" || len(plan.Clusters[0].CVEs) != 2 {
		t.Fatalf("unexpected root-cause clusters: %+v", plan.Clusters)
	}
	if plan.Metrics.KnownExploitedCampaigns != 1 || plan.Metrics.ProductionDeferredFindings != 1 {
		t.Fatalf("unexpected metrics: %+v", plan.Metrics)
	}
	if len(plan.TopDeferred) == 0 || plan.TopDeferred[0].Reason != "base_layer" || plan.TopDeferred[0].ProductionCount != 1 {
		t.Fatalf("expected production base-layer deferral, got %+v", plan.TopDeferred)
	}
}

func TestRemediationReportSummarizesDraftsAndResidualOwnerActions(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "remediation-plan.json")
	reportPath := filepath.Join(dir, "remediation-report.json")
	writeCatalogJSON(t, planPath, RemediationPlan{
		GeneratedAt: "2026-06-07T00:00:00Z",
		TopDeferred: []RemediationDeferredSummary{{
			Reason:          "base_layer",
			Package:         "glibc",
			CVE:             "CVE-2026-10003",
			Target:          "python3.13-slim",
			Tier:            "slim",
			Count:           1,
			ProductionCount: 1,
		}},
	})
	writeCatalogJSON(t, filepath.Join(dir, "remediation-summary-success.json"), map[string]any{"status": "draft_compiled"})
	writeCatalogJSON(t, filepath.Join(dir, "remediation-summary-failed.json"), map[string]any{"status": "failed"})

	stdout, err := runCLI(t, "--format", "json", "remediation", "report", "--plan", planPath, "--out", reportPath)
	if err != nil {
		t.Fatalf("remediation report failed: %v\n%s", err, stdout)
	}
	var report RemediationReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("parse report stdout: %v\n%s", err, stdout)
	}
	if report.DraftResults.Drafted != 1 || report.DraftResults.Failed != 1 {
		t.Fatalf("unexpected draft results: %+v", report.DraftResults)
	}
	if len(report.ResidualOwnerActions) != 1 || report.ResidualOwnerActions[0].Owner != "base-image-owner" {
		t.Fatalf("unexpected residual owner actions: %+v", report.ResidualOwnerActions)
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatalf("expected report output file: %v", err)
	}
}

func TestRemediationValidateOverlaysRequiresEvidenceAndDetectsCollisions(t *testing.T) {
	overlayDir := t.TempDir()
	overlayPath := filepath.Join(overlayDir, "cve-2026-10001-zlib.nix")
	if err := os.WriteFile(overlayPath, []byte("final: prev: {\n  zlib = prev.zlib.overrideAttrs (old: { version = \"1.3.2\"; });\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := runCLI(t, "remediation", "validate-overlays", "--overlay-dir", overlayDir)
	if err == nil || !strings.Contains(err.Error(), "missing evidence file") {
		t.Fatalf("expected missing evidence failure, got %v", err)
	}

	writeCatalogJSON(t, strings.TrimSuffix(overlayPath, ".nix")+".evidence.json", map[string]any{
		"status":         "draft_compiled",
		"policyDecision": map[string]any{"selected": true, "reason": "eligible"},
		"validation":     []map[string]any{{"status": "passed"}},
	})
	stdout, err := runCLI(t, "remediation", "validate-overlays", "--overlay-dir", overlayDir)
	if err != nil {
		t.Fatalf("validate overlays failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "Validated 1 remediation overlay") {
		t.Fatalf("unexpected validate output:\n%s", stdout)
	}

	collisionPath := filepath.Join(overlayDir, "cve-2026-10002-zlib.nix")
	if err := os.WriteFile(collisionPath, []byte("final: prev: {\n  zlib = prev.zlib.overrideAttrs (old: { version = \"1.3.3\"; });\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeCatalogJSON(t, strings.TrimSuffix(collisionPath, ".nix")+".evidence.json", map[string]any{
		"status":         "draft_compiled",
		"policyDecision": map[string]any{"selected": true, "reason": "eligible"},
		"validation":     []map[string]any{{"status": "passed"}},
	})
	_, err = runCLI(t, "remediation", "validate-overlays", "--overlay-dir", overlayDir)
	if err == nil || !strings.Contains(err.Error(), "also overridden") {
		t.Fatalf("expected overlay collision failure, got %v", err)
	}

	manualDir := t.TempDir()
	manualPath := filepath.Join(manualDir, "cve-2026-10003-manual.nix")
	if err := os.WriteFile(manualPath, []byte("final: prev: {\n  manualPkg = prev.manualPkg.overrideAttrs (old: { postPatch = \"true\"; });\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeCatalogJSON(t, strings.TrimSuffix(manualPath, ".nix")+".evidence.json", map[string]any{
		"status":         "manual_accepted",
		"owner":          "platform",
		"reason":         "Existing human-authored overlay with explicit owner metadata.",
		"policyDecision": map[string]any{"selected": false, "reason": "manual_existing_overlay"},
	})
	if stdout, err := runCLI(t, "remediation", "validate-overlays", "--overlay-dir", manualDir); err != nil {
		t.Fatalf("manual accepted overlay should pass despite generated hook restriction: %v\n%s", err, stdout)
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

func TestRemediationOpenPRGuardrailsAndEmptySummary(t *testing.T) {
	for name, args := range map[string][]string{
		"branch":  {"remediation", "open-pr", "--branch", "feature/not-cve", "--package", "zlib", "--cve", "CVE-2026-12345", "--dry-run"},
		"package": {"remediation", "open-pr", "--branch", "cve-remediation/cve-2026-12345-zlib", "--cve", "CVE-2026-12345", "--dry-run"},
		"cve":     {"remediation", "open-pr", "--branch", "cve-remediation/cve-2026-12345-zlib", "--package", "zlib", "--dry-run"},
	} {
		stdout, err := runCLI(t, args...)
		if err == nil {
			t.Fatalf("%s guardrail unexpectedly passed:\n%s", name, stdout)
		}
	}
	emptySummary := filepath.Join(t.TempDir(), "summary.json")
	if err := os.WriteFile(emptySummary, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	body, err := remediationPRBody("zlib", "CVE-2026-12345", "", emptySummary)
	if err != nil {
		t.Fatalf("empty summary should be ignored: %v", err)
	}
	if !strings.Contains(body, "- **Installed version:** ``") {
		t.Fatalf("empty installed version should be rendered as supplied by the body helper:\n%s", body)
	}
	if _, err := remediationPRBody("zlib", "CVE-2026-12345", "1.0", filepath.Join(t.TempDir(), "missing.json")); err != nil {
		t.Fatalf("missing summary should be ignored: %v", err)
	}
	badSummary := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badSummary, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := remediationPRBody("zlib", "CVE-2026-12345", "1.0", badSummary); err == nil || !strings.Contains(err.Error(), "failed to parse remediation summary") {
		t.Fatalf("expected bad summary parse error, got %v", err)
	}
}

func TestRemediationRunPlanSummaryAndHelpers(t *testing.T) {
	var stdout, stderr strings.Builder
	oldOut, oldErr := out, errOut
	out, errOut = &stdout, &stderr
	t.Cleanup(func() {
		out, errOut = oldOut, oldErr
	})

	plan := &RemediationPlan{
		SourceDir: "site/src/data/vulnerabilities/v1.0.0",
		Campaigns: []RemediationCampaign{{
			Package:               "openssl",
			CVE:                   "CVE-2026-12345",
			InstalledVersion:      "",
			FixedVersion:          "3.0.1",
			TargetCount:           2,
			ProductionTargetCount: 1,
		}},
		Summary: RemediationPlanSummary{
			DeferredCount:                  2,
			ProductionDeferredReasonCounts: map[string]int{"no_fixed_version": 1, "base_layer": 1},
		},
	}
	printRemediationRunPlanSummary(plan)
	if !strings.Contains(stdout.String(), "Planner selected 1 remediation campaign") ||
		!strings.Contains(stdout.String(), "? -> 3.0.1") {
		t.Fatalf("unexpected remediation run summary stdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Planner deferred 2 finding") {
		t.Fatalf("expected deferred warning, got stderr:\n%s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	printRemediationRunPlanSummary(&RemediationPlan{Summary: RemediationPlanSummary{
		ProductionDeferredReasonCounts: map[string]int{"no_fixed_version": 2, "base_layer": 1},
	}})
	if !strings.Contains(stdout.String(), "Zero fixable High or Critical") ||
		!strings.Contains(stdout.String(), "base_layer=1, no_fixed_version=2") {
		t.Fatalf("expected zero-campaign and sorted reason summary, got stdout:\n%s", stdout.String())
	}

	if envIntValue("__CLEARCUTT_BAD_INT__", 17) != 17 {
		t.Fatal("expected missing env int to return fallback")
	}
	t.Setenv("__CLEARCUTT_BAD_INT__", "nope")
	if envIntValue("__CLEARCUTT_BAD_INT__", 23) != 23 {
		t.Fatal("expected invalid env int to return fallback")
	}
	t.Setenv("__CLEARCUTT_BAD_INT__", "42")
	if envIntValue("__CLEARCUTT_BAD_INT__", 0) != 42 {
		t.Fatal("expected valid env int to parse")
	}

	if got := campaignSlug(RemediationCampaign{CVE: "CVE-2026-12345", Package: "libssl++"}); got != "cve-2026-12345-libssl" {
		t.Fatalf("unexpected campaign slug: %q", got)
	}
	if fallbackString("", "fallback") != "fallback" || firstNonEmpty("", "second", "third") != "second" {
		t.Fatal("fallback helpers returned unexpected values")
	}
	if codeQuote("pkg`name") != "`pkg'name`" {
		t.Fatalf("codeQuote did not sanitize backticks")
	}
	data := map[string]any{
		"recipe": map[string]any{"route": "version_bump"},
		"items":  []any{map[string]any{"target": "java21-slim"}, "skip"},
	}
	if stringValue(mapValue(data, "recipe"), "route") != "version_bump" || len(sliceValue(data, "items")) != 1 {
		t.Fatalf("summary map/slice helpers returned unexpected values")
	}
}

func TestResolveCoreDirBranches(t *testing.T) {
	if got, err := resolveCoreDir("/tmp/core"); err != nil || got != "/tmp/core" {
		t.Fatalf("explicit core dir failed: got %q err %v", got, err)
	}

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	if err := os.MkdirAll("scripts", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("scripts", "cve-draft-agent.py"), []byte("#!/usr/bin/env python3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveCoreDir(""); err != nil || got != "." {
		t.Fatalf("local scripts core dir failed: got %q err %v", got, err)
	}

	if err := os.RemoveAll("scripts"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join("core", "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("core", "scripts", "cve-draft-agent.py"), []byte("#!/usr/bin/env python3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveCoreDir(""); err != nil || got != "core" {
		t.Fatalf("nested core dir failed: got %q err %v", got, err)
	}

	if err := os.RemoveAll("core"); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveCoreDir(""); err == nil || !strings.Contains(err.Error(), "pass --core-dir") {
		t.Fatalf("expected missing core dir error, got %v", err)
	}
}
