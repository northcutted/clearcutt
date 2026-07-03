package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/clearcutt/internal/fixprobe"
)

// stubFixFetcher serves inline nixpkgs file contents keyed by ref; each test
// probes one source path, so the path only participates in the miss error.
type stubFixFetcher struct {
	files map[string]string
	errs  map[string]error
}

func (s *stubFixFetcher) FileAt(_ context.Context, path, ref string) ([]byte, error) {
	if err, ok := s.errs[ref]; ok {
		return nil, err
	}
	content, ok := s.files[ref]
	if !ok {
		return nil, fmt.Errorf("no stub content for ref %q (path %s)", ref, path)
	}
	return []byte(content), nil
}

// swapTriageProbeHooks replaces the production probe seams (GitHub fetcher +
// nix-eval source resolver) for one test, mirroring the out/errOut swap.
func swapTriageProbeHooks(t *testing.T, fetcher fixprobe.Fetcher, resolve func(coreDir, attr string) (string, error)) {
	t.Helper()
	oldFetcher, oldResolve, oldSources := triageNewFetcher, triageResolveSourcePath, triageResolveInputSources
	triageNewFetcher = func() fixprobe.Fetcher { return fetcher }
	triageResolveSourcePath = resolve
	// No input-source map: every position attributes to the main pin, keeping
	// pre-attribution fixtures valid without a nix binary.
	triageResolveInputSources = func(string) (map[string]string, error) { return map[string]string{}, nil }
	t.Cleanup(func() {
		triageNewFetcher, triageResolveSourcePath, triageResolveInputSources = oldFetcher, oldResolve, oldSources
	})
}

func writeTriageCoreDir(t *testing.T, pinRev string) string {
	t.Helper()
	dir := t.TempDir()
	lock := fmt.Sprintf(`{"version":7,"root":"root","nodes":{"nixpkgs":{"locked":{"rev":%q}}}}`, pinRev)
	if err := os.WriteFile(filepath.Join(dir, "flake.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func findTriageOption(t *testing.T, f TriageFinding, route string) RouteOption {
	t.Helper()
	for _, option := range f.Options {
		if option.Route == route {
			return option
		}
	}
	t.Fatalf("report has no %s option: %+v", route, f.Options)
	return RouteOption{}
}

func decodeTriageReport(t *testing.T, stdout string) TriageReport {
	t.Helper()
	// Probe-degradation notices land on stderr, which runCLI merges into the
	// same buffer; the report starts at the first brace.
	idx := strings.Index(stdout, "{")
	if idx < 0 {
		t.Fatalf("no JSON in output:\n%s", stdout)
	}
	var report TriageReport
	if err := json.Unmarshal([]byte(stdout[idx:]), &report); err != nil {
		t.Fatalf("decode triage report: %v\n%s", err, stdout)
	}
	return report
}

const opensslTriagePinRev = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// setupOpensslTriageFixture replays the 2026-07-02 openssl decision (design
// doc section 8): critical, production, fix only on staging-next (uncached).
func setupOpensslTriageFixture(t *testing.T) (scanDir, coreDir string) {
	t.Helper()
	root := t.TempDir()
	scanDir = writeRemediationScan(t, root, "v1.0.0", "python3.13-slim-amd64.json", []map[string]any{{
		"id":             "CVE-2026-34182",
		"severity":       "Critical",
		"packageName":    "openssl",
		"packageVersion": "3.6.2",
		"layer":          "runtime",
		"fixedIn":        "3.6.3",
		"fixState":       "fixed",
	}})
	coreDir = writeTriageCoreDir(t, opensslTriagePinRev)
	vulnerable := "{\n  version = \"3.6.2\";\n  patches = [ ./nix-ssl-cert-file.patch ];\n}\n"
	fixed := "{\n  version = \"3.6.3\";\n  patches = [ ./nix-ssl-cert-file.patch ];\n}\n"
	swapTriageProbeHooks(t, &stubFixFetcher{files: map[string]string{
		opensslTriagePinRev: vulnerable,
		"nixos-unstable":    vulnerable,
		"master":            vulnerable,
		"staging-next":      fixed,
	}}, func(string, string) (string, error) {
		return "pkgs/development/libraries/openssl/default.nix", nil
	})
	return scanDir, coreDir
}

const nodeTriagePinRev = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// setupNodeTriageFixture replays the node-24 decision (design doc section 8):
// preview tier, fix cached on nixos-25.11, patch-set churn between pin and fix.
func setupNodeTriageFixture(t *testing.T) (scanDir, coreDir, fleetPath string) {
	t.Helper()
	root := t.TempDir()
	scanDir = writeRemediationScan(t, root, "v1.0.0", "node24-preview-amd64.json", []map[string]any{{
		"id":             "CVE-2026-48937",
		"severity":       "Medium",
		"packageName":    "nodejs",
		"packageVersion": "24.15.0",
		"layer":          "runtime",
		"fixedIn":        "24.17.0",
		"fixState":       "fixed",
		"epssPercentile": 0.95,
	}})
	coreDir = writeTriageCoreDir(t, nodeTriagePinRev)
	fleetPath = filepath.Join(t.TempDir(), "clearcutt.fleet.yaml")
	fleetYAML := "apiVersion: clearcutt.dev/v1\nkind: FleetConfig\nremediation:\n  probe:\n    refs: [nixos-unstable, master, staging-next, nixos-25.11]\n"
	if err := os.WriteFile(fleetPath, []byte(fleetYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	pin := "{\n  version = \"24.15.0\";\n  patches = [ ./disable-v8-flag.patch ];\n}\n"
	mid := "{\n  version = \"24.16.0\";\n  patches = [ ./disable-v8-flag.patch ];\n}\n"
	fixed := "{\n  version = \"24.18.0\";\n  patches = [ ./new-v8-abi.patch ];\n}\n"
	swapTriageProbeHooks(t, &stubFixFetcher{files: map[string]string{
		nodeTriagePinRev: pin,
		"nixos-unstable": mid,
		"master":         mid,
		"staging-next":   fixed,
		"nixos-25.11":    fixed,
	}}, func(string, string) (string, error) {
		return "pkgs/development/web/nodejs/v24.nix", nil
	})
	return scanDir, coreDir, fleetPath
}

// TestRemediationTriageAttributesDedicatedPin proves a package sourced from a
// dedicated pin is priced against THAT pin, not the main one: the main pin
// already carries the fix while nixpkgs-node does not, so main-pin probing
// (the pre-attribution bug) would flip PinHasFix and recommend version_bump.
func TestRemediationTriageAttributesDedicatedPin(t *testing.T) {
	const mainRev = "cccccccccccccccccccccccccccccccccccccccc"
	const nodeRev = "dddddddddddddddddddddddddddddddddddddddd"
	root := t.TempDir()
	scanDir := writeRemediationScan(t, root, "v1.0.0", "node24-preview-amd64.json", []map[string]any{{
		"id":             "CVE-2026-48937",
		"severity":       "Medium",
		"packageName":    "nodejs",
		"packageVersion": "24.15.0",
		"layer":          "runtime",
		"fixedIn":        "24.17.0",
		"fixState":       "fixed",
		"epssPercentile": 0.95,
	}})
	coreDir := t.TempDir()
	lock := fmt.Sprintf(`{"version":7,"root":"root","nodes":{"nixpkgs":{"locked":{"rev":%q}},"nixpkgs-node":{"locked":{"rev":%q}}}}`, mainRev, nodeRev)
	if err := os.WriteFile(filepath.Join(coreDir, "flake.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	vulnerable := "{\n  version = \"24.15.0\";\n}\n"
	fixed := "{\n  version = \"24.18.0\";\n}\n"
	swapTriageProbeHooks(t, &stubFixFetcher{files: map[string]string{
		mainRev:          fixed,
		nodeRev:          vulnerable,
		"nixos-unstable": vulnerable,
		"master":         vulnerable,
		"staging-next":   vulnerable,
	}}, func(string, string) (string, error) {
		return "/nix/store/node111-source/pkgs/development/web/nodejs/v24.nix:26", nil
	})
	triageResolveInputSources = func(string) (map[string]string, error) {
		return map[string]string{"/nix/store/node111-source": "nixpkgs-node"}, nil
	}

	stdout, err := runCLI(t, "--format", "json", "remediation", "triage",
		"--scan-dir", scanDir, "--core-dir", coreDir, "--cve", "CVE-2026-48937")
	if err != nil {
		t.Fatalf("triage failed: %v\n%s", err, stdout)
	}
	report := decodeTriageReport(t, stdout)
	if len(report.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(report.Findings))
	}
	f := report.Findings[0]
	if f.Probe == nil {
		t.Fatal("probe missing")
	}
	if f.Probe.PinName != "nixpkgs-node" {
		t.Fatalf("probe pinName = %q, want nixpkgs-node", f.Probe.PinName)
	}
	if f.Probe.PinHasFix {
		t.Fatal("PinHasFix = true: probe read the main pin instead of the sourcing pin")
	}
	if f.Probe.Refs[0].Version != "24.15.0" {
		t.Fatalf("pin ref version = %q, want the node pin's 24.15.0", f.Probe.Refs[0].Version)
	}
	if bump := findTriageOption(t, f, RouteVersionBump); bump.Available {
		t.Fatalf("version_bump = %+v, want unavailable (the sourcing pin lacks the fix)", bump)
	}
}

// TestRemediationTriageOpensslWorkedExample pins the first worked example:
// rebuild recommended, accept and wait blocked by policy.
func TestRemediationTriageOpensslWorkedExample(t *testing.T) {
	scanDir, coreDir := setupOpensslTriageFixture(t)

	stdout, err := runCLI(t, "--format", "json", "remediation", "triage",
		"--scan-dir", scanDir, "--core-dir", coreDir, "--cve", "CVE-2026-34182")
	if err != nil {
		t.Fatalf("triage failed: %v\n%s", err, stdout)
	}
	report := decodeTriageReport(t, stdout)
	if report.SchemaVersion != TriageSchemaVersion {
		t.Fatalf("schemaVersion = %q, want %q", report.SchemaVersion, TriageSchemaVersion)
	}
	if report.Degraded {
		t.Fatal("healthy probe reported degraded")
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(report.Findings))
	}
	f := report.Findings[0]
	if f.RecommendedRoute != RouteFetchpatchRebuild {
		t.Fatalf("recommendedRoute = %q, want fetchpatch_rebuild", f.RecommendedRoute)
	}
	if f.Materiality == nil || f.Materiality.Disposition != "must_fix" {
		t.Fatalf("materiality = %+v, want must_fix", f.Materiality)
	}
	if f.Exposure == nil || !f.Exposure.Production || strings.Join(f.Exposure.Tiers, ",") != "slim" {
		t.Fatalf("exposure = %+v, want production(slim)", f.Exposure)
	}
	if f.Probe == nil || f.Probe.PinHasFix {
		t.Fatalf("probe = %+v, want pin without fix", f.Probe)
	}

	rebuild := findTriageOption(t, f, RouteFetchpatchRebuild)
	if !rebuild.Available || !rebuild.Recommended || rebuild.CostNow != "cold_source_build" || rebuild.RiskCarried != "none" {
		t.Fatalf("rebuild option = %+v, want available+recommended cold_source_build/none", rebuild)
	}
	if rebuild.Retirement == nil || rebuild.Retirement.Kind != "pin_carries_fix" || rebuild.Retirement.Version != "3.6.3" {
		t.Fatalf("rebuild retirement = %+v, want pin_carries_fix >= 3.6.3", rebuild.Retirement)
	}
	bump := findTriageOption(t, f, RouteVersionBump)
	if bump.Available || !strings.Contains(bump.Why, "3.6.2") {
		t.Fatalf("version_bump = %+v, want unavailable (pin still at 3.6.2)", bump)
	}
	ignore := findTriageOption(t, f, RouteScannerIgnore)
	if ignore.Available || !strings.Contains(ignore.Why, "policy blocks") {
		t.Fatalf("scanner_ignore = %+v, want blocked by policy", ignore)
	}
	wait := findTriageOption(t, f, RouteWait)
	if wait.Available || !strings.Contains(wait.Why, "above the wait ceiling") {
		t.Fatalf("wait = %+v, want blocked by severity ceiling", wait)
	}
	optin := findTriageOption(t, f, RouteUnstableOptIn)
	if optin.Available {
		t.Fatalf("unstable_optin = %+v, want unavailable (no cached ref carries the fix)", optin)
	}
}

// TestRemediationTriageNodeWorkedExample pins the second worked example:
// cached pin-hop recommended, rebuild flagged for override churn, wait open
// on the preview tier.
func TestRemediationTriageNodeWorkedExample(t *testing.T) {
	scanDir, coreDir, fleetPath := setupNodeTriageFixture(t)

	stdout, err := runCLI(t, "--format", "json", "remediation", "triage",
		"--scan-dir", scanDir, "--core-dir", coreDir, "--fleet-config", fleetPath)
	if err != nil {
		t.Fatalf("triage failed: %v\n%s", err, stdout)
	}
	report := decodeTriageReport(t, stdout)
	if report.Degraded {
		t.Fatal("healthy probe reported degraded")
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(report.Findings))
	}
	f := report.Findings[0]
	if f.RecommendedRoute != RouteUnstableOptIn {
		t.Fatalf("recommendedRoute = %q, want unstable_optin", f.RecommendedRoute)
	}
	if f.Materiality == nil || f.Materiality.Disposition != "auto_accept" || f.Materiality.Reason != "non_production" {
		t.Fatalf("materiality = %+v, want auto_accept(non_production)", f.Materiality)
	}
	if f.Probe == nil || f.Probe.OverrideRisk == nil || f.Probe.OverrideRisk.Level != fixprobe.RiskHigh {
		t.Fatalf("probe override risk = %+v, want high (patch-set churn)", f.Probe)
	}

	optin := findTriageOption(t, f, RouteUnstableOptIn)
	if !optin.Available || !optin.Recommended || !strings.Contains(optin.Why, "nixos-25.11") {
		t.Fatalf("unstable_optin = %+v, want recommended pin-hop to nixos-25.11", optin)
	}
	if optin.Retirement == nil || optin.Retirement.Kind != "pin_carries_fix" || optin.Retirement.Version != "24.17.0" {
		t.Fatalf("optin retirement = %+v, want pin_carries_fix >= 24.17.0", optin.Retirement)
	}
	rebuild := findTriageOption(t, f, RouteFetchpatchRebuild)
	if !rebuild.Available || rebuild.RiskCarried != "override_patch_churn" {
		t.Fatalf("rebuild = %+v, want available with override_patch_churn", rebuild)
	}
	wait := findTriageOption(t, f, RouteWait)
	if !wait.Available || wait.Retirement == nil || wait.Retirement.Kind != "ref_carries_fix" || wait.Retirement.Ref != "nixos-unstable" {
		t.Fatalf("wait = %+v, want available watching nixos-unstable", wait)
	}
	if wait.Retirement.Expires == "" {
		t.Fatalf("wait retirement %+v must carry the WaitMaxDays expiry backstop", wait.Retirement)
	}
	ignore := findTriageOption(t, f, RouteScannerIgnore)
	if !ignore.Available || ignore.Retirement == nil || ignore.Retirement.Kind != "expiry" {
		t.Fatalf("scanner_ignore = %+v, want available with expiry retirement", ignore)
	}
	bump := findTriageOption(t, f, RouteVersionBump)
	if bump.Available {
		t.Fatalf("version_bump = %+v, want unavailable (pin at 24.15.0)", bump)
	}
}

// TestRemediationTriageDegradedFallsBackToStaticClassifier pins the design's
// degradation contract: a dead probe (and --no-probe) yields exactly the
// static classifier's answer — never less available than today's planning.
func TestRemediationTriageDegradedFallsBackToStaticClassifier(t *testing.T) {
	scanDir, coreDir := setupOpensslTriageFixture(t)
	swapTriageProbeHooks(t, &stubFixFetcher{}, func(string, string) (string, error) {
		return "", errors.New("nix eval unavailable in this environment")
	})

	stdout, err := runCLI(t, "--format", "json", "remediation", "triage",
		"--scan-dir", scanDir, "--core-dir", coreDir)
	if err != nil {
		t.Fatalf("degraded triage must not fail: %v\n%s", err, stdout)
	}
	report := decodeTriageReport(t, stdout)
	if !report.Degraded {
		t.Fatal("dead probe must mark the report degraded")
	}
	f := report.Findings[0]
	if f.Probe != nil {
		t.Fatalf("probe snapshot should be absent when resolution failed, got %+v", f.Probe)
	}
	// The static classifier routes a fixable, non-crypto, non-opted-in finding
	// to version_bump; the degraded recommendation must match it.
	if f.RecommendedRoute != RouteVersionBump {
		t.Fatalf("degraded recommendedRoute = %q, want static version_bump", f.RecommendedRoute)
	}
	bump := findTriageOption(t, f, RouteVersionBump)
	if !bump.Available || !bump.Recommended {
		t.Fatalf("version_bump = %+v, want available+recommended under static fallback", bump)
	}

	noProbe, err := runCLI(t, "--format", "json", "remediation", "triage",
		"--scan-dir", scanDir, "--core-dir", coreDir, "--no-probe")
	if err != nil {
		t.Fatalf("--no-probe triage failed: %v\n%s", err, noProbe)
	}
	noProbeReport := decodeTriageReport(t, noProbe)
	if !noProbeReport.Degraded || noProbeReport.Findings[0].RecommendedRoute != RouteVersionBump {
		t.Fatalf("--no-probe must equal the static classifier: %+v", noProbeReport.Findings[0])
	}
}

func TestRemediationTriageTableMarksRecommendedRoute(t *testing.T) {
	scanDir, coreDir := setupOpensslTriageFixture(t)

	stdout, err := runCLI(t, "remediation", "triage", "--scan-dir", scanDir, "--core-dir", coreDir)
	if err != nil {
		t.Fatalf("triage failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"CVE-2026-34182 openssl 3.6.2 -> 3.6.3",
		"severity=critical",
		"exposure=production(slim)",
		"ROUTE", "COST NOW", "RISK CARRIED", "RETIRES",
		"staging-next ✓ uncached",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("table output missing %q:\n%s", want, stdout)
		}
	}
	marked := ""
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, "▸") {
			marked = line
			break
		}
	}
	if !strings.Contains(marked, RouteFetchpatchRebuild) {
		t.Fatalf("recommended marker not on fetchpatch_rebuild:\n%s", stdout)
	}
}

// TestRemediationTriageDecideWait exercises the one genuinely new route end to
// end: the decision record must pass the validate-overlays sweep Task D added.
func TestRemediationTriageDecideWait(t *testing.T) {
	scanDir, coreDir, fleetPath := setupNodeTriageFixture(t)
	backstop := time.Now().UTC().AddDate(0, 2, 0).Format("2006-01-02")

	stdout, err := runCLI(t, "remediation", "triage",
		"--scan-dir", scanDir, "--core-dir", coreDir, "--fleet-config", fleetPath,
		"--decide", "wait", "--owner", "platform",
		"--reason", "fix merged to staging-next; preview tier can wait for the channel",
		"--expires", backstop, "--decided-by", "agent:triage-bot")
	if err != nil {
		t.Fatalf("decide wait failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "[triage] wait decision ->") {
		t.Fatalf("expected wait decision line:\n%s", stdout)
	}

	recordPath := filepath.Join(coreDir, "overlays", "cve", "cve-2026-48937-nodejs.decision.evidence.json")
	raw, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("decision record not written: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("parse decision record: %v\n%s", err, raw)
	}
	if record["status"] != "triage_wait" || record["owner"] != "platform" {
		t.Fatalf("unexpected record identity: %s", raw)
	}
	triage, _ := record["triage"].(map[string]any)
	if triage == nil || triage["route"] != "wait" || triage["decidedBy"] != "agent:triage-bot" {
		t.Fatalf("unexpected triage block: %s", raw)
	}
	retirement, _ := triage["retirement"].(map[string]any)
	if retirement == nil || retirement["kind"] != "ref_carries_fix" || retirement["ref"] != "nixos-unstable" || retirement["expires"] != backstop {
		t.Fatalf("unexpected retirement: %s", raw)
	}
	if triage["probe"] == nil {
		t.Fatalf("decision record must snapshot the probe evidence: %s", raw)
	}

	// The record must survive the governance gate.
	if validated, err := runCLI(t, "remediation", "validate-overlays", "--overlay-dir", filepath.Join(coreDir, "overlays", "cve")); err != nil {
		t.Fatalf("decision record failed validate-overlays: %v\n%s", err, validated)
	}
}

// TestRemediationTriageDecideScannerIgnoreDelegates confirms --decide
// scanner_ignore reuses the existing ignore writer (grype rule + expiring
// evidence) and only adds the triage stamp.
func TestRemediationTriageDecideScannerIgnoreDelegates(t *testing.T) {
	scanDir, coreDir, fleetPath := setupNodeTriageFixture(t)

	stdout, err := runCLI(t, "remediation", "triage",
		"--scan-dir", scanDir, "--core-dir", coreDir, "--fleet-config", fleetPath,
		"--decide", "scanner_ignore", "--owner", "platform",
		"--reason", "preview tier only; fix lands with the next channel bump")
	if err != nil {
		t.Fatalf("decide scanner_ignore failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "[remediation-ignore]") {
		t.Fatalf("expected delegation to the ignore writer:\n%s", stdout)
	}

	grypeRaw, err := os.ReadFile(filepath.Join(coreDir, ".grype.yaml"))
	if err != nil {
		t.Fatalf(".grype.yaml not written: %v", err)
	}
	if !strings.Contains(string(grypeRaw), "CVE-2026-48937") || !strings.Contains(string(grypeRaw), "24.15.0") {
		t.Fatalf("grype rule missing finding details:\n%s", grypeRaw)
	}

	evidencePath := filepath.Join(coreDir, "overlays", "cve", "cve-2026-48937-nodejs.ignore.evidence.json")
	raw, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("ignore evidence not written: %v", err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	triage, _ := evidence["triage"].(map[string]any)
	if triage == nil || triage["route"] != "scanner_ignore" {
		t.Fatalf("ignore evidence missing triage stamp: %s", raw)
	}
	if evidence["expires"] == "" || evidence["expires"] == nil {
		t.Fatalf("delegated ignore must carry the AcceptedExpiryDays backstop: %s", raw)
	}

	if validated, err := runCLI(t, "remediation", "validate-overlays",
		"--overlay-dir", filepath.Join(coreDir, "overlays", "cve"),
		"--grype-config", filepath.Join(coreDir, ".grype.yaml")); err != nil {
		t.Fatalf("delegated ignore failed validate-overlays: %v\n%s", err, validated)
	}
}

func TestRemediationTriageDecideUnstableOptinEmitsSnippet(t *testing.T) {
	scanDir, coreDir, fleetPath := setupNodeTriageFixture(t)

	stdout, err := runCLI(t, "remediation", "triage",
		"--scan-dir", scanDir, "--core-dir", coreDir, "--fleet-config", fleetPath,
		"--decide", "unstable_optin", "--owner", "platform",
		"--reason", "pin-hop node to the cached stable channel")
	if err != nil {
		t.Fatalf("decide unstable_optin failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"softOptIns:",
		"- package: nodejs",
		"ref: nixos-25.11",
		"- cve: CVE-2026-48937",
		"fixedVersion: 24.17.0",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("snippet missing %q:\n%s", want, stdout)
		}
	}

	raw, err := os.ReadFile(filepath.Join(coreDir, "overlays", "cve", "cve-2026-48937-nodejs.decision.evidence.json"))
	if err != nil {
		t.Fatalf("decision record not written: %v", err)
	}
	if !strings.Contains(string(raw), `"status": "triage_decided"`) {
		t.Fatalf("expected triage_decided record:\n%s", raw)
	}
}

func TestRemediationTriageDecideValidation(t *testing.T) {
	scanDir, coreDir, fleetPath := setupNodeTriageFixture(t)
	base := []string{"remediation", "triage", "--scan-dir", scanDir, "--core-dir", coreDir, "--fleet-config", fleetPath}

	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "unknown route",
			args:    []string{"--decide", "pray", "--owner", "o", "--reason", "r"},
			wantErr: "is not a known route",
		},
		{
			name:    "unavailable route rejected",
			args:    []string{"--decide", "version_bump", "--owner", "o", "--reason", "r"},
			wantErr: "is not available",
		},
		{
			name:    "owner and reason required",
			args:    []string{"--decide", "wait"},
			wantErr: "--owner and --reason",
		},
		{
			name:    "malformed expires",
			args:    []string{"--decide", "wait", "--owner", "o", "--reason", "r", "--expires", "soon"},
			wantErr: "--expires must be YYYY-MM-DD",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runCLI(t, append(append([]string{}, base...), tc.args...)...)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestRemediationTriageStrictEscalatesWhenNoRouteAvailable uses the committed
// fixture plan: a KEV, unfixable, production-shipped finding closes every
// route (KEV blocks wait/ignore; no fix blocks the rest), which is exactly the
// escalation signal strict mode turns into exit code 2.
func TestRemediationTriageStrictEscalatesWhenNoRouteAvailable(t *testing.T) {
	planPath := filepath.Join("testdata", "triage", "plan-no-route.json")

	stdout, err := runCLI(t, "remediation", "triage", "--plan", planPath, "--no-probe")
	if err != nil {
		t.Fatalf("non-strict triage must stay informational: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "no route available under policy") {
		t.Fatalf("expected escalation note in table output:\n%s", stdout)
	}

	_, err = runCLI(t, "remediation", "triage", "--plan", planPath, "--no-probe", "--strict")
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("strict mode must exit with ErrCheckFailed, got %v", err)
	}

	report := struct{ out string }{}
	report.out, err = runCLI(t, "--format", "json", "remediation", "triage", "--plan", planPath, "--no-probe")
	if err != nil {
		t.Fatalf("json triage failed: %v", err)
	}
	decoded := decodeTriageReport(t, report.out)
	if decoded.Findings[0].RecommendedRoute != "" {
		t.Fatalf("recommendedRoute = %q, want empty escalation signal", decoded.Findings[0].RecommendedRoute)
	}
}

func TestRemediationTriageFilterRejectsUnknownFinding(t *testing.T) {
	scanDir, coreDir := setupOpensslTriageFixture(t)
	_, err := runCLI(t, "remediation", "triage", "--scan-dir", scanDir, "--core-dir", coreDir,
		"--cve", "CVE-1999-0001", "--no-probe")
	if err == nil || !strings.Contains(err.Error(), "no in-scope finding matches") {
		t.Fatalf("expected filter miss error, got %v", err)
	}
}

func TestFlakeLockRevAndSourcePathHelpers(t *testing.T) {
	dir := writeTriageCoreDir(t, opensslTriagePinRev)
	revs, err := flakeLockRevs(filepath.Join(dir, "flake.lock"))
	if err != nil || revs["nixpkgs"] != opensslTriagePinRev {
		t.Fatalf("flakeLockRevs = %v, %v", revs, err)
	}
	if _, ok := revs["nixpkgs-node"]; ok {
		t.Fatal("missing input must not appear in the rev map")
	}
	if _, err := flakeLockRevs(filepath.Join(dir, "missing.lock")); err == nil {
		t.Fatal("missing lock file must error")
	}

	pins := triagePinMap{
		revs:  map[string]string{"nixpkgs": "mainrev", "nixpkgs-node": "noderev"},
		bySrc: map[string]string{"/nix/store/node111-source": "nixpkgs-node"},
	}
	if name, rev := pins.attribute("/nix/store/node111-source"); name != "nixpkgs-node" || rev != "noderev" {
		t.Fatalf("dedicated-pin attribution = %s/%s", name, rev)
	}
	if name, rev := pins.attribute("/nix/store/unknown-source"); name != "nixpkgs" || rev != "mainrev" {
		t.Fatalf("unknown source must fall back to the main pin, got %s/%s", name, rev)
	}
	if name, rev := pins.attribute(""); name != "nixpkgs" || rev != "mainrev" {
		t.Fatalf("empty source must fall back to the main pin, got %s/%s", name, rev)
	}
	if got := nixpkgsStoreSource("/nix/store/abc123-source/pkgs/development/libraries/openssl/default.nix:142"); got != "/nix/store/abc123-source" {
		t.Fatalf("nixpkgsStoreSource = %q", got)
	}
	if got := nixpkgsStoreSource("pkgs/development/libraries/openssl/default.nix"); got != "" {
		t.Fatalf("repo-relative position must have no store source, got %q", got)
	}

	cases := []struct {
		position string
		want     string
	}{
		{"/nix/store/abc123-source/pkgs/development/libraries/openssl/default.nix:142", "pkgs/development/libraries/openssl/default.nix"},
		{"/nix/store/abc123-source/pkgs/top-level/all-packages.nix", "pkgs/top-level/all-packages.nix"},
		{"/nix/store/abc123-source", ""},
		{"pkgs/by-name/zl/zlib/package.nix:7", "pkgs/by-name/zl/zlib/package.nix"},
	}
	for _, tc := range cases {
		if got := nixpkgsSourcePath(tc.position); got != tc.want {
			t.Fatalf("nixpkgsSourcePath(%q) = %q, want %q", tc.position, got, tc.want)
		}
	}
}
