package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	scanengine "github.com/northcutted/clearcutt/internal/scan"
)

func TestSelectScanTagsUsesDepthWindowAndExplicitPrecedence(t *testing.T) {
	old := scanOpts
	t.Cleanup(func() { scanOpts = old })

	scanOpts = scanFlags{depth: "2"}
	selected, err := selectScanTags([]string{"v1.0.0", "v1.0.1", "v1.0.2", "v1.0.3"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(selected, ",") != "v1.0.3,v1.0.2" {
		t.Fatalf("unexpected depth selection: %v", selected)
	}

	scanOpts = scanFlags{depth: "1", all: true, tags: "v1.0.0,v1.0.3"}
	selected, err = selectScanTags([]string{"v1.0.0", "v1.0.1", "v1.0.2", "v1.0.3"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(selected, ",") != "v1.0.0,v1.0.3" {
		t.Fatalf("explicit tags should override all/depth, got: %v", selected)
	}
}

func TestCommandEnvAndFormattingHelpers(t *testing.T) {
	t.Setenv("CLEARCUTT_TEST_ENV", "custom")
	if got := envOr("CLEARCUTT_TEST_ENV", "fallback"); got != "custom" {
		t.Fatalf("envOr should prefer env value, got %q", got)
	}
	if got := envOr("CLEARCUTT_TEST_ENV_MISSING", "fallback"); got != "fallback" {
		t.Fatalf("envOr should fall back, got %q", got)
	}
	if parseScanBool(" yes ") != true || parseScanBool("off") != false {
		t.Fatal("parseScanBool did not handle yes/off branches")
	}
	if joinOrNone(nil) != "(none)" {
		t.Fatal("joinOrNone should render empty lists")
	}
}

func TestSelectScanTagsCoversAllDefaultAndInvalidDepth(t *testing.T) {
	old := scanOpts
	t.Cleanup(func() { scanOpts = old })

	allTags := []string{"v1.0.0", "v1.0.1"}
	scanOpts = scanFlags{all: true}
	selected, err := selectScanTags(allTags, true)
	if err != nil || strings.Join(selected, ",") != strings.Join(allTags, ",") {
		t.Fatalf("all-tags selection = %v err=%v", selected, err)
	}

	scanOpts = scanFlags{depth: "10"}
	selected, err = selectScanTags(allTags, true)
	if err != nil || len(selected) != len(allTags) {
		t.Fatalf("depth covering all tags = %v err=%v", selected, err)
	}

	scanOpts = scanFlags{}
	selected, err = selectScanTags(allTags, true)
	if err != nil || len(selected) != len(allTags) {
		t.Fatalf("default selection = %v err=%v", selected, err)
	}

	scanOpts = scanFlags{depth: "invalid"}
	selected, err = selectScanTags(allTags, false)
	if err != nil || len(selected) != len(allTags) {
		t.Fatalf("non-strict invalid depth should scan all tags, got %v err=%v", selected, err)
	}
	if _, err = selectScanTags(allTags, true); err == nil || !strings.Contains(err.Error(), "invalid tag window depth") {
		t.Fatalf("strict invalid depth should fail, got %v", err)
	}
}

func TestScanCommandUsesFakeGrypeAndWritesReports(t *testing.T) {
	sbomDir := filepath.Join(t.TempDir(), "sboms")
	outDir := filepath.Join(t.TempDir(), "vulns")
	writeTestFile(t, filepath.Join(sbomDir, "v1.0.0", "python3.13-slim-amd64.sbom.json"), []byte(`{"spdxVersion":"SPDX-2.3"}`))
	writeTestFile(t, filepath.Join(sbomDir, "v1.0.0", "ignored.txt"), []byte(`ignored`))
	writeTestFile(t, filepath.Join(sbomDir, "v0.9.0", "python3.13-slim-amd64.sbom.json"), []byte(`{"spdxVersion":"SPDX-2.3"}`))

	grype := writeFakeGrype(t, `{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2026-0001",
        "severity": "Critical",
        "dataSource": "https://example.invalid/cve",
        "namespace": "nvd:cpe",
        "description": "runtime vuln",
        "fix": { "versions": ["3.13.2"], "state": "fixed" },
        "cvss": [
          { "type": "secondary", "version": "3.1", "vector": "CVSS:3.1/LOW", "metrics": { "baseScore": 4.0 } },
          { "type": "primary", "version": "3.1", "vector": "CVSS:3.1/HIGH", "metrics": { "baseScore": 9.8 } }
        ],
        "epss": [
          { "date": "2026-01-01", "epss": 0.1, "percentile": 0.2 },
          { "date": "2026-02-01", "epss": 0.3, "percentile": 0.4 }
        ],
        "risk": 88.5
      },
      "artifact": {
        "name": "python3.13",
        "version": "3.13.1",
        "purl": "pkg:generic/python@3.13.1",
        "sourceInfo": ""
      }
    },
    {
      "vulnerability": {
        "id": "CVE-2026-0002",
        "severity": "Low",
        "fix": { "versions": [], "state": "" }
      },
      "artifact": {
        "name": "openssl",
        "version": "3.5.0",
        "purl": ["pkg:nix/openssl@3.5.0"],
        "sourceInfo": "/nix/store/openssl"
      }
    },
    {
      "vulnerability": {
        "id": "",
        "severity": "",
        "fix": { "versions": [], "state": "" }
      },
      "artifact": {
        "name": "basepkg",
        "version": "1.0.0",
        "purl": [],
        "sourceInfo": ""
      }
    }
  ]
}`)
	t.Setenv("GRYPE_BIN", grype)

	stdout, err := runCLI(t,
		"scan",
		"--mode", "release",
		"--sbom-dir", sbomDir,
		"--out-dir", outDir,
		"--tags", "v1.0.0",
		"--concurrency", "1",
	)
	if err != nil {
		t.Fatalf("scan failed: %v\n%s", err, stdout)
	}
	raw, err := os.ReadFile(filepath.Join(outDir, "v1.0.0", "python3.13-slim-amd64.json"))
	if err != nil {
		t.Fatalf("expected scan report: %v", err)
	}
	var report scanengine.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("failed to decode scan report: %v\n%s", err, raw)
	}
	if report.Scanner != "grype-0.99.0-test" || report.DBBuiltAt == nil || *report.DBBuiltAt != "2026-02-01T00:00:00Z" {
		t.Fatalf("unexpected scanner metadata: %#v", report)
	}
	if report.CountsBySeverity.Critical != 1 || report.CountsBySeverity.Low != 1 || report.CountsBySeverity.Unknown != 1 {
		t.Fatalf("unexpected severity counts: %#v", report.CountsBySeverity)
	}
	if len(report.Findings) != 3 || report.Findings[0].ID != "CVE-2026-0001" || report.Findings[0].Remediation.Status != "eligible" {
		t.Fatalf("unexpected normalized findings: %#v", report.Findings)
	}
	if report.Findings[2].ID != "UNKNOWN" || report.Findings[2].Layer != "base" {
		t.Fatalf("expected unknown base finding last, got %#v", report.Findings[2])
	}
	if _, err := os.Stat(filepath.Join(outDir, "v0.9.0", "python3.13-slim-amd64.json")); !os.IsNotExist(err) {
		t.Fatalf("explicit tag scan should not write older tag, stat err=%v", err)
	}
}

func TestScanBestEffortWarningsAndScanSBOMFailures(t *testing.T) {
	t.Setenv("GRYPE_BIN", filepath.Join(t.TempDir(), "missing-grype"))
	stdout, err := runCLI(t, "scan", "--mode", "catalog", "--sbom-dir", t.TempDir())
	if err != nil {
		t.Fatalf("best-effort missing grype should not fail: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "not on PATH") {
		t.Fatalf("expected warning for missing grype, got:\n%s", stdout)
	}

	grype := writeScript(t, "grype", `#!/bin/sh
set -eu
if [ "$1" = "version" ]; then
  printf '%s\n' '{"application":"grype-test"}'
  exit 0
fi
printf 'not-json'
`)
	outPath := filepath.Join(t.TempDir(), "report.json")
	_, err = scanSBOM(grype, nil, scanWorkItem{target: "java21-slim", sbomPath: filepath.Join(t.TempDir(), "sbom.json"), outPath: outPath}, "grype-test", nil, scanengine.NormalizeOptions{})
	if err == nil || !strings.Contains(err.Error(), "unparseable JSON") {
		t.Fatalf("expected unparseable JSON error, got %v", err)
	}

	failing := writeScript(t, "grype", `#!/bin/sh
set -eu
if [ "$1" = "version" ]; then
  printf '%s\n' '{'
  exit 0
fi
printf 'scan failed loudly' >&2
exit 7
`)
	version, db := grypeVersionProbe(failing)
	if version != "grype" || db != nil {
		t.Fatalf("malformed version probe should fall back, got %q %v", version, db)
	}
	_, err = scanSBOM(failing, []string{"--add-cpes-if-none"}, scanWorkItem{target: "java21-slim", sbomPath: "missing.sbom.json", outPath: outPath}, "bad", nil, scanengine.NormalizeOptions{})
	if err == nil || !strings.Contains(err.Error(), "grype failed") || !strings.Contains(err.Error(), "scan failed loudly") {
		t.Fatalf("expected grype failure with stderr snippet, got %v", err)
	}
}

func TestScanKEVCatalogLoaderBranches(t *testing.T) {
	if ptr := strPtrOrNil(""); ptr != nil {
		t.Fatalf("empty string should not produce pointer: %v", *ptr)
	}
	if ptr := strPtrOrNil("2026.06.09"); ptr == nil || *ptr != "2026.06.09" {
		t.Fatalf("expected string pointer, got %v", ptr)
	}

	catalog, status, version := loadScanKEVCatalog("")
	if catalog != nil || status != "unavailable" || version != nil {
		t.Fatalf("blank KEV path should be unavailable, got catalog=%v status=%q version=%v", catalog, status, version)
	}

	missingPath := filepath.Join(t.TempDir(), "missing-kev.json")
	catalog, status, version = loadScanKEVCatalog(missingPath)
	if catalog != nil || status != "unavailable" || version != nil {
		t.Fatalf("missing KEV path should be unavailable, got catalog=%v status=%q version=%v", catalog, status, version)
	}

	invalidPath := filepath.Join(t.TempDir(), "invalid-kev.json")
	writeTestFile(t, invalidPath, []byte(`not-json`))
	catalog, status, version = loadScanKEVCatalog(invalidPath)
	if catalog != nil || status != "unavailable" || version != nil {
		t.Fatalf("invalid KEV path should be unavailable, got catalog=%v status=%q version=%v", catalog, status, version)
	}

	validPath := filepath.Join(t.TempDir(), "kev.json")
	writeTestFile(t, validPath, []byte(`{
  "catalogVersion": "2026.06.09",
  "count": 1,
  "vulnerabilities": [
    {
      "cveID": "CVE-2026-0001",
      "vendorProject": "Python",
      "product": "Python",
      "knownRansomwareCampaignUse": "Known",
      "dateAdded": "2026-06-09"
    }
  ]
}`))
	catalog, status, version = loadScanKEVCatalog(validPath)
	if catalog == nil || status != "available" || version == nil || *version != "2026.06.09" || catalog.Count != 1 {
		t.Fatalf("valid KEV path should load catalog, got catalog=%#v status=%q version=%v", catalog, status, version)
	}
}

func TestScanStrictModeFailsWhenGrypeMissing(t *testing.T) {
	t.Setenv("GRYPE_BIN", filepath.Join(t.TempDir(), "missing-grype"))
	stdout, err := runCLI(t, "scan", "--mode", "release", "--sbom-dir", t.TempDir())
	if err == nil {
		t.Fatalf("expected strict scan failure, got success:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "not on PATH") {
		t.Fatalf("expected missing grype failure, got %v", err)
	}
}

func writeScript(t *testing.T, name, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFakeGrype(t *testing.T, resultJSON string) string {
	t.Helper()
	dir := t.TempDir()
	resultPath := filepath.Join(dir, "result.json")
	if err := os.WriteFile(resultPath, []byte(resultJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "grype")
	script := `#!/bin/sh
set -eu
if [ "$1" = "version" ]; then
  printf '%s\n' '{"version":"0.99.0-test","db":{"built":"2026-02-01T00:00:00Z"}}'
  exit 0
fi
cat "$CLEARCUTT_FAKE_GRYPE_RESULT"
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLEARCUTT_FAKE_GRYPE_RESULT", resultPath)
	return path
}
