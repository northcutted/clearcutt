package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeGrypeMatchesFixtureOutput(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "commands", "testdata", "scan", "grype-python3.13-slim.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result GrypeResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}

	dbBuiltAt := "2026-05-28T00:00:00Z"
	report := NormalizeGrype(
		result,
		"2026-05-31T00:00:00.000Z",
		"grype-0.0.0-test",
		&dbBuiltAt,
		TargetMetadata("python3.13-slim"),
	)
	got, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	expected, err := os.ReadFile(filepath.Join("..", "commands", "testdata", "scan", "expected-python3.13-slim.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(string(expected)) {
		t.Fatalf("normalized scan output drifted.\n got:\n%s\nwant:\n%s", got, expected)
	}
}

func TestParseKEVCatalogAndNormalizeAnnotatesKnownExploited(t *testing.T) {
	rawKEV := []byte(`{
  "catalogVersion": "2026.06.07",
  "dateReleased": "2026-06-07T00:00:00Z",
  "count": 1,
  "vulnerabilities": [
    {
      "cveID": "CVE-2026-6100",
      "vendorProject": "Python",
      "product": "CPython",
      "vulnerabilityName": "CPython test advisory",
      "dateAdded": "2026-06-07",
      "requiredAction": "Apply updates",
      "dueDate": "2026-06-21",
      "knownRansomwareCampaignUse": "Unknown"
    }
  ]
}`)
	kevCatalog, err := ParseKEVCatalog(rawKEV)
	if err != nil {
		t.Fatalf("parse KEV catalog: %v", err)
	}
	version := kevCatalog.CatalogVersion
	epss := 0.72
	percentile := 0.94
	report := NormalizeGrypeWithOptions(
		GrypeResult{Matches: []grypeMatch{{
			Vulnerability: grypeVuln{
				ID:       "CVE-2026-6100",
				Severity: "High",
				Fix:      grypeFix{State: "fixed", Versions: []string{"3.13.14"}},
				Epss:     []grypeEpss{{Epss: &epss, Percentile: &percentile}},
			},
			Artifact: grypeArtifact{Name: "python", Version: "3.13.13"},
		}}},
		"2026-06-07T00:00:00Z",
		"grype-test",
		nil,
		TargetMetadata("python3.13-slim"),
		NormalizeOptions{KEVCatalog: kevCatalog, KEVStatus: "available", KEVCatalogVersion: &version},
	)

	if report.KEVStatus != "available" || report.KEVCatalogVersion == nil || *report.KEVCatalogVersion != "2026.06.07" {
		t.Fatalf("unexpected KEV scan metadata: status=%q version=%v", report.KEVStatus, report.KEVCatalogVersion)
	}
	if len(report.Findings) != 1 || report.Findings[0].KEV == nil || !report.Findings[0].KEV.KnownExploited {
		t.Fatalf("expected known-exploited finding annotation, got %+v", report.Findings)
	}
	if report.Findings[0].KEV.VendorProject == nil || *report.Findings[0].KEV.VendorProject != "Python" {
		t.Fatalf("unexpected KEV vendor metadata: %+v", report.Findings[0].KEV)
	}
}

func TestScanClassificationBranchMatrix(t *testing.T) {
	languages := map[string]string{
		"core":   "Core",
		"java":   "Java",
		"node":   "Node.js",
		"python": "Python",
		"go":     "Go",
		"dotnet": ".NET",
		"rust":   "Rust",
		"cc":     "C/C++",
		"other":  "other",
	}
	for in, want := range languages {
		if got := displayLanguage(in); got != want {
			t.Fatalf("displayLanguage(%q) = %q, want %q", in, got, want)
		}
	}

	primaryPackages := []struct {
		meta targetMeta
		pkg  string
	}{
		{TargetMetadata("python3.14-slim"), "python3.14"},
		{TargetMetadata("java21-dev"), "openjdk-headless"},
		{TargetMetadata("node22-dev"), "nodejs_22"},
		{TargetMetadata("go1.26-dev"), "go_1_26"},
		{TargetMetadata("dotnet8-slim"), "aspnetcore-runtime"},
		{TargetMetadata("rust1.95-dev"), "cargo"},
		{TargetMetadata("cc15-dev"), "clang"},
	}
	for _, tc := range primaryPackages {
		if !isPrimaryRuntimePackage(tc.meta, tc.pkg) {
			t.Fatalf("%s should be primary for %+v", tc.pkg, tc.meta)
		}
		if classifyLayer(tc.meta, tc.pkg, "", nil) != "runtime" {
			t.Fatalf("%s should classify as runtime package", tc.pkg)
		}
	}

	java := TargetMetadata("java21-slim")
	inclusions := map[string]string{
		"openjdk":        "primary_runtime",
		"nss-cacert":     "trust_store",
		"bash":           "tier_tooling",
		"cups":           "java_compatibility",
		"libtiff":        "java_compatibility",
		"zlib":           "runtime_dependency",
		"transitive-lib": "transitive_runtime",
	}
	for pkg, want := range inclusions {
		if got := inclusionMetadata(java, pkg, "runtime").Category; got != want {
			t.Fatalf("inclusionMetadata(%q) = %q, want %q", pkg, got, want)
		}
	}
	if got := inclusionMetadata(java, "glibc", "base").Category; got != "base_image" {
		t.Fatalf("base inclusion category = %q", got)
	}
	outputHashPurl := "pkg:generic/pkg?outputhash=abc"
	if got := classifyLayer(TargetMetadata("node22-slim"), "pkg", "", &outputHashPurl); got != "runtime" {
		t.Fatalf("outputhash purl should classify as runtime, got %q", got)
	}
}
