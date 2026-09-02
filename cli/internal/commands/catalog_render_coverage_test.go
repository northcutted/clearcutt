package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogDiffAndSummaryRenderBranches(t *testing.T) {
	oldOut := out
	oldFormat := GlobalOpts.Format
	defer func() {
		out = oldOut
		GlobalOpts.Format = oldFormat
	}()

	var diffBuf bytes.Buffer
	out = &diffBuf
	printCatalogDirectoryDiff(catalogDirectoryDiff{
		OldPath:       "old",
		NewPath:       "new",
		AddedImages:   []string{"ruby3.4-distroless"},
		RemovedImages: []string{"python3.13-dev"},
		ChangedImages: []catalogImageChange{{
			ID:                "java21-distroless",
			LatestTag:         &stringChange{From: "", To: "v1"},
			ManifestDigest:    &stringChange{From: "sha256:old", To: "sha256:new"},
			PackageCount:      &intChange{From: 10, To: 12},
			CriticalFindings:  &intChange{From: 1, To: 0},
			HighFindings:      &intChange{From: 3, To: 2},
			Signature:         &boolChange{From: false, To: true},
			Provenance:        &boolChange{From: false, To: true},
			LifecycleStatus:   &stringChange{From: "preview", To: "active"},
			ProductionAllowed: &boolChange{From: false, To: true},
			EvidenceProperties: map[string]string{
				"sbom": "false -> true",
			},
		}},
	})
	diffOut := diffBuf.String()
	for _, needle := range []string{"Added images:", "Removed images:", "latestTag: missing -> v1", "evidence.sbom: false -> true"} {
		if !strings.Contains(diffOut, needle) {
			t.Fatalf("catalog diff output missing %q:\n%s", needle, diffOut)
		}
	}

	diffBuf.Reset()
	printCatalogDirectoryDiff(catalogDirectoryDiff{OldPath: "old", NewPath: "new"})
	if !strings.Contains(diffBuf.String(), "Changed images: none") {
		t.Fatalf("expected no-change diff output, got:\n%s", diffBuf.String())
	}

	summary := catalogSummaryReport{
		Owner:            "acme",
		Repo:             "platform",
		GeneratedAt:      "2026-06-06T00:00:00Z",
		LatestTag:        "v1",
		RegistryBase:     "ghcr.io/acme/platform",
		ImageCount:       2,
		ReleaseCount:     1,
		SignedCount:      1,
		ProvenanceCount:  1,
		SBOMCount:        2,
		ScanCount:        2,
		PassingCount:     1,
		CriticalFindings: 0,
		HighFindings:     2,
		LifecycleCounts:  map[string]int{"active": 2},
		TierCounts:       map[string]int{"distroless": 1, "slim": 1},
		LanguageCounts:   map[string]int{"java": 1, "ruby": 1},
	}
	var summaryBuf bytes.Buffer
	out = &summaryBuf
	GlobalOpts.Format = "table"
	if err := printCatalogSummary(summary); err != nil {
		t.Fatalf("print table summary: %v", err)
	}
	if !strings.Contains(summaryBuf.String(), "Catalog:        acme/platform") {
		t.Fatalf("unexpected table summary:\n%s", summaryBuf.String())
	}
	GlobalOpts.Format = "json"
	summaryBuf.Reset()
	if err := printCatalogSummary(summary); err != nil || !strings.Contains(summaryBuf.String(), `"imageCount": 2`) {
		t.Fatalf("unexpected JSON summary err=%v out=\n%s", err, summaryBuf.String())
	}
	GlobalOpts.Format = "yaml"
	summaryBuf.Reset()
	if err := printCatalogSummary(summary); err != nil || !strings.Contains(summaryBuf.String(), "imageCount: 2") {
		t.Fatalf("unexpected YAML summary err=%v out=\n%s", err, summaryBuf.String())
	}
}

func TestSiteOverrideBranches(t *testing.T) {
	root := t.TempDir()
	if err := applySiteOverrides(filepath.Join(root, "out"), ""); err != nil {
		t.Fatalf("empty overrides should be a no-op: %v", err)
	}

	fileSource := filepath.Join(root, "not-dir")
	if err := os.WriteFile(fileSource, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applySiteOverrides(filepath.Join(root, "out"), fileSource); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("expected non-directory override error, got %v", err)
	}

	unsupportedFile := filepath.Join(root, "unsupported-file")
	if err := os.MkdirAll(unsupportedFile, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unsupportedFile, "README.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applySiteOverrides(filepath.Join(root, "out"), unsupportedFile); err == nil || !strings.Contains(err.Error(), "unsupported site override") {
		t.Fatalf("expected unsupported file override error, got %v", err)
	}

	unsupportedDir := filepath.Join(root, "unsupported-dir")
	if err := os.MkdirAll(filepath.Join(unsupportedDir, "layouts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := applySiteOverrides(filepath.Join(root, "out"), unsupportedDir); err == nil || !strings.Contains(err.Error(), "unsupported site override directory") {
		t.Fatalf("expected unsupported directory override error, got %v", err)
	}

	outputDir := filepath.Join(root, "site")
	sourceDir := filepath.Join(root, "overrides")
	for _, dir := range []string{
		filepath.Join(outputDir, "src", "pages"),
		filepath.Join(sourceDir, ".ignored"),
		filepath.Join(sourceDir, "components"),
		filepath.Join(sourceDir, "pages", "node_modules"),
		filepath.Join(sourceDir, "pages", ".astro"),
		filepath.Join(sourceDir, "styles"),
		filepath.Join(sourceDir, "public"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(outputDir, "src", "pages", "about.astro"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	fixtures := map[string]string{
		filepath.Join(sourceDir, "components", "Badge.astro"):        "<span>Badge</span>",
		filepath.Join(sourceDir, "pages", "about.md"):                "---\ntitle: About\n---\n# About\n",
		filepath.Join(sourceDir, "pages", "raw.txt"):                 "plain",
		filepath.Join(sourceDir, "pages", "node_modules", "skip.md"): "skip",
		filepath.Join(sourceDir, "pages", ".astro", "skip.md"):       "skip",
		filepath.Join(sourceDir, "styles", "theme.css"):              ":root { color: black; }",
		filepath.Join(sourceDir, "public", "robots.txt"):             "User-agent: *\n",
		filepath.Join(sourceDir, ".ignored", "should-not-copy.txt"):  "skip",
	}
	for path, body := range fixtures {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	if err := applySiteOverrides(outputDir, sourceDir); err != nil {
		t.Fatalf("apply site overrides: %v", err)
	}
	if fileExists(filepath.Join(outputDir, "src", "pages", "about.astro")) {
		t.Fatal("markdown page override should remove conflicting astro page")
	}
	about := string(readFile(t, filepath.Join(outputDir, "src", "pages", "about.md")))
	if !strings.Contains(about, "layout: ../layouts/Base.astro") {
		t.Fatalf("markdown override did not receive layout:\n%s", about)
	}
	for _, copied := range []string{
		filepath.Join(outputDir, "src", "components", "Badge.astro"),
		filepath.Join(outputDir, "src", "pages", "raw.txt"),
		filepath.Join(outputDir, "src", "styles", "theme.css"),
		filepath.Join(outputDir, "public", "robots.txt"),
	} {
		if !fileExists(copied) {
			t.Fatalf("expected override copy at %s", copied)
		}
	}
	for _, skipped := range []string{
		filepath.Join(outputDir, "src", "pages", "node_modules", "skip.md"),
		filepath.Join(outputDir, "src", "pages", ".astro", "skip.md"),
		filepath.Join(outputDir, "should-not-copy.txt"),
	} {
		if fileExists(skipped) {
			t.Fatalf("override path should have been skipped: %s", skipped)
		}
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}
