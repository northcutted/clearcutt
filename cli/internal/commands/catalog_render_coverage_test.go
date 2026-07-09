package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
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

func TestPlatformNixAndSiteHelperBranches(t *testing.T) {
	root := t.TempDir()

	existing := "keep = true\n\n" + clearcuttNixConfigBegin + "\nold = true\n" + clearcuttNixConfigEnd + "\n\ntrailing = true\n"
	replaced := replaceManagedNixConfigBlock(existing, "new = true\n")
	if !strings.Contains(replaced, "keep = true") || !strings.Contains(replaced, "new = true") || strings.Contains(replaced, "old = true") || !strings.Contains(replaced, "trailing = true") {
		t.Fatalf("managed nix config block was not replaced correctly:\n%s", replaced)
	}
	if !strings.Contains(replaceManagedNixConfigBlock("", "new = true"), clearcuttNixConfigBegin) {
		t.Fatal("empty nix config should receive managed block")
	}
	if got := trustedNixCachePublicKey(fleet.NixCache{PublicKey: "cache-key"}); got != "cache-key" {
		t.Fatalf("trusted public key without signing key = %q", got)
	}

	xdg := filepath.Join(root, "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	userConfig, err := writeUserNixConfig("experimental-features = nix-command flakes\n")
	if err != nil {
		t.Fatalf("write user nix config: %v", err)
	}
	if !strings.HasPrefix(userConfig, xdg) || !strings.Contains(string(readFile(t, userConfig)), clearcuttNixConfigBegin) {
		t.Fatalf("unexpected user nix config %s", userConfig)
	}

	fileOutput := filepath.Join(root, "file-output")
	if err := os.WriteFile(fileOutput, []byte("not a dir"), 0o644); err != nil {
		t.Fatal("write file output seed failed")
	}
	if err := prepareBuildOutput(fileOutput, false); err == nil {
		t.Fatal("prepareBuildOutput should reject a file path")
	}
	nonEmpty := filepath.Join(root, "non-empty")
	if err := os.MkdirAll(nonEmpty, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nonEmpty, "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := prepareBuildOutput(nonEmpty, false); err == nil {
		t.Fatal("prepareBuildOutput should reject non-empty output without clean")
	}
	if err := prepareBuildOutput(nonEmpty, true); err != nil {
		t.Fatalf("prepareBuildOutput clean failed: %v", err)
	}

	templatePath := filepath.Join(root, "template")
	workDir := filepath.Join(root, "work")
	if err := os.MkdirAll(filepath.Join(templatePath, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensureNodeDependencies(workDir, templatePath, false, detectPackageManager(workDir)); err != nil {
		t.Fatalf("expected template node_modules symlink: %v", err)
	}
	if !fileExists(filepath.Join(workDir, "node_modules")) {
		t.Fatal("node_modules symlink was not created")
	}
	missingDeps := filepath.Join(root, "missing-deps")
	if err := ensureNodeDependencies(missingDeps, "", false, detectPackageManager(missingDeps)); err == nil {
		t.Fatal("ensureNodeDependencies should require install when node_modules is unavailable")
	}

	siteOut := filepath.Join(root, "site-out")
	if err := os.MkdirAll(siteOut, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeSiteConfig(siteOut, ""); err != nil {
		t.Fatalf("write default site config: %v", err)
	}
	sourceConfig := filepath.Join(root, "source.site.yaml")
	if err := os.WriteFile(sourceConfig, []byte("site:\n  title: Source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeSiteConfig(siteOut, sourceConfig); err != nil {
		t.Fatalf("copy source site config: %v", err)
	}

	rawWithFrontmatter := []byte("---\ntitle: Page\n---\n# Page\n")
	if got := string(ensureMarkdownLayout(rawWithFrontmatter, "../layouts/Base.astro")); !strings.Contains(got, "layout: ../layouts/Base.astro") {
		t.Fatalf("layout was not injected:\n%s", got)
	}
	rawWithLayout := []byte("---\nlayout: custom\n---\n# Page\n")
	if got := string(ensureMarkdownLayout(rawWithLayout, "../layouts/Base.astro")); got != string(rawWithLayout) {
		t.Fatalf("existing layout should be preserved:\n%s", got)
	}
	if got := string(ensureMarkdownLayout([]byte("# Plain\n"), "../layouts/Base.astro")); !strings.HasPrefix(got, "---\nlayout: ../layouts/Base.astro") {
		t.Fatalf("plain markdown did not receive frontmatter:\n%s", got)
	}

	t.Setenv("XDG_CONFIG_HOME", "")
	defaultUserConfig, err := userNixConfigPath()
	if err != nil {
		t.Fatalf("default user nix config path: %v", err)
	}
	if !strings.HasSuffix(filepath.ToSlash(defaultUserConfig), "/.config/nix/nix.conf") {
		t.Fatalf("unexpected default nix config path: %s", defaultUserConfig)
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
