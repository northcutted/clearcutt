package commands

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/catalog"
	"github.com/northcutted/clearcutt/internal/catalogbuild"
	"github.com/northcutted/clearcutt/internal/fleet"
)

func TestCatalogValidateSummarizeAndInspectNamespace(t *testing.T) {
	validateOut, err := runCLI(t, "--catalog", fixtureCatalog(), "catalog", "validate")
	if err != nil {
		t.Fatalf("catalog validate should pass with warnings: %v\n%s", err, validateOut)
	}
	if !strings.Contains(validateOut, "0 error(s)") || !strings.Contains(validateOut, "layerDigest mapping is unavailable") {
		t.Fatalf("expected validation warning output, got:\n%s", validateOut)
	}

	strictOut, err := runCLI(t, "--catalog", fixtureCatalog(), "catalog", "validate", "--warnings-as-errors")
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("warnings-as-errors should return ErrCheckFailed, got %v\n%s", err, strictOut)
	}

	schemaOut, err := runCLI(t, "--catalog", fixtureCatalog(), "catalog", "validate", "--schema-version", catalog.ImageRecordSchemaVersion)
	if !errors.Is(err, ErrCheckFailed) || !strings.Contains(schemaOut, "schemaVersion <missing>") {
		t.Fatalf("schema-version should require generated image records, got err=%v\n%s", err, schemaOut)
	}

	summaryOut, err := runCLI(t, "--catalog", fixtureCatalog(), "--format", "json", "catalog", "summarize")
	if err != nil {
		t.Fatalf("catalog summarize failed: %v\n%s", err, summaryOut)
	}
	var summary catalogSummaryReport
	if err := json.Unmarshal([]byte(summaryOut), &summary); err != nil {
		t.Fatalf("failed to decode summary JSON: %v\n%s", err, summaryOut)
	}
	if summary.ImageCount != 1 || summary.SignedCount != 1 || summary.SBOMCount != 1 {
		t.Fatalf("unexpected summary: %#v", summary)
	}

	inspectOut, err := runCLI(t, "--catalog", fixtureCatalog(), "catalog", "inspect", "java21-distroless")
	if err != nil {
		t.Fatalf("catalog inspect failed: %v\n%s", err, inspectOut)
	}
	if !strings.Contains(inspectOut, "Digest Reference:") || !strings.Contains(inspectOut, "SPDX SBOMs:") {
		t.Fatalf("catalog inspect did not delegate to image inspector:\n%s", inspectOut)
	}
}

func TestCatalogDirectoryDiffReportsIndexLevelChanges(t *testing.T) {
	oldDir := copyFixtureCatalog(t)
	newDir := copyFixtureCatalog(t)

	indexPath := filepath.Join(newDir, "index.json")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	var index catalog.CatalogIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatal(err)
	}
	newDigest := "sha256:changed"
	index.Images[0].LatestManifestDigest = &newDigest
	index.Images[0].LatestPackageCount++
	if index.Images[0].VulnSummary == nil {
		index.Images[0].VulnSummary = &catalog.VulnSummary{}
	}
	index.Images[0].VulnSummary.High = 7
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(indexPath, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, err := runCLI(t, "--format", "json", "catalog", "diff", "--old", oldDir, "--new", newDir)
	if err != nil {
		t.Fatalf("catalog diff failed: %v\n%s", err, stdout)
	}
	var diff catalogDirectoryDiff
	if err := json.Unmarshal([]byte(stdout), &diff); err != nil {
		t.Fatalf("failed to decode diff JSON: %v\n%s", err, stdout)
	}
	if len(diff.ChangedImages) != 1 || diff.ChangedImages[0].ManifestDigest == nil || diff.ChangedImages[0].HighFindings == nil {
		t.Fatalf("expected digest and high CVE changes, got %#v", diff)
	}
}

func TestCatalogSiteScaffoldCopiesTemplateAndCatalog(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "site")
	stdout, err := runCLI(t, "catalog", "site", "scaffold", "--catalog", fixtureCatalog(), "--output", outDir)
	if err != nil {
		t.Fatalf("catalog site scaffold failed: %v\n%s", err, stdout)
	}
	for _, path := range []string{
		filepath.Join(outDir, "package.json"),
		filepath.Join(outDir, "astro.config.mjs"),
		filepath.Join(outDir, "README.md"),
		filepath.Join(outDir, "clearcutt.site.yaml"),
		filepath.Join(outDir, "src", "lib", "catalog.ts"),
		filepath.Join(outDir, "public", "catalog", "index.json"),
		filepath.Join(outDir, "public", "catalog", "images", "java21-distroless.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected scaffolded file %s: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "src", "data", "catalog", "index.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scaffold should not copy repo-local src/data/catalog, stat err=%v", err)
	}
	configRaw, err := os.ReadFile(filepath.Join(outDir, "clearcutt.site.yaml"))
	if err != nil {
		t.Fatalf("expected scaffolded site config: %v", err)
	}
	for _, want := range []string{
		"kyvernoPolicies: false",
		"sourceRepo:",
		"registry:",
		"support:",
		"terminology:",
	} {
		if !strings.Contains(string(configRaw), want) {
			t.Fatalf("expected scaffolded site config to contain %q, got:\n%s", want, configRaw)
		}
	}
	readmeRaw, err := os.ReadFile(filepath.Join(outDir, "README.md"))
	if err != nil {
		t.Fatalf("expected scaffolded README: %v", err)
	}
	for _, want := range []string{
		"clearcutt.site.yaml",
		"site-overrides",
		"site.features",
		"site.terminology",
		"source repository",
		"registry",
	} {
		if !strings.Contains(string(readmeRaw), want) {
			t.Fatalf("expected scaffolded README to contain %q, got:\n%s", want, readmeRaw)
		}
	}
	assertRawEvidenceDirs(t, filepath.Join(outDir, "public", "catalog"))
	if !strings.Contains(stdout, "npm run dev") {
		t.Fatalf("expected next-step output, got:\n%s", stdout)
	}

	stdout, err = runCLI(t, "catalog", "site", "scaffold", "--catalog", fixtureCatalog(), "--output", outDir)
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("expected non-empty output protection, got err=%v\n%s", err, stdout)
	}
}

func TestCatalogSiteScaffoldWritesReadmeForTemplateWithoutOne(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	outDir := filepath.Join(t.TempDir(), "site")

	stdout, err := runCLI(t,
		"catalog", "site", "scaffold",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--output", outDir,
	)
	if err != nil {
		t.Fatalf("catalog site scaffold failed: %v\n%s", err, stdout)
	}

	raw, err := os.ReadFile(filepath.Join(outDir, "README.md"))
	if err != nil {
		t.Fatalf("expected generated README: %v", err)
	}
	for _, want := range []string{
		"ClearCutt Catalog Site",
		"public/catalog",
		"clearcutt.site.yaml",
		"site-overrides",
		"Kyverno",
	} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("expected generated README to contain %q, got:\n%s", want, raw)
		}
	}
}

func TestCatalogSiteScaffoldPreservesTemplateReadme(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	const customReadme = "# Custom Catalog Template\n\nInternal docs stay here.\n"
	if err := os.WriteFile(filepath.Join(templateDir, "README.md"), []byte(customReadme), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "site")

	stdout, err := runCLI(t,
		"catalog", "site", "scaffold",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--output", outDir,
	)
	if err != nil {
		t.Fatalf("catalog site scaffold failed: %v\n%s", err, stdout)
	}
	raw, err := os.ReadFile(filepath.Join(outDir, "README.md"))
	if err != nil {
		t.Fatalf("expected copied README: %v", err)
	}
	if string(raw) != customReadme {
		t.Fatalf("expected custom template README to be preserved, got:\n%s", raw)
	}
}

func TestCatalogSiteScaffoldAppliesSiteOverrides(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	if err := os.MkdirAll(filepath.Join(templateDir, "src", "pages"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(templateDir, "src", "pages", "index.astro"), []byte("<h1>Template home</h1>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	overridesDir := filepath.Join(t.TempDir(), "site-overrides")
	for _, dir := range []string{
		filepath.Join(overridesDir, "components"),
		filepath.Join(overridesDir, "pages"),
		filepath.Join(overridesDir, "styles"),
		filepath.Join(overridesDir, "public", "branding"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(overridesDir, "components", "ImageHeader.astro"): "<section>Custom image header</section>\n",
		filepath.Join(overridesDir, "pages", "index.md"):               "# Custom home\n",
		filepath.Join(overridesDir, "styles", "theme.css"):             ":root { --brand: #123456; }\n",
		filepath.Join(overridesDir, "public", "branding", "logo.svg"):  "<svg viewBox=\"0 0 1 1\"></svg>\n",
	}
	for path, contents := range files {
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	outDir := filepath.Join(t.TempDir(), "site")
	stdout, err := runCLI(t,
		"catalog", "site", "scaffold",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--overrides", overridesDir,
		"--output", outDir,
	)
	if err != nil {
		t.Fatalf("catalog site scaffold --overrides failed: %v\n%s", err, stdout)
	}
	for rel, want := range map[string]string{
		filepath.Join("src", "components", "ImageHeader.astro"): "<section>Custom image header</section>\n",
		filepath.Join("src", "styles", "theme.css"):             ":root { --brand: #123456; }\n",
		filepath.Join("public", "branding", "logo.svg"):         "<svg viewBox=\"0 0 1 1\"></svg>\n",
	} {
		raw, err := os.ReadFile(filepath.Join(outDir, rel))
		if err != nil {
			t.Fatalf("expected override file %s: %v", rel, err)
		}
		if string(raw) != want {
			t.Fatalf("override file %s = %q, want %q", rel, raw, want)
		}
	}
	raw, err := os.ReadFile(filepath.Join(outDir, "src", "pages", "index.md"))
	if err != nil {
		t.Fatalf("expected markdown page override: %v", err)
	}
	if !strings.Contains(string(raw), "layout: ../layouts/Base.astro") || !strings.Contains(string(raw), "# Custom home") {
		t.Fatalf("markdown page override should get the default layout, got:\n%s", raw)
	}
	if _, err := os.Stat(filepath.Join(outDir, "public", "catalog", "index.json")); err != nil {
		t.Fatalf("expected scaffolded catalog to remain present after overrides: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "src", "pages", "index.astro")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("page override should remove conflicting index.astro, stat err=%v", err)
	}
	if !strings.Contains(stdout, "[site] applied overrides from "+overridesDir) {
		t.Fatalf("expected override output, got:\n%s", stdout)
	}
}

func TestCatalogSiteScaffoldRejectsUnsupportedOverrideRoot(t *testing.T) {
	overridesDir := filepath.Join(t.TempDir(), "site-overrides")
	if err := os.MkdirAll(filepath.Join(overridesDir, "layouts"), 0o755); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(t.TempDir(), "site")
	stdout, err := runCLI(t,
		"catalog", "site", "scaffold",
		"--catalog", fixtureCatalog(),
		"--overrides", overridesDir,
		"--output", outDir,
	)
	if err == nil || !strings.Contains(err.Error(), `unsupported site override directory "layouts"`) {
		t.Fatalf("expected unsupported override root error, got err=%v\n%s", err, stdout)
	}
}

func TestCatalogSiteEjectCopiesTemplateWithoutCatalogData(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	outDir := filepath.Join(t.TempDir(), "ejected")

	stdout, err := runCLI(t,
		"catalog", "site", "eject",
		"--template", templateDir,
		"--output", outDir,
	)
	if err != nil {
		t.Fatalf("catalog site eject failed: %v\n%s", err, stdout)
	}
	for _, path := range []string{
		filepath.Join(outDir, "package.json"),
		filepath.Join(outDir, "astro.config.mjs"),
		filepath.Join(outDir, "clearcutt.site.yaml"),
		filepath.Join(outDir, "src", "lib", "catalog.ts"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected ejected file %s: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "public", "catalog", "index.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("eject should not copy catalog data, stat err=%v", err)
	}
	if !strings.Contains(stdout, "Ejected catalog site template") || !strings.Contains(stdout, "add catalog data under public/catalog") {
		t.Fatalf("expected eject next-step output, got:\n%s", stdout)
	}

	stdout, err = runCLI(t,
		"catalog", "site", "eject",
		"--template", templateDir,
		"--output", outDir,
	)
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("expected non-empty output protection, got err=%v\n%s", err, stdout)
	}
}

func TestCatalogSiteBuildRequiresInstallWhenDependenciesMissing(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	outDir := filepath.Join(t.TempDir(), "dist")

	stdout, err := runCLI(t,
		"catalog", "site", "build",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--output", outDir,
	)
	if err == nil || !strings.Contains(err.Error(), "dependencies are not installed") {
		t.Fatalf("expected missing dependency error, got err=%v\n%s", err, stdout)
	}
}

func TestCatalogSiteBuildRunsInstallAndCopiesStaticOutput(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "npm.log")
	fakeNPM := filepath.Join(binDir, "npm")
	if err := os.WriteFile(fakeNPM, []byte(`#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FAKE_NPM_LOG"
if [ "$1" = "install" ] || [ "$1" = "ci" ]; then
  mkdir -p node_modules
  exit 0
fi
if [ "$1" = "run" ] && [ "${2:-}" = "build" ]; then
  mkdir -p dist
  printf 'base=%s\n' "${BASE_PATH:-}" > dist/index.html
  cp -R public/catalog dist/catalog
  exit 0
fi
exit 2
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_NPM_LOG", logPath)

	outDir := filepath.Join(t.TempDir(), "dist")
	stdout, err := runCLI(t,
		"catalog", "site", "build",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--output", outDir,
		"--install",
		"--base-path", "/docs",
	)
	if err != nil {
		t.Fatalf("catalog site build failed: %v\n%s", err, stdout)
	}
	index, err := os.ReadFile(filepath.Join(outDir, "index.html"))
	if err != nil {
		t.Fatalf("expected built index: %v", err)
	}
	if string(index) != "base=/docs\n" {
		t.Fatalf("BASE_PATH was not passed to build: %q", index)
	}
	if _, err := os.Stat(filepath.Join(outDir, "catalog", "index.json")); err != nil {
		t.Fatalf("expected catalog assets in built output: %v", err)
	}
	logRaw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logRaw)
	if !strings.Contains(log, "install") || !strings.Contains(log, "run build") {
		t.Fatalf("expected install and build npm calls, got:\n%s", log)
	}
	if !strings.Contains(stdout, "Built catalog site at") {
		t.Fatalf("expected build success output, got:\n%s", stdout)
	}
}

func TestCatalogSiteBuildCanGenerateCatalogFromFleetConfig(t *testing.T) {
	const target = "python3.13-slim"
	const tag = "v1.0.0"
	const publishedAt = "2026-05-29T13:44:59Z"

	templateDir := writeMinimalSiteTemplate(t)
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "npm.log")
	fakeNPM := filepath.Join(binDir, "npm")
	if err := os.WriteFile(fakeNPM, []byte(`#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FAKE_NPM_LOG"
if [ "$1" = "install" ] || [ "$1" = "ci" ]; then
  mkdir -p node_modules
  exit 0
fi
if [ "$1" = "run" ] && [ "${2:-}" = "build" ]; then
  mkdir -p dist
  printf 'generated\n' > dist/index.html
  cp -R public/catalog dist/catalog
  exit 0
fi
exit 2
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_NPM_LOG", logPath)
	t.Setenv("SBOM_CACHE_DIR", filepath.Join(t.TempDir(), "sboms"))
	t.Setenv("ENRICHMENT_DIR", filepath.Join(t.TempDir(), "missing-enrichment"))
	t.Setenv("VULN_DIR", filepath.Join(t.TempDir(), "missing-vulns"))

	spdxRaw, err := os.ReadFile(filepath.Join("testdata", "catalog", "spdx-fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeCatalogReleaseSource{
		releases: []catalogbuild.Release{{
			Tag:         tag,
			Name:        "v1.0.0",
			PublishedAt: publishedAt,
			Assets: []catalogbuild.Asset{
				{Name: target + "-amd64.sbom.json", URL: "https://example.invalid/" + target + "-amd64.sbom.json"},
			},
		}},
		assets: map[string][]byte{
			target + "-amd64.sbom.json": spdxRaw,
		},
	}
	oldNewReleaseSource := newReleaseSource
	t.Cleanup(func() { newReleaseSource = oldNewReleaseSource })
	newReleaseSource = func(owner, repo, token string) catalogbuild.ReleaseSource {
		if owner != "acme" || repo != "platform" {
			t.Fatalf("unexpected release source request for %s/%s", owner, repo)
		}
		return source
	}

	cfg := fleet.DefaultConfig("acme", "platform")
	cfg.Matrix.Languages = []string{"python3.13"}
	cfg.Matrix.Tiers = []string{"slim"}
	cfg.Catalog.ReleaseLimit = 1
	configRaw, err := fleet.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal fleet config: %v", err)
	}
	configPath := filepath.Join(t.TempDir(), "clearcutt.fleet.yaml")
	if err := os.WriteFile(configPath, configRaw, 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(t.TempDir(), "site-dist")
	stdout, err := runCLI(t,
		"catalog", "site", "build",
		"--config", configPath,
		"--template", templateDir,
		"--output", outDir,
		"--install",
	)
	if err != nil {
		t.Fatalf("catalog site build --config failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"[gather] wrote python3.13-slim (1 releases)",
		"[generate] wrote summary.json",
		"[site-build] generated catalog data from " + configPath,
		"Built catalog site at " + outDir,
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected one-shot build output to contain %q, got:\n%s", want, stdout)
		}
	}
	raw, err := os.ReadFile(filepath.Join(outDir, "catalog", "index.json"))
	if err != nil {
		t.Fatalf("expected built catalog index: %v", err)
	}
	var index catalog.CatalogIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatalf("failed to decode built catalog index: %v\n%s", err, raw)
	}
	if index.SchemaVersion != catalog.CatalogIndexSchemaVersion || len(index.Images) != 1 || index.Images[0].ID != target {
		t.Fatalf("unexpected generated index in built site: %#v", index)
	}
	if _, err := os.Stat(filepath.Join(outDir, "catalog", "schemas", "image-record.v1.schema.json")); err != nil {
		t.Fatalf("expected generated schema assets in built site: %v", err)
	}
	if !contains(source.downloads, target+"-amd64.sbom.json") {
		t.Fatalf("expected one-shot build to download SBOM asset, got %v", source.downloads)
	}
}

func TestCatalogSiteBuildCanGenerateCatalogFromImagesInventory(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "npm.log")
	fakeNPM := filepath.Join(binDir, "npm")
	if err := os.WriteFile(fakeNPM, []byte(`#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FAKE_NPM_LOG"
if [ "$1" = "install" ] || [ "$1" = "ci" ]; then
  mkdir -p node_modules
  exit 0
fi
if [ "$1" = "run" ] && [ "${2:-}" = "build" ]; then
  mkdir -p dist
  printf 'generated\n' > dist/index.html
  cp -R public/catalog dist/catalog
  exit 0
fi
exit 2
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_NPM_LOG", logPath)

	inventoryPath := filepath.Join(t.TempDir(), "images.yaml")
	if err := os.WriteFile(inventoryPath, []byte(`images:
  - id: java21-distroless
    image: ghcr.io/acme/base/java21:v1.2.3
    language:
      id: java
      displayName: Java
      version: "21"
    tier: distroless
    architectures:
      - amd64
`), 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(t.TempDir(), "site-dist")
	stdout, err := runCLI(t,
		"catalog", "site", "build",
		"--images", inventoryPath,
		"--template", templateDir,
		"--output", outDir,
		"--install",
		"--owner", "acme",
		"--repo", "base-images",
		"--generated-at", "2026-06-04T12:00:00Z",
	)
	if err != nil {
		t.Fatalf("catalog site build --images failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"[generate] wrote 1 generic OCI image record(s)",
		"[site-build] generated catalog data from " + inventoryPath,
		"Built catalog site at " + outDir,
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected one-shot images build output to contain %q, got:\n%s", want, stdout)
		}
	}
	index, err := catalog.LoadCatalogIndex(filepath.Join(outDir, "catalog"))
	if err != nil {
		t.Fatalf("expected built catalog index: %v", err)
	}
	if index.Owner != "acme" || index.Repo != "base-images" || len(index.Images) != 1 || index.Images[0].ID != "java21-distroless" {
		t.Fatalf("unexpected one-shot images catalog index: %#v", index)
	}
	assertRawEvidenceDirs(t, filepath.Join(outDir, "catalog"))
}

func TestCatalogSiteBuildRejectsConflictingGeneratedCatalogInputs(t *testing.T) {
	inventoryPath := filepath.Join(t.TempDir(), "images.yaml")
	if err := os.WriteFile(inventoryPath, []byte("images: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, err := runCLI(t,
		"catalog", "site", "build",
		"--config", "clearcutt.fleet.yaml",
		"--images", inventoryPath,
		"--output", filepath.Join(t.TempDir(), "site"),
	)
	if err == nil || !strings.Contains(err.Error(), "--config and --images are mutually exclusive") {
		t.Fatalf("expected conflicting input error, got err=%v\n%s", err, stdout)
	}
}

func TestCatalogSitePreviewPrintsFallbackWhenDependenciesMissing(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	workDir := filepath.Join(t.TempDir(), "preview")

	stdout, err := runCLI(t,
		"catalog", "site", "preview",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--work-dir", workDir,
	)
	if err != nil {
		t.Fatalf("preview fallback should not fail: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"Catalog preview was not started",
		"npm install",
		"npm run dev -- --host 127.0.0.1 --port 4321",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected fallback output to contain %q, got:\n%s", want, stdout)
		}
	}
	if _, err := os.Stat(filepath.Join(workDir, "public", "catalog", "index.json")); err != nil {
		t.Fatalf("preview fallback should leave reusable work-dir materialized: %v", err)
	}
}

func TestCatalogSitePreviewRunsInstallAndDevServerCommand(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "npm.log")
	fakeNPM := filepath.Join(binDir, "npm")
	if err := os.WriteFile(fakeNPM, []byte(`#!/bin/sh
set -eu
printf '%s BASE_PATH=%s\n' "$*" "${BASE_PATH:-}" >> "$FAKE_NPM_LOG"
if [ "$1" = "install" ] || [ "$1" = "ci" ]; then
  mkdir -p node_modules
  exit 0
fi
if [ "$1" = "run" ] && [ "${2:-}" = "dev" ]; then
  exit 0
fi
exit 2
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_NPM_LOG", logPath)

	workDir := filepath.Join(t.TempDir(), "preview")
	stdout, err := runCLI(t,
		"catalog", "site", "preview",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--work-dir", workDir,
		"--install",
		"--base-path", "/catalog",
		"--host", "0.0.0.0",
		"--port", "4567",
	)
	if err != nil {
		t.Fatalf("catalog site preview failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "http://0.0.0.0:4567") {
		t.Fatalf("expected preview URL output, got:\n%s", stdout)
	}
	logRaw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logRaw)
	for _, want := range []string{
		"install BASE_PATH=",
		"run dev -- --host 0.0.0.0 --port 4567 BASE_PATH=/catalog",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("expected npm log to contain %q, got:\n%s", want, log)
		}
	}
}

func TestCatalogGenerateWritesSummaryJSONFromExistingRecords(t *testing.T) {
	outDir := copyFixtureCatalog(t)
	oldNewReleaseSource := newReleaseSource
	t.Cleanup(func() { newReleaseSource = oldNewReleaseSource })
	newReleaseSource = func(owner, repo, token string) catalogbuild.ReleaseSource {
		return &fakeCatalogReleaseSource{}
	}

	stdout, err := runCLI(t,
		"catalog", "generate",
		"--owner", "northcutted",
		"--repo", "clearcutt",
		"--registry-base", "ghcr.io/northcutted/clearcutt",
		"--output", outDir,
		"--vuln-dir", filepath.Join(t.TempDir(), "missing-vulns"),
		"--generated-at", "2026-06-03T12:00:00Z",
	)
	if err != nil {
		t.Fatalf("catalog generate failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "[generate] wrote summary.json") {
		t.Fatalf("expected summary output, got:\n%s", stdout)
	}
	raw, err := os.ReadFile(filepath.Join(outDir, "summary.json"))
	if err != nil {
		t.Fatalf("expected generated summary.json: %v", err)
	}
	var summary catalogSummaryReport
	if err := json.Unmarshal(raw, &summary); err != nil {
		t.Fatalf("failed to decode generated summary: %v\n%s", err, raw)
	}
	if summary.ImageCount != 1 || summary.LatestTag == "" {
		t.Fatalf("unexpected generated summary: %#v", summary)
	}
	for _, schemaName := range []string{"catalog-index.v1.schema.json", "image-record.v1.schema.json"} {
		schemaRaw, err := os.ReadFile(filepath.Join(outDir, "schemas", schemaName))
		if err != nil {
			t.Fatalf("expected generated schema %s: %v", schemaName, err)
		}
		if !strings.Contains(string(schemaRaw), "schemaVersion") {
			t.Fatalf("expected generated schema %s to describe schemaVersion", schemaName)
		}
		if schemaName == "image-record.v1.schema.json" && !strings.Contains(string(schemaRaw), "catalog-index.v1.schema.json#/definitions/Lifecycle") {
			t.Fatalf("expected image schema to reference versioned catalog index schema:\n%s", schemaRaw)
		}
	}
	index, err := catalog.LoadCatalogIndex(outDir)
	if err != nil {
		t.Fatalf("expected generated index: %v", err)
	}
	if index.SchemaVersion != catalog.CatalogIndexSchemaVersion {
		t.Fatalf("expected generated index schemaVersion %q, got %q", catalog.CatalogIndexSchemaVersion, index.SchemaVersion)
	}
	if index.Generator == nil || index.Generator.Name != "clearcutt" || index.Generator.Version != Version || index.Generator.Commit != "unknown" {
		t.Fatalf("unexpected generated index generator metadata: %#v", index.Generator)
	}
	if index.Source == nil || index.Source.Owner != "northcutted" || index.Source.Repo != "clearcutt" || index.Source.RegistryBase != "ghcr.io/northcutted/clearcutt" {
		t.Fatalf("unexpected generated index source metadata: %#v", index.Source)
	}
	if index.Summary == nil || index.Summary.ImageCount != 1 || index.Summary.ReleaseCount != 1 || index.Summary.SBOMCount != 1 || index.Summary.ScanCount != 1 {
		t.Fatalf("unexpected generated index summary: %#v", index.Summary)
	}
	assertRawEvidenceDirs(t, outDir)
	if len(index.Images) != 1 {
		t.Fatalf("expected one generated image summary, got %d", len(index.Images))
	}
	record, err := catalog.LoadImageRecord(outDir, index.Images[0].ID)
	if err != nil {
		t.Fatalf("expected generated image record: %v", err)
	}
	if record.SchemaVersion != catalog.ImageRecordSchemaVersion {
		t.Fatalf("expected generated image schemaVersion %q, got %q", catalog.ImageRecordSchemaVersion, record.SchemaVersion)
	}
	validateOut, err := runCLI(t, "--catalog", outDir, "catalog", "validate", "--schema-version", catalog.CatalogIndexSchemaVersion)
	if err != nil {
		t.Fatalf("generated catalog should satisfy index schema version: %v\n%s", err, validateOut)
	}
	validateOut, err = runCLI(t, "--catalog", outDir, "catalog", "validate", "--schema-version", catalog.ImageRecordSchemaVersion)
	if err != nil {
		t.Fatalf("generated catalog should satisfy image schema version: %v\n%s", err, validateOut)
	}
}

func TestCatalogGenerateFromGenericOCIImagesInventory(t *testing.T) {
	inventoryPath := filepath.Join(t.TempDir(), "images.yaml")
	if err := os.WriteFile(inventoryPath, []byte(`images:
  - id: java21-distroless
    image: ghcr.io/acme/base/java21:v1.2.3
    language:
      id: java
      displayName: Java
      version: "21"
    tier: distroless
    architectures:
      - amd64
      - arm64
`), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "catalog")

	stdout, err := runCLI(t,
		"catalog", "generate",
		"--images", inventoryPath,
		"--output", outDir,
		"--owner", "acme",
		"--repo", "base-images",
		"--generated-at", "2026-06-04T12:00:00Z",
	)
	if err != nil {
		t.Fatalf("catalog generate --images failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"[generate] wrote 1 generic OCI image record(s)",
		"[generate] wrote summary.json",
		"[generate] wrote schemas/",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected generic generate output to contain %q, got:\n%s", want, stdout)
		}
	}

	index, err := catalog.LoadCatalogIndex(outDir)
	if err != nil {
		t.Fatalf("expected generated index: %v", err)
	}
	if index.SchemaVersion != catalog.CatalogIndexSchemaVersion {
		t.Fatalf("expected index schemaVersion %q, got %q", catalog.CatalogIndexSchemaVersion, index.SchemaVersion)
	}
	if index.Owner != "acme" || index.Repo != "base-images" || index.RegistryBase != "ghcr.io" {
		t.Fatalf("unexpected generic index identity: %#v", index)
	}
	if index.Generator == nil || index.Generator.Name != "clearcutt" || index.Generator.Version != Version || index.Generator.Commit != "unknown" {
		t.Fatalf("unexpected generic generator metadata: %#v", index.Generator)
	}
	if index.Source == nil || index.Source.Owner != "acme" || index.Source.Repo != "base-images" || index.Source.RegistryBase != "ghcr.io" {
		t.Fatalf("unexpected generic source metadata: %#v", index.Source)
	}
	if index.Summary == nil || index.Summary.ImageCount != 1 || index.Summary.ReleaseCount != 1 || index.Summary.SignedCount != 0 || index.Summary.SBOMCount != 0 {
		t.Fatalf("unexpected generic index summary: %#v", index.Summary)
	}
	assertRawEvidenceDirs(t, outDir)
	if len(index.Images) != 1 {
		t.Fatalf("expected one image summary, got %d", len(index.Images))
	}
	summary := index.Images[0]
	if summary.ID != "java21-distroless" || summary.LatestTag != "v1.2.3" || summary.Language != "java" || summary.Tier != "distroless" {
		t.Fatalf("unexpected generic image summary: %#v", summary)
	}
	if !contains(summary.Architectures, "amd64") || !contains(summary.Architectures, "arm64") {
		t.Fatalf("expected amd64 and arm64 summary architectures, got %v", summary.Architectures)
	}
	if summary.Signed || summary.Provenance || summary.Passed {
		t.Fatalf("generic inventory should preserve unavailable evidence as false states: %#v", summary)
	}
	if summary.Evidence == nil || summary.Evidence.ArchCount != 2 || summary.Evidence.Signature || summary.Evidence.Provenance || summary.Evidence.SBOM {
		t.Fatalf("unexpected generic summary evidence: %#v", summary.Evidence)
	}

	record, err := catalog.LoadImageRecord(outDir, "java21-distroless")
	if err != nil {
		t.Fatalf("expected generated image record: %v", err)
	}
	if record.SchemaVersion != catalog.ImageRecordSchemaVersion {
		t.Fatalf("expected image schemaVersion %q, got %q", catalog.ImageRecordSchemaVersion, record.SchemaVersion)
	}
	if record.Registry != "ghcr.io" || record.ImageName != "java21" || record.FullName != "ghcr.io/acme/base/java21" {
		t.Fatalf("unexpected generic image reference fields: %#v", record)
	}
	if len(record.Releases) != 1 {
		t.Fatalf("expected one generic release, got %d", len(record.Releases))
	}
	release := record.Releases[0]
	if release.Tag != "v1.2.3" || !release.IsLatest || release.ManifestDigest != nil || release.Signature != nil || release.Provenance != nil {
		t.Fatalf("unexpected generic release fields: %#v", release)
	}
	if release.Evidence == nil || release.Evidence.ArchCount != 2 || release.Evidence.Signature || release.Evidence.Provenance || release.Evidence.SBOM {
		t.Fatalf("unexpected generic release evidence: %#v", release.Evidence)
	}
	if len(release.Architectures) != 2 {
		t.Fatalf("expected two generic architectures, got %d", len(release.Architectures))
	}
	for _, arch := range release.Architectures {
		if arch.OS != "linux" || arch.SBOM.PackageCount != 0 || len(arch.SBOM.Packages) != 0 || arch.TestResults != nil || arch.Vulnerabilities != nil {
			t.Fatalf("unexpected generic architecture payload: %#v", arch)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "schemas", "catalog-index.v1.schema.json")); err != nil {
		t.Fatalf("expected generated catalog index schema: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "schemas", "image-record.v1.schema.json")); err != nil {
		t.Fatalf("expected generated image record schema: %v", err)
	}

	validateOut, err := runCLI(t, "--catalog", outDir, "catalog", "validate", "--schema-version", catalog.CatalogIndexSchemaVersion)
	if err != nil {
		t.Fatalf("generic catalog should satisfy index schema version: %v\n%s", err, validateOut)
	}
	validateOut, err = runCLI(t, "--catalog", outDir, "catalog", "validate", "--schema-version", catalog.ImageRecordSchemaVersion)
	if err != nil {
		t.Fatalf("generic catalog should satisfy image schema version: %v\n%s", err, validateOut)
	}
	if !strings.Contains(validateOut, "missing signature evidence") || !strings.Contains(validateOut, "missing or incomplete SBOM evidence") {
		t.Fatalf("expected generic validation warnings for unavailable evidence, got:\n%s", validateOut)
	}
}

func TestCatalogGenerateFromGenericOCIImagesRejectsUnsupportedArchitecture(t *testing.T) {
	inventoryPath := filepath.Join(t.TempDir(), "images.yaml")
	if err := os.WriteFile(inventoryPath, []byte(`images:
  - id: node-dev
    image: registry.example.com/platform/node-dev:v1
    language:
      id: node
      displayName: Node.js
      version: "22"
    tier: dev
    architectures:
      - s390x
`), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "catalog")

	stdout, err := runCLI(t,
		"catalog", "generate",
		"--images", inventoryPath,
		"--output", outDir,
		"--generated-at", "2026-06-04T12:00:00Z",
	)
	if err == nil || !strings.Contains(err.Error(), `unsupported architecture "s390x"`) {
		t.Fatalf("expected unsupported architecture error, got err=%v\n%s", err, stdout)
	}
}

func copyFixtureCatalog(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "catalog")
	if err := copyCatalogTree(fixtureCatalog(), dst); err != nil {
		t.Fatal(err)
	}
	return dst
}

func assertRawEvidenceDirs(t *testing.T, catalogPath string) {
	t.Helper()
	for _, rel := range []string{
		filepath.Join("raw", "sbom"),
		filepath.Join("raw", "provenance"),
		filepath.Join("raw", "scans"),
		filepath.Join("raw", "test-results"),
	} {
		info, err := os.Stat(filepath.Join(catalogPath, rel))
		if err != nil {
			t.Fatalf("expected generated raw evidence directory %s: %v", rel, err)
		}
		if !info.IsDir() {
			t.Fatalf("expected generated raw evidence path %s to be a directory", rel)
		}
	}
}

func writeMinimalSiteTemplate(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "template")
	if err := os.MkdirAll(filepath.Join(dir, "src", "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"scripts":{"build":"astro build"}}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "astro.config.mjs"), []byte("export default {};\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src", "lib", "catalog.ts"), []byte("export {};\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}
