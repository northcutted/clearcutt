package commands

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
)

func writeFleetConfig(t *testing.T, dir string) string {
	t.Helper()
	raw, err := fleet.Marshal(fleet.DefaultConfig("acme", "platform"))
	if err != nil {
		t.Fatalf("marshal fleet config: %v", err)
	}
	path := filepath.Join(dir, "clearcutt.fleet.yaml")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write fleet config: %v", err)
	}
	return path
}

func writeFleetConfigStruct(t *testing.T, path string, cfg fleet.Config) {
	t.Helper()
	raw, err := fleet.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal fleet config: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write fleet config: %v", err)
	}
}

func TestMatrixExportFromFleetEmitsGitHubImageMatrix(t *testing.T) {
	path := writeFleetConfig(t, t.TempDir())
	stdout, err := runCLI(t, "--format", "json", "matrix", "export", "--source", "fleet", "--fleet-config", path, "--github-actions", "--matrix", "image")
	if err != nil {
		t.Fatalf("matrix export failed: %v\n%s", err, stdout)
	}
	var got struct {
		Include []struct {
			Language string `json:"language"`
			Tier     string `json:"tier"`
		} `json:"include"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout)
	}
	if len(got.Include) == 0 {
		t.Fatalf("expected non-empty matrix")
	}
	if got.Include[0].Language != "coreLTS" || got.Include[0].Tier != "dev" {
		t.Fatalf("unexpected first matrix cell: %#v", got.Include[0])
	}
}

func TestMatrixExportFleetTableYAMLAndValidation(t *testing.T) {
	path := writeFleetConfig(t, t.TempDir())
	stdout, err := runCLI(t, "matrix", "export", "--source", "fleet", "--fleet-config", path)
	if err != nil {
		t.Fatalf("fleet table matrix failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "fleet") || !strings.Contains(stdout, "ghcr.io/acme") {
		t.Fatalf("unexpected fleet table output:\n%s", stdout)
	}
	stdout, err = runCLI(t, "--format", "json", "matrix", "export", "--source", "fleet", "--fleet-config", path)
	if err != nil {
		t.Fatalf("fleet json matrix failed: %v\n%s", err, stdout)
	}
	var fleetJSON struct {
		Registry fleet.Registry `json:"registry"`
		Branding fleet.Branding `json:"branding"`
	}
	if err := json.Unmarshal([]byte(stdout), &fleetJSON); err != nil {
		t.Fatalf("unmarshal fleet json: %v\n%s", err, stdout)
	}
	if fleetJSON.Registry.ImagePrefix != "platform" || fleetJSON.Branding.ProductName != "Platform" {
		t.Fatalf("fleet json should expose fork identity, got %#v", fleetJSON)
	}
	stdout, err = runCLI(t, "--format", "yaml", "matrix", "export", "--source", "fleet", "--fleet-config", path)
	if err != nil {
		t.Fatalf("fleet yaml matrix failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "registryBase: ghcr.io/acme/platform") {
		t.Fatalf("unexpected fleet YAML output:\n%s", stdout)
	}
	stdout, err = runCLI(t, "matrix", "export", "--source", "fleet", "--fleet-config", path, "--github-actions", "--matrix", "wrong")
	if err == nil || !strings.Contains(err.Error(), "--matrix must be release or image") {
		t.Fatalf("expected invalid matrix kind error, got %v\n%s", err, stdout)
	}
}

func TestMatrixExplainRuntimeLine(t *testing.T) {
	path := writeFleetConfig(t, t.TempDir())
	stdout, err := runCLI(t, "--format", "json", "matrix", "explain", "java21", "--fleet-config", path)
	if err != nil {
		t.Fatalf("matrix explain failed: %v\n%s", err, stdout)
	}
	var got MatrixRuntimeExplanation
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("unmarshal matrix explanation: %v\n%s", err, stdout)
	}
	if got.ID != "java21" || got.Language != "java" || got.Version != "21" {
		t.Fatalf("unexpected runtime explanation: %#v", got)
	}
	if !got.SelectedInFleet || got.AppTemplateRuntime != "java" {
		t.Fatalf("expected java21 to be selected with a java app template: %#v", got)
	}
	if strings.Join(got.ImageIDs, ",") != "java21-dev,java21-slim,java21-distroless" {
		t.Fatalf("unexpected image IDs: %#v", got.ImageIDs)
	}

	stdout, err = runCLI(t, "matrix", "explain", "ruby3.4", "--fleet-config", path)
	if err == nil || !strings.Contains(err.Error(), "unsupported runtime line") {
		t.Fatalf("expected unsupported runtime error, got %v\n%s", err, stdout)
	}
}

func TestMatrixAddRemoveUpdatesFleetConfig(t *testing.T) {
	root := t.TempDir()
	cfg := fleet.DefaultConfig("acme", "platform")
	cfg.Matrix.Languages = []string{"java21"}
	raw, err := fleet.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal fleet config: %v", err)
	}
	path := filepath.Join(root, "clearcutt.fleet.yaml")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write fleet config: %v", err)
	}

	stdout, err := runCLI(t, "matrix", "add", "java25", "--fleet-config", path, "--tiers", "dev,slim", "--systems", "x86_64-linux")
	if err != nil {
		t.Fatalf("matrix add failed: %v\n%s", err, stdout)
	}
	loaded, err := fleet.Load(path)
	if err != nil {
		t.Fatalf("load updated config: %v", err)
	}
	if !containsString(loaded.Matrix.Languages, "java25") {
		t.Fatalf("matrix add did not select java25: %#v", loaded.Matrix.Languages)
	}

	stdout, err = runCLI(t, "matrix", "remove", "java21", "--fleet-config", path)
	if err != nil {
		t.Fatalf("matrix remove failed: %v\n%s", err, stdout)
	}
	loaded, err = fleet.Load(path)
	if err != nil {
		t.Fatalf("load updated config: %v", err)
	}
	if containsString(loaded.Matrix.Languages, "java21") {
		t.Fatalf("matrix remove did not remove java21: %#v", loaded.Matrix.Languages)
	}
}

func TestRuntimeScaffoldValidateAndTemplateRuby(t *testing.T) {
	root := t.TempDir()
	configPath := writeFleetConfig(t, root)
	coreDir := filepath.Join(root, "core")

	stdout, err := runCLI(t, "runtime", "scaffold", "ruby3.4", "--fleet-config", configPath, "--core-dir", coreDir)
	if err != nil {
		t.Fatalf("runtime scaffold failed: %v\n%s", err, stdout)
	}
	loaded, err := fleet.Load(configPath)
	if err != nil {
		t.Fatalf("load scaffolded config: %v", err)
	}
	ruby, ok := loaded.RuntimeLineInfo("ruby3.4")
	if !ok {
		t.Fatalf("ruby3.4 was not added to runtimeLines: %#v", loaded.RuntimeLines)
	}
	if ruby.Language != "ruby" || ruby.Version != "3.4" || ruby.AppTemplateRuntime != "ruby" {
		t.Fatalf("unexpected ruby runtime line: %#v", ruby)
	}
	if !containsString(loaded.Matrix.Languages, "ruby3.4") {
		t.Fatalf("ruby3.4 should be selected in matrix.languages: %#v", loaded.Matrix.Languages)
	}
	if !containsString(loaded.Templates.Runtimes, "ruby") {
		t.Fatalf("ruby template runtime should be enabled: %#v", loaded.Templates.Runtimes)
	}
	extension, err := os.ReadFile(filepath.Join(coreDir, "lib", "runtime-extensions.nix"))
	if err != nil {
		t.Fatalf("read runtime extension: %v", err)
	}
	for _, needle := range []string{`ruby = {`, `"3.4" = {`, `overlayName = "clearcuttRuby34";`, `ruby_3_4`} {
		if !strings.Contains(string(extension), needle) {
			t.Fatalf("runtime extension missing %q:\n%s", needle, extension)
		}
	}

	stdout, err = runCLI(t, "--format", "json", "runtime", "validate", "ruby3.4", "--fleet-config", configPath, "--core-dir", coreDir)
	if err != nil {
		t.Fatalf("runtime validate failed: %v\n%s", err, stdout)
	}
	var validation RuntimeValidation
	if err := json.Unmarshal([]byte(stdout), &validation); err != nil {
		t.Fatalf("unmarshal runtime validation: %v\n%s", err, stdout)
	}
	if validation.Status != "pass" {
		t.Fatalf("runtime validation did not pass: %#v", validation)
	}

	stdout, err = runCLI(t, "--format", "json", "matrix", "explain", "ruby3.4", "--fleet-config", configPath)
	if err != nil {
		t.Fatalf("matrix explain ruby failed: %v\n%s", err, stdout)
	}
	var explanation MatrixRuntimeExplanation
	if err := json.Unmarshal([]byte(stdout), &explanation); err != nil {
		t.Fatalf("unmarshal ruby explanation: %v\n%s", err, stdout)
	}
	if !explanation.SelectedInFleet || explanation.AppTemplateRuntime != "ruby" {
		t.Fatalf("ruby explanation should include custom selection/template: %#v", explanation)
	}

	outDir := filepath.Join(root, "ruby-template")
	stdout, err = runCLI(t, "app", "template", "ruby", "--fleet-config", configPath, "--output", outDir, "--name", "ruby-template")
	if err != nil {
		t.Fatalf("ruby app template failed: %v\n%s", err, stdout)
	}
	dockerfile, err := os.ReadFile(filepath.Join(outDir, "Dockerfile"))
	if err != nil {
		t.Fatalf("read ruby Dockerfile: %v", err)
	}
	if !strings.Contains(string(dockerfile), "ruby3.4") || !strings.Contains(string(dockerfile), "ruby -c app.rb") {
		t.Fatalf("ruby Dockerfile did not use scaffolded runtime:\n%s", dockerfile)
	}
}

func TestAppTemplateRejectsRuntimeNotEnabledInFleet(t *testing.T) {
	root := t.TempDir()
	configPath := writeFleetConfig(t, root)
	outDir := filepath.Join(root, "ruby-template")
	stdout, err := runCLI(t, "app", "template", "ruby", "--fleet-config", configPath, "--output", outDir)
	if err == nil {
		t.Fatalf("expected ruby template to fail before runtime scaffold enables it:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), `app template runtime "ruby" is supported but not enabled in templates.runtimes`) {
		t.Fatalf("unexpected ruby template error: %v\n%s", err, stdout)
	}
	if _, statErr := os.Stat(filepath.Join(outDir, "Dockerfile")); !os.IsNotExist(statErr) {
		t.Fatalf("disabled runtime should not write template files, stat err=%v", statErr)
	}
}

func TestAppTemplateRejectsUnsupportedRuntimeBeforeAndAfterEnablement(t *testing.T) {
	root := t.TempDir()
	configPath := writeFleetConfig(t, root)
	outDir := filepath.Join(root, "rust-template")
	stdout, err := runCLI(t, "app", "template", "rust", "--fleet-config", configPath, "--output", outDir)
	if err == nil {
		t.Fatalf("expected unsupported rust template to fail:\n%s", stdout)
	}
	for _, needle := range []string{`unsupported app template runtime "rust"`, "java, node, python, go, ruby"} {
		if !strings.Contains(err.Error(), needle) {
			t.Fatalf("unsupported runtime error missing %q: %v\n%s", needle, err, stdout)
		}
	}

	cfg, err := fleet.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Templates.Runtimes = append(cfg.Templates.Runtimes, "rust")
	writeFleetConfigStruct(t, configPath, cfg)
	stdout, err = runCLI(t, "app", "template", "rust", "--fleet-config", configPath, "--output", outDir)
	if err == nil {
		t.Fatalf("enabled-but-unsupported rust template should still fail:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), `unsupported app template runtime "rust"`) {
		t.Fatalf("unexpected enabled unsupported runtime error: %v\n%s", err, stdout)
	}
}

func TestRuntimeScaffoldRejectsUnsupportedAppTemplateRuntime(t *testing.T) {
	root := t.TempDir()
	configPath := writeFleetConfig(t, root)
	coreDir := filepath.Join(root, "core")
	stdout, err := runCLI(t,
		"runtime", "scaffold", "rust1.96",
		"--fleet-config", configPath,
		"--core-dir", coreDir,
		"--language", "rust",
		"--version", "1.96",
		"--package", "rustc",
		"--app-template-runtime", "rust",
	)
	if err == nil {
		t.Fatalf("expected runtime scaffold to reject unsupported app template runtime:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), `unsupported app template runtime "rust"`) {
		t.Fatalf("unexpected scaffold error: %v\n%s", err, stdout)
	}
}

func TestAppTemplateWritesBuildCertifyAndRebaseFiles(t *testing.T) {
	dir := t.TempDir()
	path := writeFleetConfig(t, dir)
	outDir := filepath.Join(dir, "node-template")
	stdout, err := runCLI(t, "app", "template", "node", "--fleet-config", path, "--output", outDir, "--name", "node-template")
	if err != nil {
		t.Fatalf("app template failed: %v\n%s", err, stdout)
	}
	for _, rel := range []string{
		"Dockerfile",
		"certification-policy.yaml",
		".github/workflows/release.yml",
		".github/workflows/rebase.yml",
		".devcontainer/devcontainer.json",
	} {
		if _, err := os.Stat(filepath.Join(outDir, rel)); err != nil {
			t.Fatalf("expected %s: %v", rel, err)
		}
	}
	releaseRaw, err := os.ReadFile(filepath.Join(outDir, ".github/workflows/release.yml"))
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	release := string(releaseRaw)
	for _, needle := range []string{"cosign sign", "actions/attest-build-provenance", "actions/attest-sbom", "SHA256SUMS.txt", "cosign verify-blob", "clearcutt certify", "--image-ref"} {
		if !strings.Contains(release, needle) {
			t.Fatalf("generated release workflow missing %q:\n%s", needle, release)
		}
	}
	if strings.Contains(release, "certify-app@") || strings.Contains(release, "@v4") || strings.Contains(release, "@v6") {
		t.Fatalf("generated release workflow must not contain old action tags:\n%s", release)
	}
	rebaseRaw, err := os.ReadFile(filepath.Join(outDir, ".github/workflows/rebase.yml"))
	if err != nil {
		t.Fatalf("read rebase workflow: %v", err)
	}
	rebase := string(rebaseRaw)
	for _, needle := range []string{"SHA256SUMS.txt", "cosign verify-blob", "clearcutt app rebase"} {
		if !strings.Contains(rebase, needle) {
			t.Fatalf("generated rebase workflow missing %q:\n%s", needle, rebase)
		}
	}
}

func TestPlatformInitWritesStarterKitAndHonorsForce(t *testing.T) {
	root := t.TempDir()
	// Seed a consumer example carrying the upstream identity to confirm init
	// localizes deployment/admission manifests in place.
	policyPath := filepath.Join(root, "examples", "k8s-deployment", "kyverno-policy.yaml")
	if err := os.MkdirAll(filepath.Dir(policyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	seedPolicy := "# ClearCutt Admission Policy\nimageReferences:\n  - \"ghcr.io/northcutted/clearcutt/clearcutt-*\"\nsubjectRegExp: \"^https://github.com/northcutted/clearcutt/.github/workflows/release.yml@refs/heads/main$\"\n"
	if err := os.WriteFile(policyPath, []byte(seedPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, err := runCLI(t, "platform", "init", "--output", root, "--owner", "acme", "--repo", "platform")
	if err != nil {
		t.Fatalf("platform init failed: %v\n%s", err, stdout)
	}
	for _, rel := range []string{
		"clearcutt.fleet.yaml",
		"core/lib/platform-metadata.nix",
		"docs/platform-kit.md",
		"examples/clearcutt-template-java/Dockerfile",
		"examples/clearcutt-template-node/Dockerfile",
		"examples/clearcutt-template-python/Dockerfile",
		"examples/clearcutt-template-go/Dockerfile",
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Fatalf("expected generated %s: %v", rel, err)
		}
	}
	doc, err := os.ReadFile(filepath.Join(root, "docs", "platform-kit.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), "ghcr.io/acme/platform") || !strings.Contains(string(doc), "SLSA Build L3 provenance") {
		t.Fatalf("platform doc missing product copy:\n%s", doc)
	}
	metadata, err := os.ReadFile(filepath.Join(root, "core", "lib", "platform-metadata.nix"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(metadata), `sourceURL = "https://github.com/acme/platform"`) {
		t.Fatalf("platform metadata missing fork source URL:\n%s", metadata)
	}
	// Branding/image identity must flow from the fork's config, not hardcoded.
	for _, needle := range []string{`productName = "Platform"`, `imagePrefix = "platform"`, `vendor = "acme"`} {
		if !strings.Contains(string(metadata), needle) {
			t.Fatalf("platform metadata missing %q:\n%s", needle, metadata)
		}
	}
	if strings.Contains(string(metadata), "ClearCutt") {
		t.Fatalf("fork platform metadata must not carry upstream ClearCutt brand:\n%s", metadata)
	}
	policy, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(policy), "northcutted/clearcutt") {
		t.Fatalf("kyverno policy still references upstream identity:\n%s", policy)
	}
	if strings.Contains(string(policy), "ClearCutt") || strings.Contains(string(policy), "clearcutt-") {
		t.Fatalf("kyverno policy still carries upstream brand/prefix:\n%s", policy)
	}
	if !strings.Contains(string(policy), "ghcr.io/acme/platform/platform-*") {
		t.Fatalf("kyverno policy image namespace+prefix not localized:\n%s", policy)
	}
	if !strings.Contains(string(policy), "https://github.com/acme/platform/") {
		t.Fatalf("kyverno policy signing identity not localized:\n%s", policy)
	}
	if !strings.Contains(string(policy), "Platform Admission Policy") {
		t.Fatalf("kyverno policy brand not localized to product name:\n%s", policy)
	}
	if _, err := runCLI(t, "platform", "init", "--output", root, "--owner", "acme", "--repo", "platform"); err == nil {
		t.Fatal("expected second init without --force to reject existing files")
	}
	if stdout, err := runCLI(t, "platform", "init", "--output", root, "--owner", "acme", "--repo", "platform", "--force"); err != nil {
		t.Fatalf("platform init --force failed: %v\n%s", err, stdout)
	}
}

func TestPlatformStatusPassesForWiredRoot(t *testing.T) {
	root := t.TempDir()
	writeFleetConfig(t, root)
	files := map[string]string{
		".github/workflows/release.yml":                 "if: ${{ github.ref != 'refs/heads/main' }}\n--workflow-identity \"https://github.com/${{ github.repository }}/.github/workflows/release.yml@${{ github.ref }}\"\nmatrix export --source fleet\nclearcutt platform setup-nix\nclearcutt fleet publish-target\nclearcutt fleet assemble-target\nclearcutt fleet finalize-release\nslsa-github-generator\n",
		".github/workflows/pr-gate.yml":                 "matrix export --source fleet\nclearcutt platform setup-nix\nclearcutt fleet certify-target\n",
		".github/workflows/rebase.yml":                  "clearcutt app rebase\n",
		".github/workflows/publish-pages.yml":           "clearcutt catalog build\n",
		".github/actions/setup-nix/action.yml":          "clearcutt platform setup-nix applies fork-specific fleet cache config\n",
		".github/actions/certify-app/action.yml":        "name: certify\n",
		"core/flake.nix":                                "inputs = {}\n",
		"core/lib/platform-metadata.nix":                "https://github.com/acme/platform\n",
		"examples/clearcutt-template-java/Dockerfile":   "FROM scratch\n",
		"examples/clearcutt-template-node/Dockerfile":   "FROM scratch\n",
		"examples/clearcutt-template-python/Dockerfile": "FROM scratch\n",
		"examples/clearcutt-template-go/Dockerfile":     "FROM scratch\n",
		"examples/k8s-deployment/kyverno-policy.yaml":   "imageReferences:\n  - \"ghcr.io/acme/platform/clearcutt-*\"\n",
	}
	for rel, body := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	stdout, err := runCLI(t, "--format", "json", "platform", "status", "--output", root)
	if err != nil {
		t.Fatalf("platform status failed: %v\n%s", err, stdout)
	}
	var got PlatformStatus
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("unmarshal status: %v\n%s", err, stdout)
	}
	if got.Status != "pass" {
		t.Fatalf("status = %q, checks = %#v", got.Status, got.Checks)
	}
}

func TestPlatformStatusFailsWhenReleaseBranchGuardDrifts(t *testing.T) {
	root := t.TempDir()
	cfg := fleet.DefaultConfig("acme", "platform")
	cfg.Release.SourceBranch = "release"
	cfg.Release.WorkflowIdentity = "https://github.com/acme/platform/.github/workflows/release.yml@refs/heads/release"
	cfg.Rebase.WorkflowIdentity = "https://github.com/acme/platform/.github/workflows/rebase.yml@refs/heads/release"
	raw, err := fleet.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal fleet config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "clearcutt.fleet.yaml"), raw, 0o644); err != nil {
		t.Fatalf("write fleet config: %v", err)
	}
	files := map[string]string{
		".github/workflows/release.yml":                 "if: ${{ github.ref != 'refs/heads/main' }}\n--workflow-identity \"https://github.com/${{ github.repository }}/.github/workflows/release.yml@${{ github.ref }}\"\nmatrix export --source fleet\nclearcutt platform setup-nix\nclearcutt fleet publish-target\nclearcutt fleet assemble-target\nclearcutt fleet finalize-release\nslsa-github-generator\n",
		".github/workflows/pr-gate.yml":                 "matrix export --source fleet\nclearcutt platform setup-nix\nclearcutt fleet certify-target\n",
		".github/workflows/rebase.yml":                  "clearcutt app rebase\n",
		".github/workflows/publish-pages.yml":           "clearcutt catalog build\n",
		".github/actions/setup-nix/action.yml":          "clearcutt platform setup-nix applies fork-specific fleet cache config\n",
		".github/actions/certify-app/action.yml":        "name: certify\n",
		"core/flake.nix":                                "inputs = {}\n",
		"core/lib/platform-metadata.nix":                "https://github.com/acme/platform\n",
		"examples/clearcutt-template-java/Dockerfile":   "FROM scratch\n",
		"examples/clearcutt-template-node/Dockerfile":   "FROM scratch\n",
		"examples/clearcutt-template-python/Dockerfile": "FROM scratch\n",
		"examples/clearcutt-template-go/Dockerfile":     "FROM scratch\n",
		"examples/k8s-deployment/kyverno-policy.yaml":   "imageReferences:\n  - \"ghcr.io/acme/platform/clearcutt-*\"\n",
	}
	for rel, body := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	stdout, err := runCLI(t, "--format", "json", "platform", "status", "--output", root)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected ErrCheckFailed, got %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "release.sourceBranch.guard") {
		t.Fatalf("expected source branch guard failure, got:\n%s", stdout)
	}
}

func TestPlatformSetupNixWritesConfigAndGithubEnv(t *testing.T) {
	root := t.TempDir()
	cfg := fleet.DefaultConfig("acme", "platform")
	cfg.Release.NixCache = fleet.NixCache{
		Bucket:         "acme-nix-cache",
		PublicBaseURL:  "https://nix-cache.acme.example",
		SigningKeyName: "acme-cache-1",
		PublicKey:      "acme-cache-1:abc123",
	}
	raw, err := fleet.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal fleet config: %v", err)
	}
	cfgPath := filepath.Join(root, "clearcutt.fleet.yaml")
	if err := os.WriteFile(cfgPath, raw, 0o644); err != nil {
		t.Fatalf("write fleet config: %v", err)
	}

	xdg := filepath.Join(root, "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	ghEnv := filepath.Join(root, "github-env")
	configOut := filepath.Join(root, "generated", "nix.conf")

	oldCapture := captureExternalOutput
	captureExternalOutput = func(c externalCommand) (string, error) {
		if c.Name == "nix" && strings.Join(c.Args, " ") == "--version" {
			return "nix (Nix) 2.24.0\n", nil
		}
		t.Fatalf("unexpected capture command: %#v", c)
		return "", nil
	}
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	stdout, err := runCLI(t,
		"--format", "json",
		"platform", "setup-nix",
		"--repo-root", root,
		"--skip-warm",
		"--write-user-config",
		"--github-env", ghEnv,
		"--config-output", configOut,
	)
	if err != nil {
		t.Fatalf("setup-nix failed: %v\n%s", err, stdout)
	}
	var result NixSetupResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("parse setup result: %v\n%s", err, stdout)
	}
	if !result.CacheConfigured || result.NixVersion != "nix (Nix) 2.24.0" {
		t.Fatalf("unexpected setup result: %#v", result)
	}

	for _, path := range []string{filepath.Join(xdg, "nix", "nix.conf"), ghEnv, configOut} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(raw)
		for _, want := range []string{
			"https://nix-cache.acme.example",
			"acme-cache-1:abc123",
			"experimental-features = nix-command flakes",
			"sandbox = true",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s missing %q:\n%s", path, want, text)
			}
		}
		if strings.Contains(text, "allow-import-from-derivation") {
			t.Fatalf("%s should not enable import-from-derivation globally:\n%s", path, text)
		}
	}
	ghRaw, err := os.ReadFile(ghEnv)
	if err != nil {
		t.Fatalf("read github env: %v", err)
	}
	if !strings.Contains(string(ghRaw), "NIX_CONFIG<<CLEARCUTT_NIX_CONFIG") {
		t.Fatalf("github env did not export NIX_CONFIG:\n%s", ghRaw)
	}
}

func TestPlatformSetupNixRunsCommandInsideConfiguredDevShell(t *testing.T) {
	root := t.TempDir()
	coreDir := filepath.Join(root, "core")
	if err := os.MkdirAll(coreDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := fleet.DefaultConfig("acme", "platform")
	cfg.Release.NixCache = fleet.NixCache{
		PublicBaseURL:  "https://nix-cache.acme.example",
		SigningKeyName: "acme-cache-1",
		PublicKey:      "abc123",
	}
	raw, err := fleet.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal fleet config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "clearcutt.fleet.yaml"), raw, 0o644); err != nil {
		t.Fatalf("write fleet config: %v", err)
	}

	var calls []externalCommand
	oldRun := runExternalCommand
	oldCapture := captureExternalOutput
	runExternalCommand = func(c externalCommand) error {
		calls = append(calls, c)
		return nil
	}
	captureExternalOutput = func(c externalCommand) (string, error) {
		if c.Name == "nix" && strings.Join(c.Args, " ") == "--version" {
			return "nix (Nix) 2.24.0\n", nil
		}
		t.Fatalf("unexpected capture command: %#v", c)
		return "", nil
	}
	t.Cleanup(func() {
		runExternalCommand = oldRun
		captureExternalOutput = oldCapture
	})

	if _, err := runCLI(t,
		"platform", "setup-nix",
		"--repo-root", root,
		"--core-dir", "core",
		"--",
		"./tests/verify.sh",
	); err != nil {
		t.Fatalf("setup-nix command failed: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected one nix develop command, got %#v", calls)
	}
	call := calls[0]
	if call.Name != "nix" || call.Dir != coreDir {
		t.Fatalf("unexpected command: %#v", call)
	}
	joined := strings.Join(call.Args, " ")
	for _, want := range []string{
		"develop --extra-experimental-features nix-command flakes --accept-flake-config",
		"--option extra-substituters https://nix-cache.acme.example",
		"--option extra-trusted-public-keys acme-cache-1:abc123",
		"--command ./tests/verify.sh",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("nix develop args missing %q in %q", want, joined)
		}
	}
}

func TestPlatformStatusFailsMissingRootAndRendersYAML(t *testing.T) {
	root := t.TempDir()
	stdout, err := runCLI(t, "--format", "yaml", "platform", "status", "--output", root)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected missing platform root to fail, got %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "status: fail") || !strings.Contains(stdout, "fleet.config") || !strings.Contains(stdout, "release.workflow") || !strings.Contains(stdout, "rebase.workflow") {
		t.Fatalf("expected YAML failure report, got:\n%s", stdout)
	}
}
