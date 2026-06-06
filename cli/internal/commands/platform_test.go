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
	for _, needle := range []string{"cosign sign", "actions/attest-build-provenance", "actions/attest-sbom", "certify-app"} {
		if !strings.Contains(release, needle) {
			t.Fatalf("generated release workflow missing %q:\n%s", needle, release)
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
		".github/workflows/release.yml":                 "matrix export --source fleet\nclearcutt platform setup-nix\nclearcutt fleet publish-target\nclearcutt fleet assemble-target\nclearcutt fleet finalize-release\nslsa-github-generator\n",
		".github/workflows/pr-gate.yml":                 "clearcutt platform setup-nix\nclearcutt fleet certify-target\n",
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
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s missing %q:\n%s", path, want, text)
			}
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
