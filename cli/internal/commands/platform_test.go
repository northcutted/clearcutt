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
		".github/workflows/release.yml":                 "matrix export --source fleet\nslsa-github-generator\n",
		".github/workflows/rebase.yml":                  "clearcutt app rebase\n",
		".github/workflows/publish-pages.yml":           "clearcutt catalog build\n",
		".github/actions/certify-app/action.yml":        "name: certify\n",
		"core/lib/platform-metadata.nix":                "https://github.com/acme/platform\n",
		"examples/clearcutt-template-java/Dockerfile":   "FROM scratch\n",
		"examples/clearcutt-template-node/Dockerfile":   "FROM scratch\n",
		"examples/clearcutt-template-python/Dockerfile": "FROM scratch\n",
		"examples/clearcutt-template-go/Dockerfile":     "FROM scratch\n",
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
