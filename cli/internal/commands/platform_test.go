package commands

import (
	"encoding/json"
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

func TestPlatformStatusPassesForWiredRoot(t *testing.T) {
	root := t.TempDir()
	writeFleetConfig(t, root)
	files := map[string]string{
		".github/workflows/release.yml":                 "matrix export --source fleet\nslsa-github-generator\n",
		".github/workflows/publish-pages.yml":           "clearcutt catalog build\n",
		".github/actions/certify-app/action.yml":        "name: certify\n",
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
