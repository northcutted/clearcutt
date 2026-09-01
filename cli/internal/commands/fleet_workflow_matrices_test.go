package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
)

func TestFleetWorkflowMatricesWritesGitHubOutputs(t *testing.T) {
	root := t.TempDir()
	cfg := fleet.DefaultConfig("acme", "platform")
	cfg.Matrix.Systems = []string{"x86_64-linux", "aarch64-linux"}
	cfg.Matrix.Languages = []string{"node24"}
	cfg.Matrix.Tiers = []string{"slim", "distroless"}
	cfg.Services = []fleet.ServiceImage{{ID: "postgres16", Template: "postgres", Version: "16"}}
	raw, err := fleet.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	cfgPath := filepath.Join(root, fleet.DefaultConfigPath)
	if err := os.WriteFile(cfgPath, raw, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	ghOut := filepath.Join(root, "github-output")

	stdout, err := runCLI(t,
		"--format", "json",
		"fleet", "workflow-matrices",
		"--fleet-config", cfgPath,
		"--github-output", ghOut,
	)
	if err != nil {
		t.Fatalf("workflow-matrices failed: %v\n%s", err, stdout)
	}

	var matrices fleetWorkflowMatrices
	if err := json.Unmarshal([]byte(stdout), &matrices); err != nil {
		t.Fatalf("stdout should be JSON: %v\n%s", err, stdout)
	}
	if len(matrices.ReleaseMatrix.Include) != 4 {
		t.Fatalf("release matrix cells = %d, want 4", len(matrices.ReleaseMatrix.Include))
	}
	if len(matrices.ImageMatrix.Include) != 2 {
		t.Fatalf("image matrix cells = %d, want 2", len(matrices.ImageMatrix.Include))
	}
	if len(matrices.ServiceReleaseMatrix.Include) != 2 {
		t.Fatalf("service release matrix cells = %d, want 2", len(matrices.ServiceReleaseMatrix.Include))
	}
	if len(matrices.ServiceImageMatrix.Include) != 1 {
		t.Fatalf("service image matrix cells = %d, want 1", len(matrices.ServiceImageMatrix.Include))
	}

	ghRaw, err := os.ReadFile(ghOut)
	if err != nil {
		t.Fatalf("read github output: %v", err)
	}
	gh := string(ghRaw)
	for _, want := range []string{
		`release_matrix={"include":[`,
		`image_matrix={"include":[`,
		`service_release_matrix={"include":[`,
		`service_image_matrix={"include":[`,
		`"service":"postgres16"`,
		`"language":"node24"`,
	} {
		if !strings.Contains(gh, want) {
			t.Fatalf("github output missing %q:\n%s", want, gh)
		}
	}
}

func TestFleetWorkflowMatricesTableSummary(t *testing.T) {
	root := t.TempDir()
	cfgPath := writeFleetTestConfig(t, root, fleet.Config{
		Matrix: fleet.Matrix{Systems: []string{"x86_64-linux"}, Languages: []string{"java21"}, Tiers: []string{"slim"}},
	})

	stdout, err := runCLI(t,
		"fleet", "workflow-matrices",
		"--fleet-config", cfgPath,
	)
	if err != nil {
		t.Fatalf("workflow-matrices table failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{"release", "image", "service-release", "service-image"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("table output missing %q:\n%s", want, stdout)
		}
	}
}
