package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
)

func TestCatalogWorkflowParamsWritesGitHubOutputs(t *testing.T) {
	root := t.TempDir()
	cfg := fleet.DefaultConfig("acme", "platform")
	cfg.Catalog.ReleaseLimit = 12
	cfg.Catalog.ScanDepth = "5"
	raw, err := fleet.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal fleet config: %v", err)
	}
	cfgPath := filepath.Join(root, "clearcutt.fleet.yaml")
	if err := os.WriteFile(cfgPath, raw, 0o644); err != nil {
		t.Fatalf("write fleet config: %v", err)
	}
	ghOut := filepath.Join(root, "github-output")

	stdout, err := runCLI(t,
		"--format", "json",
		"catalog", "workflow-params",
		"--fleet-config", cfgPath,
		"--release-limit", "3",
		"--github-output", ghOut,
	)
	if err != nil {
		t.Fatalf("catalog workflow-params failed: %v\n%s", err, stdout)
	}
	var params catalogWorkflowParams
	if err := json.Unmarshal([]byte(stdout), &params); err != nil {
		t.Fatalf("stdout should be JSON: %v\n%s", err, stdout)
	}
	if params.ReleaseLimit != 3 || params.ScanDepth != "5" {
		t.Fatalf("unexpected params: %#v", params)
	}
	rawOut, err := os.ReadFile(ghOut)
	if err != nil {
		t.Fatalf("read github output: %v", err)
	}
	gh := string(rawOut)
	for _, want := range []string{"limit=3", "scan_depth=5"} {
		if !strings.Contains(gh, want) {
			t.Fatalf("github output missing %q:\n%s", want, gh)
		}
	}
}

func TestCatalogVexAllWritesPerImageDocuments(t *testing.T) {
	catalogDir := writeCommandSmokeCatalog(t)
	outputDir := filepath.Join(t.TempDir(), "vex")

	stdout, err := runCLI(t,
		"--catalog", catalogDir,
		"--format", "json",
		"catalog", "vex-all",
		"--output-dir", outputDir,
	)
	if err != nil {
		t.Fatalf("catalog vex-all failed: %v\n%s", err, stdout)
	}
	var result catalogVexAllResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout should be JSON: %v\n%s", err, stdout)
	}
	if result.Count != 1 || len(result.Images) != 1 || result.Images[0] != "java21-distroless" {
		t.Fatalf("unexpected vex-all result: %#v", result)
	}
	raw, err := os.ReadFile(filepath.Join(outputDir, "java21-distroless.json"))
	if err != nil {
		t.Fatalf("read generated VEX: %v", err)
	}
	var doc OpenVEXDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse generated VEX: %v\n%s", err, raw)
	}
	if len(doc.Statements) == 0 {
		t.Fatalf("expected VEX statements in generated document: %#v", doc)
	}
}
