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

func TestFleetSeedCachePlanWritesNeededMatrix(t *testing.T) {
	root := t.TempDir()
	cfgPath := writeFleetTestConfig(t, root, fleet.Config{
		Matrix: fleet.Matrix{Systems: []string{"x86_64-linux"}, Languages: []string{"node24", "java21"}, Tiers: []string{"slim"}},
	})
	coreDir := filepath.Join(root, "core")
	if err := os.MkdirAll(coreDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ghOut := filepath.Join(root, "github-output")

	oldCapture := captureExternalOutput
	calls := []externalCommand{}
	captureExternalOutput = func(c externalCommand) (string, error) {
		calls = append(calls, c)
		joined := strings.Join(c.Args, " ")
		switch {
		case strings.Contains(joined, `"node24-slim"`):
			return "these 4 paths will be built:\n  /nix/store/node24-slim\n", nil
		case strings.Contains(joined, `"java21-slim"`):
			return "nothing to build\n", nil
		default:
			t.Fatalf("unexpected dry-run command: %#v", c)
			return "", nil
		}
	}
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	stdout, err := runCLI(t,
		"--format", "json",
		"fleet", "seed-cache-plan",
		"--fleet-config", cfgPath,
		"--core-dir", coreDir,
		"--github-output", ghOut,
	)
	if err != nil {
		t.Fatalf("seed-cache-plan failed: %v\n%s", err, stdout)
	}
	if len(calls) != 2 {
		t.Fatalf("expected dry-run per matrix cell, got %#v", calls)
	}
	for _, call := range calls {
		if call.Name != "nix" || call.Dir != coreDir {
			t.Fatalf("unexpected dry-run command: %#v", call)
		}
		joined := strings.Join(call.Args, " ")
		for _, want := range []string{"build", "--dry-run", "--accept-flake-config", ".#packages.x86_64-linux."} {
			if !strings.Contains(joined, want) {
				t.Fatalf("dry-run args missing %q in %q", want, joined)
			}
		}
	}

	var plan fleetSeedCachePlan
	if err := json.Unmarshal([]byte(stdout), &plan); err != nil {
		t.Fatalf("seed-cache-plan stdout should be JSON: %v\n%s", err, stdout)
	}
	if !plan.HasWork || plan.Count != 1 || len(plan.Matrix.Include) != 1 {
		t.Fatalf("unexpected plan: %#v", plan)
	}
	if got := plan.Matrix.Include[0]; got.Language != "node24" || got.Tier != "slim" || got.System != "x86_64-linux" {
		t.Fatalf("unexpected needed cell: %#v", got)
	}

	raw, err := os.ReadFile(ghOut)
	if err != nil {
		t.Fatalf("read github output: %v", err)
	}
	gh := string(raw)
	if !strings.Contains(gh, "has_work=true") || !strings.Contains(gh, `seed_matrix={"include":[{"system":"x86_64-linux","language":"node24","tier":"slim"}]}`) {
		t.Fatalf("unexpected github output:\n%s", gh)
	}
}

func TestFleetSeedCachePlanNoWork(t *testing.T) {
	root := t.TempDir()
	cfgPath := writeFleetTestConfig(t, root, fleet.Config{
		Matrix: fleet.Matrix{Systems: []string{"x86_64-linux"}, Languages: []string{"coreLTS"}, Tiers: []string{"distroless"}},
	})
	ghOut := filepath.Join(root, "github-output")

	oldCapture := captureExternalOutput
	captureExternalOutput = func(c externalCommand) (string, error) {
		return "all paths are already valid\n", nil
	}
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	stdout, err := runCLI(t,
		"fleet", "seed-cache-plan",
		"--fleet-config", cfgPath,
		"--core-dir", filepath.Join(root, "core"),
		"--github-output", ghOut,
	)
	if err != nil {
		t.Fatalf("seed-cache-plan no-work failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "cells needing a seed build: 0") {
		t.Fatalf("expected no-work summary, got:\n%s", stdout)
	}
	raw, err := os.ReadFile(ghOut)
	if err != nil {
		t.Fatalf("read github output: %v", err)
	}
	if !strings.Contains(string(raw), "has_work=false") || !strings.Contains(string(raw), `seed_matrix={"include":[]}`) {
		t.Fatalf("unexpected github output:\n%s", raw)
	}
}

func TestFleetSeedCachePlanRefusesPartialOutputOnDryRunFailure(t *testing.T) {
	root := t.TempDir()
	cfgPath := writeFleetTestConfig(t, root, fleet.Config{
		Matrix: fleet.Matrix{Systems: []string{"x86_64-linux"}, Languages: []string{"node24", "java21"}, Tiers: []string{"slim"}},
	})
	ghOut := filepath.Join(root, "github-output")

	oldCapture := captureExternalOutput
	captureExternalOutput = func(c externalCommand) (string, error) {
		if strings.Contains(strings.Join(c.Args, " "), `"java21-slim"`) {
			return "", errors.New("eval failed")
		}
		return "will be built\n", nil
	}
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	stdout, err := runCLI(t,
		"fleet", "seed-cache-plan",
		"--fleet-config", cfgPath,
		"--core-dir", filepath.Join(root, "core"),
		"--github-output", ghOut,
	)
	if err == nil || !strings.Contains(err.Error(), "refusing to emit a partial seed set") {
		t.Fatalf("expected partial-output refusal, got err=%v stdout=\n%s", err, stdout)
	}
	if _, statErr := os.Stat(ghOut); !os.IsNotExist(statErr) {
		t.Fatalf("github output should not be written on partial failure, stat=%v", statErr)
	}
}
