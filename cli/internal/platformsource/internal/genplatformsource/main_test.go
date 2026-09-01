package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
)

func TestRunGeneratesArchiveFromRepoRoot(t *testing.T) {
	root := t.TempDir()
	for rel, body := range map[string]string{
		fleet.DefaultConfigPath: "registry:\n  host: ghcr.io\n",
		"go.work":              "go 1.22\n",
		"cli/go.mod":           "module example.com/clearcutt\n",
	} {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dest, err := run(filepath.Join(root, "cli"), false)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("expected generated archive at %s: %v", dest, err)
	}
	if _, err := run(filepath.Join(root, "cli"), true); err != nil {
		t.Fatalf("check should pass after generation: %v", err)
	}
}

func TestRunCheckFailsWhenArchiveIsStale(t *testing.T) {
	root := t.TempDir()
	for rel, body := range map[string]string{
		fleet.DefaultConfigPath: "registry:\n  host: ghcr.io\n",
		"go.work":              "go 1.22\n",
		"cli/go.mod":           "module example.com/clearcutt\n",
	} {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := run(filepath.Join(root, "cli"), false); err != nil {
		t.Fatalf("run: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := run(filepath.Join(root, "cli"), true); err == nil {
		t.Fatal("expected stale archive check to fail")
	}
}

func TestRunFailsOutsideRepo(t *testing.T) {
	if _, err := run(t.TempDir(), false); err == nil {
		t.Fatal("expected error outside a repo root")
	}
}
