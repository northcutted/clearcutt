package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunGeneratesArchiveFromRepoRoot(t *testing.T) {
	root := t.TempDir()
	for rel, body := range map[string]string{
		"clearcutt.fleet.yaml": "registry:\n  host: ghcr.io\n",
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
	dest, err := run(filepath.Join(root, "cli"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("expected generated archive at %s: %v", dest, err)
	}
}

func TestRunFailsOutsideRepo(t *testing.T) {
	if _, err := run(t.TempDir()); err == nil {
		t.Fatal("expected error outside a repo root")
	}
}
