package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunFromCopiesTemplateAndSkipsExcludedPaths(t *testing.T) {
	root := t.TempDir()
	siteDir := filepath.Join(root, "site")
	destDir := filepath.Join(root, "template")
	for _, dir := range []string{
		filepath.Join(siteDir, "src", "components"),
		filepath.Join(siteDir, "node_modules", "pkg"),
		filepath.Join(siteDir, "dist"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(siteDir, "src", "components", "Card.astro"), []byte("<div />\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(siteDir, "node_modules", "pkg", "ignored.js"), []byte("ignored"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(siteDir, "dist", "ignored.html"), []byte("ignored"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "stale.txt"), []byte("stale"), 0o644); err != nil {
		if err := os.MkdirAll(destDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destDir, "stale.txt"), []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := runFrom(siteDir, destDir); err != nil {
		t.Fatalf("runFrom failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(destDir, "src", "components", "Card.astro")); err != nil {
		t.Fatalf("expected copied component: %v", err)
	}
	if _, err := os.Stat(filepath.Join(destDir, "node_modules")); !os.IsNotExist(err) {
		t.Fatalf("node_modules should be excluded, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(destDir, "stale.txt")); !os.IsNotExist(err) {
		t.Fatalf("stale destination should have been removed, err=%v", err)
	}
}

func TestRunFromAndCopyFileErrors(t *testing.T) {
	root := t.TempDir()
	if err := runFrom(filepath.Join(root, "missing-site"), filepath.Join(root, "template")); err == nil || !strings.Contains(err.Error(), "live site directory not found") {
		t.Fatalf("expected missing site error, got %v", err)
	}
	if err := copyFile(filepath.Join(root, "missing"), filepath.Join(root, "out")); err == nil {
		t.Fatal("copyFile should fail for a missing source")
	}

	src := filepath.Join(root, "src.txt")
	dst := filepath.Join(root, "nested", "dst.txt")
	if err := os.WriteFile(src, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile failed: %v", err)
	}
	if raw, err := os.ReadFile(dst); err != nil || string(raw) != "ok" {
		t.Fatalf("unexpected copied data %q err=%v", raw, err)
	}
}
