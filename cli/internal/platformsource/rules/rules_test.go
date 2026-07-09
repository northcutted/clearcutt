package rules

import (
	"os"
	"testing"
)

func TestSkipPath(t *testing.T) {
	for _, path := range []string{".git", "site/dist/index.html", "cli/coverage.out", "cache/file.pyc", "node_modules"} {
		if !SkipPath(path, nil) {
			t.Errorf("SkipPath(%q) = false", path)
		}
	}
	for _, path := range []string{"README.md", "cli/internal/commands/root.go", "site/src/pages/index.astro"} {
		if SkipPath(path, os.FileInfo(nil)) {
			t.Errorf("SkipPath(%q) = true", path)
		}
	}
}
