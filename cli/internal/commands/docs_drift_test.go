package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCurrentDocsAndSiteAvoidStaleReleaseAndPrimaryForkTagline(t *testing.T) {
	root, ok := findRepoRoot()
	if !ok {
		t.Skip("repo root not found")
	}
	scanRoots := []string{
		filepath.Join(root, "README.md"),
		filepath.Join(root, "docs"),
		filepath.Join(root, "site", "src"),
	}
	for _, scanRoot := range scanRoots {
		err := filepath.WalkDir(scanRoot, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				rel, relErr := filepath.Rel(root, path)
				if relErr == nil && strings.HasPrefix(filepath.ToSlash(rel), "docs/analysis") {
					return filepath.SkipDir
				}
				return nil
			}
			if !isCurrentDocsOrSiteTextFile(path) {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			body := string(raw)
			if strings.Contains(body, "v0.17.0") {
				t.Fatalf("%s contains stale hardcoded release tag v0.17.0", path)
			}
			if strings.Contains(body, "The forkable platform kit and reference implementation") {
				t.Fatalf("%s reintroduces the old primary README tagline", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func isCurrentDocsOrSiteTextFile(path string) bool {
	switch filepath.Ext(path) {
	case ".md", ".mdx", ".astro", ".ts", ".tsx":
		return true
	default:
		return false
	}
}
