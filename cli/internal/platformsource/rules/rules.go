package rules

import (
	"io/fs"
	"path/filepath"
	"strings"
)

var Entries = []string{
	".github",
	"cli",
	"core",
	"docs",
	"examples",
	"schemas",
	"site",
	".gitignore",
	"AGENTS.md",
	"CHANGELOG.md",
	"CODE_OF_CONDUCT.md",
	"CONTRIBUTING.md",
	"FORKING.md",
	"LICENSE",
	"Makefile",
	"README.md",
	"SECURITY.md",
	"clearcutt.fleet.yaml",
	"go.work",
	"go.work.sum",
}

func SkipPath(rel string, info fs.FileInfo) bool {
	clean := filepath.ToSlash(filepath.Clean(rel))
	base := filepath.Base(clean)
	if base == ".DS_Store" || base == ".git" || base == "node_modules" || base == ".astro" || base == ".pytest_cache" || base == "__pycache__" {
		return true
	}
	if strings.HasSuffix(base, ".pyc") {
		return true
	}
	for _, prefix := range []string{
		"cli/coverage",
		"cli/coverage.html",
		"cli/coverage-low-functions.txt",
		"cli/coverage-packages.txt",
		"cli/coverage.txt",
		"cli/coverage.out",
		"cli/clearcutt",
		"cli/core",
		"cli/docs",
		"cli/examples",
		"cli/site",
		"cli/internal/platformsource/archive/source.zip",
		"cli/internal/platformsource/archive/source.zip.tmp",
		"core/build-outputs",
		"site/dist",
		"site/src/data/catalog",
		"site/src/data/enrichment",
		"site/src/data/sboms",
		"site/src/data/vulnerabilities",
	} {
		if clean == prefix || strings.HasPrefix(clean, prefix+"/") {
			return true
		}
	}
	return false
}
