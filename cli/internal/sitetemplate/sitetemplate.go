// Package sitetemplate embeds the portable Astro evidence-portal template so the
// clearcutt binary can scaffold and build a catalog site without the source
// repository present on disk.
//
// The embedded template mirrors the live site/ directory minus build artifacts,
// installed dependencies, and data-pipeline inputs (see the rules subpackage).
// Regenerate it with `go generate ./...` after changing site/; the
// TestEmbeddedTemplateMatchesSite drift test fails if it falls out of sync.
//
//go:generate go run ./internal/gensite
package sitetemplate

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

// all:template includes dotfiles such as .gitignore, which the default embed
// pattern would otherwise skip.
//
//go:embed all:template
var embedded embed.FS

// FS returns the embedded template rooted at its top level (package.json, src/, …).
func FS() (fs.FS, error) {
	return fs.Sub(embedded, "template")
}

// Materialize writes the embedded template into dst, creating directories as
// needed. It is the binary-only equivalent of copying the live site/ template
// from disk, and produces an identical tree.
func Materialize(dst string) error {
	sub, err := FS()
	if err != nil {
		return err
	}
	return fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(dst, filepath.FromSlash(p))
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		data, err := fs.ReadFile(sub, p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}
