package platformsource

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/northcutted/clearcutt/internal/platformsource/rules"
)

// requireEmbeddedOrSkip lets bare `go test` pass on a fresh clone (where the
// generated archive is absent) while CI, which generates the archive first and
// sets CLEARCUTT_REQUIRE_EMBEDDED_SOURCE=1, still fails if generation was lost.
func requireEmbeddedOrSkip(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrNotEmbedded) {
		return
	}
	if os.Getenv("CLEARCUTT_REQUIRE_EMBEDDED_SOURCE") != "" {
		t.Fatalf("embedded source archive required but absent: %v", err)
	}
	t.Skipf("source archive not generated; run `go run ./internal/platformsource/internal/genplatformsource` (%v)", err)
}

func TestEmbeddedPlatformSourceMaterializes(t *testing.T) {
	root, cleanup, err := Materialize()
	requireEmbeddedOrSkip(t, err)
	if err != nil {
		t.Fatalf("materialize embedded source: %v", err)
	}
	defer cleanup()
	for _, rel := range []string{
		"clearcutt-source/clearcutt.yaml",
		"clearcutt-source/.github/workflows/release.yml",
		"clearcutt-source/cli/go.mod",
		"clearcutt-source/cli/internal/platformsource/archive/README.md",
		"clearcutt-source/core/flake.nix",
		"clearcutt-source/site/package.json",
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Fatalf("embedded platform source missing %s: %v", rel, err)
		}
	}
	for _, rel := range []string{
		"clearcutt-source/cli/site",
		"clearcutt-source/site/src/data/catalog",
		"clearcutt-source/cli/internal/platformsource/archive/source.zip",
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); !os.IsNotExist(err) {
			t.Fatalf("embedded platform source should exclude %s, stat err=%v", rel, err)
		}
	}
}

func TestEmbeddedPlatformSourceMatchesLiveTree(t *testing.T) {
	repoRoot, ok := findTestRepoRoot(t)
	if !ok {
		t.Skip("live repo root not present; skipping platform source drift check")
	}
	raw, err := Bytes()
	requireEmbeddedOrSkip(t, err)
	if err != nil {
		t.Fatalf("read embedded source: %v", err)
	}
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("open embedded source zip: %v", err)
	}
	embedded := map[string][]byte{}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || !file.FileInfo().Mode().IsRegular() {
			continue
		}
		rel, err := filepath.Rel("clearcutt-source", filepath.FromSlash(file.Name))
		if err != nil || rel == "." || rel == ".." || rel == "" || rel[0] == '.' && len(rel) >= 2 && rel[:2] == ".." {
			t.Fatalf("unexpected embedded path %q", file.Name)
		}
		src, err := file.Open()
		if err != nil {
			t.Fatalf("open embedded %s: %v", file.Name, err)
		}
		data, err := readAllAndClose(src)
		if err != nil {
			t.Fatalf("read embedded %s: %v", file.Name, err)
		}
		embedded[filepath.ToSlash(rel)] = data
	}

	live := map[string][]byte{}
	if err := walkLiveSource(repoRoot, func(rel string, raw []byte) {
		live[filepath.ToSlash(rel)] = raw
	}); err != nil {
		t.Fatalf("walk live source: %v", err)
	}
	for rel, raw := range live {
		got, ok := embedded[rel]
		if !ok {
			t.Errorf("embedded platform source is missing %s (run `go -C cli run ./internal/platformsource/internal/genplatformsource`)", rel)
			continue
		}
		if !bytes.Equal(got, raw) {
			t.Errorf("embedded platform source is stale for %s (run `go -C cli run ./internal/platformsource/internal/genplatformsource`)", rel)
		}
	}
	for rel := range embedded {
		if _, ok := live[rel]; !ok {
			t.Errorf("embedded platform source has stale extra file %s (run `go -C cli run ./internal/platformsource/internal/genplatformsource`)", rel)
		}
	}
}

func findTestRepoRoot(t *testing.T) (string, bool) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return FindRepoRoot(wd)
}

func walkLiveSource(root string, visit func(string, []byte)) error {
	for _, entry := range rules.Entries {
		start := filepath.Join(root, entry)
		if _, err := os.Stat(start); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if err := filepath.WalkDir(start, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if rules.SkipPath(rel, info) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() || !info.Mode().IsRegular() {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			visit(rel, raw)
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func readAllAndClose(src interface {
	Read([]byte) (int, error)
	Close() error
}) ([]byte, error) {
	defer src.Close()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(src)
	return buf.Bytes(), err
}
