package commands

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// nixPathRef matches a Nix path literal that points at a file in the same tree —
// `./tests/foo.py`, `${./lib/bar.nix}`, `import ./overlays/baz.nix`. Nix resolves
// these at EVALUATION time, so a dangling one is not a build failure you discover
// late: it is an eval failure that takes down every consumer of the flake at once.
var nixPathRef = regexp.MustCompile(`\.\/[A-Za-z0-9._\-/]+`)

// TestCoreNixSourcesReferenceOnlyExistingPaths guards the failure mode that broke
// the whole PR gate once: core/ files were deleted while core/flake.nix still
// imported them, so all 24 matrix cells and the verification suite failed at nix
// eval with "Path 'core/overlays/cve-remediation.nix' does not exist".
//
// Nothing else catches this locally. `go build` does not read Nix, actionlint does
// not resolve Nix paths, and the flake itself can only be evaluated on a machine
// with Nix installed — which the developer machine may not have. This test is a
// cheap stand-in that runs everywhere.
func TestCoreNixSourcesReferenceOnlyExistingPaths(t *testing.T) {
	root, ok := findRepoRoot()
	if !ok {
		t.Skip("repo root not found")
	}
	coreDir := filepath.Join(root, "core")
	if _, err := os.Stat(coreDir); err != nil {
		t.Skipf("core/ not present: %v", err)
	}

	var checked, refs int
	err := filepath.WalkDir(coreDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".nix") {
			return err
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		checked++
		dir := filepath.Dir(path)
		for _, match := range nixPathRef.FindAllString(string(body), -1) {
			// Trailing punctuation is not part of the path literal.
			ref := strings.TrimRight(match, ".;,)}")
			// A bare "./" or a path that is only dots is not a file reference.
			if ref == "./" || strings.Trim(ref, "./") == "" {
				continue
			}
			refs++
			if _, statErr := os.Stat(filepath.Join(dir, ref)); statErr != nil {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s references %s, which does not exist "+
					"(nix resolves this at eval time, so it breaks every flake consumer)", rel, ref)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk core/: %v", err)
	}
	if checked == 0 {
		t.Fatal("no .nix files were checked; the guard is not actually running")
	}
	t.Logf("checked %d path reference(s) across %d .nix file(s)", refs, checked)
}
