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

// nixFormals extracts the parameter names from a Nix file's leading formal
// argument set — the `{ pkgs, nodePinPkgs ? pkgs }:` header. It returns nil when
// the file does not open with one, so callers skip files it cannot parse rather
// than guessing.
func nixFormals(body string) map[string]bool {
	trimmed := strings.TrimLeft(stripNixComments(body), " \t\n")
	if !strings.HasPrefix(trimmed, "{") {
		return nil
	}
	depth, end := 0, -1
	for i, r := range trimmed {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	// A formal set is followed by a colon; anything else is an attrset literal.
	if end < 0 || !strings.HasPrefix(strings.TrimLeft(trimmed[end+1:], " \t\n"), ":") {
		return nil
	}
	names := map[string]bool{}
	for _, part := range strings.Split(trimmed[1:end], ",") {
		part = strings.TrimSpace(part)
		if i := strings.Index(part, "?"); i >= 0 {
			part = strings.TrimSpace(part[:i])
		}
		if part == "" || part == "..." {
			continue
		}
		if ident := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_'-]*$`); ident.MatchString(part) {
			names[part] = true
		}
	}
	return names
}

func stripNixComments(body string) string {
	var b strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

var nixImportCall = regexp.MustCompile(`import\s+(\.\/[A-Za-z0-9._\-/]+\.nix)\s*\{([^}]*)\}`)
var nixArgName = regexp.MustCompile(`(?m)^\s*(?:inherit\s*(?:\([^)]*\))?\s*)?([A-Za-z_][A-Za-z0-9_'-]*)\s*=`)
var nixInherit = regexp.MustCompile(`inherit\s+((?:[A-Za-z_][A-Za-z0-9_'-]*\s*)+);`)

// TestCoreNixImportsPassOnlyDeclaredArguments guards the second failure mode from
// the same root cause as the dangling-path bug: a parameter is dropped from a
// lib/*.nix file while a caller still passes it, and Nix fails at eval with
// "function 'anonymous lambda' called with unexpected argument 'cryptoPkgs'".
//
// It only flags UNEXPECTED arguments, never missing ones: a missing argument may
// be legitimately supplied by a default, and detecting that reliably would need a
// real Nix evaluator. Unexpected arguments are exactly the error CI hit and are
// unambiguous from the formals alone.
func TestCoreNixImportsPassOnlyDeclaredArguments(t *testing.T) {
	root, ok := findRepoRoot()
	if !ok {
		t.Skip("repo root not found")
	}
	coreDir := filepath.Join(root, "core")
	if _, err := os.Stat(coreDir); err != nil {
		t.Skipf("core/ not present: %v", err)
	}

	formals := map[string]map[string]bool{}
	var callSites int
	err := filepath.WalkDir(coreDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".nix") {
			return err
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, m := range nixImportCall.FindAllStringSubmatch(stripNixComments(string(body)), -1) {
			target := filepath.Join(filepath.Dir(path), m[1])
			declared, cached := formals[target]
			if !cached {
				targetBody, tErr := os.ReadFile(target)
				if tErr != nil {
					continue // the path guard above already reports missing files
				}
				declared = nixFormals(string(targetBody))
				formals[target] = declared
			}
			if declared == nil {
				continue // not a formal-argument module; nothing to check
			}
			callSites++
			passed := map[string]bool{}
			for _, arg := range nixArgName.FindAllStringSubmatch(m[2], -1) {
				passed[arg[1]] = true
			}
			for _, inh := range nixInherit.FindAllStringSubmatch(m[2], -1) {
				for _, name := range strings.Fields(inh[1]) {
					passed[name] = true
				}
			}
			for name := range passed {
				if !declared[name] {
					rel, _ := filepath.Rel(root, path)
					relTarget, _ := filepath.Rel(root, target)
					t.Errorf("%s passes %q to %s, which does not declare it "+
						"(nix fails at eval: \"called with unexpected argument '%s'\")",
						rel, name, relTarget, name)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk core/: %v", err)
	}
	if callSites == 0 {
		t.Fatal("no import call sites were checked; the guard is not actually running")
	}
	t.Logf("checked %d import call site(s)", callSites)
}
