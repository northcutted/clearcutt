package versionpolicy

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestVersionPolicyMirrorMatchesCanonical enforces that the embedded mirror
// (cli/internal/versionpolicy/version-policy.json) is byte-identical to the
// canonical policy (core/lib/version-policy.json). The two files exist because
// the Nix flake can only read inside core/ and the Go binary can only //go:embed
// inside cli/; this test is the bridge that keeps them from drifting. When it
// fails, copy the canonical over the mirror:
//
//	cp core/lib/version-policy.json cli/internal/versionpolicy/version-policy.json
func TestVersionPolicyMirrorMatchesCanonical(t *testing.T) {
	root, ok := findRepoRoot()
	if !ok {
		t.Skip("repo root marker not found; skipping canonical mirror check (vendored build)")
	}
	canonicalPath := filepath.Join(root, "core", "lib", "version-policy.json")
	canonical, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Skipf("canonical policy %s not present (%v); skipping mirror check", canonicalPath, err)
	}
	if !bytes.Equal(canonical, policyJSON) {
		t.Fatalf("embedded mirror is out of sync with canonical %s.\n"+
			"Re-sync with: cp core/lib/version-policy.json cli/internal/versionpolicy/version-policy.json",
			canonicalPath)
	}
}

// findRepoRoot walks upward from the working directory looking for a ClearCutt
// checkout marker, mirroring commands.findRepoRoot without importing it.
func findRepoRoot() (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		for _, marker := range []string{"clearcutt.yaml", "go.work"} {
			if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
				return dir, true
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}
