package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/versionpolicy"
)

func TestCheckGithubRegistryCredentialNames(t *testing.T) {
	oldCapture := captureExternalOutput
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	type result struct{ check, status, detail string }
	collect := func() (*[]result, func(string, string, string)) {
		results := &[]result{}
		return results, func(check, status, detail string) {
			*results = append(*results, result{check, status, detail})
		}
	}

	captureExternalOutput = func(c externalCommand) (string, error) {
		return `[{"name":"CLEARCUTT_REGISTRY_USER"}]`, nil
	}
	secrets := []githubName{{Name: "CLEARCUTT_REGISTRY_TOKEN"}}
	results, add := collect()
	checkGithubRegistryCredentialNames("acme/fleet", secrets, nil, add)
	if len(*results) != 1 || (*results)[0].status != "pass" {
		t.Fatalf("configured credentials should pass, got %#v", *results)
	}

	results, add = collect()
	checkGithubRegistryCredentialNames("acme/fleet", nil, nil, add)
	if len(*results) != 1 || (*results)[0].status != "fail" {
		t.Fatalf("missing token secret should fail, got %#v", *results)
	}

	captureExternalOutput = func(c externalCommand) (string, error) {
		return "", fmt.Errorf("gh unavailable")
	}
	results, add = collect()
	checkGithubRegistryCredentialNames("acme/fleet", secrets, nil, add)
	if len(*results) != 1 || (*results)[0].status != "fail" || !strings.Contains((*results)[0].detail, "read failed") {
		t.Fatalf("gh read failure should fail with detail, got %#v", *results)
	}
}

func TestRemoveNativeCVEOverlay(t *testing.T) {
	coreDir := t.TempDir()
	overlay := nativeCVEOverlayPath(coreDir, "CVE-2026-0001", "openssl")
	evidence := nativeCVEOverlayEvidencePath(coreDir, "CVE-2026-0001", "openssl")
	for _, path := range []string{overlay, evidence} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeNativeCVEOverlay(coreDir, "CVE-2026-0001", "openssl"); err != nil {
		t.Fatalf("remove overlay: %v", err)
	}
	for _, path := range []string{overlay, evidence} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected %s removed, err=%v", path, err)
		}
	}
	// Removing already-absent files is a no-op, not an error.
	if err := removeNativeCVEOverlay(coreDir, "CVE-2026-0001", "openssl"); err != nil {
		t.Fatalf("second remove should be a no-op: %v", err)
	}
}

func TestDeletePathAndChildren(t *testing.T) {
	entries := map[string]overlayStoreEntry{
		"nix/store/aaa":          {},
		"nix/store/aaa/lib":      {},
		"nix/store/aaa/lib/x.so": {},
		"nix/store/aaab":         {},
		"nix/store/bbb":          {},
	}
	deletePathAndChildren(entries, "nix/store/aaa")
	if len(entries) != 2 {
		t.Fatalf("expected exactly the prefix subtree removed, got %#v", entries)
	}
	if _, ok := entries["nix/store/aaab"]; !ok {
		t.Fatal("sibling with shared string prefix must survive")
	}
	if _, ok := entries["nix/store/bbb"]; !ok {
		t.Fatal("unrelated entry must survive")
	}
}

func TestVersionPolicyLoaded(t *testing.T) {
	policy := versionpolicy.Loaded()
	if len(policy.Languages) == 0 {
		t.Fatal("embedded version policy should classify at least one language")
	}
}
