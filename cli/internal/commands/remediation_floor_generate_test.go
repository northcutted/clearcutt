package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeCryptoResolver struct {
	identities map[string][]CryptoIdentity
	err        error
}

func (f fakeCryptoResolver) Resolve(system string) ([]CryptoIdentity, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.identities[system], nil
}

func TestRunRemediationGenerateFloorWritesAndChecks(t *testing.T) {
	oldOpts := runtimeFloorOpts
	t.Cleanup(func() { runtimeFloorOpts = oldOpts })

	outPath := filepath.Join(t.TempDir(), "runtime-dep-floor.json")
	resolver := fakeCryptoResolver{identities: map[string][]CryptoIdentity{
		"x86_64-linux": {{
			Name:      "openssl",
			CVE:       "CVE-2026-0001",
			System:    "x86_64-linux",
			Pin:       "nixpkgs",
			Rev:       "abc123",
			Output:    "out",
			Version:   "3.6.3",
			StorePath: "/nix/store/aaaa-openssl-3.6.3",
		}},
	}}

	runtimeFloorOpts = runtimeFloorFlags{
		out:     outPath,
		systems: "x86_64-linux",
	}
	if err := runRemediationGenerateFloor(resolver); err != nil {
		t.Fatalf("generate floor: %v", err)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read generated allowlist: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("generated allowlist is not JSON: %v\n%s", err, raw)
	}

	// --check against the file just written must pass.
	runtimeFloorOpts.check = true
	if err := runRemediationGenerateFloor(resolver); err != nil {
		t.Fatalf("check against freshly generated allowlist should pass: %v", err)
	}

	// A drifted resolver must fail the check.
	drifted := fakeCryptoResolver{identities: map[string][]CryptoIdentity{
		"x86_64-linux": {{
			Name:      "openssl",
			CVE:       "CVE-2026-0001",
			System:    "x86_64-linux",
			Pin:       "nixpkgs",
			Rev:       "def456",
			Output:    "out",
			Version:   "3.6.4",
			StorePath: "/nix/store/bbbb-openssl-3.6.4",
		}},
	}}
	if err := runRemediationGenerateFloor(drifted); err == nil {
		t.Fatal("check with drifted identities should fail")
	}

	// No systems is a usage error; resolver failures propagate.
	runtimeFloorOpts.check = false
	runtimeFloorOpts.systems = ""
	if err := runRemediationGenerateFloor(resolver); err == nil {
		t.Fatal("empty --systems should error")
	}
	runtimeFloorOpts.systems = "x86_64-linux"
	if err := runRemediationGenerateFloor(fakeCryptoResolver{err: fmt.Errorf("eval failed")}); err == nil || !strings.Contains(err.Error(), "eval failed") {
		t.Fatalf("resolver error should propagate, got %v", err)
	}
}

func TestNixEvalResolverDecodesIdentities(t *testing.T) {
	resolver := newNixEvalResolver("core")
	resolver.runJSON = func(args ...string) ([]byte, error) {
		if len(args) == 0 || args[0] != "eval" {
			t.Fatalf("unexpected nix args: %v", args)
		}
		return []byte(`[{"name":"openssl","system":"x86_64-linux","storePath":"/nix/store/aaaa-openssl-3.6.3"}]`), nil
	}
	ids, err := resolver.Resolve("x86_64-linux")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(ids) != 1 || ids[0].Name != "openssl" {
		t.Fatalf("unexpected identities: %#v", ids)
	}

	resolver.runJSON = func(args ...string) ([]byte, error) {
		return []byte("not json"), nil
	}
	if _, err := resolver.Resolve("x86_64-linux"); err == nil {
		t.Fatal("invalid JSON should error")
	}
	resolver.runJSON = func(args ...string) ([]byte, error) {
		return nil, fmt.Errorf("nix not installed")
	}
	if _, err := resolver.Resolve("x86_64-linux"); err == nil || !strings.Contains(err.Error(), "nix eval") {
		t.Fatalf("runner error should be wrapped, got %v", err)
	}
}
