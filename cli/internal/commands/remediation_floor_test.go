package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/certify"
	"github.com/northcutted/clearcutt/internal/fleet"
)

// fakeResolver returns canned identities per system, mimicking the flake's
// cryptoIdentities output without invoking nix.
type fakeResolver struct {
	bySystem map[string][]CryptoIdentity
	err      error
}

func (f fakeResolver) Resolve(system string) ([]CryptoIdentity, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.bySystem[system], nil
}

func opensslID(system, output, hash string) CryptoIdentity {
	return CryptoIdentity{
		Name: "openssl", CVE: "CVE-2026-34182", System: system, Pin: "nixpkgs",
		Rev: "abc123", Output: output, Version: "3.6.3", StorePath: hash + "-openssl-3.6.3" + suffix(output),
	}
}

func sqliteID(system, output, hash string) CryptoIdentity {
	return CryptoIdentity{
		Name: "sqlite", CVE: "CVE-2026-11822", System: system, Pin: "nixpkgs",
		Rev: "abc123", Output: output, Version: "3.53.2", StorePath: hash + "-sqlite-3.53.2" + suffix(output),
	}
}

func suffix(output string) string {
	if output == "out" {
		return ""
	}
	return "-" + output
}

func sampleResolver() fakeResolver {
	return fakeResolver{bySystem: map[string][]CryptoIdentity{
		"x86_64-linux": {
			opensslID("x86_64-linux", "out", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			opensslID("x86_64-linux", "bin", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
			sqliteID("x86_64-linux", "out", "cccccccccccccccccccccccccccccccc"),
		},
		"aarch64-linux": {
			opensslID("aarch64-linux", "out", "dddddddddddddddddddddddddddddddd"),
			sqliteID("aarch64-linux", "out", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
		},
	}}
}

func TestGenerateCryptoAllowlistGroupsAndSorts(t *testing.T) {
	allowlist, err := generateCryptoAllowlist(sampleResolver(), []string{"x86_64-linux", "aarch64-linux"}, fleet.DefaultRemediationPolicy())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if allowlist.Trust != "nixpkgs" {
		t.Errorf("expected default trust nixpkgs, got %q", allowlist.Trust)
	}
	if allowlist.SchemaVersion != runtimeFloorSchemaVersion {
		t.Errorf("unexpected schema version %q", allowlist.SchemaVersion)
	}
	if len(allowlist.Deps) != 2 {
		t.Fatalf("expected 2 deps (openssl, sqlite), got %d", len(allowlist.Deps))
	}
	// Deps sorted: openssl before sqlite.
	if allowlist.Deps[0].Name != "openssl" || allowlist.Deps[1].Name != "sqlite" {
		t.Errorf("deps not sorted: %q, %q", allowlist.Deps[0].Name, allowlist.Deps[1].Name)
	}
	// openssl: 2 (x86) + 1 (aarch) = 3 known-good.
	if got := len(allowlist.Deps[0].KnownGood); got != 3 {
		t.Errorf("expected 3 openssl identities, got %d", got)
	}
	if allowlist.Deps[0].CVE != "CVE-2026-34182" {
		t.Errorf("unexpected openssl cve %q", allowlist.Deps[0].CVE)
	}
}

func TestGenerateCryptoAllowlistDedupsByStorePath(t *testing.T) {
	// Both systems resolve the SAME store path (the coincidence the real pins
	// exhibit). It must appear once.
	r := fakeResolver{bySystem: map[string][]CryptoIdentity{
		"x86_64-linux":  {opensslID("x86_64-linux", "out", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
		"aarch64-linux": {opensslID("aarch64-linux", "out", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
	}}
	allowlist, err := generateCryptoAllowlist(r, []string{"x86_64-linux", "aarch64-linux"}, fleet.DefaultRemediationPolicy())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(allowlist.Deps) != 1 || len(allowlist.Deps[0].KnownGood) != 1 {
		t.Fatalf("expected 1 deduped identity, got %+v", allowlist.Deps)
	}
}

func TestGenerateCryptoAllowlistRecordsReproduceTrust(t *testing.T) {
	policy := fleet.DefaultRemediationPolicy()
	policy.CryptoTrust = fleet.CryptoTrustReproduce
	allowlist, err := generateCryptoAllowlist(sampleResolver(), []string{"x86_64-linux"}, policy)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if allowlist.Trust != "reproduce" {
		t.Errorf("expected trust reproduce, got %q", allowlist.Trust)
	}
}

func TestGenerateCryptoAllowlistEmptyResolutionFailsClosed(t *testing.T) {
	r := fakeResolver{bySystem: map[string][]CryptoIdentity{"x86_64-linux": {}}}
	if _, err := generateCryptoAllowlist(r, []string{"x86_64-linux"}, fleet.DefaultRemediationPolicy()); err == nil {
		t.Fatal("expected error on empty resolution (vacuous allowlist)")
	}
}

// The generated file must be loadable by the gate AND must pass for the resolved
// identities — the end-to-end contract between generator and gate.
func TestGeneratedAllowlistLoadsAndGatesByIdentity(t *testing.T) {
	allowlist, err := generateCryptoAllowlist(sampleResolver(), []string{"x86_64-linux", "aarch64-linux"}, fleet.DefaultRemediationPolicy())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	p := filepath.Join(t.TempDir(), "runtime-dep-floor.json")
	if err := writeCryptoAllowlistFile(p, allowlist); err != nil {
		t.Fatalf("write: %v", err)
	}
	floor, err := certify.LoadRuntimeDepFloor(p)
	if err != nil {
		t.Fatalf("gate failed to load generated allowlist: %v", err)
	}
	paths := filepath.Join(t.TempDir(), "store-paths")
	body := "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.3\n" + // known-good
		"/nix/store/cccccccccccccccccccccccccccccccc-sqlite-3.53.2\n" // known-good
	if err := os.WriteFile(paths, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := certify.ScanStorePathsForRuntimeCve(paths, floor)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !res.Clean() {
		t.Fatalf("expected clean for known-good identities, got: %v", res.Violations)
	}

	// An off-allowlist openssl fails.
	bad := filepath.Join(t.TempDir(), "bad-paths")
	if err := os.WriteFile(bad, []byte("/nix/store/99999999999999999999999999999999-openssl-3.6.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = certify.ScanStorePathsForRuntimeCve(bad, floor)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Clean() {
		t.Fatal("expected off-allowlist openssl to violate")
	}
}

func TestCheckCryptoAllowlistInSync(t *testing.T) {
	allowlist, err := generateCryptoAllowlist(sampleResolver(), []string{"x86_64-linux"}, fleet.DefaultRemediationPolicy())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	p := filepath.Join(t.TempDir(), "floor.json")
	if err := writeCryptoAllowlistFile(p, allowlist); err != nil {
		t.Fatalf("write: %v", err)
	}

	prevOut, prevQuiet := runtimeFloorOpts.out, GlobalOpts.Quiet
	GlobalOpts.Quiet = true
	defer func() { runtimeFloorOpts.out, GlobalOpts.Quiet = prevOut, prevQuiet }()
	runtimeFloorOpts.out = p

	// In sync.
	if err := checkCryptoAllowlistInSync(p, allowlist); err != nil {
		t.Errorf("expected in sync, got: %v", err)
	}

	// Drift: regenerate with an extra resolved identity.
	r2 := sampleResolver()
	r2.bySystem["x86_64-linux"] = append(r2.bySystem["x86_64-linux"], opensslID("x86_64-linux", "dev", "ffffffffffffffffffffffffffffffff"))
	want2, err := generateCryptoAllowlist(r2, []string{"x86_64-linux"}, fleet.DefaultRemediationPolicy())
	if err != nil {
		t.Fatalf("generate2: %v", err)
	}
	err = checkCryptoAllowlistInSync(p, want2)
	if err == nil {
		t.Fatal("expected drift error")
	}
	if !strings.Contains(err.Error(), "out of sync") {
		t.Errorf("unexpected drift error: %v", err)
	}
}

func TestNixEvalResolverDecodesJSON(t *testing.T) {
	ids := []CryptoIdentity{
		{Name: "openssl", CVE: "CVE-2026-34182", System: "x86_64-linux", Pin: "nixpkgs", Rev: "r", Output: "out", Version: "3.6.3", StorePath: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.3"},
	}
	raw, _ := json.Marshal(ids)
	r := nixEvalResolver{
		flakeDir: "core",
		runJSON: func(args ...string) ([]byte, error) {
			// Sanity: the attr path is built correctly.
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "core#cryptoIdentities.x86_64-linux") {
				t.Errorf("unexpected nix args: %v", args)
			}
			return raw, nil
		},
	}
	got, err := r.Resolve("x86_64-linux")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 1 || got[0].StorePath != ids[0].StorePath {
		t.Fatalf("unexpected decode: %+v", got)
	}
}

func TestSplitCommaList(t *testing.T) {
	got := splitCommaList(" x86_64-linux , aarch64-linux ,")
	if len(got) != 2 || got[0] != "x86_64-linux" || got[1] != "aarch64-linux" {
		t.Fatalf("unexpected split: %v", got)
	}
}
