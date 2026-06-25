package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
)

func TestFlakeRef(t *testing.T) {
	cases := map[string]string{
		"":             ".",
		".":            ".",
		"core":         "./core",
		"./core":       "./core",
		"../core":      "../core",
		"/abs/core":    "/abs/core",
		"path:core":    "path:core",
		"git+file://x": "git+file://x",
	}
	for in, want := range cases {
		if got := flakeRef(in); got != want {
			t.Errorf("flakeRef(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadCryptoAllowlistFileErrors(t *testing.T) {
	dir := t.TempDir()
	// Missing file.
	if _, err := loadCryptoAllowlistFile(filepath.Join(dir, "nope.json")); err == nil {
		t.Error("expected error for missing file")
	}
	// Bad JSON.
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{not json"), 0o644)
	if _, err := loadCryptoAllowlistFile(bad); err == nil {
		t.Error("expected error for bad JSON")
	}
	// Empty deps.
	empty := filepath.Join(dir, "empty.json")
	_ = os.WriteFile(empty, []byte(`{"deps":[]}`), 0o644)
	if _, err := loadCryptoAllowlistFile(empty); err == nil {
		t.Error("expected error for empty deps")
	}
	// Valid.
	good := filepath.Join(dir, "good.json")
	allowlist, _ := generateCryptoAllowlist(sampleResolver(), []string{"x86_64-linux"}, fleet.DefaultRemediationPolicy())
	if err := writeCryptoAllowlistFile(good, allowlist); err != nil {
		t.Fatal(err)
	}
	if f, err := loadCryptoAllowlistFile(good); err != nil || len(f.Deps) == 0 {
		t.Errorf("expected a valid load, got err=%v", err)
	}
}

func TestWriteCryptoAllowlistFileBadDir(t *testing.T) {
	// A path under a file (not a dir) cannot be created.
	dir := t.TempDir()
	notADir := filepath.Join(dir, "afile")
	_ = os.WriteFile(notADir, []byte("x"), 0o644)
	allowlist, _ := generateCryptoAllowlist(sampleResolver(), []string{"x86_64-linux"}, fleet.DefaultRemediationPolicy())
	if err := writeCryptoAllowlistFile(filepath.Join(notADir, "sub", "out.json"), allowlist); err == nil {
		t.Error("expected error writing under a non-directory")
	}
}

func TestCheckCryptoAllowlistInSyncErrors(t *testing.T) {
	dir := t.TempDir()
	want, _ := generateCryptoAllowlist(sampleResolver(), []string{"x86_64-linux"}, fleet.DefaultRemediationPolicy())

	prevQuiet := GlobalOpts.Quiet
	GlobalOpts.Quiet = true
	defer func() { GlobalOpts.Quiet = prevQuiet }()

	// Missing committed file.
	if err := checkCryptoAllowlistInSync(filepath.Join(dir, "nope.json"), want); err == nil {
		t.Error("expected error for missing committed file")
	}
	// Bad JSON committed file.
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{bad"), 0o644)
	if err := checkCryptoAllowlistInSync(bad, want); err == nil {
		t.Error("expected error for bad committed JSON")
	}
}

// writeRouteFixtures lays down a coreDir/tests/runtime-dep-floor.json so the
// route-context loader can read the crypto CVEs from a real file.
func writeRouteFixtures(t *testing.T) string {
	t.Helper()
	coreDir := t.TempDir()
	allowlist, err := generateCryptoAllowlist(sampleResolver(), []string{"x86_64-linux"}, fleet.DefaultRemediationPolicy())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := writeCryptoAllowlistFile(filepath.Join(coreDir, "tests", "runtime-dep-floor.json"), allowlist); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}
	return coreDir
}

func TestLoadRouteContextFromAllowlist(t *testing.T) {
	coreDir := writeRouteFixtures(t)
	ctx := LoadRouteContext(coreDir, "")
	// openssl/sqlite CVEs are picked up from the committed-shape allowlist.
	if ctx.cryptoCVEs["CVE-2026-34182"] != "openssl" {
		t.Errorf("expected openssl CVE in context, got %v", ctx.cryptoCVEs)
	}
	if ctx.cryptoCVEs["CVE-2026-11822"] != "sqlite" {
		t.Errorf("expected sqlite CVE in context, got %v", ctx.cryptoCVEs)
	}
	if ctx.cryptoTrust != fleet.CryptoTrustNixpkgs {
		t.Errorf("expected nixpkgs trust, got %q", ctx.cryptoTrust)
	}
	// A campaign for an allowlisted crypto CVE routes substitute_vex.
	route, _ := ctx.classifyCampaignRoute(RemediationCampaign{Package: "openssl", CVE: "CVE-2026-34182"})
	if route != RouteSubstituteVEX {
		t.Errorf("expected substitute_vex, got %q", route)
	}
}

// The real committed fleet config carries a node22 soft opt-in + cryptoTrust, so
// loading it exercises the unstable-opt-in branch of the context loader.
func TestLoadRouteContextFromRealFleetConfig(t *testing.T) {
	fleetPath := filepath.Join("..", "..", "..", "clearcutt.fleet.yaml")
	if _, err := os.Stat(fleetPath); err != nil {
		t.Skip("repo fleet config not found from test cwd")
	}
	ctx := LoadRouteContext("", fleetPath)
	if len(ctx.unstablePkgs) == 0 && len(ctx.unstableCVEs) == 0 {
		t.Error("expected the node22 soft opt-in to populate the unstable maps")
	}
}

func TestEnrichPlanRoutesBestEffort(t *testing.T) {
	coreDir := writeRouteFixtures(t)
	plan := &RemediationPlan{Campaigns: []RemediationCampaign{
		{Package: "openssl", CVE: "CVE-2026-34182"},
		{Package: "zlib", CVE: "CVE-2026-1", FixedVersion: "1.3.2"},
	}}
	enrichPlanRoutesBestEffort(plan, coreDir)
	if plan.Campaigns[0].RecommendedRoute != RouteSubstituteVEX {
		t.Errorf("openssl route = %q", plan.Campaigns[0].RecommendedRoute)
	}
	if plan.Campaigns[1].RecommendedRoute != RouteVersionBump {
		t.Errorf("zlib route = %q", plan.Campaigns[1].RecommendedRoute)
	}
	// nil plan is a no-op (must not panic).
	enrichPlanRoutesBestEffort(nil, coreDir)
}

// TestRunRemediationVexCrypto exercises the vex-crypto command handler end to
// end (no nix needed): it reads the allowlist, writes the OpenVEX doc, and
// derives the .grype.yaml suppression from it.
func TestRunRemediationVexCrypto(t *testing.T) {
	coreDir := writeRouteFixtures(t)
	vexOut := filepath.Join(t.TempDir(), "crypto.openvex.json")
	grypeCfg := filepath.Join(t.TempDir(), ".grype.yaml")

	prev := remediationVexCryptoOpts
	prevQuiet := GlobalOpts.Quiet
	GlobalOpts.Quiet = true
	defer func() { remediationVexCryptoOpts, GlobalOpts.Quiet = prev, prevQuiet }()

	remediationVexCryptoOpts = remediationVexCryptoFlags{
		coreDir:     coreDir,
		product:     "pkg:nix/test",
		vexOut:      vexOut,
		grypeConfig: grypeCfg,
		pkgType:     "binary",
	}
	if err := runRemediationVexCrypto(); err != nil {
		t.Fatalf("runRemediationVexCrypto: %v", err)
	}
	if _, err := os.Stat(vexOut); err != nil {
		t.Errorf("expected OpenVEX written: %v", err)
	}
	raw, err := os.ReadFile(grypeCfg)
	if err != nil || len(raw) == 0 {
		t.Errorf("expected .grype.yaml suppression written: %v", err)
	}
}

func TestDistinctStorePathsTruncates(t *testing.T) {
	known := []CryptoKnownGood{
		{StorePath: "a-openssl-3.6.3"},
		{StorePath: "b-openssl-3.6.3"},
		{StorePath: "c-openssl-3.6.3"},
		{StorePath: "d-openssl-3.6.3"},
		{StorePath: "e-openssl-3.6.3"},
		{StorePath: "f-openssl-3.6.3"},
	}
	got := distinctStorePaths(known)
	if len(got) != 5 {
		t.Fatalf("expected 4 paths + a '+N more' marker = 5 entries, got %d: %v", len(got), got)
	}
	if got[4] != "+2 more" {
		t.Errorf("expected truncation marker, got %q", got[4])
	}
}
