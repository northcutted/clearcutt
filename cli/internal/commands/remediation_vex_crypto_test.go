package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/clearcutt/internal/fleet"
	"sigs.k8s.io/yaml"
)

func sampleAllowlist(t *testing.T, trust string) *CryptoAllowlistFile {
	t.Helper()
	policy := fleet.DefaultRemediationPolicy()
	if trust != "" {
		policy.CryptoTrust = trust
	}
	allowlist, err := generateCryptoAllowlist(sampleResolver(), []string{"x86_64-linux", "aarch64-linux"}, policy)
	if err != nil {
		t.Fatalf("generate allowlist: %v", err)
	}
	return allowlist
}

func TestBuildCryptoVexEmitsNotAffectedPerCVE(t *testing.T) {
	doc, rules, err := buildCryptoVex(sampleAllowlist(t, ""), "pkg:nix/clearcutt-fleet", "binary", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("buildCryptoVex: %v", err)
	}
	// openssl + sqlite each carry a CVE -> two statements.
	if len(doc.Statements) != 2 {
		t.Fatalf("expected 2 VEX statements, got %d", len(doc.Statements))
	}
	cves := map[string]OpenVEXStatement{}
	for _, s := range doc.Statements {
		cves[s.Vulnerability.Name] = s
		if s.Status != vexNotAffected {
			t.Errorf("statement %s status=%q, want not_affected", s.Vulnerability.Name, s.Status)
		}
		if s.Justification != "vulnerable_code_not_present" {
			t.Errorf("statement %s justification=%q", s.Vulnerability.Name, s.Justification)
		}
		if s.Products[0].ID != "pkg:nix/clearcutt-fleet" {
			t.Errorf("unexpected product: %s", s.Products[0].ID)
		}
	}
	if _, ok := cves["CVE-2026-34182"]; !ok {
		t.Error("missing openssl CVE statement")
	}
	if s, ok := cves["CVE-2026-11822"]; !ok {
		t.Error("missing sqlite CVE statement")
	} else if !strings.Contains(s.ImpactStatement, "patched-not-bumped") {
		t.Errorf("impact statement missing provenance framing: %s", s.ImpactStatement)
	}

	// One grype rule per (cve, distinct version). Both deps have a single
	// version, so two rules total.
	if len(rules) != 2 {
		t.Fatalf("expected 2 VEX-derived grype rules, got %d", len(rules))
	}
	for _, r := range rules {
		if r.Package == nil || r.Package.Version == "" {
			t.Errorf("rule missing package/version: %+v", r)
		}
		if !strings.Contains(r.Reason, "OpenVEX not_affected") {
			t.Errorf("rule reason should cite the VEX: %s", r.Reason)
		}
	}
}

func TestBuildCryptoVexReproduceTrustNotesRebuild(t *testing.T) {
	doc, _, err := buildCryptoVex(sampleAllowlist(t, fleet.CryptoTrustReproduce), "p", "binary", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("buildCryptoVex: %v", err)
	}
	if !strings.Contains(doc.Statements[0].ImpactStatement, "independently rebuilt") {
		t.Errorf("reproduce trust should note the rebuild: %s", doc.Statements[0].ImpactStatement)
	}
}

func TestBuildCryptoVexSkipsDepsWithoutCVE(t *testing.T) {
	allowlist := &CryptoAllowlistFile{
		Trust: "nixpkgs",
		Deps: []CryptoAllowlistDep{
			{Name: "openssl", CVE: "", KnownGood: []CryptoKnownGood{{StorePath: "a-openssl-3.6.3", Version: "3.6.3"}}},
			{Name: "sqlite", CVE: "CVE-2026-11822", KnownGood: []CryptoKnownGood{{StorePath: "b-sqlite-3.53.2", Version: "3.53.2"}}},
		},
	}
	doc, rules, err := buildCryptoVex(allowlist, "p", "binary", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("buildCryptoVex: %v", err)
	}
	if len(doc.Statements) != 1 || doc.Statements[0].Vulnerability.Name != "CVE-2026-11822" {
		t.Fatalf("expected only the sqlite CVE statement, got %+v", doc.Statements)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
}

// The VEX-derived rules must be consumable by the grype-ignore writer, and the
// resulting .grype.yaml must round-trip — proving the VEX -> suppression bridge.
func TestCryptoVexDerivedSuppressionRoundTrips(t *testing.T) {
	_, rules, err := buildCryptoVex(sampleAllowlist(t, ""), "p", "binary", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("buildCryptoVex: %v", err)
	}
	grypePath := filepath.Join(t.TempDir(), ".grype.yaml")
	added, err := addGrypeIgnoreRules(grypePath, rules)
	if err != nil {
		t.Fatalf("addGrypeIgnoreRules: %v", err)
	}
	if added != len(rules) {
		t.Errorf("expected %d rules added, got %d", len(rules), added)
	}
	// Re-applying is idempotent (no double suppression).
	again, err := addGrypeIgnoreRules(grypePath, rules)
	if err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if again != 0 {
		t.Errorf("expected idempotent re-apply, added %d", again)
	}

	raw, err := os.ReadFile(grypePath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg grypeConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("re-parse .grype.yaml: %v", err)
	}
	if len(cfg.Ignore) != len(rules) {
		t.Errorf("expected %d ignore rules in file, got %d", len(rules), len(cfg.Ignore))
	}
}
