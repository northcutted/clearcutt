package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeStatusJSON writes a JSON fixture, creating parent directories the
// ledger paths (overlays/cve, tests) do not exist under a fresh core dir.
func writeStatusJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCatalogJSON(t, path, v)
}

// writeStatusLedgerFixture seeds one carried decision per ledger source under
// a core workspace: overlay evidence with a triage block, a scanner ignore,
// a wait decision record, a fleet soft opt-in, and a crypto allowlist entry.
func writeStatusLedgerFixture(t *testing.T) (coreDir, fleetPath string) {
	t.Helper()
	coreDir = writeTriageCoreDir(t, opensslTriagePinRev)
	overlayDir := filepath.Join(coreDir, "overlays", "cve")
	if err := os.MkdirAll(overlayDir, 0o755); err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().AddDate(0, 3, 0).Format("2006-01-02")

	writeStatusJSON(t, filepath.Join(overlayDir, "cve-2026-11111-zlib.evidence.json"), map[string]any{
		"schemaVersion":  "clearcutt.remediation.evidence/v1",
		"status":         "draft_compiled",
		"cve":            "CVE-2026-11111",
		"package":        "zlib",
		"policyDecision": map[string]any{"selected": true, "reason": "eligible"},
		"validation":     []map[string]any{{"status": "passed"}},
		"triage": map[string]any{
			"schemaVersion": "clearcutt.triage/v1",
			"route":         "fetchpatch_rebuild",
			"decidedBy":     "human",
			"retirement":    map[string]any{"kind": "pin_carries_fix", "package": "zlib", "version": "1.3.2"},
		},
	})
	writeStatusJSON(t, filepath.Join(overlayDir, "cve-2026-22222-python.ignore.evidence.json"), map[string]any{
		"schemaVersion": "clearcutt.remediation.evidence/v1",
		"status":        "scanner_suppressed",
		"cve":           "CVE-2026-22222",
		"package":       "python",
		"owner":         "platform",
		"reason":        "fix not yet in nixpkgs",
		"expires":       future,
		"suppressions":  []map[string]any{},
	})
	writeStatusJSON(t, filepath.Join(overlayDir, "cve-2026-33333-nodejs.decision.evidence.json"), map[string]any{
		"schemaVersion":    "clearcutt.remediation.evidence/v1",
		"status":           "triage_wait",
		"cve":              "CVE-2026-33333",
		"package":          "nodejs",
		"installedVersion": "24.15.0",
		"fixedVersion":     "24.17.0",
		"owner":            "platform",
		"reason":           "fix on staging-next; preview tier waits for the channel",
		"triage": map[string]any{
			"schemaVersion": "clearcutt.triage/v1",
			"route":         "wait",
			"decidedBy":     "human",
			"retirement":    map[string]any{"kind": "ref_carries_fix", "package": "nodejs", "ref": "nixos-unstable", "version": "24.17.0"},
		},
	})
	writeStatusJSON(t, filepath.Join(coreDir, "tests", "runtime-dep-floor.json"), map[string]any{
		"schemaVersion": "clearcutt.runtime-crypto-allowlist/v1",
		"trust":         "nixpkgs",
		"deps": []map[string]any{{
			"name":       "openssl",
			"cve":        "CVE-2026-55555",
			"provenance": "nixpkgs",
			"knownGood":  []map[string]any{},
		}},
	})

	fleetPath = filepath.Join(t.TempDir(), "clearcutt.fleet.yaml")
	fleetYAML := `apiVersion: clearcutt.dev/v1
kind: FleetConfig
remediation:
  unstable:
    softOptIns:
      - package: dotnet
        ref: nixos-unstable
        owner: platform
        fixes:
          - cve: CVE-2026-44444
            installedVersion: 8.0.14
            fixedVersion: 8.0.20
`
	if err := os.WriteFile(fleetPath, []byte(fleetYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	return coreDir, fleetPath
}

func TestRemediationStatusAggregatesLedgerSources(t *testing.T) {
	coreDir, fleetPath := writeStatusLedgerFixture(t)

	stdout, err := runCLI(t, "remediation", "status", "--core-dir", coreDir, "--fleet-config", fleetPath)
	if err != nil {
		t.Fatalf("status failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"SOURCE", "CVE", "PACKAGE", "ROUTE", "RETIRES", "STATE",
		"overlay", "CVE-2026-11111", "fetchpatch_rebuild", "pin >= 1.3.2",
		"ignore", "CVE-2026-22222", "scanner_ignore", "expires",
		"decision", "CVE-2026-33333", "wait", "nixos-unstable >= 24.17.0", "waiting",
		"fleet", "CVE-2026-44444", "unstable_optin", "pin >= 8.0.20",
		"crypto", "CVE-2026-55555", "substitute_vex",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("status table missing %q:\n%s", want, stdout)
		}
	}

	jsonOut, err := runCLI(t, "--format", "json", "remediation", "status", "--core-dir", coreDir, "--fleet-config", fleetPath)
	if err != nil {
		t.Fatalf("json status failed: %v\n%s", err, jsonOut)
	}
	var report RemediationStatusReport
	if err := json.NewDecoder(strings.NewReader(jsonOut)).Decode(&report); err != nil {
		t.Fatalf("decode status report: %v\n%s", err, jsonOut)
	}
	if len(report.Entries) != 5 {
		t.Fatalf("expected 5 ledger entries, got %d: %+v", len(report.Entries), report.Entries)
	}
	sources := map[string]int{}
	for _, entry := range report.Entries {
		sources[entry.Source]++
	}
	for _, source := range []string{"overlay", "ignore", "decision", "fleet", "crypto"} {
		if sources[source] != 1 {
			t.Fatalf("expected one %s entry, got %+v", source, sources)
		}
	}
}

func TestRemediationStatusMarksExpiredSuppressions(t *testing.T) {
	coreDir := writeTriageCoreDir(t, opensslTriagePinRev)
	overlayDir := filepath.Join(coreDir, "overlays", "cve")
	expired := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	writeStatusJSON(t, filepath.Join(overlayDir, "cve-2026-77777-curl.ignore.evidence.json"), map[string]any{
		"schemaVersion": "clearcutt.remediation.evidence/v1",
		"status":        "scanner_suppressed",
		"cve":           "CVE-2026-77777",
		"package":       "curl",
		"owner":         "platform",
		"reason":        "expired on purpose",
		"expires":       expired,
	})

	stdout, err := runCLI(t, "remediation", "status", "--core-dir", coreDir)
	if err != nil {
		t.Fatalf("status failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "expired") {
		t.Fatalf("expected expired state:\n%s", stdout)
	}
}

// TestRemediationStatusCheckRetirementsFires pins the three condition kinds:
// the pin catching up (retire), the watched ref landing the fix (act), and a
// lapsed expiry backstop (expired). pin_carries_fix must probe the CURRENT
// pin from core/flake.lock, not any rev recorded at decision time.
func TestRemediationStatusCheckRetirementsFires(t *testing.T) {
	coreDir := writeTriageCoreDir(t, opensslTriagePinRev)
	overlayDir := filepath.Join(coreDir, "overlays", "cve")
	expired := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")

	writeStatusJSON(t, filepath.Join(overlayDir, "cve-2026-34182-openssl.decision.evidence.json"), map[string]any{
		"schemaVersion":    "clearcutt.remediation.evidence/v1",
		"status":           "triage_decided",
		"cve":              "CVE-2026-34182",
		"package":          "openssl",
		"installedVersion": "3.6.2",
		"fixedVersion":     "3.6.3",
		"owner":            "platform",
		"reason":           "cold rebuild until the pin catches up",
		"triage": map[string]any{
			"schemaVersion": "clearcutt.triage/v1",
			"route":         "fetchpatch_rebuild",
			"decidedBy":     "human",
			"retirement":    map[string]any{"kind": "pin_carries_fix", "package": "openssl", "version": "3.6.3"},
		},
	})
	writeStatusJSON(t, filepath.Join(overlayDir, "cve-2026-48937-nodejs.decision.evidence.json"), map[string]any{
		"schemaVersion":    "clearcutt.remediation.evidence/v1",
		"status":           "triage_wait",
		"cve":              "CVE-2026-48937",
		"package":          "nodejs",
		"installedVersion": "24.15.0",
		"fixedVersion":     "24.17.0",
		"owner":            "platform",
		"reason":           "waiting for the channel",
		"triage": map[string]any{
			"schemaVersion": "clearcutt.triage/v1",
			"route":         "wait",
			"decidedBy":     "human",
			"retirement":    map[string]any{"kind": "ref_carries_fix", "package": "nodejs", "ref": "nixos-unstable", "version": "24.17.0"},
		},
	})
	// Not yet retirable: the pin carries 3.6.3, below this watch version.
	writeStatusJSON(t, filepath.Join(overlayDir, "cve-2026-88888-openssl.decision.evidence.json"), map[string]any{
		"schemaVersion": "clearcutt.remediation.evidence/v1",
		"status":        "triage_decided",
		"cve":           "CVE-2026-88888",
		"package":       "openssl",
		"fixedVersion":  "9.9.9",
		"owner":         "platform",
		"reason":        "future fix",
		"triage": map[string]any{
			"schemaVersion": "clearcutt.triage/v1",
			"route":         "fetchpatch_rebuild",
			"decidedBy":     "human",
			"retirement":    map[string]any{"kind": "pin_carries_fix", "package": "openssl", "version": "9.9.9"},
		},
	})
	writeStatusJSON(t, filepath.Join(overlayDir, "cve-2026-77777-curl.ignore.evidence.json"), map[string]any{
		"schemaVersion": "clearcutt.remediation.evidence/v1",
		"status":        "scanner_suppressed",
		"cve":           "CVE-2026-77777",
		"package":       "curl",
		"owner":         "platform",
		"reason":        "expired suppression",
		"expires":       expired,
	})

	swapTriageProbeHooks(t, &stubFixFetcher{files: map[string]string{
		opensslTriagePinRev: "version = \"3.6.3\";\n",
		"nixos-unstable":    "version = \"24.17.0\";\n",
	}}, func(_, attr string) (string, error) {
		return fmt.Sprintf("pkgs/by-name/%s/package.nix", attr), nil
	})

	stdout, err := runCLI(t, "remediation", "status", "--check-retirements", "--core-dir", coreDir)
	if err != nil {
		t.Fatalf("check-retirements failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"[retirement] retire: CVE-2026-34182 (openssl) pin_carries_fix — pin nixpkgs now carries 3.6.3 (>= 3.6.3)",
		"[retirement] act: CVE-2026-48937 (nodejs) ref_carries_fix — nixos-unstable now carries 24.17.0 (>= 24.17.0)",
		"[retirement] expired: CVE-2026-77777 (curl) expiry — expired " + expired,
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("fired output missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "CVE-2026-88888 (openssl) pin_carries_fix") {
		t.Fatalf("unfired condition must not report:\n%s", stdout)
	}

	jsonOut, err := runCLI(t, "--format", "json", "remediation", "status", "--check-retirements", "--core-dir", coreDir)
	if err != nil {
		t.Fatalf("json check-retirements failed: %v\n%s", err, jsonOut)
	}
	var report RemediationStatusReport
	if err := json.NewDecoder(strings.NewReader(jsonOut)).Decode(&report); err != nil {
		t.Fatalf("decode status report: %v\n%s", err, jsonOut)
	}
	if len(report.Fired) != 3 {
		t.Fatalf("expected 3 fired conditions, got %+v", report.Fired)
	}
	states := map[string]string{}
	for _, entry := range report.Entries {
		states[entry.CVE] = entry.State
	}
	if states["CVE-2026-34182"] != "retire" || states["CVE-2026-48937"] != "act" || states["CVE-2026-77777"] != "expired" || states["CVE-2026-88888"] != "active" {
		t.Fatalf("unexpected entry states: %+v", states)
	}

	_, err = runCLI(t, "remediation", "status", "--check-retirements", "--strict", "--core-dir", coreDir)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("strict mode with fired conditions must exit ErrCheckFailed, got %v", err)
	}
}

// TestRemediationStatusCheckRetirementsQuietWhenNothingFires guards the
// scheduled-workflow contract: a clean sweep exits zero even under --strict.
func TestRemediationStatusCheckRetirementsQuietWhenNothingFires(t *testing.T) {
	coreDir := writeTriageCoreDir(t, opensslTriagePinRev)
	overlayDir := filepath.Join(coreDir, "overlays", "cve")
	writeStatusJSON(t, filepath.Join(overlayDir, "cve-2026-34182-openssl.decision.evidence.json"), map[string]any{
		"schemaVersion": "clearcutt.remediation.evidence/v1",
		"status":        "triage_decided",
		"cve":           "CVE-2026-34182",
		"package":       "openssl",
		"fixedVersion":  "3.6.3",
		"owner":         "platform",
		"reason":        "cold rebuild until the pin catches up",
		"triage": map[string]any{
			"schemaVersion": "clearcutt.triage/v1",
			"route":         "fetchpatch_rebuild",
			"decidedBy":     "human",
			"retirement":    map[string]any{"kind": "pin_carries_fix", "package": "openssl", "version": "3.6.3"},
		},
	})
	swapTriageProbeHooks(t, &stubFixFetcher{files: map[string]string{
		opensslTriagePinRev: "version = \"3.6.2\";\n",
	}}, func(string, string) (string, error) {
		return "pkgs/development/libraries/openssl/default.nix", nil
	})

	stdout, err := runCLI(t, "remediation", "status", "--check-retirements", "--strict", "--core-dir", coreDir)
	if err != nil {
		t.Fatalf("clean sweep must pass strict mode: %v\n%s", err, stdout)
	}
	if strings.Contains(stdout, "[retirement]") {
		t.Fatalf("nothing should fire while the pin lags:\n%s", stdout)
	}
}

func TestRemediationStatusRequiresWorkspaceForRetirementChecks(t *testing.T) {
	overlayDir := t.TempDir()
	_, err := runCLI(t, "remediation", "status", "--overlay-dir", overlayDir, "--check-retirements")
	if err == nil || !strings.Contains(err.Error(), "--check-retirements needs the core workspace") {
		t.Fatalf("expected workspace requirement error, got %v", err)
	}

	// The plain ledger read works from the overlay dir alone.
	stdout, err := runCLI(t, "remediation", "status", "--overlay-dir", overlayDir)
	if err != nil {
		t.Fatalf("ledger read failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "No carried remediation decisions found.") {
		t.Fatalf("expected empty-ledger message:\n%s", stdout)
	}
}
