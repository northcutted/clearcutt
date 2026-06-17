package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
)

// writeFloorEvidence drops a *.evidence.json into dir for the floor generator.
func writeFloorEvidence(t *testing.T, dir, name string, body map[string]any) {
	t.Helper()
	raw, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
}

func opensslEvidence() map[string]any {
	return map[string]any{
		"cve":         "CVE-2026-34182",
		"package":     "openssl",
		"riskFactors": map[string]any{"knownExploited": false, "severity": "critical"},
		"expectedRemoved": []map[string]any{
			{"cve": "CVE-2026-34182", "package": "openssl", "installedVersion": "3.6.2", "fixedVersion": "3.6.3"},
		},
	}
}

func sqliteEvidence() map[string]any {
	return map[string]any{
		"cve":         "CVE-2026-11822",
		"package":     "sqlite",
		"riskFactors": map[string]any{"knownExploited": false, "severity": "high"},
		"expectedRemoved": []map[string]any{
			{"cve": "CVE-2026-11822", "package": "sqlite", "installedVersion": "3.51.2", "fixedVersion": "3.53.2"},
		},
	}
}

func floorByName(deps []RuntimeFloorDep) map[string]string {
	m := map[string]string{}
	for _, d := range deps {
		m[d.Name] = d.MinVersion
	}
	return m
}

func TestGenerateRuntimeFloorDefaultPolicyFloorsCryptoDeps(t *testing.T) {
	dir := t.TempDir()
	writeFloorEvidence(t, dir, "openssl.evidence.json", opensslEvidence())
	writeFloorEvidence(t, dir, "sqlite.evidence.json", sqliteEvidence())

	floor, warnings, err := generateRuntimeFloor(dir, fleet.DefaultRemediationPolicy())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no conservative-default warnings, got %v", warnings)
	}
	got := floorByName(floor.Deps)
	if got["openssl"] != "3.6.3" || got["sqlite"] != "3.53.2" {
		t.Fatalf("unexpected floor deps: %+v", floor.Deps)
	}
	// Deps are sorted by name for a stable diff.
	if floor.Deps[0].Name != "openssl" || floor.Deps[1].Name != "sqlite" {
		t.Fatalf("deps not sorted by name: %+v", floor.Deps)
	}
	if len(floor.Accepted) != 0 {
		t.Fatalf("expected nothing accepted under default policy, got %+v", floor.Accepted)
	}
}

func TestGenerateRuntimeFloorLoosenedPolicyDropsBelowBar(t *testing.T) {
	dir := t.TempDir()
	writeFloorEvidence(t, dir, "openssl.evidence.json", opensslEvidence())
	writeFloorEvidence(t, dir, "sqlite.evidence.json", sqliteEvidence())

	// minimumSeverity=critical: sqlite (high) drops below the bar; openssl stays.
	policy := fleet.DefaultRemediationPolicy()
	policy.MinimumSeverity = "critical"

	floor, _, err := generateRuntimeFloor(dir, policy)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	got := floorByName(floor.Deps)
	if _, ok := got["sqlite"]; ok {
		t.Fatalf("sqlite should be dropped under critical-only policy, got %+v", floor.Deps)
	}
	if got["openssl"] != "3.6.3" {
		t.Fatalf("openssl should stay floored, got %+v", floor.Deps)
	}
	if len(floor.Accepted) != 1 || floor.Accepted[0].Name != "sqlite" || floor.Accepted[0].Reason != "below_risk_threshold" {
		t.Fatalf("expected sqlite recorded as policy-accepted below_risk_threshold, got %+v", floor.Accepted)
	}
}

func TestGenerateRuntimeFloorKEVAlwaysFloorsLowSeverity(t *testing.T) {
	dir := t.TempDir()
	// A low-severity but KEV-listed version-bump CVE must stay floored even under
	// a critical-only severity policy: kev:always is the non-loosenable guardrail.
	writeFloorEvidence(t, dir, "kev.evidence.json", map[string]any{
		"cve":         "CVE-2026-99999",
		"package":     "openssl",
		"riskFactors": map[string]any{"knownExploited": true, "severity": "low"},
		"expectedRemoved": []map[string]any{
			{"cve": "CVE-2026-99999", "package": "openssl", "installedVersion": "3.6.2", "fixedVersion": "3.6.3"},
		},
	})

	policy := fleet.DefaultRemediationPolicy()
	policy.MinimumSeverity = "critical"
	policy.EPSSPercentile = 0.99

	floor, _, err := generateRuntimeFloor(dir, policy)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if floorByName(floor.Deps)["openssl"] != "3.6.3" {
		t.Fatalf("KEV finding must stay floored regardless of severity, got %+v", floor.Deps)
	}
}

func TestGenerateRuntimeFloorSkipsFetchpatchNoVersionBump(t *testing.T) {
	dir := t.TempDir()
	writeFloorEvidence(t, dir, "openssl.evidence.json", opensslEvidence())
	// A fetchpatch overlay (CPython branch patch) keeps the version: no
	// fixedVersion, so it is not version-floorable and must be skipped.
	writeFloorEvidence(t, dir, "python.evidence.json", map[string]any{
		"cve":         "CVE-2026-7210",
		"package":     "python313",
		"riskFactors": map[string]any{"knownExploited": false, "severity": "high"},
		"expectedRemoved": []map[string]any{
			{"cve": "CVE-2026-7210", "package": "python", "installedVersion": "3.13.13"},
		},
	})

	floor, _, err := generateRuntimeFloor(dir, fleet.DefaultRemediationPolicy())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	got := floorByName(floor.Deps)
	if _, ok := got["python313"]; ok {
		t.Fatalf("fetchpatch overlay should not be version-floored, got %+v", floor.Deps)
	}
	if _, ok := got["python"]; ok {
		t.Fatalf("fetchpatch overlay should not be version-floored, got %+v", floor.Deps)
	}
	if got["openssl"] != "3.6.3" {
		t.Fatalf("openssl should still be floored, got %+v", floor.Deps)
	}
}

func TestGenerateRuntimeFloorConservativeDefaultWhenUngated(t *testing.T) {
	dir := t.TempDir()
	// No structured severity/EPSS/KEV: the policy cannot evaluate it, so it is
	// floored conservatively (fail-closed) and flagged — never silently dropped.
	writeFloorEvidence(t, dir, "ungated.evidence.json", map[string]any{
		"cve":         "CVE-2026-55555",
		"package":     "openssl",
		"riskFactors": map[string]any{"knownExploited": false},
		"expectedRemoved": []map[string]any{
			{"cve": "CVE-2026-55555", "package": "openssl", "installedVersion": "3.6.2", "fixedVersion": "3.6.3"},
		},
	})

	floor, warnings, err := generateRuntimeFloor(dir, fleet.DefaultRemediationPolicy())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if floorByName(floor.Deps)["openssl"] != "3.6.3" {
		t.Fatalf("ungated evidence should be floored conservatively, got %+v", floor.Deps)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected one conservative-default warning, got %v", warnings)
	}
}

func TestGenerateRuntimeFloorPicksMaxFixedVersion(t *testing.T) {
	dir := t.TempDir()
	writeFloorEvidence(t, dir, "openssl.evidence.json", map[string]any{
		"cve":         "CVE-2026-34182",
		"package":     "openssl",
		"riskFactors": map[string]any{"knownExploited": false, "severity": "critical"},
		"expectedRemoved": []map[string]any{
			{"cve": "CVE-2026-34182", "package": "openssl", "installedVersion": "3.6.2", "fixedVersion": "3.6.3"},
			{"cve": "CVE-2026-34999", "package": "openssl", "installedVersion": "3.6.2", "fixedVersion": "3.6.10"},
			{"cve": "CVE-2026-34000", "package": "openssl", "installedVersion": "3.6.2", "fixedVersion": "3.6.3-rc1"},
		},
	})

	floor, _, err := generateRuntimeFloor(dir, fleet.DefaultRemediationPolicy())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// 3.6.10 > 3.6.3 (tuple, not string); 3.6.3-rc1 is non-numeric and skipped.
	if got := floorByName(floor.Deps)["openssl"]; got != "3.6.10" {
		t.Fatalf("expected max clean version 3.6.10, got %q", got)
	}
}

func TestGenerateRuntimeFloorEmptyGuard(t *testing.T) {
	dir := t.TempDir() // no evidence files
	_, _, err := generateRuntimeFloor(dir, fleet.DefaultRemediationPolicy())
	if err == nil {
		t.Fatal("expected an error for an empty floor, got nil")
	}
}

// A must_fix overlay whose only fix versions are malformed must fail closed, not
// silently vanish from the gate (the silent-loss failure class).
func TestGenerateRuntimeFloorFailsClosedOnMalformedMustFixVersion(t *testing.T) {
	dir := t.TempDir()
	writeFloorEvidence(t, dir, "bad.evidence.json", map[string]any{
		"cve":         "CVE-2026-7",
		"package":     "openssl",
		"riskFactors": map[string]any{"knownExploited": false, "severity": "critical"},
		"expectedRemoved": []map[string]any{
			{"cve": "CVE-2026-7", "package": "openssl", "installedVersion": "3.6.2", "fixedVersion": "3.6.3-rc1"},
		},
	})
	_, _, err := generateRuntimeFloor(dir, fleet.DefaultRemediationPolicy())
	if err == nil || !strings.Contains(err.Error(), "must_fix but no expectedRemoved.fixedVersion") {
		t.Fatalf("expected fail-closed on a malformed must_fix version, got %v", err)
	}
}

func TestRuntimeFloorAcceptedDrift(t *testing.T) {
	want := []RuntimeFloorAcceptance{{Name: "sqlite", CVE: "CVE-1", Reason: "below_risk_threshold"}}
	if runtimeFloorAcceptedDrift(nil, want) == "" {
		t.Fatal("a newly-dropped dep should surface as accepted drift")
	}
	if runtimeFloorAcceptedDrift(want, want) != "" {
		t.Fatal("identical accepted sets should report no drift")
	}
}

func TestRuntimeFloorDepDrift(t *testing.T) {
	have := []RuntimeFloorDep{{Name: "openssl", MinVersion: "3.6.2"}, {Name: "gone", MinVersion: "1.0"}}
	want := []RuntimeFloorDep{{Name: "openssl", MinVersion: "3.6.3"}, {Name: "sqlite", MinVersion: "3.53.2"}}
	drift := runtimeFloorDepDrift(have, want)
	for _, expect := range []string{"openssl", "sqlite", "gone"} {
		if !strings.Contains(drift, expect) {
			t.Fatalf("drift should mention %q, got:\n%s", expect, drift)
		}
	}
	if runtimeFloorDepDrift(want, want) != "" {
		t.Fatal("identical floors should report no drift")
	}
}

func TestIsCleanDottedNumeric(t *testing.T) {
	for _, ok := range []string{"3", "3.6", "3.6.3", "3.53.2"} {
		if !isCleanDottedNumeric(ok) {
			t.Errorf("%q should be clean dotted-numeric", ok)
		}
	}
	for _, bad := range []string{"", "3.6.3-rc1", "3.6.3a", "v3.6", "3..6", "3.x"} {
		if isCleanDottedNumeric(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
