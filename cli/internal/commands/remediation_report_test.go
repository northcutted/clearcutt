package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTriageOverlay seeds one overlay + paired evidence carrying the given
// triage block (nil = no block) so validate-overlays exercises the full path.
func writeTriageOverlay(t *testing.T, dir string, triage any) {
	t.Helper()
	overlayPath := filepath.Join(dir, "cve-2026-20001-zlib.nix")
	if err := os.WriteFile(overlayPath, []byte("final: prev: {\n  zlib = prev.zlib.overrideAttrs (old: { version = \"1.3.2\"; });\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	evidence := map[string]any{
		"schemaVersion":  "clearcutt.remediation.evidence/v1",
		"status":         "draft_compiled",
		"policyDecision": map[string]any{"selected": true, "reason": "eligible"},
		"validation":     []map[string]any{{"status": "passed"}},
	}
	if triage != nil {
		evidence["triage"] = triage
	}
	writeCatalogJSON(t, strings.TrimSuffix(overlayPath, ".nix")+".evidence.json", evidence)
}

func TestRemediationValidateOverlaysTriageBlocks(t *testing.T) {
	future := time.Now().UTC().AddDate(0, 3, 0).Format("2006-01-02")
	expired := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")

	cases := []struct {
		name    string
		triage  any
		wantErr string
	}{
		{
			name: "route only",
			triage: map[string]any{
				"schemaVersion": "clearcutt.triage/v1",
				"route":         "substitute_vex",
				"decidedBy":     "human",
			},
		},
		{
			name: "expiry retirement in the future",
			triage: map[string]any{
				"route":      "scanner_ignore",
				"decidedBy":  "human",
				"retirement": map[string]any{"kind": "expiry", "expires": future},
			},
		},
		{
			name: "pin retirement needs no expires",
			triage: map[string]any{
				"route":      "fetchpatch_rebuild",
				"decidedBy":  "agent:triage-bot",
				"retirement": map[string]any{"kind": "pin_carries_fix", "package": "zlib", "version": "1.3.3"},
			},
		},
		{
			name: "wait route with ref retirement",
			triage: map[string]any{
				"route":      "wait",
				"decidedBy":  "policy",
				"retirement": map[string]any{"kind": "ref_carries_fix", "ref": "nixos-unstable", "version": "1.3.3"},
			},
		},
		{
			name:    "triage not an object",
			triage:  "scanner_ignore",
			wantErr: "triage must be an object",
		},
		{
			name:    "unknown route",
			triage:  map[string]any{"route": "hope_for_the_best"},
			wantErr: `triage route "hope_for_the_best" is not a known route`,
		},
		{
			name:    "missing route",
			triage:  map[string]any{"decidedBy": "human"},
			wantErr: `triage route "" is not a known route`,
		},
		{
			name: "unknown retirement kind",
			triage: map[string]any{
				"route":      "wait",
				"retirement": map[string]any{"kind": "eventually"},
			},
			wantErr: `triage retirement kind "eventually" is not a known kind`,
		},
		{
			name: "expiry retirement without expires",
			triage: map[string]any{
				"route":      "scanner_ignore",
				"retirement": map[string]any{"kind": "expiry"},
			},
			wantErr: "triage expiry retirement requires expires",
		},
		{
			name: "expiry retirement with malformed date",
			triage: map[string]any{
				"route":      "scanner_ignore",
				"retirement": map[string]any{"kind": "expiry", "expires": "soon"},
			},
			wantErr: "triage retirement expires is invalid",
		},
		{
			name: "expired expiry retirement",
			triage: map[string]any{
				"route":      "scanner_ignore",
				"retirement": map[string]any{"kind": "expiry", "expires": expired},
			},
			wantErr: "triage retirement expired " + expired,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTriageOverlay(t, dir, tc.triage)
			_, err := runCLI(t, "remediation", "validate-overlays", "--overlay-dir", dir)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("valid triage block rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestRemediationValidateOverlaysSweepsDecisionEvidence(t *testing.T) {
	future := time.Now().UTC().AddDate(0, 1, 0).Format("2006-01-02")
	expired := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	valid := func() map[string]any {
		return map[string]any{
			"schemaVersion": "clearcutt.remediation.evidence/v1",
			"status":        "triage_wait",
			"cve":           "CVE-2026-48937",
			"package":       "nodejs_24",
			"owner":         "ClearCutt maintainers",
			"reason":        "Fix merged to staging-next; below the wait severity ceiling on the preview tier.",
			"triage": map[string]any{
				"schemaVersion": "clearcutt.triage/v1",
				"route":         "wait",
				"decidedBy":     "human",
				"decidedAt":     "2026-07-02T21:04:00Z",
				"retirement":    map[string]any{"kind": "ref_carries_fix", "ref": "nixos-unstable", "version": "24.17.0"},
			},
		}
	}

	cases := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr string
	}{
		{
			name:   "triage_decided status also accepted",
			mutate: func(d map[string]any) { d["status"] = "triage_decided" },
		},
		{
			name:    "wrong schemaVersion",
			mutate:  func(d map[string]any) { d["schemaVersion"] = "clearcutt.triage/v1" },
			wantErr: `has schemaVersion "clearcutt.triage/v1", want clearcutt.remediation.evidence/v1`,
		},
		{
			name:    "unexpected status",
			mutate:  func(d map[string]any) { d["status"] = "scanner_suppressed" },
			wantErr: `has status "scanner_suppressed", want triage_wait or triage_decided`,
		},
		{
			name:    "missing owner",
			mutate:  func(d map[string]any) { delete(d, "owner") },
			wantErr: "requires owner and reason",
		},
		{
			name:    "blank reason",
			mutate:  func(d map[string]any) { d["reason"] = "  " },
			wantErr: "requires owner and reason",
		},
		{
			name:    "missing triage block",
			mutate:  func(d map[string]any) { delete(d, "triage") },
			wantErr: "missing triage block",
		},
		{
			name: "expired retirement inside decision",
			mutate: func(d map[string]any) {
				d["triage"].(map[string]any)["retirement"] = map[string]any{"kind": "expiry", "expires": expired}
			},
			wantErr: "triage retirement expired " + expired,
		},
		{
			name: "unexpired expiry retirement passes",
			mutate: func(d map[string]any) {
				d["triage"].(map[string]any)["retirement"] = map[string]any{"kind": "expiry", "expires": future}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			record := valid()
			tc.mutate(record)
			writeCatalogJSON(t, filepath.Join(dir, "cve-2026-48937-nodejs24.decision.evidence.json"), record)
			_, err := runCLI(t, "remediation", "validate-overlays", "--overlay-dir", dir)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("valid decision record rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}

	// The happy path reports the decision sweep alongside the overlay count.
	dir := t.TempDir()
	writeCatalogJSON(t, filepath.Join(dir, "cve-2026-48937-nodejs24.decision.evidence.json"), valid())
	stdout, err := runCLI(t, "remediation", "validate-overlays", "--overlay-dir", dir)
	if err != nil {
		t.Fatalf("valid decision record failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "Validated 1 triage decision record(s).") {
		t.Fatalf("expected decision record count in output:\n%s", stdout)
	}

	// Malformed JSON is a governance failure, not a crash.
	if err := os.WriteFile(filepath.Join(dir, "cve-2026-48938-nodejs24.decision.evidence.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = runCLI(t, "remediation", "validate-overlays", "--overlay-dir", dir)
	if err == nil || !strings.Contains(err.Error(), "failed to parse decision evidence") {
		t.Fatalf("expected parse failure for malformed decision record, got %v", err)
	}
}

// TestRemediationValidateOverlaysRealEvidenceRegression pins the pre-triage
// contract: a real committed evidence file (no triage block) must keep
// validating byte-for-byte as it did before the triage extension.
func TestRemediationValidateOverlaysRealEvidenceRegression(t *testing.T) {
	fixture := filepath.Join("testdata", "remediation", "cve-2026-34182-openssl.evidence.json")
	status, err := validateOverlayEvidence(fixture)
	if err != nil {
		t.Fatalf("real evidence file no longer validates: %v", err)
	}
	if status != "manual_accepted" {
		t.Fatalf("status = %q, want manual_accepted", status)
	}

	// The same file also passes the full validate-overlays sweep when paired
	// with its overlay.
	dir := t.TempDir()
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cve-2026-34182-openssl.evidence.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cve-2026-34182-openssl.nix"), []byte("final: prev: {\n  openssl = prev.openssl.overrideAttrs (old: { });\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, err := runCLI(t, "remediation", "validate-overlays", "--overlay-dir", dir)
	if err != nil {
		t.Fatalf("real evidence overlay pair failed validate-overlays: %v\n%s", err, stdout)
	}
}
