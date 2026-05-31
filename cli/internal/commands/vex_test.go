package commands

import (
	"encoding/json"
	"testing"
)

var validVexStatuses = map[string]bool{
	"not_affected": true, "affected": true, "fixed": true, "under_investigation": true,
}

var validVexJustifications = map[string]bool{
	"component_not_present":                             true,
	"vulnerable_code_not_present":                       true,
	"vulnerable_code_not_in_execute_path":               true,
	"vulnerable_code_cannot_be_controlled_by_adversary": true,
	"inline_mitigations_already_exist":                  true,
}

func TestVex_GeneratesCompliantDocument(t *testing.T) {
	stdout, err := runCLI(t, "vex", "java21-distroless", "--catalog", fixtureCatalog())
	if err != nil {
		t.Fatalf("vex failed: %v\n%s", err, stdout)
	}

	var doc OpenVEXDocument
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("failed to parse OpenVEX JSON: %v\n%s", err, stdout)
	}
	if len(doc.Statements) == 0 {
		t.Fatal("expected at least one VEX statement for the fixture's finding")
	}

	for i, stmt := range doc.Statements {
		if !validVexStatuses[stmt.Status] {
			t.Errorf("statement[%d] %s: invalid OpenVEX status %q", i, stmt.Vulnerability.Name, stmt.Status)
		}
		// A justification is only valid when status is not_affected.
		if stmt.Justification != "" {
			if stmt.Status != "not_affected" {
				t.Errorf("statement[%d] %s: justification present on status %q (only valid for not_affected)", i, stmt.Vulnerability.Name, stmt.Status)
			}
			if !validVexJustifications[stmt.Justification] {
				t.Errorf("statement[%d] %s: invalid OpenVEX justification %q", i, stmt.Vulnerability.Name, stmt.Justification)
			}
		}
	}

	// The fixture's CVE-2026-9999 is deferred to the base layer -> not_affected.
	if doc.Statements[0].Vulnerability.Name != "CVE-2026-9999" || doc.Statements[0].Status != "not_affected" {
		t.Errorf("expected CVE-2026-9999 to map to not_affected, got %q -> %q",
			doc.Statements[0].Vulnerability.Name, doc.Statements[0].Status)
	}
}

// An exception status with no direct OpenVEX equivalent must not leak through.
func TestVexStatusMapping(t *testing.T) {
	cases := map[string]string{
		"accepted_risk":       "not_affected",
		"false_positive":      "not_affected",
		"affected":            "affected",
		"fixed":               "fixed",
		"under_investigation": "under_investigation",
		"nonsense":            "under_investigation",
	}
	for in, want := range cases {
		if got := vexStatusFromException(in); got != want {
			t.Errorf("vexStatusFromException(%q) = %q, want %q", in, got, want)
		}
		if !validVexStatuses[vexStatusFromException(in)] {
			t.Errorf("vexStatusFromException(%q) produced an invalid OpenVEX status", in)
		}
	}
}
