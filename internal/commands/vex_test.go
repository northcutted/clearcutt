package commands_test

import (
	"path/filepath"
	"testing"

	"github.com/northcutted/clearcutt/internal/catalog"
)

func TestVexMapping(t *testing.T) {
	catalogPath := filepath.Join("..", "testdata", "catalog")

	// Load image record
	rec, err := catalog.LoadImageRecord(catalogPath, "java21-distroless")
	if err != nil {
		t.Fatalf("Failed to load image record: %v", err)
	}

	if len(rec.Releases) == 0 {
		t.Fatalf("No releases in test record")
	}

	rel := rec.Releases[0]

	// Verify standard fields are loaded correctly
	if rel.ManifestDigest == nil || *rel.ManifestDigest == "" {
		t.Fatalf("Release is missing manifest digest")
	}

	// Assert architectures loaded
	if len(rel.Architectures) == 0 {
		t.Fatalf("No architectures present in release record")
	}

	arch := rel.Architectures[0]
	if arch.Vulnerabilities == nil {
		t.Fatalf("Vulnerabilities info is missing from architecture payload")
	}

	findings := arch.Vulnerabilities.Findings
	if len(findings) == 0 {
		t.Fatalf("No vulnerability findings present to verify mappings")
	}

	// Verify that the findings map correctly
	finding := findings[0]
	if finding.ID == "" {
		t.Errorf("Finding ID is empty")
	}

	if finding.Remediation != nil {
		status := finding.Remediation.Status
		reason := finding.Remediation.Reason

		if status != "deferred" && status != "eligible" && status != "fixed" {
			t.Errorf("Invalid remediation status mapping: %s", status)
		}

		if reason == "base_layer" {
			// This matches vex.go logic where base_layer is marked not_affected with vulnerable_code_not_in_execute_path
			if status != "deferred" {
				t.Errorf("Base layer findings are expected to be deferred by default")
			}
		}
	}
}
