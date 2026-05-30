package commands_test

import (
	"path/filepath"
	"testing"

	"github.com/northcutted/clearcutt/internal/catalog"
)

func TestVerifyLogic(t *testing.T) {
	catalogPath := filepath.Join("..", "testdata", "catalog")

	// 1. Load image record
	rec, err := catalog.LoadImageRecord(catalogPath, "java21-distroless")
	if err != nil {
		t.Fatalf("Failed to load image record: %v", err)
	}

	if len(rec.Releases) == 0 {
		t.Fatalf("No releases in test record")
	}

	rel := rec.Releases[0]

	// Assert manifest digest presence
	if rel.ManifestDigest == nil || *rel.ManifestDigest == "" {
		t.Errorf("Expected manifest digest to be present")
	}

	// Assert architectures present
	if len(rel.Architectures) != 1 {
		t.Errorf("Expected exactly 1 architecture in fixture, got %d", len(rel.Architectures))
	}

	arch := rel.Architectures[0]

	// Assert test results passed
	if arch.TestResults == nil || arch.TestResults.Status != "passed" {
		t.Errorf("Expected conformance tests to pass")
	}

	// Assert signature verified
	if rel.Signature == nil || !rel.Signature.CosignBundlePresent {
		t.Errorf("Expected signature bundle to be present")
	}

	// Assert SLSA Level 3 presence
	if rel.Provenance == nil || rel.Provenance.SlsaLevel != 3 {
		t.Errorf("Expected SLSA level 3 provenance")
	}
}
