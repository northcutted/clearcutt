package commands_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/catalog"
)

func TestPolicyGatingGeneration(t *testing.T) {
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

	// Assert signature certificate metadata exists
	if rel.Signature == nil || rel.Signature.Certificate == nil {
		t.Fatalf("OIDC Certificate metadata is missing from signature bundle")
	}

	cert := rel.Signature.Certificate
	if cert.Subject == nil || *cert.Subject == "" {
		t.Errorf("Expected non-empty OIDC Certificate subject")
	}

	if cert.Issuer == nil || *cert.Issuer == "" {
		t.Errorf("Expected non-empty OIDC Certificate issuer")
	}

	// Verify that the policy subject details map to OIDC expectations
	if !strings.Contains(*cert.Subject, "release.yml") {
		t.Errorf("Expected OIDC subject to contain GitHub release workflow identifier")
	}
}
