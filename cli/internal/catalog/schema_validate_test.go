package catalog

import (
	"strings"
	"testing"
)

// TestSchemaFileForVersion maps every supported schemaVersion to its embedded
// schema file and rejects unknown versions.
func TestSchemaFileForVersion(t *testing.T) {
	for version, want := range map[string]string{
		CatalogIndexSchemaVersion:     "catalog-index.v1.schema.json",
		CatalogIndexSchemaVersionV2:   "catalog-index.v2.schema.json",
		ImageRecordSchemaVersion:      "image-record.v1.schema.json",
		ImageRecordSchemaVersionV2:    "image-record.v2.schema.json",
		EvidenceManifestSchemaVersion: "evidence-manifest.v1.schema.json",
	} {
		got, ok := SchemaFileForVersion(version)
		if !ok || got != want {
			t.Errorf("SchemaFileForVersion(%q) = %q, %t; want %q, true", version, got, ok, want)
		}
	}
	if got, ok := SchemaFileForVersion("clearcutt.catalog.index/v99"); ok {
		t.Errorf("SchemaFileForVersion accepted unknown version, returned %q", got)
	}
}

// TestSchemaValidatorReportsViolationsWithPointers exercises the failing path:
// a document missing required keys must yield JSON-pointer-addressed
// violations rather than a bare error.
func TestSchemaValidatorReportsViolationsWithPointers(t *testing.T) {
	validator, err := NewSchemaValidator()
	if err != nil {
		t.Fatalf("NewSchemaValidator: %v", err)
	}

	violations, err := validator.Validate("catalog-index.v1.schema.json", []byte(`{
		"generatedAt": "2026-06-10T00:00:00Z",
		"owner": "o",
		"repo": "r",
		"repoUrl": "https://github.com/o/r",
		"registryBase": "ghcr.io/o/r",
		"latestTag": "v1",
		"releases": [],
		"languages": [],
		"tiers": [{"id": "slim", "name": "Slim"}],
		"images": []
	}`))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(violations) == 0 {
		t.Fatal("expected violations for an index missing required keys")
	}
	joined := strings.Join(violations, "\n")
	if !strings.Contains(joined, "/tiers/0") {
		t.Errorf("violations should point at /tiers/0 (missing blurb), got:\n%s", joined)
	}
	for _, violation := range violations {
		if !strings.Contains(violation, ": ") {
			t.Errorf("violation %q is not in \"<pointer>: <message>\" form", violation)
		}
	}
}

// TestSchemaValidatorRejectsUnknownSchemaAndBadJSON covers the error paths a
// caller can hit before any schema evaluation happens.
func TestSchemaValidatorRejectsUnknownSchemaAndBadJSON(t *testing.T) {
	validator, err := NewSchemaValidator()
	if err != nil {
		t.Fatalf("NewSchemaValidator: %v", err)
	}
	if _, err := validator.Validate("nope.schema.json", []byte(`{}`)); err == nil {
		t.Error("expected an error for an unknown schema file")
	}
	if _, err := validator.Validate("catalog-index.v1.schema.json", []byte(`{not json`)); err == nil {
		t.Error("expected an error for malformed JSON")
	}
}
