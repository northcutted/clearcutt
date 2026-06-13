package catalog

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestSchemaArtifactsIncludesVersionedSchemas guards the set of versioned schemas
// bundled into the binary and emitted by `catalog generate` under schemas/.
func TestSchemaArtifactsIncludesVersionedSchemas(t *testing.T) {
	artifacts, err := SchemaArtifacts()
	if err != nil {
		t.Fatalf("SchemaArtifacts: %v", err)
	}
	got := map[string]bool{}
	for _, a := range artifacts {
		if len(a.Data) == 0 {
			t.Errorf("schema %s is empty", a.Name)
		}
		got[a.Name] = true
	}
	for _, want := range []string{
		"catalog-index.v1.schema.json",
		"catalog-index.v2.schema.json",
		"evidence-manifest.v1.schema.json",
		"image-record.v1.schema.json",
		"image-record.v2.schema.json",
		"package-entry.v1.schema.json",
		"vulnerability-finding.v1.schema.json",
	} {
		if !got[want] {
			t.Errorf("SchemaArtifacts is missing %s", want)
		}
	}
}

// TestEmbeddedSchemasMatchRootSchemas keeps the schemas embedded in the binary
// byte-identical to their published counterparts in the repository's root
// schemas/ directory: `catalog validate` enforces the embedded copies while
// consumers read the root copies, so any drift would split the contract.
func TestEmbeddedSchemasMatchRootSchemas(t *testing.T) {
	artifacts, err := SchemaArtifacts()
	if err != nil {
		t.Fatalf("SchemaArtifacts: %v", err)
	}
	if len(artifacts) == 0 {
		t.Fatal("no embedded schema artifacts")
	}
	rootDir := filepath.Join("..", "..", "..", "schemas")
	for _, artifact := range artifacts {
		rootCopy, err := os.ReadFile(filepath.Join(rootDir, artifact.Name))
		if err != nil {
			t.Errorf("embedded schema %s has no root counterpart: %v", artifact.Name, err)
			continue
		}
		if !bytes.Equal(artifact.Data, rootCopy) {
			t.Errorf("schemas/%s differs from the embedded copy in cli/internal/catalog/schemas/; keep both byte-identical", artifact.Name)
		}
	}
}
