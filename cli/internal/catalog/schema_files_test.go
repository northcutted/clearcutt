package catalog

import "testing"

// TestSchemaArtifactsIncludesAllV1Schemas guards the set of versioned schemas
// bundled into the binary and emitted by `catalog generate` under schemas/.
func TestSchemaArtifactsIncludesAllV1Schemas(t *testing.T) {
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
		"image-record.v1.schema.json",
		"package-entry.v1.schema.json",
		"vulnerability-finding.v1.schema.json",
	} {
		if !got[want] {
			t.Errorf("SchemaArtifacts is missing %s", want)
		}
	}
}
