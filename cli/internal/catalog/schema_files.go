package catalog

import (
	"embed"
	"io/fs"
	"path"
)

//go:embed schemas/*.json
var schemaFS embed.FS

// SchemaArtifact is a versioned JSON schema file emitted with generated catalogs.
type SchemaArtifact struct {
	Name string
	Data []byte
}

// SchemaArtifacts returns the JSON schemas bundled into the CLI binary.
func SchemaArtifacts() ([]SchemaArtifact, error) {
	entries, err := fs.ReadDir(schemaFS, "schemas")
	if err != nil {
		return nil, err
	}
	artifacts := make([]SchemaArtifact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		data, err := schemaFS.ReadFile(path.Join("schemas", name))
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, SchemaArtifact{
			Name: name,
			Data: data,
		})
	}
	return artifacts, nil
}
