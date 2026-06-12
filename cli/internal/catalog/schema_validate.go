package catalog

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
)

// schemaBaseURL anchors the embedded schema files so the relative cross-file
// $refs they carry (e.g. "catalog-index.v1.schema.json#/definitions/Lifecycle")
// resolve against sibling schemas instead of the filesystem.
const schemaBaseURL = "https://clearcutt.dev/schemas/"

// SchemaFileForVersion maps a declared schemaVersion to the embedded JSON
// Schema file that defines it.
func SchemaFileForVersion(version string) (string, bool) {
	switch version {
	case CatalogIndexSchemaVersion:
		return "catalog-index.v1.schema.json", true
	case CatalogIndexSchemaVersionV2:
		return "catalog-index.v2.schema.json", true
	case ImageRecordSchemaVersion:
		return "image-record.v1.schema.json", true
	case ImageRecordSchemaVersionV2:
		return "image-record.v2.schema.json", true
	case EvidenceManifestSchemaVersion:
		return "evidence-manifest.v1.schema.json", true
	}
	return "", false
}

// SchemaValidator validates catalog JSON documents against the versioned JSON
// Schemas embedded in the binary (the same files `catalog generate` publishes
// under schemas/).
type SchemaValidator struct {
	compiled map[string]*jsonschema.Schema
}

// NewSchemaValidator compiles every embedded schema once so callers can
// validate many documents cheaply.
func NewSchemaValidator() (*SchemaValidator, error) {
	artifacts, err := SchemaArtifacts()
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	for _, artifact := range artifacts {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(artifact.Data))
		if err != nil {
			return nil, fmt.Errorf("parse embedded schema %s: %w", artifact.Name, err)
		}
		if err := compiler.AddResource(schemaBaseURL+artifact.Name, doc); err != nil {
			return nil, fmt.Errorf("register embedded schema %s: %w", artifact.Name, err)
		}
	}
	compiled := make(map[string]*jsonschema.Schema, len(artifacts))
	for _, artifact := range artifacts {
		schema, err := compiler.Compile(schemaBaseURL + artifact.Name)
		if err != nil {
			return nil, fmt.Errorf("compile embedded schema %s: %w", artifact.Name, err)
		}
		compiled[artifact.Name] = schema
	}
	return &SchemaValidator{compiled: compiled}, nil
}

// Validate checks raw JSON document bytes against the named embedded schema
// and returns one "<json-pointer>: <message>" violation per failing location.
func (v *SchemaValidator) Validate(schemaFile string, data []byte) ([]string, error) {
	schema, ok := v.compiled[schemaFile]
	if !ok {
		return nil, fmt.Errorf("no embedded schema %s", schemaFile)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse document: %w", err)
	}
	err = schema.Validate(instance)
	if err == nil {
		return nil, nil
	}
	validationErr, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return nil, err
	}
	violations := flattenSchemaViolations(validationErr)
	sort.Strings(violations)
	return violations, nil
}

// flattenSchemaViolations renders the validation error tree as one
// JSON-pointer-addressed message per concrete failure. It walks the detailed
// (hierarchical) output rather than the basic (flat) output because the basic
// renderer collapses single-cause $ref chains and drops their sibling errors.
func flattenSchemaViolations(err *jsonschema.ValidationError) []string {
	violations := []string{}
	var walk func(unit jsonschema.OutputUnit)
	walk = func(unit jsonschema.OutputUnit) {
		if len(unit.Errors) > 0 {
			for _, child := range unit.Errors {
				walk(child)
			}
			return
		}
		if unit.Error == nil {
			return
		}
		switch unit.Error.Kind.(type) {
		case *kind.Reference, *kind.Schema:
			return
		}
		pointer := unit.InstanceLocation
		if pointer == "" {
			pointer = "(root)"
		}
		violations = append(violations, fmt.Sprintf("%s: %s", pointer, unit.Error.String()))
	}
	walk(*err.DetailedOutput())
	return violations
}
