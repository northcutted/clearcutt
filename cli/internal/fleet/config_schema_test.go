package fleet

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"sigs.k8s.io/yaml"
)

const fleetSchemaName = "clearcutt-fleet.schema.json"

// repoRootPath resolves a path relative to the repository root (the fleet
// package lives at cli/internal/fleet).
func repoRootPath(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", ".."}, parts...)...)
}

func compileFleetSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(repoRootPath("schemas", fleetSchemaName))
	if err != nil {
		t.Fatalf("read fleet schema: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse fleet schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(fleetSchemaName, doc); err != nil {
		t.Fatalf("register fleet schema: %v", err)
	}
	schema, err := compiler.Compile(fleetSchemaName)
	if err != nil {
		t.Fatalf("compile fleet schema: %v", err)
	}
	return schema
}

func validateYAMLAgainstFleetSchema(t *testing.T, schema *jsonschema.Schema, rawYAML []byte) error {
	t.Helper()
	rawJSON, err := yaml.YAMLToJSON(rawYAML)
	if err != nil {
		t.Fatalf("convert fleet config to JSON: %v", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(rawJSON))
	if err != nil {
		t.Fatalf("parse fleet config JSON: %v", err)
	}
	return schema.Validate(instance)
}

// TestFleetConfigFileSatisfiesPublishedSchema validates the committed
// clearcutt.fleet.yaml against schemas/clearcutt-fleet.schema.json so the
// published schema and the reference config can never drift apart. The check
// is generic over the file's contents (e.g. whatever matrix.languages lists).
func TestFleetConfigFileSatisfiesPublishedSchema(t *testing.T) {
	rawYAML, err := os.ReadFile(repoRootPath(DefaultConfigPath))
	if err != nil {
		t.Fatalf("read %s: %v", DefaultConfigPath, err)
	}

	firstLine, _, _ := strings.Cut(string(rawYAML), "\n")
	wantHeader := "# yaml-language-server: $schema=./schemas/" + fleetSchemaName
	if firstLine != wantHeader {
		t.Errorf("%s must start with %q so editors validate it, got %q", DefaultConfigPath, wantHeader, firstLine)
	}

	schema := compileFleetSchema(t)
	if err := validateYAMLAgainstFleetSchema(t, schema, rawYAML); err != nil {
		t.Fatalf("%s does not satisfy schemas/%s:\n%v", DefaultConfigPath, fleetSchemaName, err)
	}

	// The committed file must also load through the CLI's own validation.
	if _, err := Load(repoRootPath(DefaultConfigPath)); err != nil {
		t.Fatalf("fleet.Load rejects the committed config: %v", err)
	}
}

// TestFleetSchemaAcceptsRuntimeLinesExtension proves the documented
// runtimeLines extension mechanism produces configs that satisfy the
// published schema (it previously failed under additionalProperties: false).
func TestFleetSchemaAcceptsRuntimeLinesExtension(t *testing.T) {
	cfg := DefaultConfig("acme", "images")
	cfg.RuntimeLines = []RuntimeLine{{
		ID:                 "ruby3.4",
		Language:           "ruby",
		Version:            "3.4",
		AppTemplateRuntime: "ruby",
		Description:        "Ruby 3.4 runtime line",
		PackageCandidates:  []string{"ruby_3_4"},
		DevPackages:        []string{"bundler"},
		Smoke:              []string{"ruby --version"},
	}}
	cfg.Matrix.Languages = append(cfg.Matrix.Languages, "ruby3.4")

	rawYAML, err := Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal extended fleet config: %v", err)
	}

	schema := compileFleetSchema(t)
	if err := validateYAMLAgainstFleetSchema(t, schema, rawYAML); err != nil {
		t.Fatalf("runtimeLines extension does not satisfy schemas/%s:\n%v", fleetSchemaName, err)
	}

	// And the schema still has teeth: an unknown top-level key must fail.
	broken := append([]byte("unknownTopLevelKey: true\n"), rawYAML...)
	if err := validateYAMLAgainstFleetSchema(t, schema, broken); err == nil {
		t.Fatal("schema accepted an unknown top-level key; additionalProperties guard lost")
	} else if !strings.Contains(fmt.Sprint(err), "unknownTopLevelKey") {
		t.Fatalf("expected additionalProperties violation for unknownTopLevelKey, got: %v", err)
	}
}
