package commands

import (
	"strings"
	"testing"
)

func TestGlobalFormatValidation(t *testing.T) {
	t.Run("rejects unknown format before the command runs", func(t *testing.T) {
		stdout, err := runCLI(t, "--catalog", fixtureCatalog(), "list", "--format", "jsno")
		if err == nil {
			t.Fatalf("expected unknown --format to fail, got success:\n%s", stdout)
		}
		want := `unknown --format "jsno" (expected table, json, or yaml)`
		if err.Error() != want {
			t.Fatalf("unexpected error message: got %q, want %q", err.Error(), want)
		}
	})

	t.Run("accepts every documented format case-insensitively", func(t *testing.T) {
		for _, format := range []string{"table", "json", "yaml", "yml", "JSON", "Table", "YAML"} {
			stdout, err := runCLI(t, "--catalog", fixtureCatalog(), "list", "--format", format)
			if err != nil {
				t.Fatalf("--format %s should be accepted: %v\n%s", format, err, stdout)
			}
		}
	})

	t.Run("validates on subcommands through the root hook", func(t *testing.T) {
		stdout, err := runCLI(t, "--catalog", fixtureCatalog(), "verify", "catalog", "--format", "xml")
		if err == nil || !strings.Contains(err.Error(), `unknown --format "xml"`) {
			t.Fatalf("expected format validation on verify catalog, got err=%v\n%s", err, stdout)
		}
	})
}
