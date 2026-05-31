package commands

import (
	"bytes"
	"path/filepath"
	"testing"
)

// fixtureCatalog is the path to the committed test catalog fixture.
func fixtureCatalog() string {
	return filepath.Join("..", "testdata", "catalog")
}

// runCLI executes the full root command with the given args, capturing everything
// written to the package output writers. It exercises real flag parsing, command
// wiring, and the error model, and returns captured stdout plus the Execute error.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()

	var buf bytes.Buffer
	oldOut, oldErr := out, errOut
	out, errOut = &buf, &buf
	defer func() { out, errOut = oldOut, oldErr }()

	cmd := NewRootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := cmd.Execute()
	return buf.String(), err
}
