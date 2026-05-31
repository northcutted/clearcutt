package commands

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeYAML(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exceptions.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp yaml: %v", err)
	}
	return path
}

func TestExceptionsValidate_Success(t *testing.T) {
	path := writeYAML(t, `apiVersion: clearcutt.dev/v1
kind: VulnerabilityExceptions
metadata:
  name: clearcutt-test-exceptions
spec:
  exceptions:
    - id: CVE-2026-9999
      package: openssl
      image: java21-distroless
      release: v1.0.0
      status: not_affected
      reason: inherited_from_base
      owner: security
      createdAt: "2026-05-29"
      expiresAt: "2999-06-29"
      references:
        - https://example.invalid/advisory
      notes: "No fixed package is available from upstream."`)

	if _, err := runCLI(t, "exceptions", "validate", path); err != nil {
		t.Errorf("expected valid document, got %v", err)
	}
}

func TestExceptionsValidate_ExpiredFails(t *testing.T) {
	path := writeYAML(t, `apiVersion: clearcutt.dev/v1
kind: VulnerabilityExceptions
metadata:
  name: clearcutt-test-exceptions
spec:
  exceptions:
    - id: CVE-2026-9999
      package: openssl
      image: java21-distroless
      release: v1.0.0
      status: not_affected
      reason: inherited_from_base
      owner: security
      createdAt: "2000-01-01"
      expiresAt: "2000-06-29"`)

	stdout, err := runCLI(t, "exceptions", "validate", path)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected ErrCheckFailed for expired exception, got %v", err)
	}
	if !strings.Contains(stdout, "expired") {
		t.Errorf("expected an 'expired' diagnostic, got:\n%s", stdout)
	}
}

// A bad schema header is a plain error, not a gate failure.
func TestExceptionsValidate_BadSchemaIsPlainError(t *testing.T) {
	path := writeYAML(t, `apiVersion: wrong/v1
kind: VulnerabilityExceptions
metadata:
  name: x
spec:
  exceptions: []`)

	_, err := runCLI(t, "exceptions", "validate", path)
	if err == nil {
		t.Fatal("expected an error for invalid apiVersion")
	}
	if errors.Is(err, ErrCheckFailed) {
		t.Errorf("schema header errors should be plain errors, not ErrCheckFailed")
	}
}
