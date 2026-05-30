package commands

import (
	"os"
	"testing"
)

func TestExceptionsValidate_Success(t *testing.T) {
	exited := false
	osExit = func(code int) { exited = true }
	defer func() { osExit = os.Exit }()

	content := `apiVersion: clearcutt.dev/v1
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
      expiresAt: "2026-06-29"
      references:
        - https://example.invalid/advisory
      notes: "No fixed package is available from upstream."`

	tmpFile, err := os.CreateTemp("", "clearcutt-exceptions-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	os.WriteFile(tmpFile.Name(), []byte(content), 0644)

	exceptionsOpts = exceptionsFlags{failOnExpired: false}
	err = runExceptionsValidate(tmpFile.Name())
	if err != nil {
		t.Errorf("runExceptionsValidate failed: %v", err)
	}
	if exited {
		t.Errorf("Expected no exit, but process exited")
	}
}
