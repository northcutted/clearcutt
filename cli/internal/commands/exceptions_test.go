package commands

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestExceptionsMatchAndValidationBranches(t *testing.T) {
	doc := &ExceptionsDoc{}
	doc.Spec.Exceptions = []ExceptionEntry{{
		ID:        "CVE-2026-1111",
		Package:   "*",
		Image:     "*",
		Release:   "*",
		Status:    "accepted_risk",
		Reason:    "temporary_business_exception",
		CreatedAt: "2026-01-01",
		ExpiresAt: "bad-date",
	}}
	if entry, expired := doc.Match("CVE-2026-1111", "openssl", "java21-distroless", "v1.0.0", time.Now().UTC()); entry == nil || !expired {
		t.Fatalf("invalid expiresAt should match as expired, entry=%+v expired=%v", entry, expired)
	}
	if entry, expired := doc.Match("CVE-2026-2222", "openssl", "java21-distroless", "v1.0.0", time.Now().UTC()); entry != nil || expired {
		t.Fatalf("nonmatching exception should not match, entry=%+v expired=%v", entry, expired)
	}

	path := writeYAML(t, `apiVersion: clearcutt.dev/v1
kind: VulnerabilityExceptions
metadata:
  name: expired-but-allowed
spec:
  exceptions:
    - id: CVE-2026-9999
      package: openssl
      image: java21-distroless
      release: v1.0.0
      status: accepted_risk
      reason: temporary_business_exception
      owner: security
      createdAt: "2026-01-01"
      expiresAt: "2000-01-01"
      references:
        - https://example.invalid/risk`)
	stdout, err := runCLI(t, "exceptions", "validate", path, "--fail-on-expired-exceptions=false")
	if err != nil {
		t.Fatalf("expired exception should validate when flag disables expiry failure: %v\n%s", err, stdout)
	}

	bad := writeYAML(t, `apiVersion: clearcutt.dev/v1
kind: VulnerabilityExceptions
metadata:
  name: bad-exceptions
spec:
  exceptions:
    - id: bad-cve
      package: ""
      image: ""
      release: ""
      status: accepted_risk
      reason: no_such_reason
      owner: ""
      createdAt: "bad"
      expiresAt: "bad"`)
	stdout, err = runCLI(t, "exceptions", "validate", bad)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected invalid exception document to gate fail, got %v\n%s", err, stdout)
	}
	for _, want := range []string{"invalid CVE", "package is required", "references are required", "invalid createdAt", "invalid expiresAt"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %q diagnostic in:\n%s", want, stdout)
		}
	}
}

func TestExceptionsInit(t *testing.T) {
	tempPath := filepath.Join(t.TempDir(), "new-exceptions.yaml")
	stdout, err := runCLI(t, "exceptions", "init", tempPath)
	if err != nil {
		t.Fatalf("expected exceptions init to succeed, got: %v\n%s", err, stdout)
	}

	if _, err := os.Stat(tempPath); err != nil {
		t.Fatalf("expected exceptions template file to be created, got error: %v", err)
	}

	// Validate the initialized template to verify it conforms to the schema rules
	if _, err := runCLI(t, "exceptions", "validate", tempPath); err != nil {
		t.Errorf("expected initialized template to be fully valid, got: %v", err)
	}
}
