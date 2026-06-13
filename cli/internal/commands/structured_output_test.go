package commands

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// The gating family must emit the same check-list shape `verify image` and
// `platform status` use: an overall status plus {id, status, message} checks.

func TestVerifyCatalogStructuredOutput(t *testing.T) {
	stdout, runErr := runCLI(t, "--catalog", fixtureCatalog(), "verify", "catalog", "--format", "json")

	var response VerifyCatalogResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("verify catalog --format json should emit JSON, got %v:\n%s", err, stdout)
	}
	if response.Status != "pass" && response.Status != "fail" {
		t.Fatalf("unexpected status %q", response.Status)
	}
	if len(response.Checks) == 0 {
		t.Fatalf("expected at least one check, got:\n%s", stdout)
	}
	if response.Status == "fail" && !errors.Is(runErr, ErrCheckFailed) {
		t.Fatalf("fail status must map to ErrCheckFailed, got %v", runErr)
	}
	if response.Status == "pass" && runErr != nil {
		t.Fatalf("pass status should not error, got %v", runErr)
	}

	yamlOut, _ := runCLI(t, "--catalog", fixtureCatalog(), "verify", "catalog", "--format", "yaml")
	var yamlResponse VerifyCatalogResponse
	if err := yaml.Unmarshal([]byte(yamlOut), &yamlResponse); err != nil {
		t.Fatalf("verify catalog --format yaml should emit YAML, got %v:\n%s", err, yamlOut)
	}
	if yamlResponse.Status != response.Status {
		t.Fatalf("yaml status %q diverges from json status %q", yamlResponse.Status, response.Status)
	}
}

func TestVerifyCatalogStructuredOutputOnFailure(t *testing.T) {
	dir := t.TempDir()
	lifecycle := map[string]any{"status": "active", "support": "lts", "productionAllowed": true}
	index := map[string]any{
		"latestTag": "v2.0.0",
		"images": []any{map[string]any{
			"id": "coreLTS-slim", "latestTag": "v1.0.0", "lifecycle": lifecycle,
		}},
	}
	writeCatalogFixture(t, dir, index, map[string]any{})

	stdout, err := runCLI(t, "--catalog", dir, "verify", "catalog", "--format", "json")
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected ErrCheckFailed, got %v\n%s", err, stdout)
	}
	var response VerifyCatalogResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("failure output must stay valid JSON, got %v:\n%s", err, stdout)
	}
	if response.Status != "fail" || len(response.Checks) == 0 || response.Checks[0].Status != "fail" {
		t.Fatalf("expected failing check list, got:\n%s", stdout)
	}
}

func TestConformanceStructuredOutput(t *testing.T) {
	stdout, runErr := runCLI(t, "conformance", "run", "--format", "json")
	if runErr != nil && !errors.Is(runErr, ErrCheckFailed) {
		t.Fatalf("conformance run should only fail as a policy gate, got %v", runErr)
	}

	var response ConformanceResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("conformance --format json should emit the check-list shape, got %v:\n%s", err, stdout)
	}
	if response.Status != "pass" && response.Status != "fail" {
		t.Fatalf("unexpected status %q", response.Status)
	}
	if len(response.Checks) == 0 {
		t.Fatalf("expected checks in conformance response:\n%s", stdout)
	}
	for _, check := range response.Checks {
		if check.ID == "" || (check.Status != "pass" && check.Status != "fail") {
			t.Fatalf("malformed check %#v", check)
		}
	}
}

func TestExceptionsValidateStructuredOutput(t *testing.T) {
	dir := t.TempDir()

	valid := filepath.Join(dir, "valid.yaml")
	if err := os.WriteFile(valid, []byte(`apiVersion: clearcutt.dev/v1
kind: VulnerabilityExceptions
metadata:
  name: triage
spec:
  exceptions:
    - id: CVE-2030-12345
      package: openssl
      image: java21-distroless
      release: v1.0.0
      status: accepted_risk
      reason: no_fix_available
      owner: security@acme.com
      createdAt: 2026-01-01
      expiresAt: 2099-01-01
      references:
        - https://example.com/ticket/1
`), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, err := runCLI(t, "exceptions", "validate", valid, "--format", "json")
	if err != nil {
		t.Fatalf("expected valid document to pass, got %v:\n%s", err, stdout)
	}
	var response ExceptionsValidateResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("exceptions validate --format json should emit JSON, got %v:\n%s", err, stdout)
	}
	if response.Status != "pass" || response.Document != "triage" || response.Exceptions != 1 {
		t.Fatalf("unexpected pass payload: %#v", response)
	}

	invalid := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(invalid, []byte(`apiVersion: clearcutt.dev/v1
kind: VulnerabilityExceptions
metadata:
  name: triage
spec:
  exceptions:
    - id: NOT-A-CVE
      package: ""
      image: java21-distroless
      release: v1.0.0
      status: bogus
      reason: no_fix_available
      owner: security@acme.com
      createdAt: 2026-01-01
      expiresAt: 2020-01-01
`), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, err = runCLI(t, "exceptions", "validate", invalid, "--format", "json")
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected ErrCheckFailed, got %v\n%s", err, stdout)
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("failing exceptions validate must stay valid JSON, got %v:\n%s", err, stdout)
	}
	if response.Status != "fail" || len(response.Checks) < 3 {
		t.Fatalf("expected failing checks payload, got:\n%s", stdout)
	}
	for _, check := range response.Checks {
		if !strings.HasPrefix(check.ID, "spec.exceptions[0]") || check.Status != "fail" {
			t.Fatalf("malformed failure check %#v", check)
		}
	}
}

func TestVerifyRebuildStructuredOutput(t *testing.T) {
	dir := t.TempDir()
	runtimeFile := filepath.Join(dir, "runtime.txt")
	graftedFile := filepath.Join(dir, "grafted.txt")
	for _, path := range []string{runtimeFile, graftedFile} {
		if err := os.WriteFile(path, []byte("/nix/store/aaa-runtime\n/nix/store/bbb-lib\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	stdout, err := runCLI(t, "verify", "rebuild",
		"--target", "java21-distroless",
		"--runtime-closure-file", runtimeFile,
		"--grafted-closure-file", graftedFile,
		"--require-closure-equivalence",
		"--format", "json",
	)
	if err != nil {
		t.Fatalf("expected closure equivalence to pass, got %v:\n%s", err, stdout)
	}
	var predicate verifyRebuildPredicate
	if err := json.Unmarshal([]byte(stdout), &predicate); err != nil {
		t.Fatalf("verify rebuild --format json should emit the predicate, got %v:\n%s", err, stdout)
	}
	if predicate.Status != "pass" || len(predicate.Checks) == 0 {
		t.Fatalf("unexpected predicate payload:\n%s", stdout)
	}
	if strings.Contains(stdout, "[rebuild]") {
		t.Fatalf("structured output must not interleave human progress lines:\n%s", stdout)
	}
}
