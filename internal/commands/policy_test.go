package commands

import (
	"strings"
	"testing"
)

func TestPolicy_KyvernoGeneration(t *testing.T) {
	stdout, err := runCLI(t, "policy", "java21-distroless",
		"--catalog", fixtureCatalog(), "--engine", "kyverno", "--namespace", "apps")
	if err != nil {
		t.Fatalf("policy kyverno failed: %v", err)
	}
	for _, want := range []string{"kind: ClusterPolicy", "verify-cosign-signature", "namespaces: [\"apps\"]"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("kyverno output missing %q\n%s", want, stdout)
		}
	}
	// The fixture's OIDC subject should be threaded into the keyless attestor block.
	if !strings.Contains(stdout, "release.yml") {
		t.Errorf("expected OIDC subject from the catalog signature certificate in output")
	}
}

func TestPolicy_GatekeeperGeneration(t *testing.T) {
	stdout, err := runCLI(t, "policy", "java21-distroless",
		"--catalog", fixtureCatalog(), "--engine", "gatekeeper")
	if err != nil {
		t.Fatalf("policy gatekeeper failed: %v", err)
	}
	for _, want := range []string{"kind: ConstraintTemplate", "K8sCosignSignatureVerify", "requireNonRoot:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("gatekeeper output missing %q\n%s", want, stdout)
		}
	}
}

// strict must add a real, non-root workload guarantee that production does not.
func TestPolicy_StrictAddsNonRoot(t *testing.T) {
	strict, err := runCLI(t, "policy", "java21-distroless",
		"--catalog", fixtureCatalog(), "--engine", "kyverno", "--environment", "strict")
	if err != nil {
		t.Fatalf("policy strict failed: %v", err)
	}
	if !strings.Contains(strict, "require-run-as-non-root") || !strings.Contains(strict, "runAsNonRoot: true") {
		t.Errorf("strict profile must enforce runAsNonRoot, output:\n%s", strict)
	}

	prod, err := runCLI(t, "policy", "java21-distroless",
		"--catalog", fixtureCatalog(), "--engine", "kyverno", "--environment", "production")
	if err != nil {
		t.Fatalf("policy production failed: %v", err)
	}
	if strings.Contains(prod, "require-run-as-non-root") {
		t.Errorf("production profile should not include the strict-only non-root rule")
	}
}
