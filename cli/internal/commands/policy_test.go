package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
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

func TestPolicy_KyvernoProductionSemantics(t *testing.T) {
	stdout, err := runCLI(t, "policy", "java21-distroless",
		"--catalog", fixtureCatalog(), "--engine", "kyverno", "--namespace", "apps", "--environment", "production")
	if err != nil {
		t.Fatalf("policy kyverno failed: %v", err)
	}
	doc := parsePolicyYAML(t, stdout)
	if got := nestedString(doc, "kind"); got != "ClusterPolicy" {
		t.Fatalf("expected ClusterPolicy, got %q", got)
	}
	if got := nestedString(doc, "spec", "validationFailureAction"); got != "Enforce" {
		t.Fatalf("expected enforce validation action, got %q", got)
	}
	rules := nestedSlice(doc, "spec", "rules")
	verifyRule := findPolicyRule(t, rules, "verify-cosign-signature")
	verifyImages := nestedSlice(verifyRule, "verifyImages")
	if len(verifyImages) == 0 {
		t.Fatalf("verify-cosign-signature missing verifyImages")
	}
	verifyImage, ok := verifyImages[0].(map[string]interface{})
	if !ok {
		t.Fatalf("verifyImages[0] has unexpected shape: %#v", verifyImages[0])
	}
	for _, key := range []string{"mutateDigest", "verifyDigest", "required"} {
		if got, ok := verifyImage[key].(bool); !ok || !got {
			t.Fatalf("verifyImages[0].%s must be true, got %#v", key, verifyImage[key])
		}
	}
	if got := nestedSlice(verifyImage, "attestors"); len(got) == 0 {
		t.Fatalf("verifyImages[0] must include keyless attestors")
	}
	attestations := nestedSlice(verifyImage, "attestations")
	if len(attestations) == 0 {
		t.Fatalf("verifyImages[0] must include SLSA attestations")
	}
	attestation, ok := attestations[0].(map[string]interface{})
	if !ok {
		t.Fatalf("attestations[0] has unexpected shape: %#v", attestations[0])
	}
	if got := nestedString(attestation, "predicateType"); got != "https://slsa.dev/provenance/v1" {
		t.Fatalf("expected SLSA predicate type, got %q", got)
	}
	_ = findPolicyRule(t, rules, "deny-dev-images")
}

func TestPolicy_K8sExampleUsesCanonicalProvenancePredicate(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "k8s-deployment", "kyverno-policy.yaml"))
	if err != nil {
		t.Fatalf("read k8s policy example: %v", err)
	}
	doc := parsePolicyYAML(t, string(raw))
	rules := nestedSlice(doc, "spec", "rules")
	rule := findPolicyRule(t, rules, "verify-clearcutt-base-provenance")
	verifyImages := nestedSlice(rule, "verifyImages")
	if len(verifyImages) == 0 {
		t.Fatalf("verify-clearcutt-base-provenance missing verifyImages")
	}
	verifyImage, ok := verifyImages[0].(map[string]interface{})
	if !ok {
		t.Fatalf("verifyImages[0] has unexpected shape: %#v", verifyImages[0])
	}
	attestations := nestedSlice(verifyImage, "attestations")
	if len(attestations) != 1 {
		t.Fatalf("expected one provenance attestation gate, got %#v", attestations)
	}
	attestation, ok := attestations[0].(map[string]interface{})
	if !ok {
		t.Fatalf("attestations[0] has unexpected shape: %#v", attestations[0])
	}
	if got := nestedString(attestation, "predicateType"); got != "https://slsa.dev/provenance/v1" {
		t.Fatalf("k8s admission example must use canonical SLSA provenance predicate, got %q", got)
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

func TestPolicyRejectsMismatchedSignerSubject(t *testing.T) {
	catalogDir := copyFixtureCatalog(t)
	imagePath := filepath.Join(catalogDir, "images", "java21-distroless.json")
	raw, err := os.ReadFile(imagePath)
	if err != nil {
		t.Fatalf("read fixture image: %v", err)
	}
	var image map[string]interface{}
	if err := json.Unmarshal(raw, &image); err != nil {
		t.Fatalf("decode fixture image: %v", err)
	}
	releases := image["releases"].([]interface{})
	latest := releases[0].(map[string]interface{})
	signature := latest["signature"].(map[string]interface{})
	certificate := signature["certificate"].(map[string]interface{})
	certificate["subject"] = "https://github.com/northcutted/clearcutt/.github/workflows/release.yml@refs/heads/main"
	updated, err := json.MarshalIndent(image, "", "  ")
	if err != nil {
		t.Fatalf("encode fixture image: %v", err)
	}
	if err := os.WriteFile(imagePath, updated, 0644); err != nil {
		t.Fatalf("write fixture image: %v", err)
	}

	stdout, err := runCLI(t, "policy", "java21-distroless",
		"--catalog", catalogDir, "--engine", "kyverno")
	if err == nil {
		t.Fatalf("expected policy generation to fail for mismatched signer subject:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "unrelated workflow identity") {
		t.Fatalf("expected unrelated workflow identity error, got %v\n%s", err, stdout)
	}
}

func TestPolicy_KyvernoDeniesPreviewReleaseWhenConfigured(t *testing.T) {
	catalogDir := copyFixtureCatalog(t)
	imagePath := filepath.Join(catalogDir, "images", "java21-distroless.json")
	raw, err := os.ReadFile(imagePath)
	if err != nil {
		t.Fatalf("read fixture image: %v", err)
	}
	var image map[string]interface{}
	if err := json.Unmarshal(raw, &image); err != nil {
		t.Fatalf("decode fixture image: %v", err)
	}
	releases := image["releases"].([]interface{})
	latest := releases[0].(map[string]interface{})
	lifecycle := latest["lifecycle"].(map[string]interface{})
	lifecycle["status"] = "preview"
	updated, err := json.MarshalIndent(image, "", "  ")
	if err != nil {
		t.Fatalf("encode fixture image: %v", err)
	}
	if err := os.WriteFile(imagePath, updated, 0644); err != nil {
		t.Fatalf("write fixture image: %v", err)
	}

	stdout, err := runCLI(t, "policy", "java21-distroless",
		"--catalog", catalogDir, "--engine", "kyverno", "--environment", "production")
	if err != nil {
		t.Fatalf("policy kyverno failed: %v", err)
	}
	doc := parsePolicyYAML(t, stdout)
	rules := nestedSlice(doc, "spec", "rules")
	previewRule := findPolicyRule(t, rules, "deny-preview-images")
	if got := nestedString(previewRule, "validate", "message"); !strings.Contains(got, "Preview lifecycle images") {
		t.Fatalf("preview rule message missing lifecycle context: %q", got)
	}
	if !strings.Contains(stdout, "!ghcr.io/test-owner/test-repo/clearcutt-java:*") {
		t.Fatalf("preview rule must deny the generated image reference, output:\n%s", stdout)
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

func parsePolicyYAML(t *testing.T, stdout string) map[string]interface{} {
	t.Helper()
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("parse generated policy YAML: %v\n%s", err, stdout)
	}
	return doc
}

func nestedString(root map[string]interface{}, keys ...string) string {
	current := interface{}(root)
	for _, key := range keys {
		m, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		current = m[key]
	}
	value, _ := current.(string)
	return value
}

func nestedSlice(root map[string]interface{}, keys ...string) []interface{} {
	current := interface{}(root)
	for _, key := range keys {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current = m[key]
	}
	value, _ := current.([]interface{})
	return value
}

func findPolicyRule(t *testing.T, rules []interface{}, name string) map[string]interface{} {
	t.Helper()
	for _, item := range rules {
		rule, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if nestedString(rule, "name") == name {
			return rule
		}
	}
	t.Fatalf("generated policy missing rule %q in %#v", name, rules)
	return nil
}
