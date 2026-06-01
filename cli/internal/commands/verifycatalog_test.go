package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCatalogJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeCatalogFixture(t *testing.T, dir string, index any, images map[string]any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "images"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCatalogJSON(t, filepath.Join(dir, "index.json"), index)
	for id, rec := range images {
		writeCatalogJSON(t, filepath.Join(dir, "images", id+".json"), rec)
	}
}

func completeEvidence(signature bool) map[string]any {
	return map[string]any{
		"signature":              signature,
		"provenance":             true,
		"sbom":                   true,
		"tests":                  true,
		"vulnerabilities":        true,
		"archCount":              1,
		"sbomArchCount":          1,
		"testArchCount":          1,
		"passedTestArchCount":    1,
		"vulnerabilityArchCount": 1,
	}
}

func zeroExceptions() map[string]any {
	return map[string]any{
		"total": 0, "expired": 0, "active": 0, "acceptedRisk": 0,
		"noFixAvailable": 0, "falsePositive": 0, "inheritedFromBase": 0,
	}
}

// A latest image whose index summary advertises a signature the release evidence
// does not actually carry must fail verification (signed=true vs evidence=false).
func TestVerifyCatalogFailsWhenSignatureInferredFromProvenance(t *testing.T) {
	dir := t.TempDir()
	lifecycle := map[string]any{"status": "active", "support": "lts", "productionAllowed": true}
	runtimeContract := map[string]any{"shellPresent": true, "packageManagerPresent": false, "productionTier": true}
	evidence := completeEvidence(false)

	index := map[string]any{
		"latestTag": "v1.0.0",
		"images": []any{map[string]any{
			"id": "coreLTS-slim", "latestTag": "v1.0.0", "signed": true, "provenance": true,
			"lifecycle": lifecycle, "runtimeContract": runtimeContract, "evidence": evidence,
		}},
	}
	release := map[string]any{
		"tag": "v1.0.0", "signature": nil,
		"provenance":      map[string]any{"predicateType": "https://slsa.dev/provenance/v1"},
		"lifecycle":       lifecycle,
		"runtimeContract": runtimeContract,
		"exceptions":      zeroExceptions(),
		"evidence":        evidence,
		"architectures":   []any{},
	}
	record := map[string]any{"id": "coreLTS-slim", "lifecycle": lifecycle, "runtimeContract": runtimeContract, "releases": []any{release}}
	writeCatalogFixture(t, dir, index, map[string]any{"coreLTS-slim": record})

	stdout, err := runCLI(t, "--catalog", dir, "verify-catalog")
	if err == nil {
		t.Fatalf("expected verification to fail, got success:\n%s", stdout)
	}
	if !strings.Contains(stdout, "index signed=true") {
		t.Fatalf("expected signed/evidence mismatch, got:\n%s", stdout)
	}
}

func TestVerifyCatalogAcceptsCompleteLatestEvidence(t *testing.T) {
	dir := t.TempDir()
	lifecycle := map[string]any{"status": "active", "support": "lts", "productionAllowed": true}
	runtimeContract := map[string]any{"shellPresent": true, "packageManagerPresent": false, "productionTier": true}
	evidence := completeEvidence(true)

	index := map[string]any{
		"latestTag": "v1.0.0",
		"images": []any{map[string]any{
			"id": "coreLTS-slim", "latestTag": "v1.0.0", "signed": true, "provenance": true,
			"lifecycle": lifecycle, "runtimeContract": runtimeContract, "evidence": evidence,
		}},
	}
	release := map[string]any{
		"tag": "v1.0.0", "signature": map[string]any{"cosignBundlePresent": true},
		"provenance":      map[string]any{"predicateType": "https://slsa.dev/provenance/v1"},
		"lifecycle":       lifecycle,
		"runtimeContract": runtimeContract,
		"exceptions":      zeroExceptions(),
		"evidence":        evidence,
		"architectures":   []any{},
	}
	record := map[string]any{"id": "coreLTS-slim", "lifecycle": lifecycle, "runtimeContract": runtimeContract, "releases": []any{release}}
	writeCatalogFixture(t, dir, index, map[string]any{"coreLTS-slim": record})

	stdout, err := runCLI(t, "--catalog", dir, "verify-catalog")
	if err != nil {
		t.Fatalf("expected verification to pass, got %v:\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "ok: 1 latest images") {
		t.Fatalf("expected ok summary, got:\n%s", stdout)
	}
}

// When no published image carries the index's latest tag, verification must fail
// rather than vacuously pass on an empty set.
func TestVerifyCatalogFailsWhenNoLatestImages(t *testing.T) {
	dir := t.TempDir()
	lifecycle := map[string]any{"status": "active", "support": "lts", "productionAllowed": true}
	index := map[string]any{
		"latestTag": "v2.0.0",
		"images": []any{map[string]any{
			"id": "coreLTS-slim", "latestTag": "v1.0.0", "lifecycle": lifecycle,
		}},
	}
	writeCatalogFixture(t, dir, index, map[string]any{})

	stdout, err := runCLI(t, "--catalog", dir, "verify-catalog")
	if err == nil {
		t.Fatalf("expected verification to fail, got success:\n%s", stdout)
	}
	if !strings.Contains(stdout, "no images are published for latest tag v2.0.0") {
		t.Fatalf("expected no-latest-images failure, got:\n%s", stdout)
	}
}

func TestVerifyCatalogFailsWhenRequiredRawFieldsAreMissing(t *testing.T) {
	dir := t.TempDir()
	lifecycle := map[string]any{"status": "active", "support": "lts", "productionAllowed": true}
	runtimeContract := map[string]any{"shellPresent": true, "packageManagerPresent": false, "productionTier": true}
	evidence := completeEvidence(true)

	index := map[string]any{
		"latestTag": "v1.0.0",
		"images": []any{map[string]any{
			"id": "coreLTS-slim", "latestTag": "v1.0.0", "signed": true, "provenance": true,
			"lifecycle": lifecycle, "evidence": evidence,
		}},
	}
	release := map[string]any{
		"tag": "v1.0.0", "signature": map[string]any{"cosignBundlePresent": true},
		"provenance":      map[string]any{"predicateType": "https://slsa.dev/provenance/v1"},
		"lifecycle":       lifecycle,
		"runtimeContract": runtimeContract,
		"evidence":        evidence,
		"architectures":   []any{},
	}
	record := map[string]any{"id": "coreLTS-slim", "lifecycle": lifecycle, "runtimeContract": runtimeContract, "releases": []any{release}}
	writeCatalogFixture(t, dir, index, map[string]any{"coreLTS-slim": record})

	stdout, err := runCLI(t, "--catalog", dir, "verify-catalog")
	if err == nil {
		t.Fatalf("expected verification to fail, got success:\n%s", stdout)
	}
	for _, want := range []string{
		"index summary is missing runtimeContract",
		"release v1.0.0 is missing exceptions",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %q in verifier output, got:\n%s", want, stdout)
		}
	}
}
