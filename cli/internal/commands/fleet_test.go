package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
)

func TestFleetPublishTargetUsesConfigAndStagesArchAssets(t *testing.T) {
	root := t.TempDir()
	cfgPath := writeFleetTestConfig(t, root, fleet.Config{
		Registry: fleet.Registry{Host: "registry.example.com", Owner: "acme", Repository: "base-images", ImagePrefix: "acme-base"},
		Matrix:   fleet.Matrix{Systems: []string{"x86_64-linux", "aarch64-linux"}, Languages: []string{"node24"}, Tiers: []string{"slim"}},
	})
	coreDir := filepath.Join(root, "core")
	outputDir := filepath.Join(coreDir, "build-outputs")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatalf("mkdir outputs: %v", err)
	}
	for _, name := range []string{"node24-slim.sbom.json", "node24-slim.test-results.json"} {
		if err := os.WriteFile(filepath.Join(outputDir, name), []byte(`{}`), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	var calls []externalCommand
	oldRun := runExternalCommand
	runExternalCommand = func(c externalCommand) error {
		calls = append(calls, c)
		return nil
	}
	t.Cleanup(func() { runExternalCommand = oldRun })

	if _, err := runCLI(t,
		"fleet", "publish-target",
		"--fleet-config", cfgPath,
		"--core-dir", coreDir,
		"--system", "aarch64-linux",
		"--language", "node24",
		"--tier", "slim",
		"--version-tag", "v1.2.3",
	); err != nil {
		t.Fatalf("publish-target error: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected one external command, got %#v", calls)
	}
	call := calls[0]
	if call.Name != "nix" || call.Dir != coreDir {
		t.Fatalf("unexpected command: %#v", call)
	}
	joined := strings.Join(call.Args, " ")
	for _, want := range []string{"develop", "--command ./pipeline/pipeline.sh", "--system aarch64-linux", "--registry registry.example.com", "--repo acme/base-images", "--version-tag v1.2.3", "node24-slim"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("nix args missing %q in %q", want, joined)
		}
	}
	if !containsString(call.Env, "CLEARCUTT_IMAGE_PREFIX=acme-base") {
		t.Fatalf("missing image-prefix env: %#v", call.Env)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "node24-slim-arm64.sbom.json")); err != nil {
		t.Fatalf("expected arm64 SBOM staging copy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "node24-slim-arm64.test-results.json")); err != nil {
		t.Fatalf("expected arm64 test-results staging copy: %v", err)
	}
}

func TestFleetCertifyTargetDoesNotPublish(t *testing.T) {
	root := t.TempDir()
	cfgPath := writeFleetTestConfig(t, root, fleet.Config{
		Registry: fleet.Registry{Host: "registry.example.com", Owner: "acme", Repository: "base-images", ImagePrefix: "acme-base"},
		Matrix:   fleet.Matrix{Systems: []string{"x86_64-linux"}, Languages: []string{"java25"}, Tiers: []string{"distroless"}},
		Release: fleet.Release{NixCache: fleet.NixCache{
			PublicBaseURL:  "https://nix-cache.acme.example",
			SigningKeyName: "acme-cache-1",
			PublicKey:      "abc123",
		}},
	})
	coreDir := filepath.Join(root, "core")

	var calls []externalCommand
	oldRun := runExternalCommand
	runExternalCommand = func(c externalCommand) error {
		calls = append(calls, c)
		return nil
	}
	t.Cleanup(func() { runExternalCommand = oldRun })

	if _, err := runCLI(t,
		"fleet", "certify-target",
		"--fleet-config", cfgPath,
		"--core-dir", coreDir,
		"--system", "x86_64-linux",
		"--language", "java25",
		"--tier", "distroless",
	); err != nil {
		t.Fatalf("certify-target error: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected one external command, got %#v", calls)
	}
	joined := strings.Join(calls[0].Args, " ")
	if strings.Contains(joined, "--publish") {
		t.Fatalf("certify-target must not publish: %q", joined)
	}
	if !strings.Contains(joined, "--skip-local-signing") || !strings.Contains(joined, "java25-distroless") {
		t.Fatalf("certify-target args missing expected gate flags: %q", joined)
	}
	if !strings.Contains(joined, "--option extra-substituters https://nix-cache.acme.example") ||
		!strings.Contains(joined, "--option extra-trusted-public-keys acme-cache-1:abc123") {
		t.Fatalf("certify-target args missing Nix cache options: %q", joined)
	}
}

func TestFleetAssembleTargetUsesConfigAndWritesDigestManifest(t *testing.T) {
	root := t.TempDir()
	cfgPath := writeFleetTestConfig(t, root, fleet.Config{
		Registry: fleet.Registry{Host: "registry.example.com", Owner: "acme", Repository: "fleet", ImagePrefix: "base"},
		Matrix:   fleet.Matrix{Systems: []string{"x86_64-linux", "aarch64-linux"}, Languages: []string{"coreLTS"}, Tiers: []string{"distroless"}},
	})
	outputDir := filepath.Join(root, "build-outputs")
	for _, dir := range []string{"x86_64", "aarch64"} {
		if err := os.MkdirAll(filepath.Join(outputDir, dir), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		for _, name := range []string{"coreLTS-distroless.sbom.json", "coreLTS-distroless.test-results.json"} {
			if err := os.WriteFile(filepath.Join(outputDir, dir, name), []byte(`{}`), 0o644); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
	}

	var calls []externalCommand
	oldRun := runExternalCommand
	oldCapture := captureExternalOutput
	runExternalCommand = func(c externalCommand) error {
		calls = append(calls, c)
		return nil
	}
	captureExternalOutput = func(c externalCommand) (string, error) {
		calls = append(calls, c)
		return "sha256:abc123\n", nil
	}
	t.Cleanup(func() {
		runExternalCommand = oldRun
		captureExternalOutput = oldCapture
	})

	if _, err := runCLI(t,
		"fleet", "assemble-target",
		"--fleet-config", cfgPath,
		"--build-outputs", outputDir,
		"--language", "coreLTS",
		"--tier", "distroless",
		"--version-tag", "v9.8.7",
	); err != nil {
		t.Fatalf("assemble-target error: %v", err)
	}
	allArgs := flattenCalls(calls)
	for _, want := range []string{
		"crane index append -t registry.example.com/acme/fleet/base-corelts:distroless -m registry.example.com/acme/fleet/base-corelts:_stage-distroless-amd64 -m registry.example.com/acme/fleet/base-corelts:_stage-distroless-arm64",
		"cosign sign --yes registry.example.com/acme/fleet/base-corelts:v9.8.7-distroless",
		"cosign attest --yes --type spdxjson --predicate " + filepath.Join(outputDir, "x86_64", "coreLTS-distroless.sbom.json"),
		"cosign attest --yes --type custom --predicate " + filepath.Join(outputDir, "aarch64", "coreLTS-distroless.test-results.json"),
		"crane digest registry.example.com/acme/fleet/base-corelts:distroless",
	} {
		if !strings.Contains(allArgs, want) {
			t.Fatalf("missing command fragment %q in:\n%s", want, allArgs)
		}
	}
	raw, err := os.ReadFile(filepath.Join(outputDir, "digests", "coreLTS-distroless.digest.json"))
	if err != nil {
		t.Fatalf("read digest manifest: %v", err)
	}
	var manifest fleetDigestManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse digest manifest: %v", err)
	}
	if manifest.Image != "registry.example.com/acme/fleet/base-corelts" || manifest.Digest != "sha256:abc123" {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
}

func TestFleetAggregateDigestsWritesGithubOutput(t *testing.T) {
	outputDir := t.TempDir()
	raw := []byte(`{"image":"ghcr.io/acme/fleet/base-node24","digest":"sha256:222","language":"node24","tier":"slim","rollingTag":"slim","versionedTag":"v1.0.0-slim"}`)
	if err := os.WriteFile(filepath.Join(outputDir, "node24-slim.digest.json"), raw, 0o644); err != nil {
		t.Fatalf("write digest: %v", err)
	}
	ghOut := filepath.Join(t.TempDir(), "github-output")
	stdout, err := runCLI(t,
		"--format", "json",
		"fleet", "aggregate-digests",
		"--build-outputs", outputDir,
		"--github-output", ghOut,
	)
	if err != nil {
		t.Fatalf("aggregate-digests error: %v", err)
	}
	if !strings.Contains(stdout, `"language":"node24"`) {
		t.Fatalf("unexpected stdout: %s", stdout)
	}
	ghRaw, err := os.ReadFile(ghOut)
	if err != nil {
		t.Fatalf("read github output: %v", err)
	}
	if !strings.HasPrefix(string(ghRaw), "matrix=[") || !strings.Contains(string(ghRaw), `"digest":"sha256:222"`) {
		t.Fatalf("unexpected github output: %s", ghRaw)
	}
}

func writeFleetTestConfig(t *testing.T, root string, partial fleet.Config) string {
	t.Helper()
	cfg := fleet.DefaultConfig("acme", "fleet")
	if partial.Registry.Host != "" {
		cfg.Registry = partial.Registry
	}
	if len(partial.Matrix.Systems) > 0 {
		cfg.Matrix = partial.Matrix
	}
	if partial.Release.NixCache.Bucket != "" || partial.Release.NixCache.PublicBaseURL != "" || partial.Release.NixCache.PublicKey != "" {
		cfg.Release.NixCache = partial.Release.NixCache
	}
	raw, err := fleet.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal fleet config: %v", err)
	}
	path := filepath.Join(root, "clearcutt.fleet.yaml")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write fleet config: %v", err)
	}
	return path
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func flattenCalls(calls []externalCommand) string {
	lines := make([]string, 0, len(calls))
	for _, call := range calls {
		lines = append(lines, strings.TrimSpace(call.Name+" "+strings.Join(call.Args, " ")))
	}
	return strings.Join(lines, "\n")
}
