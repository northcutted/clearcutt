package commands

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/oci"
)

func TestFleetPublishCacheUsesAbsoluteSigningKeyPath(t *testing.T) {
	root := t.TempDir()
	cfgPath := writeFleetTestConfig(t, root, fleet.Config{
		Registry: fleet.Registry{Host: "registry.example.com", Owner: "acme", Repository: "base-images", ImagePrefix: "acme-base"},
		Matrix:   fleet.Matrix{Systems: []string{"x86_64-linux"}, Languages: []string{"java21"}, Tiers: []string{"slim"}},
		Release: fleet.Release{NixCache: fleet.NixCache{
			Bucket:             "acme-nix-cache",
			PublicBaseURL:      "https://nix-cache.acme.example",
			SigningKeyName:     "acme-cache-1",
			PublicKey:          "abc123",
			CloudflareZoneName: "acme.example",
		}},
	})
	coreDir := filepath.Join(root, "core")
	if err := os.MkdirAll(coreDir, 0o755); err != nil {
		t.Fatalf("mkdir core: %v", err)
	}
	t.Setenv("NIX_CACHE_SECRET_KEY", "secret-key-material")
	t.Setenv("AWS_ACCESS_KEY_ID", "access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "account")

	var calls []externalCommand
	oldRun := runExternalCommand
	oldCapture := captureExternalOutput
	runExternalCommand = func(c externalCommand) error {
		calls = append(calls, c)
		return nil
	}
	captureExternalOutput = func(c externalCommand) (string, error) {
		calls = append(calls, c)
		switch c.Name {
		case "nix":
			return "/nix/store/abc123-java21-slim\n", nil
		case "aws", "curl":
			return "Sig: acme-cache-1:signed\n", nil
		default:
			t.Fatalf("unexpected capture command: %#v", c)
			return "", nil
		}
	}
	t.Cleanup(func() {
		runExternalCommand = oldRun
		captureExternalOutput = oldCapture
	})

	if _, err := runCLI(t,
		"fleet", "publish-cache",
		"--fleet-config", cfgPath,
		"--core-dir", coreDir,
		"--system", "x86_64-linux",
		"--language", "java21",
		"--tier", "slim",
	); err != nil {
		t.Fatalf("publish-cache error: %v", err)
	}
	allArgs := flattenCalls(calls)
	if strings.Contains(allArgs, "secret-key=core/secret-key.pem") || strings.Contains(allArgs, "--key-file core/secret-key.pem") {
		t.Fatalf("publish-cache used repo-relative signing key path:\n%s", allArgs)
	}

	var signKeyFile, cacheStore string
	for _, call := range calls {
		if call.Name == "nix" && len(call.Args) >= 5 && strings.Join(call.Args[:3], " ") == "store sign --recursive" {
			for i, arg := range call.Args {
				if arg == "--key-file" && i+1 < len(call.Args) {
					signKeyFile = call.Args[i+1]
				}
			}
		}
		if call.Name == "nix" && len(call.Args) > 0 && call.Args[0] == "copy" {
			for i, arg := range call.Args {
				if arg == "--to" && i+1 < len(call.Args) {
					cacheStore = call.Args[i+1]
				}
			}
		}
	}
	if signKeyFile == "" || !filepath.IsAbs(signKeyFile) {
		t.Fatalf("sign command should use absolute key path, got %q in:\n%s", signKeyFile, allArgs)
	}
	if cacheStore == "" || !strings.Contains(cacheStore, "secret-key="+signKeyFile) {
		t.Fatalf("copy cache store should use the same absolute key path %q, got %q", signKeyFile, cacheStore)
	}
}

func TestFleetAssembleTargetUsesConfigAndWritesDigestManifest(t *testing.T) {
	root := t.TempDir()
	cfgPath := writeFleetTestConfig(t, root, fleet.Config{
		Registry: fleet.Registry{Host: "registry.example.com", Owner: "acme", Repository: "fleet", ImagePrefix: "base"},
		Matrix:   fleet.Matrix{Systems: []string{"x86_64-linux", "aarch64-linux"}, Languages: []string{"java21"}, Tiers: []string{"distroless"}},
	})
	outputDir := filepath.Join(root, "build-outputs")
	for _, dir := range []string{"x86_64", "aarch64"} {
		if err := os.MkdirAll(filepath.Join(outputDir, dir), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		for _, name := range []string{"java21-distroless.sbom.json", "java21-distroless.test-results.json"} {
			if err := os.WriteFile(filepath.Join(outputDir, dir, name), []byte(`{}`), 0o644); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
	}

	var calls []externalCommand
	var indexCalls []struct {
		ref     string
		sources []oci.IndexImage
	}
	oldRun := runExternalCommand
	oldPushIndex := fleetPushImageIndex
	runExternalCommand = func(c externalCommand) error {
		calls = append(calls, c)
		return nil
	}
	fleetPushImageIndex = func(client *oci.Client, ref string, sources []oci.IndexImage) (string, error) {
		indexCalls = append(indexCalls, struct {
			ref     string
			sources []oci.IndexImage
		}{ref: ref, sources: append([]oci.IndexImage(nil), sources...)})
		return "sha256:abc123", nil
	}
	t.Cleanup(func() {
		runExternalCommand = oldRun
		fleetPushImageIndex = oldPushIndex
	})

	if _, err := runCLI(t,
		"fleet", "assemble-target",
		"--fleet-config", cfgPath,
		"--build-outputs", outputDir,
		"--language", "java21",
		"--tier", "distroless",
		"--version-tag", "v9.8.7",
	); err != nil {
		t.Fatalf("assemble-target error: %v", err)
	}
	if len(indexCalls) != 2 {
		t.Fatalf("expected rolling and versioned index pushes, got %#v", indexCalls)
	}
	if indexCalls[0].ref != "registry.example.com/acme/fleet/base-java21:distroless" ||
		indexCalls[1].ref != "registry.example.com/acme/fleet/base-java21:v9.8.7-distroless" {
		t.Fatalf("unexpected index refs: %#v", indexCalls)
	}
	if len(indexCalls[0].sources) != 2 {
		t.Fatalf("unexpected index sources: %#v", indexCalls[0].sources)
	}
	for _, want := range []string{
		"registry.example.com/acme/fleet/base-java21:_stage-distroless-amd64",
		"registry.example.com/acme/fleet/base-java21:_stage-distroless-arm64",
	} {
		var found bool
		for _, source := range indexCalls[0].sources {
			if source.Ref == want && source.OS == "linux" && source.Architecture != "" {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing index source %q in %#v", want, indexCalls[0].sources)
		}
	}
	allArgs := flattenCalls(calls)
	for _, want := range []string{
		"nix develop --extra-experimental-features nix-command flakes --accept-flake-config --command cosign sign --yes registry.example.com/acme/fleet/base-java21:v9.8.7-distroless",
		"--command cosign attest --yes --type spdxjson --predicate " + filepath.Join(outputDir, "x86_64", "java21-distroless.sbom.json"),
		"--command cosign attest --yes --type custom --predicate " + filepath.Join(outputDir, "aarch64", "java21-distroless.test-results.json"),
	} {
		if !strings.Contains(allArgs, want) {
			t.Fatalf("missing command fragment %q in:\n%s", want, allArgs)
		}
	}
	for _, call := range calls {
		if call.Name == "cosign" {
			t.Fatalf("assemble-target should use core-pinned cosign through nix, got direct command: %#v", call)
		}
	}
	if strings.Contains(allArgs, "crane") {
		t.Fatalf("assemble-target should not shell out to crane, got:\n%s", allArgs)
	}
	raw, err := os.ReadFile(filepath.Join(outputDir, "digests", "java21-distroless.digest.json"))
	if err != nil {
		t.Fatalf("read digest manifest: %v", err)
	}
	var manifest fleetDigestManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse digest manifest: %v", err)
	}
	if manifest.Image != "registry.example.com/acme/fleet/base-java21" || manifest.Digest != "sha256:abc123" {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
}

// TestFleetAssembleTargetPredicatePathsAreAbsolute guards the release-blocking
// regression where a RELATIVE --build-outputs produced a relative cosign
// --predicate path: runCoreToolCommand runs cosign with cwd=coreDir, so a path
// relative to the CLI's own cwd resolved against coreDir and cosign reported
// "no such file or directory" for every target. The predicate must be absolute
// regardless of how build-outputs was passed.
func TestFleetAssembleTargetPredicatePathsAreAbsolute(t *testing.T) {
	root := t.TempDir()
	cfgPath := writeFleetTestConfig(t, root, fleet.Config{
		Registry: fleet.Registry{Host: "registry.example.com", Owner: "acme", Repository: "fleet", ImagePrefix: "base"},
		Matrix:   fleet.Matrix{Systems: []string{"x86_64-linux", "aarch64-linux"}, Languages: []string{"java21"}, Tiers: []string{"distroless"}},
	})
	// Resolve the relative --build-outputs under a temp cwd so the real
	// digest-manifest write lands there and is cleaned up, not in the package.
	t.Chdir(t.TempDir())

	var calls []externalCommand
	oldRun := runExternalCommand
	oldPushIndex := fleetPushImageIndex
	runExternalCommand = func(c externalCommand) error {
		calls = append(calls, c)
		return nil
	}
	fleetPushImageIndex = func(_ *oci.Client, _ string, _ []oci.IndexImage) (string, error) {
		return "sha256:abc123", nil
	}
	t.Cleanup(func() {
		runExternalCommand = oldRun
		fleetPushImageIndex = oldPushIndex
	})

	// Relative --build-outputs is what the release workflow actually passes.
	if _, err := runCLI(t,
		"fleet", "assemble-target",
		"--fleet-config", cfgPath,
		"--build-outputs", "build-outputs",
		"--language", "java21",
		"--tier", "distroless",
		"--version-tag", "v9.8.7",
	); err != nil {
		t.Fatalf("assemble-target error: %v", err)
	}

	predicates := 0
	for _, call := range calls {
		for i, arg := range call.Args {
			if arg != "--predicate" || i+1 >= len(call.Args) {
				continue
			}
			predicates++
			if !filepath.IsAbs(call.Args[i+1]) {
				t.Fatalf("cosign --predicate must be absolute, got %q", call.Args[i+1])
			}
		}
	}
	if predicates == 0 {
		t.Fatal("expected at least one cosign --predicate invocation")
	}
}

func TestFleetAggregateDigestsWritesGithubOutput(t *testing.T) {
	outputDir := t.TempDir()
	raw := []byte(`{"image":"ghcr.io/acme/fleet/base-node24","digest":"sha256:222","language":"node24","tier":"slim","rollingTag":"slim","versionedTag":"v1.0.0-slim"}`)
	if err := os.WriteFile(filepath.Join(outputDir, "node24-slim.digest.json"), raw, 0o644); err != nil {
		t.Fatalf("write digest: %v", err)
	}
	serviceRaw := []byte(`{"image":"ghcr.io/acme/fleet/service-postgres16","digest":"sha256:333","language":"postgres16","tier":"service","rollingTag":"service","versionedTag":"v1.0.0-service"}`)
	if err := os.WriteFile(filepath.Join(outputDir, "postgres16.digest.json"), serviceRaw, 0o644); err != nil {
		t.Fatalf("write service digest: %v", err)
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
	if !strings.Contains(string(ghRaw), `fleet_matrix=[`) || !strings.Contains(string(ghRaw), `"language":"node24"`) {
		t.Fatalf("github output missing fleet matrix: %s", ghRaw)
	}
	if !strings.Contains(string(ghRaw), `service_matrix=[`) || !strings.Contains(string(ghRaw), `"language":"postgres16"`) {
		t.Fatalf("github output missing service matrix: %s", ghRaw)
	}
}

func TestUploadReleaseAssetsRetriesIndividualAssetUploads(t *testing.T) {
	outputDir := t.TempDir()
	for _, name := range []string{"alpha.sbom.json", "beta.test-results.json", "ignored.txt"} {
		if err := os.WriteFile(filepath.Join(outputDir, name), []byte(`{}`), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	var calls []externalCommand
	failures := 0
	oldRun := runExternalCommand
	oldSleep := releaseAssetUploadSleep
	oldAttempts := releaseAssetUploadMaxAttempts
	oldRetryDelay := releaseAssetUploadRetryDelay
	oldThrottle := releaseAssetUploadThrottle
	runExternalCommand = func(c externalCommand) error {
		calls = append(calls, c)
		if strings.Contains(strings.Join(c.Args, " "), "alpha.sbom.json") && failures == 0 {
			failures++
			return errors.New("HTTP 403: You have exceeded a secondary rate limit")
		}
		return nil
	}
	var sleeps []time.Duration
	releaseAssetUploadSleep = func(d time.Duration) {
		sleeps = append(sleeps, d)
	}
	releaseAssetUploadMaxAttempts = 3
	releaseAssetUploadRetryDelay = 10 * time.Second
	releaseAssetUploadThrottle = 2 * time.Second
	t.Cleanup(func() {
		runExternalCommand = oldRun
		releaseAssetUploadSleep = oldSleep
		releaseAssetUploadMaxAttempts = oldAttempts
		releaseAssetUploadRetryDelay = oldRetryDelay
		releaseAssetUploadThrottle = oldThrottle
	})

	if err := uploadReleaseAssets("v1.2.3", outputDir); err != nil {
		t.Fatalf("uploadReleaseAssets error: %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("expected retry plus second asset upload, got %#v", calls)
	}
	for _, call := range calls {
		if call.Name != "gh" || len(call.Args) != 5 || call.Args[0] != "release" || call.Args[1] != "upload" || call.Args[2] != "v1.2.3" || call.Args[4] != "--clobber" {
			t.Fatalf("unexpected upload command: %#v", call)
		}
		if strings.Contains(call.Args[3], "ignored.txt") {
			t.Fatalf("uploaded non-release asset: %#v", calls)
		}
	}
	if !strings.Contains(calls[0].Args[3], "alpha.sbom.json") || !strings.Contains(calls[1].Args[3], "alpha.sbom.json") || !strings.Contains(calls[2].Args[3], "beta.test-results.json") {
		t.Fatalf("expected per-asset retry order, got %#v", calls)
	}
	if len(sleeps) != 2 || sleeps[0] != 10*time.Second || sleeps[1] != 2*time.Second {
		t.Fatalf("expected retry and throttle sleeps, got %#v", sleeps)
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
