package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
)

func TestFleetBuildCLIAssetsBuildsSignsAndChecksumsDeterministically(t *testing.T) {
	root := t.TempDir()
	sourceDir := filepath.Join(root, "cli")
	if err := os.MkdirAll(filepath.Join(sourceDir, "cmd", "clearcutt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "go.mod"), []byte("module example.com/clearcutt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Repo-root markers so the embedded-archive regeneration step can run.
	for _, marker := range []string{fleet.DefaultConfigPath, "go.work"} {
		if err := os.WriteFile(filepath.Join(root, marker), []byte("# test\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	outputDir := filepath.Join(root, "build-outputs")
	githubOutput := filepath.Join(root, "github-output.txt")

	oldFleetOpts := fleetOpts
	oldRun := runExternalCommand
	defer func() {
		fleetOpts = oldFleetOpts
		runExternalCommand = oldRun
	}()

	builds := []externalCommand{}
	signs := []externalCommand{}
	runExternalCommand = func(c externalCommand) error {
		switch c.Name {
		case "go":
			builds = append(builds, c)
			outputPath := argAfter(c.Args, "-o")
			if outputPath == "" {
				t.Fatalf("go build missing -o: %#v", c.Args)
			}
			body := "binary:" + envValue(c.Env, "GOOS") + "/" + envValue(c.Env, "GOARCH") + ":" + strings.Join(c.Args, " ")
			if err := os.WriteFile(outputPath, []byte(body), 0o755); err != nil {
				t.Fatalf("write fake binary: %v", err)
			}
		case "fake-cosign":
			signs = append(signs, c)
			bundlePath := argAfter(c.Args, "--bundle")
			if bundlePath == "" {
				t.Fatalf("cosign missing --bundle: %#v", c.Args)
			}
			assetPath := c.Args[2]
			if err := os.WriteFile(bundlePath, []byte("sig:"+filepath.Base(assetPath)), 0o644); err != nil {
				t.Fatalf("write fake signature: %v", err)
			}
		default:
			t.Fatalf("unexpected command: %#v", c)
		}
		return nil
	}

	stdout, err := runCLI(t,
		"fleet", "build-cli-assets",
		"--source-dir", sourceDir,
		"--build-outputs", outputDir,
		"--version-tag", "1.2.3",
		"--sign",
		"--cosign-bin", "fake-cosign",
		"--github-output", githubOutput,
	)
	if err != nil {
		t.Fatalf("fleet build-cli-assets failed: %v\n%s", err, stdout)
	}
	if len(builds) != 6 {
		t.Fatalf("expected six go builds, got %d", len(builds))
	}
	if len(signs) != 6 {
		t.Fatalf("expected six cosign sign-blob calls, got %d", len(signs))
	}
	seen := map[string]bool{}
	for _, build := range builds {
		name := filepath.Base(argAfter(build.Args, "-o"))
		seen[name] = true
		if build.Dir != sourceDir {
			t.Fatalf("go build should run in source dir %s, got %s", sourceDir, build.Dir)
		}
		if !strings.Contains(strings.Join(build.Args, " "), "Version=v1.2.3") {
			t.Fatalf("go build did not stamp version: %#v", build.Args)
		}
		if envValue(build.Env, "CGO_ENABLED") != "0" || envValue(build.Env, "GOOS") == "" || envValue(build.Env, "GOARCH") == "" {
			t.Fatalf("go build env missing target controls: %#v", build.Env)
		}
	}
	for _, name := range expectedCLIAssetNames() {
		if !seen[name] {
			t.Fatalf("missing build for %s; saw %#v", name, seen)
		}
		if !nonEmptyFile(filepath.Join(outputDir, name)) {
			t.Fatalf("missing binary asset %s", name)
		}
		if !nonEmptyFile(filepath.Join(outputDir, name+".sig")) {
			t.Fatalf("missing signature asset %s.sig", name)
		}
	}

	manifestPath := filepath.Join(outputDir, cliAssetsManifestName)
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest cliAssetManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse manifest: %v\n%s", err, raw)
	}
	if manifest.VersionTag != "v1.2.3" || len(manifest.Assets) != 12 {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	if manifest.Assets[0].Signature == "" {
		t.Fatalf("binary manifest entries should name signature bundles: %#v", manifest.Assets[0])
	}

	checksumPath := filepath.Join(outputDir, "SHA256SUMS.txt")
	checksumRaw, err := os.ReadFile(checksumPath)
	if err != nil {
		t.Fatalf("read checksum manifest: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(checksumRaw)), "\n")
	if len(lines) != 13 {
		t.Fatalf("expected 13 checksum lines for 6 binaries, 6 signatures, and manifest, got %d:\n%s", len(lines), checksumRaw)
	}
	names := make([]string, 0, len(lines))
	for _, line := range lines {
		_, name, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("checksum line did not use sha256sum format: %q", line)
		}
		names = append(names, name)
	}
	sorted := append([]string{}, names...)
	sort.Strings(sorted)
	if strings.Join(names, "\n") != strings.Join(sorted, "\n") {
		t.Fatalf("checksum lines are not deterministic:\n%s", checksumRaw)
	}
	for _, name := range append(expectedCLIAssetNames(), cliAssetsManifestName) {
		if !strings.Contains(string(checksumRaw), "  "+name+"\n") {
			t.Fatalf("checksum manifest missing %s:\n%s", name, checksumRaw)
		}
	}
	if !strings.Contains(string(checksumRaw), sha256HexForFile(t, filepath.Join(outputDir, "clearcutt-linux-amd64"))+"  clearcutt-linux-amd64\n") {
		t.Fatalf("checksum manifest does not contain real linux amd64 digest:\n%s", checksumRaw)
	}

	githubRaw, err := os.ReadFile(githubOutput)
	if err != nil {
		t.Fatalf("read github output: %v", err)
	}
	for _, needle := range []string{"cli_assets_manifest=", "cli_assets_checksum=", "cli_assets_count=13"} {
		if !strings.Contains(string(githubRaw), needle) {
			t.Fatalf("github output missing %q:\n%s", needle, githubRaw)
		}
	}
}

func TestFleetBuildCLIAssetsRejectsMissingSourceDir(t *testing.T) {
	oldFleetOpts := fleetOpts
	defer func() {
		fleetOpts = oldFleetOpts
	}()

	stdout, err := runCLI(t,
		"fleet", "build-cli-assets",
		"--source-dir", filepath.Join(t.TempDir(), "missing"),
		"--version-tag", "v1.2.3",
	)
	if err == nil {
		t.Fatalf("expected missing source-dir error:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "go.mod and cmd/clearcutt") {
		t.Fatalf("unexpected error: %v\n%s", err, stdout)
	}
}

func expectedCLIAssetNames() []string {
	return []string{
		"clearcutt-darwin-amd64",
		"clearcutt-darwin-arm64",
		"clearcutt-linux-amd64",
		"clearcutt-linux-arm64",
		"clearcutt-windows-amd64.exe",
		"clearcutt-windows-arm64.exe",
	}
}

func argAfter(args []string, flag string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			return strings.TrimPrefix(item, prefix)
		}
	}
	return ""
}

func sha256HexForFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
