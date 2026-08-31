package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/build"
	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/oci"
)

type fakeFleetBuildRunner struct {
	archive []byte
}

func (f *fakeFleetBuildRunner) Run(dir, name string, args ...string) error {
	if name == "nix" {
		// Resolve like the real subprocess: relative out-links land under dir.
		outLink := testFlagValue(args, "--out-link")
		if outLink != "" && !filepath.IsAbs(outLink) {
			outLink = filepath.Join(dir, outLink)
		}
		return os.WriteFile(outLink, f.archive, 0o644)
	}
	return nil
}

func (f *fakeFleetBuildRunner) Capture(dir, outPath, name string, args ...string) error {
	switch name {
	case "syft":
		return os.WriteFile(outPath, []byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`), 0o644)
	case "grype":
		return os.WriteFile(outPath, []byte(`{"matches":[]}`), 0o644)
	default:
		return nil
	}
}

func testFlagValue(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// Drives the native-Go default build engine path through to internal/build,
// which fails fast on a Darwin system — covering the engine wiring without
// needing a Linux builder.
func TestFleetCertifyTargetDefaultEngineFailsFastOnDarwin(t *testing.T) {
	dir := t.TempDir()
	cfg := fleet.DefaultConfig("acme", "fleet")
	raw, err := fleet.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	cfgPath := filepath.Join(dir, "clearcutt.fleet.yaml")
	if err := os.WriteFile(cfgPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	coreDir := filepath.Join(dir, "core")
	if err := os.MkdirAll(filepath.Join(coreDir, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err = runCLI(t, "fleet", "certify-target",
		"--fleet-config", cfgPath, "--core-dir", coreDir,
		"--system", "aarch64-darwin", "--language", "java21", "--tier", "slim")
	if err == nil {
		t.Fatal("expected the default go engine to fail fast on a Darwin system")
	}
}

func TestFleetPublishTargetGoEnginePublishesAndStagesEvidence(t *testing.T) {
	root := t.TempDir()
	cfgPath := writeFleetTestConfig(t, root, fleet.Config{
		Registry: fleet.Registry{Host: "registry.example.com", Owner: "acme", Repository: "base-images", ImagePrefix: "acme-base"},
		Matrix:   fleet.Matrix{Systems: []string{"x86_64-linux"}, Languages: []string{"node24"}, Tiers: []string{"dev"}},
	})
	coreDir := filepath.Join(root, "core")
	if err := os.MkdirAll(filepath.Join(coreDir, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A real gzipped docker archive: the engine gunzips it for Syft.
	archiveRaw, err := os.ReadFile(gateArchive(t, gateLayerTar(t, map[string]int64{
		"nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nodejs-24.15.0/bin/node": 0o755,
	})))
	if err != nil {
		t.Fatal(err)
	}
	oldRunner := fleetBuildRunner
	fleetBuildRunner = func() build.Runner {
		return &fakeFleetBuildRunner{archive: archiveRaw}
	}
	t.Cleanup(func() { fleetBuildRunner = oldRunner })

	t.Setenv("REGISTRY_USER", "robot")
	t.Setenv("REGISTRY_TOKEN", "secret")
	var pushedRef, pushedArchive string
	oldPush := fleetPushImageArchive
	fleetPushImageArchive = func(client *oci.Client, ref, archivePath string) (string, error) {
		pushedRef = ref
		pushedArchive = archivePath
		return "sha256:abc123", nil
	}
	t.Cleanup(func() { fleetPushImageArchive = oldPush })

	stdout, err := runCLI(t,
		"fleet", "publish-target",
		"--fleet-config", cfgPath,
		"--core-dir", coreDir,
		"--system", "x86_64-linux",
		"--language", "node24",
		"--tier", "dev",
		"--version-tag", "v1.2.3",
	)
	if err != nil {
		t.Fatalf("publish-target go engine failed: %v\n%s", err, stdout)
	}
	if pushedArchive != filepath.Join(coreDir, "build-outputs", "node24-dev.tar.gz") {
		t.Fatalf("pushed archive = %q", pushedArchive)
	}
	if pushedRef != "registry.example.com/acme/base-images/acme-base-node24:_stage-dev-amd64" {
		t.Fatalf("pushed ref = %q", pushedRef)
	}
	outputDir := filepath.Join(coreDir, "build-outputs")
	if _, err := os.Stat(filepath.Join(outputDir, "node24-dev-amd64.sbom.json")); err != nil {
		t.Fatalf("expected amd64 SBOM staging copy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "node24-dev-amd64.test-results.json")); err != nil {
		t.Fatalf("expected amd64 test-results staging copy: %v", err)
	}
	if !strings.Contains(stdout, "Go engine") {
		t.Fatalf("expected Go engine publish message, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "sha256:abc123") {
		t.Fatalf("expected pushed digest in publish message, got:\n%s", stdout)
	}
}
