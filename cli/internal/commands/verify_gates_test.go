package commands

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/northcutted/clearcutt/internal/fleet"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func gateLayerTar(t *testing.T, entries map[string]int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, mode := range entries {
		body := []byte("x")
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Typeflag: tar.TypeReg, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// gateArchive writes a gzipped docker-save image (one layer) and returns its path.
func gateArchive(t *testing.T, layer []byte) string {
	t.Helper()
	files := map[string][]byte{
		"config.json":   []byte(`{"config":{}}`),
		"layer0.tar":    layer,
		"manifest.json": []byte(`[{"Config":"config.json","RepoTags":["t:latest"],"Layers":["layer0.tar"]}]`),
	}
	var outer bytes.Buffer
	tw := tar.NewWriter(&outer)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(outer.Bytes()); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	p := filepath.Join(t.TempDir(), "image.tar.gz")
	if err := os.WriteFile(p, gz.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// gateFloor writes a known-good crypto identity allowlist. The two openssl
// identities below (hashes aaaa.../bbbb..., both version 3.6.3) are the patched
// builds the gate tests ship; the stock aaaa...-openssl-3.6.2 (a DIFFERENT store
// component) is deliberately absent, so it default-denies.
func gateFloor(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "floor.json")
	if err := os.WriteFile(p, []byte(gateFloorJSON()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func gateFloorJSON() string {
	return `{"deps":[
  {"name":"openssl","cve":"CVE-2026-34182","knownGood":[
    {"storePath":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-openssl-3.6.3"},
    {"storePath":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.3"}
  ]},
  {"name":"sqlite","cve":"CVE-2026-11822","knownGood":[
    {"storePath":"dddddddddddddddddddddddddddddddd-sqlite-3.53.2"}
  ]}
]}`
}

func TestVerifyClosurePurityCommand(t *testing.T) {
	clean := gateArchive(t, gateLayerTar(t, map[string]int64{
		"nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-foolib-1.0/lib/foo.so": 0o644,
	}))
	if _, err := runCLI(t, "verify", "closure-purity", clean); err != nil {
		t.Fatalf("clean image should pass closure-purity: %v", err)
	}

	impure := gateArchive(t, gateLayerTar(t, map[string]int64{
		"nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash-5.2/bin/bash": 0o755,
	}))
	if _, err := runCLI(t, "verify", "closure-purity", impure); err == nil {
		t.Fatal("image with a shell should fail closure-purity")
	}

	// Mutually-exclusive inputs are rejected.
	if _, err := runCLI(t, "verify", "closure-purity", clean, "--store-paths", "x"); err == nil {
		t.Fatal("expected exactly-one-of error")
	}
}

// Exercises --store-paths mode across all three verify gates (a closureInfo
// store-paths list instead of an image archive).
func TestVerifyGatesStorePathsMode(t *testing.T) {
	root := t.TempDir()
	storeDir := filepath.Join(root, "store", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.3")
	if err := os.MkdirAll(filepath.Join(storeDir, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storeDir, "lib", "libssl.so"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	pathsFile := filepath.Join(root, "store-paths")
	if err := os.WriteFile(pathsFile, []byte(storeDir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := runCLI(t, "verify", "closure-purity", "--store-paths", pathsFile); err != nil {
		t.Fatalf("clean store-paths closure-purity: %v", err)
	}
	if _, err := runCLI(t, "verify", "boundaries", "--store-paths", pathsFile); err != nil {
		t.Fatalf("clean store-paths boundaries: %v", err)
	}
}

func TestVerifyBoundariesCommand(t *testing.T) {
	clean := gateArchive(t, gateLayerTar(t, map[string]int64{
		"nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-openssl-3.6.3/lib/libssl.so": 0o644,
	}))
	out, err := runCLI(t, "verify", "boundaries", clean)
	if err != nil {
		t.Fatalf("clean image should pass all boundary gates: %v\n%s", err, out)
	}
	if !strings.Contains(out, "all image-security boundary gates passed") {
		t.Errorf("missing boundaries summary in:\n%s", out)
	}

	// A shell trips the umbrella too.
	impure := gateArchive(t, gateLayerTar(t, map[string]int64{
		"nix/store/cccccccccccccccccccccccccccccccc-bash-5.2/bin/bash":           0o755,
		"nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-openssl-3.6.3/lib/libssl.so": 0o644,
	}))
	if _, err := runCLI(t, "verify", "boundaries", impure); err == nil {
		t.Fatal("image with a shell should fail boundaries")
	}
}

func writeBoundarySuiteCore(t *testing.T, coreDir string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(coreDir, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(coreDir, "tests", "runtime-dep-floor.json"), []byte(gateFloorJSON()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(coreDir, "tests", "closure-purity-allowlist.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(coreDir, "build-outputs")
}

func TestVerifyBoundarySuiteUsesExistingArchives(t *testing.T) {
	coreDir := t.TempDir()
	outDir := writeBoundarySuiteCore(t, coreDir)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cleanArchive := gateArchive(t, gateLayerTar(t, map[string]int64{
		"nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-openssl-3.6.3/lib/libssl.so": 0o644,
	}))
	for _, target := range []string{"java21-slim", "java21-distroless"} {
		raw, err := os.ReadFile(cleanArchive)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outDir, target+".tar.gz"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	oldRun := runExternalCommand
	runExternalCommand = func(c externalCommand) error {
		t.Fatalf("boundary suite should not build when archives exist, got %#v", c)
		return nil
	}
	t.Cleanup(func() { runExternalCommand = oldRun })

	stdout, err := runCLI(t, "verify", "boundary-suite", "--core-dir", coreDir, "--closure-target", "java21-distroless")
	if err != nil {
		t.Fatalf("boundary suite should pass existing archives: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"[boundary-suite] closure-purity java21-distroless",
		"representative image-security boundary suite passed",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %q in boundary suite output:\n%s", want, stdout)
		}
	}
}

func TestVerifyBoundarySuiteBuildsMissingArchivesWithNix(t *testing.T) {
	coreDir := t.TempDir()
	outDir := writeBoundarySuiteCore(t, coreDir)
	cleanArchive := gateArchive(t, gateLayerTar(t, map[string]int64{
		"nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-openssl-3.6.3/lib/libssl.so": 0o644,
	}))
	archiveRaw, err := os.ReadFile(cleanArchive)
	if err != nil {
		t.Fatal(err)
	}

	oldRun := runExternalCommand
	calls := []externalCommand{}
	runExternalCommand = func(c externalCommand) error {
		calls = append(calls, c)
		if c.Name != "nix" || c.Dir != coreDir {
			t.Fatalf("unexpected build command: %#v", c)
		}
		outLink := ""
		for i, arg := range c.Args {
			if arg == "--out-link" && i+1 < len(c.Args) {
				outLink = c.Args[i+1]
			}
		}
		if outLink == "" {
			t.Fatalf("missing --out-link in %#v", c)
		}
		// Resolve like the real subprocess would: relative to c.Dir, not the
		// test process cwd — so a relative out-link/cwd mismatch fails here.
		if !filepath.IsAbs(outLink) {
			outLink = filepath.Join(c.Dir, outLink)
		}
		if err := os.MkdirAll(filepath.Dir(outLink), 0o755); err != nil {
			return err
		}
		return os.WriteFile(outLink, archiveRaw, 0o644)
	}
	t.Cleanup(func() { runExternalCommand = oldRun })

	stdout, err := runCLI(t, "verify", "boundary-suite", "--core-dir", coreDir, "--closure-target", "java21-distroless")
	if err != nil {
		t.Fatalf("boundary suite should build and pass missing archives: %v\n%s", err, stdout)
	}
	// One build now: the suite runs closure-purity over the distroless target.
	// The second build existed for the runtime-cve gate over the slim tier,
	// which was retired with runtime-scoped CVE patching.
	if len(calls) != 1 {
		t.Fatalf("expected one nix build for the default distroless archive, got %#v", calls)
	}
	joined := strings.Join(calls[0].Args, " ")
	for _, want := range []string{`.#"java21-distroless"`, "--accept-flake-config"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing build arg %q in calls %#v", want, calls)
		}
	}
	for _, target := range []string{"java21-distroless"} {
		if _, err := os.Stat(filepath.Join(outDir, target+".tar.gz")); err != nil {
			t.Fatalf("expected built archive for %s: %v", target, err)
		}
	}
}

// Regression for the PR-gate failure: `verify boundary-suite --core-dir core`
// runs nix with cwd=core, so a relative --out-link must still land where the
// suite reads it from the repo root.
func TestVerifyBoundarySuiteRelativeCoreDir(t *testing.T) {
	repoRoot := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	coreDir := filepath.Join(repoRoot, "core")
	outDir := writeBoundarySuiteCore(t, coreDir)
	cleanArchive := gateArchive(t, gateLayerTar(t, map[string]int64{
		"nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-openssl-3.6.3/lib/libssl.so": 0o644,
	}))
	archiveRaw, err := os.ReadFile(cleanArchive)
	if err != nil {
		t.Fatal(err)
	}

	oldRun := runExternalCommand
	runExternalCommand = func(c externalCommand) error {
		if c.Name != "nix" {
			t.Fatalf("unexpected command: %#v", c)
		}
		outLink := ""
		for i, arg := range c.Args {
			if arg == "--out-link" && i+1 < len(c.Args) {
				outLink = c.Args[i+1]
			}
		}
		if outLink == "" {
			t.Fatalf("missing --out-link in %#v", c)
		}
		if !filepath.IsAbs(outLink) {
			outLink = filepath.Join(c.Dir, outLink)
		}
		if err := os.MkdirAll(filepath.Dir(outLink), 0o755); err != nil {
			return err
		}
		return os.WriteFile(outLink, archiveRaw, 0o644)
	}
	t.Cleanup(func() { runExternalCommand = oldRun })

	stdout, err := runCLI(t, "verify", "boundary-suite", "--core-dir", "core", "--closure-target", "java21-distroless")
	if err != nil {
		t.Fatalf("boundary suite with a relative --core-dir failed: %v\n%s", err, stdout)
	}
	for _, target := range []string{"java21-distroless"} {
		if _, err := os.Stat(filepath.Join(outDir, target+".tar.gz")); err != nil {
			t.Fatalf("expected built archive for %s: %v", target, err)
		}
	}
}

// TestVerifyBoundarySuiteDerivesTargetsFromTheFleet covers the default path: with
// no --closure-target, the gate walks the fleet's own production distroless
// targets. This is what stops the default drifting off a renamed runtime line —
// it did exactly that twice (coreLTS-distroless, then java21-distroless), each
// time failing CI with "flake does not provide attribute".
func TestVerifyBoundarySuiteDerivesTargetsFromTheFleet(t *testing.T) {
	root := t.TempDir()
	cfgPath := writeFleetConfig(t, root)

	var calls []externalCommand
	oldRun := runExternalCommand
	runExternalCommand = func(c externalCommand) error {
		calls = append(calls, c)
		return fmt.Errorf("stop after the first realize attempt")
	}
	t.Cleanup(func() { runExternalCommand = oldRun })

	coreDir := filepath.Join(root, "core")
	if err := os.MkdirAll(filepath.Join(coreDir, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(coreDir, "tests", "closure-purity-allowlist.txt"), []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _ = runCLI(t, "verify", "boundary-suite", "--core-dir", coreDir, "--fleet-config", cfgPath)

	if len(calls) == 0 {
		t.Fatal("expected the suite to try realizing a derived target")
	}
	joined := strings.Join(calls[0].Args, " ")
	cfg, err := fleet.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := cfg.CompileMatrix(cfg.Matrix.Preview)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.ClosurePurityTargets) == 0 {
		t.Skip("fixture fleet declares no production distroless target")
	}
	want := fmt.Sprintf(".#%q", compiled.ClosurePurityTargets[0])
	if !strings.Contains(joined, want) {
		t.Fatalf("suite built %q, want the fleet-derived target %q", joined, want)
	}
}

// TestVerifyBoundarySuiteQuotesDottedFlakeAttributes guards a bug that only
// appears for runtime lines with a dotted version. A nix flake installable
// splits its attribute path on ".", so `.#python3.14-distroless` resolves as
// packages...python3 -> "14-distroless" and fails with "does not provide
// attribute". It stayed latent while the default targets were coreLTS- and
// java21-distroless, and surfaced the moment the defaults were derived from a
// fleet containing python3.14.
func TestVerifyBoundarySuiteQuotesDottedFlakeAttributes(t *testing.T) {
	root := t.TempDir()
	coreDir := filepath.Join(root, "core")
	if err := os.MkdirAll(filepath.Join(coreDir, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(coreDir, "tests", "closure-purity-allowlist.txt"), []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var calls []externalCommand
	oldRun := runExternalCommand
	runExternalCommand = func(c externalCommand) error {
		calls = append(calls, c)
		return fmt.Errorf("stop before the real build")
	}
	t.Cleanup(func() { runExternalCommand = oldRun })

	_, _ = runCLI(t, "verify", "boundary-suite", "--core-dir", coreDir, "--closure-target", "python3.14-distroless")

	if len(calls) == 0 {
		t.Fatal("expected a nix build attempt")
	}
	joined := strings.Join(calls[0].Args, " ")
	if !strings.Contains(joined, `.#"python3.14-distroless"`) {
		t.Fatalf("dotted attribute must be quoted, got: %s", joined)
	}
}
