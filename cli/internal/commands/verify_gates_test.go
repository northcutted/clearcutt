package commands

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
