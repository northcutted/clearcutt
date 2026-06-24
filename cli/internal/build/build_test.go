package build

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeRunner stands in for nix/syft/grype: "nix build" writes a prepared
// gzipped image archive to the --out-link path; syft/grype write canned output.
type fakeRunner struct {
	archive  []byte
	grypeErr error
}

func (f *fakeRunner) Run(dir, name string, args ...string) error {
	if name == "nix" {
		return os.WriteFile(flagValue(args, "--out-link"), f.archive, 0o644)
	}
	return nil
}

func (f *fakeRunner) Capture(dir, outPath, name string, args ...string) error {
	switch name {
	case "syft":
		return os.WriteFile(outPath, []byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`), 0o644)
	case "grype":
		_ = os.WriteFile(outPath, []byte(`{"matches":[]}`), 0o644)
		return f.grypeErr
	}
	return nil
}

func flagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func layerTar(t *testing.T, entries map[string]int64) []byte {
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

// gzippedDockerArchive builds a docker-save tarball with one layer and gzips it,
// matching the .tar.gz the engine writes and the gates consume.
func gzippedDockerArchive(t *testing.T, layer []byte) []byte {
	t.Helper()
	files := map[string][]byte{
		"config.json":   []byte(`{"config":{}}`),
		"layer0.tar":    layer,
		"manifest.json": []byte(`[{"Config":"config.json","RepoTags":["test:latest"],"Layers":["layer0.tar"]}]`),
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
	return gz.Bytes()
}

func testFloorPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "floor.json")
	body := `{"deps":[{"name":"openssl","minVersion":"3.6.3"},{"name":"sqlite","minVersion":"3.53.2"}]}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func runCertify(t *testing.T, target string, layer []byte, grypeErr error) (Result, error) {
	t.Helper()
	r := &fakeRunner{archive: gzippedDockerArchive(t, layer), grypeErr: grypeErr}
	opts := Options{
		Target:    target,
		System:    "x86_64-linux",
		Kind:      "runtime",
		CoreDir:   t.TempDir(),
		OutputDir: t.TempDir(),
		FloorPath: testFloorPath(t),
	}
	return CertifyTarget(r, opts, time.Unix(0, 0), nil)
}

func TestCertifyTargetCleanDistrolessPasses(t *testing.T) {
	layer := layerTar(t, map[string]int64{
		"nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.3/lib/libssl.so":     0o644,
		"nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-sqlite-3.53.2/lib/libsqlite3.so": 0o644,
	})
	res, err := runCertify(t, "coreLTS-distroless", layer, nil)
	if err != nil {
		t.Fatalf("expected clean pass, got error: %v", err)
	}
	if res.Status != "passed" {
		t.Errorf("status = %q, want passed", res.Status)
	}
	if res.ClosurePurity == nil || !*res.ClosurePurity {
		t.Errorf("closurePurity = %v, want true", res.ClosurePurity)
	}
	if res.RuntimePatchComplete == nil || !*res.RuntimePatchComplete {
		t.Errorf("runtimePatchComplete = %v, want true", res.RuntimePatchComplete)
	}
	if !res.Policy.Blocking {
		t.Errorf("distroless runtime should be blocking")
	}
}

func TestCertifyTargetImpureDistrolessFailsClosurePurity(t *testing.T) {
	layer := layerTar(t, map[string]int64{
		"nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bash-5.2/bin/bash":           0o755,
		"nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-openssl-3.6.3/lib/libssl.so": 0o644,
	})
	res, err := runCertify(t, "node24-distroless", layer, nil)
	if err == nil {
		t.Fatal("expected closure-purity gate failure")
	}
	if res.Status != "failed" || res.ClosurePurity == nil || *res.ClosurePurity {
		t.Errorf("expected failed status + closurePurity=false, got status=%q purity=%v", res.Status, res.ClosurePurity)
	}
}

func TestCertifyTargetStockOpensslFailsRuntimeCve(t *testing.T) {
	layer := layerTar(t, map[string]int64{
		"nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.2/lib/libssl.so": 0o644,
	})
	res, err := runCertify(t, "coreLTS-slim", layer, nil)
	if err == nil {
		t.Fatal("expected runtime-cve gate failure for stock openssl-3.6.2")
	}
	if res.RuntimePatchComplete == nil || *res.RuntimePatchComplete {
		t.Errorf("expected runtimePatchComplete=false, got %v", res.RuntimePatchComplete)
	}
	// slim tier runs no closure-purity gate.
	if res.ClosurePurity != nil {
		t.Errorf("slim should skip closure-purity, got %v", res.ClosurePurity)
	}
}

func TestCertifyTargetWritesPredicateFile(t *testing.T) {
	layer := layerTar(t, map[string]int64{
		"nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-openssl-3.6.3/lib/libssl.so": 0o644,
	})
	r := &fakeRunner{archive: gzippedDockerArchive(t, layer)}
	outDir := t.TempDir()
	opts := Options{Target: "coreLTS-slim", System: "x86_64-linux", Kind: "runtime", CoreDir: t.TempDir(), OutputDir: outDir, FloorPath: testFloorPath(t)}
	if _, err := CertifyTarget(r, opts, time.Unix(0, 0), nil); err != nil {
		t.Fatalf("certify: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "coreLTS-slim.test-results.json")); err != nil {
		t.Errorf("predicate file not written: %v", err)
	}
}

func TestCertifyTargetDarwinFailsFast(t *testing.T) {
	_, err := CertifyTarget(&fakeRunner{}, Options{Target: "coreLTS-slim", System: "aarch64-darwin", Kind: "runtime"}, time.Unix(0, 0), nil)
	if err == nil {
		t.Fatal("expected Darwin to fail fast")
	}
}

func TestGrypeStatus(t *testing.T) {
	cases := []struct {
		failed            bool
		kind, tier        string
		productionAllowed bool
		lifecycle, want   string
	}{
		{false, "runtime", "distroless", false, "", "passed"},
		{true, "runtime", "dev", false, "", "warning"},
		{true, "runtime", "distroless", false, "", "failed"},
		{true, "service", "service", false, "preview", "warning"},
		{true, "service", "service", true, "active", "failed"},
	}
	for _, c := range cases {
		if got := grypeStatus(c.failed, c.kind, c.tier, c.productionAllowed, c.lifecycle); got != c.want {
			t.Errorf("grypeStatus(%+v) = %q, want %q", c, got, c.want)
		}
	}
}

func TestAggregateStatus(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"passed", "passed"}, "passed"},
		{[]string{"passed", "warning"}, "warning"},
		{[]string{"warning", "failed"}, "failed"},
		{[]string{"passed", "skipped"}, "skipped"},
		{[]string{"skipped", "warning"}, "warning"},
	}
	for _, c := range cases {
		if got := aggregateStatus(c.in...); got != c.want {
			t.Errorf("aggregateStatus(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// guards that a non-nil grype error does not itself error the run when the
// tier downgrades it (dev) — only the gate verdict propagates.
func TestCertifyTargetDevTierGrypeIsWarning(t *testing.T) {
	layer := layerTar(t, map[string]int64{
		"nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.3/lib/libssl.so": 0o644,
	})
	res, err := runCertify(t, "coreLTS-dev", layer, errors.New("grype found highs"))
	if err != nil {
		t.Fatalf("dev tier grype hit should not fail the run: %v", err)
	}
	if res.Status != "warning" {
		t.Errorf("status = %q, want warning", res.Status)
	}
}
