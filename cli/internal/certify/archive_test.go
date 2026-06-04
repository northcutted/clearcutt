package certify

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testLayerTar(t *testing.T, filenames ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range filenames {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: 0}); err != nil {
			t.Fatalf("write layer header: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close layer tar: %v", err)
	}
	return buf.Bytes()
}

func testArchive(t *testing.T, files map[string][]byte, suffix string) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "image-*"+suffix)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	tw := tar.NewWriter(file)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}); err != nil {
			t.Fatalf("write archive header: %v", err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("write archive content: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close archive tar: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close archive file: %v", err)
	}
	return file.Name()
}

func gzipTestBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func testSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func testConfig(t *testing.T) []byte {
	t.Helper()
	var cfg OCIImageConfig
	cfg.Config.User = "10001"
	cfg.Config.Labels = map[string]string{"org.opencontainers.image.source": "https://github.com/acme/app"}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return data
}

func testDockerArchive(t *testing.T, config, layer []byte) string {
	t.Helper()
	manifest, err := json.Marshal([]DockerManifest{{
		Config:   "config.json",
		RepoTags: []string{"acme/app:latest"},
		Layers:   []string{"layer.tar"},
	}})
	if err != nil {
		t.Fatalf("marshal docker manifest: %v", err)
	}
	return testArchive(t, map[string][]byte{
		"manifest.json": manifest,
		"config.json":   config,
		"layer.tar":     layer,
	}, ".tar")
}

func testNestedOCIArchive(t *testing.T, config, layer []byte) string {
	t.Helper()
	configDigest := testSHA256(config)
	layerDigest := testSHA256(layer)
	manifest, err := json.Marshal(Manifest{
		Config: Descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: "sha256:" + configDigest, Size: int64(len(config))},
		Layers: []Descriptor{{MediaType: "application/vnd.oci.image.layer.v1.tar", Digest: "sha256:" + layerDigest, Size: int64(len(layer))}},
	})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	manifestDigest := testSHA256(manifest)
	nested, err := json.Marshal(Index{Manifests: []Descriptor{{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    "sha256:" + manifestDigest,
		Size:      int64(len(manifest)),
	}}})
	if err != nil {
		t.Fatalf("marshal nested index: %v", err)
	}
	nestedDigest := testSHA256(nested)
	index, err := json.Marshal(Index{Manifests: []Descriptor{{
		MediaType:   "application/vnd.oci.image.index.v1+json",
		Digest:      "sha256:" + nestedDigest,
		Size:        int64(len(nested)),
		Annotations: map[string]string{"org.opencontainers.image.ref.name": "ghcr.io/acme/app@sha256:" + nestedDigest},
	}}})
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	return testArchive(t, map[string][]byte{
		"oci-layout":                     []byte(`{"imageLayoutVersion":"1.0.0"}`),
		"index.json":                     index,
		"blobs/sha256/" + configDigest:   config,
		"blobs/sha256/" + layerDigest:    layer,
		"blobs/sha256/" + manifestDigest: manifest,
		"blobs/sha256/" + nestedDigest:   nested,
	}, ".tar")
}

func TestLoadImageArchiveResolvesDockerAndOCIArchives(t *testing.T) {
	config := testConfig(t)
	layer := testLayerTar(t, "app/main")

	dockerImage, err := LoadImageArchive(testDockerArchive(t, config, layer), t.TempDir())
	if err != nil {
		t.Fatalf("load docker archive: %v", err)
	}
	if dockerImage.Format != "docker" || len(dockerImage.ConfigRaw) == 0 || len(dockerImage.LayerPaths) != 1 || dockerImage.RepoTags[0] != "acme/app:latest" {
		t.Fatalf("unexpected docker archive resolution: %+v", dockerImage)
	}

	ociImage, err := LoadImageArchive(testNestedOCIArchive(t, config, layer), t.TempDir())
	if err != nil {
		t.Fatalf("load OCI archive: %v", err)
	}
	if ociImage.Format != "oci" || len(ociImage.ConfigRaw) == 0 || len(ociImage.LayerPaths) != 1 || len(ociImage.RepoTags) != 1 {
		t.Fatalf("unexpected OCI archive resolution: %+v", ociImage)
	}
	if !strings.HasPrefix(ociImage.RepoTags[0], "ghcr.io/acme/app@sha256:") {
		t.Fatalf("expected OCI ref annotation in repo tags, got %#v", ociImage.RepoTags)
	}
}

func TestLoadImageArchiveErrorsAndBlobHelpers(t *testing.T) {
	tempDir := t.TempDir()
	if _, err := LoadImageArchive(filepath.Join(tempDir, "missing.tar"), tempDir); err == nil || !strings.Contains(err.Error(), "unable to open") {
		t.Fatalf("expected missing archive error, got %v", err)
	}

	badGzip := filepath.Join(tempDir, "bad.tgz")
	if err := os.WriteFile(badGzip, []byte("not-gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadImageArchive(badGzip, tempDir); err == nil || !strings.Contains(err.Error(), "gzip") {
		t.Fatalf("expected gzip initialization error, got %v", err)
	}

	if got := BlobPath(map[string]string{}, "not-a-digest"); got != "" {
		t.Fatalf("malformed digest resolved to %q", got)
	}
	if got := ReadBlob(map[string]string{}, "sha256:missing"); got != nil {
		t.Fatalf("missing blob returned data: %q", got)
	}
}

func TestScanLayerForRuntimeTools(t *testing.T) {
	layerPath := filepath.Join(t.TempDir(), "layer.tar.gz")
	if err := os.WriteFile(layerPath, gzipTestBytes(t, testLayerTar(t, "bin/sh", "usr/bin/apk", "app/main")), 0o644); err != nil {
		t.Fatal(err)
	}
	shells, pkgs, err := ScanLayerForRuntimeTools(layerPath)
	if err != nil {
		t.Fatalf("scan gzipped layer: %v", err)
	}
	if len(shells) != 1 || shells[0] != "bin/sh" {
		t.Fatalf("unexpected shells: %#v", shells)
	}
	if len(pkgs) != 1 || pkgs[0] != "usr/bin/apk" {
		t.Fatalf("unexpected package managers: %#v", pkgs)
	}

	badLayer := filepath.Join(t.TempDir(), "bad-layer.tar")
	if err := os.WriteFile(badLayer, []byte("not a layer tar"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ScanLayerForRuntimeTools(badLayer); err == nil {
		t.Fatal("expected unreadable layer scan to return an error")
	}
}
