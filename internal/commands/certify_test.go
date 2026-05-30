package commands

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func createMockLayerTar(t *testing.T, filenames []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range filenames {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: 0}); err != nil {
			t.Fatalf("failed to write layer header: %v", err)
		}
	}
	tw.Close()
	return buf.Bytes()
}

func createMockTarball(t *testing.T, files map[string][]byte) string {
	t.Helper()
	tmpFile, err := os.CreateTemp(t.TempDir(), "clearcutt-test-*.tar")
	if err != nil {
		t.Fatalf("failed to create temp tarball: %v", err)
	}
	tw := tar.NewWriter(tmpFile)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(content))}); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("failed to write content: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}
	tmpFile.Close()
	return tmpFile.Name()
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(b); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	gw.Close()
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func mockConfig(t *testing.T, user string) []byte {
	t.Helper()
	var config OCIImageConfig
	config.Config.User = user
	config.Config.Labels = map[string]string{"org.opencontainers.image.source": "https://github.com/org/repo"}
	b, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return b
}

// dockerTarball builds a legacy `docker save` style archive.
func dockerTarball(t *testing.T, config, layer []byte) string {
	t.Helper()
	manifest, _ := json.Marshal([]DockerManifest{{Config: "config.json", RepoTags: []string{"test-app:latest"}, Layers: []string{"layer.tar"}}})
	return createMockTarball(t, map[string][]byte{
		"manifest.json": manifest,
		"config.json":   config,
		"layer.tar":     layer,
	})
}

// ociTarball builds an OCI-layout archive (index.json + blobs/sha256/*).
func ociTarball(t *testing.T, config, layer []byte) string {
	t.Helper()
	cfgDigest := sha256Hex(config)
	layerDigest := sha256Hex(layer)
	man, _ := json.Marshal(ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: "sha256:" + cfgDigest, Size: int64(len(config))},
		Layers: []ociDescriptor{{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + layerDigest, Size: int64(len(layer))}},
	})
	manDigest := sha256Hex(man)
	index, _ := json.Marshal(ociIndex{Manifests: []ociDescriptor{{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: "sha256:" + manDigest, Size: int64(len(man))}}})
	return createMockTarball(t, map[string][]byte{
		"oci-layout":                  []byte(`{"imageLayoutVersion":"1.0.0"}`),
		"index.json":                  index,
		"blobs/sha256/" + cfgDigest:   config,
		"blobs/sha256/" + layerDigest: layer,
		"blobs/sha256/" + manDigest:   man,
	})
}

func runCertifyJSON(t *testing.T, tarball string, extra ...string) (CertifyResponse, error) {
	t.Helper()
	args := append([]string{"certify", tarball, "--base", "java21-distroless", "--catalog", fixtureCatalog(), "--format", "json"}, extra...)
	stdout, err := runCLI(t, args...)
	var resp CertifyResponse
	if uerr := json.Unmarshal([]byte(stdout), &resp); uerr != nil {
		t.Fatalf("failed to parse certify JSON: %v\n%s", uerr, stdout)
	}
	return resp, err
}

func certifyCheck(resp CertifyResponse, id string) (string, bool) {
	for _, c := range resp.Checks {
		if c.ID == id {
			return c.Status, true
		}
	}
	return "", false
}

func TestCertify_CompliantDocker(t *testing.T) {
	tarball := dockerTarball(t, mockConfig(t, "10001"), createMockLayerTar(t, []string{"app/main.js"}))
	resp, err := runCertifyJSON(t, tarball)
	if err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
	if resp.Status != "pass" {
		t.Fatalf("expected pass, got %q", resp.Status)
	}
	if st, _ := certifyCheck(resp, "config.user.nonroot"); st != "pass" {
		t.Errorf("user.nonroot expected pass, got %q", st)
	}
	if st, _ := certifyCheck(resp, "contract.shell.absence"); st != "pass" {
		t.Errorf("shell.absence expected pass, got %q", st)
	}
}

func TestCertify_CompliantOCILayout(t *testing.T) {
	tarball := ociTarball(t, mockConfig(t, "10001"), createMockLayerTar(t, []string{"app/main.js"}))
	resp, err := runCertifyJSON(t, tarball)
	if err != nil {
		t.Fatalf("expected OCI-layout archive to certify, got %v", err)
	}
	if st, _ := certifyCheck(resp, "manifest.parsed"); st != "pass" {
		t.Errorf("manifest.parsed expected pass for OCI layout, got %q", st)
	}
	if st, _ := certifyCheck(resp, "config.user.nonroot"); st != "pass" {
		t.Errorf("user.nonroot expected pass, got %q", st)
	}
}

func TestCertify_RootViolation(t *testing.T) {
	tarball := dockerTarball(t, mockConfig(t, "root"), createMockLayerTar(t, []string{"app/main.js"}))
	resp, err := runCertifyJSON(t, tarball)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected ErrCheckFailed for root user, got %v", err)
	}
	if st, _ := certifyCheck(resp, "config.user.nonroot"); st != "fail" {
		t.Errorf("expected user.nonroot fail, got %q", st)
	}
}

// Covers both the gzip-layer decoding and the shell detection in a distroless tier.
func TestCertify_ShellViolationInGzippedLayer(t *testing.T) {
	layer := gzipBytes(t, createMockLayerTar(t, []string{"bin/sh", "usr/bin/apk"}))
	tarball := dockerTarball(t, mockConfig(t, "10001"), layer)
	resp, err := runCertifyJSON(t, tarball)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected ErrCheckFailed for shell/pkg-manager in distroless layer, got %v", err)
	}
	if st, _ := certifyCheck(resp, "contract.shell.absence"); st != "fail" {
		t.Errorf("expected shell.absence fail (gzip layer), got %q", st)
	}
	if st, _ := certifyCheck(resp, "contract.package_manager.absence"); st != "fail" {
		t.Errorf("expected package_manager.absence fail, got %q", st)
	}
}

// Required supply-chain attestations are reported as skipped (not falsely passed)
// because they cannot be verified from an offline tarball.
func TestCertify_EvidenceChecksAreSkippedNotPassed(t *testing.T) {
	tarball := dockerTarball(t, mockConfig(t, "10001"), createMockLayerTar(t, []string{"app/main.js"}))
	resp, err := runCertifyJSON(t, tarball, "--require-signature", "--require-sbom", "--require-provenance")
	if err != nil {
		t.Fatalf("offline evidence gaps should not fail certification, got %v", err)
	}
	for _, id := range []string{"evidence.signature.verified", "evidence.sbom.present", "evidence.provenance.present"} {
		st, ok := certifyCheck(resp, id)
		if !ok {
			t.Errorf("expected %s to be present", id)
		}
		if st == "pass" {
			t.Errorf("%s must not be reported as pass offline; got %q", id, st)
		}
		if st != "skip" {
			t.Errorf("%s expected skip, got %q", id, st)
		}
	}
}

func TestCertify_UnrecognizedArchiveFails(t *testing.T) {
	tarball := createMockTarball(t, map[string][]byte{"random.txt": []byte("not an image")})
	resp, err := runCertifyJSON(t, tarball)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected ErrCheckFailed for unrecognized archive, got %v", err)
	}
	if st, _ := certifyCheck(resp, "manifest.parsed"); st != "fail" {
		t.Errorf("expected manifest.parsed fail, got %q", st)
	}
}
