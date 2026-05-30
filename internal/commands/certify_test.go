package commands

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func createMockLayerTar(t *testing.T, filenames []string) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range filenames {
		hdr := &tar.Header{
			Name: name,
			Mode: 0755,
			Size: 0,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write layer header: %v", err)
		}
	}
	tw.Close()
	return buf.Bytes()
}

func createMockTarball(t *testing.T, files map[string][]byte) string {
	tmpFile, err := os.CreateTemp("", "clearcutt-test-*.tar")
	if err != nil {
		t.Fatalf("failed to create temp tarball: %v", err)
	}

	tw := tar.NewWriter(tmpFile)
	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
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

func TestRunCertify_Compliant(t *testing.T) {
	// Setup custom osExit mock
	exited := false
	exitCode := 0
	osExit = func(code int) {
		exited = true
		exitCode = code
	}
	defer func() { osExit = os.Exit }()

	// Create compliant config
	var config OCIImageConfig
	config.Config.User = "10001"
	config.Config.Labels = map[string]string{
		"org.opencontainers.image.source": "https://github.com/org/repo",
	}
	configBytes, _ := json.Marshal(config)

	// Create compliant manifest
	manifest := []DockerManifest{
		{
			Config:   "config.json",
			RepoTags: []string{"test-app:latest"},
			Layers:   []string{"layer.tar"},
		},
	}
	manifestBytes, _ := json.Marshal(manifest)

	layerBytes := createMockLayerTar(t, []string{"app/main.js"})

	tarballPath := createMockTarball(t, map[string][]byte{
		"manifest.json": manifestBytes,
		"config.json":   configBytes,
		"layer.tar":     layerBytes,
	})
	defer os.Remove(tarballPath)

	// Reset certify flags
	certifyOpts = certifyFlags{
		base: "java21-distroless",
	}
	GlobalOpts.CatalogPath = filepath.Join("..", "testdata", "catalog")
	GlobalOpts.Format = "json"

	err := runCertify(tarballPath)
	if err != nil {
		t.Fatalf("runCertify failed: %v", err)
	}

	if exited {
		t.Fatalf("Expected no exit, but exited with code %d", exitCode)
	}
}

func TestRunCertify_RootViolation(t *testing.T) {
	exited := false
	exitCode := 0
	osExit = func(code int) {
		exited = true
		exitCode = code
	}
	defer func() { osExit = os.Exit }()

	// Create non-compliant config (root user)
	var config OCIImageConfig
	config.Config.User = "root"
	config.Config.Labels = map[string]string{
		"org.opencontainers.image.source": "https://github.com/org/repo",
	}
	configBytes, _ := json.Marshal(config)

	manifest := []DockerManifest{
		{
			Config:   "config.json",
			RepoTags: []string{"test-app:latest"},
			Layers:   []string{"layer.tar"},
		},
	}
	manifestBytes, _ := json.Marshal(manifest)

	layerBytes := createMockLayerTar(t, []string{"app/main.js"})

	tarballPath := createMockTarball(t, map[string][]byte{
		"manifest.json": manifestBytes,
		"config.json":   configBytes,
		"layer.tar":     layerBytes,
	})
	defer os.Remove(tarballPath)

	certifyOpts = certifyFlags{
		base: "java21-distroless",
	}
	GlobalOpts.CatalogPath = filepath.Join("..", "testdata", "catalog")
	GlobalOpts.Format = "json"

	_ = runCertify(tarballPath)

	if !exited {
		t.Fatalf("Expected certification fail and exit")
	}
	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestRunCertify_ShellViolation(t *testing.T) {
	exited := false
	exitCode := 0
	osExit = func(code int) {
		exited = true
		exitCode = code
	}
	defer func() { osExit = os.Exit }()

	var config OCIImageConfig
	config.Config.User = "10001"
	config.Config.Labels = map[string]string{
		"org.opencontainers.image.source": "https://github.com/org/repo",
	}
	configBytes, _ := json.Marshal(config)

	manifest := []DockerManifest{
		{
			Config:   "config.json",
			RepoTags: []string{"test-app:latest"},
			Layers:   []string{"layer.tar"},
		},
	}
	manifestBytes, _ := json.Marshal(manifest)

	// Injects sh and apk under distroless base!
	layerBytes := createMockLayerTar(t, []string{"bin/sh", "usr/bin/apk"})

	tarballPath := createMockTarball(t, map[string][]byte{
		"manifest.json": manifestBytes,
		"config.json":   configBytes,
		"layer.tar":     layerBytes,
	})
	defer os.Remove(tarballPath)

	certifyOpts = certifyFlags{
		base: "java21-distroless",
	}
	GlobalOpts.CatalogPath = filepath.Join("..", "testdata", "catalog")
	GlobalOpts.Format = "json"

	_ = runCertify(tarballPath)

	if !exited {
		t.Fatalf("Expected shell violation to fail and exit")
	}
	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}
