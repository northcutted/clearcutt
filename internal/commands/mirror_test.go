package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunMirror_Success(t *testing.T) {
	tempFile, err := os.CreateTemp("", "clearcutt-mirror-*.sh")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tempFilePath := tempFile.Name()
	tempFile.Close()
	defer os.Remove(tempFilePath)

	// Reset mirror flags
	mirrorOpts = mirrorFlags{
		target: "enterprise-registry.internal/hardened",
		output: tempFilePath,
	}
	GlobalOpts.CatalogPath = filepath.Join("..", "testdata", "catalog")

	err = runMirror("java21-distroless")
	if err != nil {
		t.Fatalf("runMirror failed: %v", err)
	}

	// Verify that the generated file contains valid skopeo and cosign copy statements
	data, err := os.ReadFile(tempFilePath)
	if err != nil {
		t.Fatalf("failed to read generated mirroring script: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "#!/usr/bin/env bash") {
		t.Errorf("Expected bash shebang, got: %s", content)
	}

	if !strings.Contains(content, "skopeo copy") {
		t.Errorf("Expected skopeo copy command in script")
	}

	if !strings.Contains(content, "cosign copy") {
		t.Errorf("Expected cosign copy command in script")
	}

	if !strings.Contains(content, "enterprise-registry.internal/hardened/clearcutt-java:v1.0.0-distroless") {
		t.Errorf("Expected target registry and image tag reference to be correctly rendered")
	}
}
