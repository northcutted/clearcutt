package commands

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunOverlayGenerate(t *testing.T) {
	tests := []struct {
		runtime        string
		expectedBinary string
		explicitBinary string
	}{
		{runtime: "java25", expectedBinary: "java", explicitBinary: "java"},
		{runtime: "node22", expectedBinary: "node"},
		{runtime: "python3.14", expectedBinary: "python3"},
		{runtime: "go1.26", expectedBinary: "go"},
		{runtime: "dotnet8", expectedBinary: "dotnet"},
		{runtime: "rust1.95", expectedBinary: "rustc"},
		{runtime: "cc15", expectedBinary: "gcc"},
		{runtime: "coreLTS", expectedBinary: "sh"},
	}

	for _, tc := range tests {
		t.Run(tc.runtime, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "clearcutt-overlay-test-*")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			overlayOpts = overlayFlags{
				runtime:    tc.runtime,
				tier:       "distroless",
				base:       "registry.access.redhat.com/ubi9/ubi-minimal@sha256:123456",
				runtimeRef: "ghcr.io/northcutted/clearcutt/clearcutt-" + tc.runtime + "@sha256:654321",
				binary:     tc.explicitBinary,
				image:      "ghcr.io/acme/" + tc.runtime + "-ubi",
				output:     tmpDir,
			}

			err = runOverlayGenerate()
			if err != nil {
				t.Fatalf("runOverlayGenerate failed for %s: %v", tc.runtime, err)
			}

			if overlayOpts.binary != tc.expectedBinary {
				t.Errorf("expected resolved binary to be %q, got %q", tc.expectedBinary, overlayOpts.binary)
			}

			// Verify files exist
			files := []string{
				"clearcutt.overlay.yaml",
				"Containerfile",
				"README.md",
				"Makefile",
				"tests/smoke.sh",
				"policy/kyverno-verify-image.yaml",
				".github/workflows/build.yaml",
				".github/workflows/verify.yaml",
			}

			for _, file := range files {
				path := filepath.Join(tmpDir, file)
				if _, err := os.Stat(path); err != nil {
					t.Errorf("expected file %q was not generated for %s: %v", file, tc.runtime, err)
				}
			}
		})
	}
}
