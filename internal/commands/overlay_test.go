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
			tmpDir := t.TempDir()

			args := []string{
				"overlay", "generate",
				"--runtime", tc.runtime,
				"--tier", "distroless",
				"--base", "registry.access.redhat.com/ubi9/ubi-minimal@sha256:123456",
				"--runtime-ref", "ghcr.io/northcutted/clearcutt/clearcutt-" + tc.runtime + "@sha256:654321",
				"--image", "ghcr.io/acme/" + tc.runtime + "-ubi",
				"--output", tmpDir,
			}
			if tc.explicitBinary != "" {
				args = append(args, "--binary", tc.explicitBinary)
			}

			if _, err := runCLI(t, args...); err != nil {
				t.Fatalf("overlay generate failed for %s: %v", tc.runtime, err)
			}

			if overlayOpts.binary != tc.expectedBinary {
				t.Errorf("expected resolved binary %q, got %q", tc.expectedBinary, overlayOpts.binary)
			}

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
				if _, err := os.Stat(filepath.Join(tmpDir, file)); err != nil {
					t.Errorf("expected file %q was not generated for %s: %v", file, tc.runtime, err)
				}
			}
		})
	}
}
