package commands

import (
	"os"
	"path/filepath"
	"strings"
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
				"flake.nix",
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
			flake, err := os.ReadFile(filepath.Join(tmpDir, "flake.nix"))
			if err != nil {
				t.Fatalf("read generated flake: %v", err)
			}
			for _, needle := range []string{
				"clearcutt.lib.graftOntoBase",
				`clearcutt.url = "github:northcutted/clearcutt?dir=core"`,
				`runtime = "` + tc.runtime + `"`,
				`fromImage = mandatedBase`,
			} {
				if !strings.Contains(string(flake), needle) {
					t.Fatalf("generated flake missing %q:\n%s", needle, flake)
				}
			}
			makefile, err := os.ReadFile(filepath.Join(tmpDir, "Makefile"))
			if err != nil {
				t.Fatalf("read generated Makefile: %v", err)
			}
			if !strings.Contains(string(makefile), "GRAFTED_REF ?= $(IMAGE_NAME)@sha256:REPLACE_WITH_GRAFTED_IMAGE_DIGEST") {
				t.Fatalf("generated Makefile missing grafted digest placeholder:\n%s", makefile)
			}
			smoke, err := os.ReadFile(filepath.Join(tmpDir, "tests", "smoke.sh"))
			if err != nil {
				t.Fatalf("read generated smoke.sh: %v", err)
			}
			expectedSmokeNeedle := "/nix/store/*/bin/"
			if tc.runtime == "coreLTS" {
				expectedSmokeNeedle = "test -d /nix/store"
			}
			if strings.Contains(string(smoke), "/usr/local/bin") || !strings.Contains(string(smoke), expectedSmokeNeedle) {
				t.Fatalf("generated smoke should inspect the grafted Nix store, got:\n%s", smoke)
			}
		})
	}
}
