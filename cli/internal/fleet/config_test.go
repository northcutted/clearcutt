package fleet

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigRoundTrip(t *testing.T) {
	cfg := DefaultConfig("acme", "platform")
	raw, err := Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	path := filepath.Join(t.TempDir(), "clearcutt.fleet.yaml")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.RegistryBase() != "ghcr.io/acme/platform" {
		t.Fatalf("RegistryBase() = %q", loaded.RegistryBase())
	}
	if loaded.Release.SLSABuilder == "" {
		t.Fatalf("expected SLSA builder to be populated")
	}
	if got := len(loaded.GitHubReleaseMatrix().Include); got != len(loaded.Matrix.Systems)*len(loaded.Matrix.Languages)*len(loaded.Matrix.Tiers) {
		t.Fatalf("release matrix size = %d", got)
	}
}

func TestValidateRejectsUnsupportedTier(t *testing.T) {
	cfg := DefaultConfig("acme", "platform")
	cfg.Matrix.Tiers = []string{"debug"}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("Validate() succeeded for unsupported tier")
	}
}
