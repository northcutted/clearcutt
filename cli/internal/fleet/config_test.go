package fleet

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeriveProductName(t *testing.T) {
	cases := map[string]string{
		"base-images": "Base Images",
		"clearcutt":   "Clearcutt",
		"acme_fleet":  "Acme Fleet",
		"":            "",
	}
	for repo, want := range cases {
		if got := DeriveProductName(repo); got != want {
			t.Errorf("DeriveProductName(%q) = %q, want %q", repo, got, want)
		}
	}
}

func TestBrandingDefaultsDeriveFromForkIdentity(t *testing.T) {
	// A fork that sets only owner/repo gets branding derived from its identity,
	// never the upstream ClearCutt brand.
	cfg := Config{Registry: Registry{Owner: "acme", Repository: "base-images"}}
	cfg.applyDefaults()
	if cfg.Branding.ProductName != "Base Images" {
		t.Errorf("ProductName = %q, want %q", cfg.Branding.ProductName, "Base Images")
	}
	if cfg.Branding.Vendor != "acme" {
		t.Errorf("Vendor = %q, want %q", cfg.Branding.Vendor, "acme")
	}
	if cfg.Branding.Authors != "Base Images maintainers" {
		t.Errorf("Authors = %q, want %q", cfg.Branding.Authors, "Base Images maintainers")
	}

	// Explicit branding is preserved verbatim.
	explicit := Config{
		Registry: Registry{Owner: "acme", Repository: "base-images"},
		Branding: Branding{ProductName: "Acme Hardened Images", Vendor: "Acme Inc", Authors: "Acme Platform"},
	}
	explicit.applyDefaults()
	if explicit.Branding.ProductName != "Acme Hardened Images" || explicit.Branding.Authors != "Acme Platform" {
		t.Errorf("explicit branding not preserved: %#v", explicit.Branding)
	}
}

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
	if loaded.RepoURL() != "https://github.com/acme/platform" {
		t.Fatalf("RepoURL() = %q", loaded.RepoURL())
	}
	if loaded.Release.SLSABuilder == "" {
		t.Fatalf("expected SLSA builder to be populated")
	}
	if loaded.Release.NixCache.Bucket != "" || loaded.Release.NixCache.PublicBaseURL != "" || loaded.Release.NixCache.SigningKeyName != "" || loaded.Release.NixCache.PublicKey != "" {
		t.Fatalf("new fork defaults should not inherit an upstream Nix cache: %#v", loaded.Release.NixCache)
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

func TestFleetDefaultsMatricesAndValidationErrors(t *testing.T) {
	cfg := Config{
		Registry: Registry{Host: "ghcr.io/", Owner: "acme", Repository: "platform", ImagePrefix: "cc"},
		Matrix:   Matrix{Systems: []string{"x86_64-linux"}, Languages: []string{"java21"}, Tiers: []string{"slim"}},
		Catalog:  Catalog{ReleaseLimit: 1},
		Remediation: Remediation{
			Mode: "approved-pr",
		},
	}
	cfg.applyDefaults()
	if cfg.RepoPath() != "acme/platform" || cfg.RegistryBase() != "ghcr.io/acme/platform" {
		t.Fatalf("unexpected registry identity: repo=%q base=%q", cfg.RepoPath(), cfg.RegistryBase())
	}
	if cfg.RepoURL() != "https://github.com/acme/platform" {
		t.Fatalf("unexpected repo URL: %q", cfg.RepoURL())
	}
	if cfg.ImageName("Java21") != "ghcr.io/acme/platform/cc-java21" {
		t.Fatalf("unexpected image name: %q", cfg.ImageName("Java21"))
	}
	if got := cfg.GitHubImageMatrix().Include; len(got) != 1 || got[0].Language != "java21" || got[0].Tier != "slim" {
		t.Fatalf("unexpected image matrix: %#v", got)
	}

	for name, mutate := range map[string]func(*Config){
		"apiVersion":   func(c *Config) { c.APIVersion = "wrong/v1" },
		"kind":         func(c *Config) { c.Kind = "Wrong" },
		"registry":     func(c *Config) { c.Registry.Owner = "" },
		"matrix":       func(c *Config) { c.Matrix.Languages = nil },
		"releaseLimit": func(c *Config) { c.Catalog.ReleaseLimit = 0 },
		"remediation":  func(c *Config) { c.Remediation.Mode = "autonomous" },
	} {
		bad := cfg
		mutate(&bad)
		if err := bad.Validate(); err == nil {
			t.Fatalf("%s validation unexpectedly passed", name)
		}
	}

	if _, err := Marshal(Config{APIVersion: "wrong/v1"}); err == nil {
		t.Fatal("Marshal should validate before writing")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("Load should fail for missing file")
	}
}
