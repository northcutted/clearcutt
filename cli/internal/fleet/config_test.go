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

func TestValidateRejectsUnsupportedMatrixPublicInputs(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"unsupported system":   func(c *Config) { c.Matrix.Systems = []string{"x86_64-darwin"} },
		"duplicate system":     func(c *Config) { c.Matrix.Systems = []string{"x86_64-linux", "x86_64-linux"} },
		"unsupported language": func(c *Config) { c.Matrix.Languages = []string{"ruby3.4"} },
		"duplicate language":   func(c *Config) { c.Matrix.Languages = []string{"java21", "java21"} },
		"duplicate tier":       func(c *Config) { c.Matrix.Tiers = []string{"dev", "dev"} },
	} {
		cfg := DefaultConfig("acme", "platform")
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s validation unexpectedly passed", name)
		}
	}
}

func TestSupportedRuntimeLinesExposePublicRuntimeIDs(t *testing.T) {
	line, ok := RuntimeLineInfo("java21")
	if !ok {
		t.Fatal("java21 should be a supported runtime line")
	}
	if line.Language != "java" || line.Version != "21" || line.AppTemplateRuntime != "java" {
		t.Fatalf("unexpected java21 runtime line: %#v", line)
	}
	if _, ok := RuntimeLineInfo("ruby3.4"); ok {
		t.Fatal("ruby3.4 should not be a supported runtime line")
	}
	ids := SupportedRuntimeLineIDs()
	if len(ids) == 0 || ids[0] != "cc15" {
		t.Fatalf("supported runtime IDs should be sorted, got %#v", ids)
	}

	cfg := DefaultConfig("acme", "platform")
	cfg.RuntimeLines = []RuntimeLine{{
		ID:                "ruby3.4",
		Language:          "ruby",
		Version:           "3.4",
		PackageCandidates: []string{"ruby_3_4"},
	}}
	cfg.Matrix.Languages = []string{"ruby3.4"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("custom runtime line should validate: %v", err)
	}
	custom, ok := cfg.RuntimeLineInfo("ruby3.4")
	if !ok || custom.Language != "ruby" || custom.Version != "3.4" {
		t.Fatalf("custom runtime line not exposed: %#v", custom)
	}
	if !cfg.IsCustomRuntimeLine("ruby3.4") || cfg.IsCustomRuntimeLine("java21") {
		t.Fatalf("custom runtime helper misclassified runtime lines")
	}
	if builtins := BuiltInRuntimeLines(); len(builtins) == 0 || builtins[0].ID != "cc15" {
		t.Fatalf("built-in runtime lines should be sorted, got %#v", builtins)
	}
	if systems := SupportedSystems(); len(systems) != 2 || systems[0] != "aarch64-linux" || systems[1] != "x86_64-linux" {
		t.Fatalf("supported systems should be sorted, got %#v", systems)
	}
}

func TestCustomRuntimeLineValidationErrors(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"missing fields": func(c *Config) {
			c.RuntimeLines = []RuntimeLine{{ID: "ruby3.4"}}
		},
		"built-in conflict": func(c *Config) {
			c.RuntimeLines = []RuntimeLine{{ID: "java21", Language: "java", Version: "21", PackageCandidates: []string{"jdk21"}}}
		},
		"duplicate custom": func(c *Config) {
			c.RuntimeLines = []RuntimeLine{
				{ID: "ruby3.4", Language: "ruby", Version: "3.4", PackageCandidates: []string{"ruby_3_4"}},
				{ID: "ruby3.4", Language: "ruby", Version: "3.4", PackageCandidates: []string{"ruby_3_4"}},
			}
		},
		"missing packages": func(c *Config) {
			c.RuntimeLines = []RuntimeLine{{ID: "ruby3.4", Language: "ruby", Version: "3.4"}}
		},
		"empty system": func(c *Config) {
			c.Matrix.Systems = []string{""}
		},
		"empty language": func(c *Config) {
			c.Matrix.Languages = []string{""}
		},
	} {
		cfg := DefaultConfig("acme", "platform")
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s validation unexpectedly passed", name)
		}
	}
}

func TestServiceTemplatesApplyDefaultsAndMatrices(t *testing.T) {
	cfg := DefaultConfig("acme", "platform")
	cfg.Matrix.Systems = []string{"x86_64-linux"}
	cfg.Services = []ServiceImage{{
		ID:       "postgres16",
		Template: "postgres",
		Version:  "16",
	}}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("service config should validate: %v", err)
	}
	service, ok := cfg.ServiceInfo("postgres16")
	if !ok {
		t.Fatal("postgres16 should resolve")
	}
	if service.PackageCandidates[0] != "postgresql_16" {
		t.Fatalf("unexpected package defaults: %#v", service.PackageCandidates)
	}
	if !service.Stateful || len(service.DataDirs) != 1 || service.DataDirs[0] != "/var/lib/postgresql/data" {
		t.Fatalf("unexpected storage defaults: %#v", service)
	}
	if service.Ports[0].Port != 5432 || service.Ports[0].Protocol != "tcp" {
		t.Fatalf("unexpected port defaults: %#v", service.Ports)
	}
	if cfg.ServiceImageName("Postgres16") != "ghcr.io/acme/platform/platform-postgres16" {
		t.Fatalf("unexpected service image name: %q", cfg.ServiceImageName("Postgres16"))
	}
	if ids := cfg.ServiceIDs(); len(ids) != 1 || ids[0] != "postgres16" {
		t.Fatalf("unexpected service IDs: %#v", ids)
	}
	if got := cfg.GitHubServiceReleaseMatrix().Include; len(got) != 1 || got[0].Service != "postgres16" || got[0].System != "x86_64-linux" {
		t.Fatalf("unexpected service release matrix: %#v", got)
	}
	if got := cfg.GitHubServiceImageMatrix().Include; len(got) != 1 || got[0].Service != "postgres16" {
		t.Fatalf("unexpected service image matrix: %#v", got)
	}
	if templates := BuiltInServiceTemplates(); len(templates) != 3 || templates[0].Template != "oauth2-proxy" {
		t.Fatalf("built-in service templates should be sorted, got %#v", templates)
	}
}

func TestServiceValidationErrors(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"missing fields": func(c *Config) {
			c.Services = []ServiceImage{{ID: "postgres16"}}
		},
		"unsupported template": func(c *Config) {
			c.Services = []ServiceImage{{ID: "postgres16", Template: "mysql", Version: "8", PackageCandidates: []string{"mysql80"}}}
		},
		"duplicate service": func(c *Config) {
			c.Services = []ServiceImage{
				{ID: "postgres16", Template: "postgres", Version: "16"},
				{ID: "postgres16", Template: "postgres", Version: "16"},
			}
		},
		"stateful missing data dirs": func(c *Config) {
			c.Services = []ServiceImage{{ID: "custom", Template: "oauth2-proxy", Version: "7", PackageCandidates: []string{"oauth2-proxy"}, Stateful: true}}
		},
		"relative data dir": func(c *Config) {
			c.Services = []ServiceImage{{ID: "custom", Template: "valkey", Version: "8", PackageCandidates: []string{"valkey"}, Stateful: true, DataDirs: []string{"data"}}}
		},
		"invalid port": func(c *Config) {
			c.Services = []ServiceImage{{ID: "custom", Template: "oauth2-proxy", Version: "7", PackageCandidates: []string{"oauth2-proxy"}, Ports: []ServicePort{{Port: 70000}}}}
		},
	} {
		cfg := DefaultConfig("acme", "platform")
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s validation unexpectedly passed", name)
		}
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
