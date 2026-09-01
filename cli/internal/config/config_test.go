package config

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
	if len(ids) == 0 || ids[0] != "go1.25" {
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
	if builtins := BuiltInRuntimeLines(); len(builtins) == 0 || builtins[0].ID != "go1.25" {
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
		"apiVersion":                    func(c *Config) { c.APIVersion = "wrong/v1" },
		"kind":                          func(c *Config) { c.Kind = "Wrong" },
		"registry":                      func(c *Config) { c.Registry.Owner = "" },
		"matrix":                        func(c *Config) { c.Matrix.Languages = nil },
		"releaseLimit":                  func(c *Config) { c.Catalog.ReleaseLimit = 0 },
		"remediationPolicyTier":         func(c *Config) { c.Remediation.Policy.ProductionTiers = []string{"dev"} },
		"remediationPolicySeverity":     func(c *Config) { c.Remediation.Policy.MinimumSeverity = "urgent" },
		"remediationPolicyEPSSBoundary": func(c *Config) { c.Remediation.Policy.EPSSPercentileBoostAt = 1.1 },
		"remediationPolicyWaitSeverity": func(c *Config) { c.Remediation.Policy.WaitMaxSeverity = "urgent" },
		"remediationPolicyWaitDays":     func(c *Config) { c.Remediation.Policy.WaitMaxDays = intPtr(-1) },
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

func TestRemediationTriagePolicyDefaultsAndOverrides(t *testing.T) {
	eff := EffectiveRemediationPolicy(RemediationPolicy{})
	if eff.PreferSubstitutable == nil || !*eff.PreferSubstitutable {
		t.Errorf("preferSubstitutable should default true, got %#v", eff.PreferSubstitutable)
	}
	if eff.WaitMaxSeverity != "medium" {
		t.Errorf("waitMaxSeverity should default medium, got %q", eff.WaitMaxSeverity)
	}
	if eff.WaitMaxDays == nil || *eff.WaitMaxDays != 30 {
		t.Errorf("waitMaxDays should default 30, got %#v", eff.WaitMaxDays)
	}
	zero := EffectiveRemediationPolicy(RemediationPolicy{WaitMaxDays: intPtr(0)})
	if zero.WaitMaxDays == nil || *zero.WaitMaxDays != 0 {
		t.Errorf("explicit waitMaxDays 0 must survive normalization, got %#v", zero.WaitMaxDays)
	}

	// Explicit values survive normalization untouched, including the false
	// pointer that omitempty would otherwise conflate with unset.
	set := EffectiveRemediationPolicy(RemediationPolicy{
		PreferSubstitutable: boolPtr(false),
		WaitMaxSeverity:     "low",
		WaitMaxDays:         intPtr(7),
	})
	if set.PreferSubstitutable == nil || *set.PreferSubstitutable || set.WaitMaxSeverity != "low" || set.WaitMaxDays == nil || *set.WaitMaxDays != 7 {
		t.Errorf("explicit triage policy values not preserved: %#v", set)
	}
}

// TestConfigPathResolutionKeepsForksWorking pins the migration contract. The
// file was renamed because DefaultConfigPath implied a prerequisite that
// does not exist — governance commands never read it — but an existing fork
// must not need a flag, or a rename, to keep running.
func TestConfigPathResolutionKeepsForksWorking(t *testing.T) {
	t.Run("explicit path always wins", func(t *testing.T) {
		if got := ResolveConfigPath("custom.yaml"); got != "custom.yaml" {
			t.Fatalf("explicit path = %q", got)
		}
	})

	t.Run("legacy name is used when it is the only one present", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if err := os.WriteFile(LegacyConfigPath, []byte("kind: FleetConfig\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := ResolveConfigPath(""); got != LegacyConfigPath {
			t.Fatalf("an unmigrated fork should resolve to %q, got %q", LegacyConfigPath, got)
		}
	})

	// The case that actually matters, and that the first version got wrong.
	// Every command defaults its --config flag to the new name, so the path is
	// NEVER empty in practice. Resolving only on an empty path meant an
	// unmigrated fork failed with "clearcutt.yaml: no such file" while its
	// clearcutt.fleet.yaml sat right beside it.
	t.Run("the default value falls back to a legacy sibling", func(t *testing.T) {
		dir := t.TempDir()
		legacy := filepath.Join(dir, LegacyConfigPath)
		if err := os.WriteFile(legacy, []byte("kind: FleetConfig\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// Exactly what a command passes: the default, rebased onto a directory.
		if got := ResolveConfigPath(filepath.Join(dir, DefaultConfigPath)); got != legacy {
			t.Fatalf("a defaulted path should fall back to its legacy sibling; got %q want %q", got, legacy)
		}
	})

	t.Run("an unrelated explicit path is never rewritten", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, LegacyConfigPath), []byte("kind: FleetConfig\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// A caller who names a different file gets that file, present or not —
		// falling back here would silently read a config they did not ask for.
		custom := filepath.Join(dir, "somewhere-else.yaml")
		if got := ResolveConfigPath(custom); got != custom {
			t.Fatalf("an explicit non-default path must be returned unchanged, got %q", got)
		}
	})

	t.Run("new name wins when both exist", func(t *testing.T) {
		t.Chdir(t.TempDir())
		for _, name := range []string{DefaultConfigPath, LegacyConfigPath} {
			if err := os.WriteFile(name, []byte("kind: ClearCuttConfig\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		// A migration writes the new file and may leave the old one behind.
		// Preferring the new one means the migration takes effect; preferring
		// the old one would silently ignore it.
		if got := ResolveConfigPath(""); got != DefaultConfigPath {
			t.Fatalf("after a migration the new name must win, got %q", got)
		}
	})

	t.Run("neither present falls back to the new name", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if got := ResolveConfigPath(""); got != DefaultConfigPath {
			t.Fatalf("a fresh project should be told about %q, got %q", DefaultConfigPath, got)
		}
	})
}

// TestBothConfigKindsLoad: an existing file says kind: FleetConfig and must
// keep loading, while new files say ClearCuttConfig.
func TestBothConfigKindsLoad(t *testing.T) {
	for _, kind := range []string{ConfigKind, LegacyConfigKind} {
		cfg := DefaultConfig("acme", "platform")
		cfg.Kind = kind
		if err := cfg.Validate(); err != nil {
			t.Errorf("kind %q should be accepted: %v", kind, err)
		}
	}
	cfg := DefaultConfig("acme", "platform")
	cfg.Kind = "SomethingElse"
	if err := cfg.Validate(); err == nil {
		t.Error("an unknown kind should still be rejected")
	}
	if DefaultConfig("acme", "platform").Kind != ConfigKind {
		t.Errorf("new configs should be written as %s", ConfigKind)
	}
}
