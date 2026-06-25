package fleet

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

const DefaultConfigPath = "clearcutt.fleet.yaml"

// ReferenceOwner and ReferenceRepo identify the upstream ClearCutt project. They
// are the default fleet identity and the source identity that
// "clearcutt platform init" rewrites when localizing a fork's generated files
// and consumer example manifests.
const (
	ReferenceOwner = "northcutted"
	ReferenceRepo  = "clearcutt"
	// ReferenceProductName is the upstream product brand that platform init
	// rewrites to the fork's branding.productName in consumer example manifests.
	ReferenceProductName = "ClearCutt"
)

type Config struct {
	APIVersion   string            `json:"apiVersion"`
	Kind         string            `json:"kind"`
	Metadata     Metadata          `json:"metadata"`
	Registry     Registry          `json:"registry"`
	Branding     Branding          `json:"branding"`
	Site         Site              `json:"site"`
	Matrix       Matrix            `json:"matrix"`
	Release      Release           `json:"release"`
	Rebase       Rebase            `json:"rebase"`
	Catalog      Catalog           `json:"catalog"`
	Admission    Admission         `json:"admission"`
	Remediation  Remediation       `json:"remediation"`
	Templates    Templates         `json:"templates"`
	RuntimeLines []RuntimeLine     `json:"runtimeLines,omitempty"`
	Services     []ServiceImage    `json:"services,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
}

type Metadata struct {
	Name string `json:"name"`
}

type Registry struct {
	Host        string `json:"host"`
	Owner       string `json:"owner"`
	Repository  string `json:"repository"`
	ImagePrefix string `json:"imagePrefix"`
}

// Branding holds the human-facing product identity that the pipeline stamps
// onto its outputs: OCI image labels (vendor/authors/description), the in-image
// /etc/passwd account label, the catalog/site title, and generated docs. These
// are inputs — a fork sets them once and every produced artifact carries the
// fork's identity, never "ClearCutt". The CLI name and the clearcutt.dev schema
// dialect are deliberately NOT branding; they are the tool/format contract.
type Branding struct {
	ProductName string `json:"productName"`
	Vendor      string `json:"vendor"`
	Authors     string `json:"authors"`
}

type Site struct {
	Title       string `json:"title"`
	Pages       bool   `json:"pages"`
	BasePath    string `json:"basePath"`
	Description string `json:"description"`
}

type Matrix struct {
	Systems []string `json:"systems"`
	// Languages is the RESOLVED flat list of runtime line ids the matrix builds
	// ("coreLTS", "java21", ...). It is populated directly from the legacy flat
	// list, or resolved from LanguageSelectors via the version policy. Downstream
	// consumers always read this resolved list.
	Languages []string `json:"languages"`
	Tiers     []string `json:"tiers"`
	// Preview is the fleet's persistent opt-in to preview-channel runtimes; it
	// can be overridden per run by --allow-preview. Only affects the language-
	// level form (LanguageSelectors); the legacy flat list is explicit.
	Preview bool `json:"preview,omitempty"`
	// LanguageSelectors holds the language-level form of matrix.languages when in
	// use ([{language, channel}, ...]); empty for the legacy flat list. Retained
	// so --allow-preview can re-resolve and so marshalling preserves the form.
	LanguageSelectors []LanguageSelector `json:"-"`
}

type Release struct {
	SourceBranch     string   `json:"sourceBranch"`
	WorkflowIdentity string   `json:"workflowIdentity"`
	SLSABuilder      string   `json:"slsaBuilder"`
	NixCache         NixCache `json:"nixCache,omitempty"`
}

type NixCache struct {
	Bucket             string `json:"bucket,omitempty"`
	PublicBaseURL      string `json:"publicBaseUrl,omitempty"`
	SigningKeyName     string `json:"signingKeyName,omitempty"`
	PublicKey          string `json:"publicKey,omitempty"`
	CloudflareZoneName string `json:"cloudflareZoneName,omitempty"`
}

type Rebase struct {
	WorkflowIdentity string `json:"workflowIdentity"`
}

type Catalog struct {
	ReleaseLimit int    `json:"releaseLimit"`
	ScanDepth    string `json:"scanDepth"`
	ScanAll      bool   `json:"scanAll"`
}

type Admission struct {
	Engine        string `json:"engine"`
	Environment   string `json:"environment"`
	Namespace     string `json:"namespace"`
	DenyDevTier   bool   `json:"denyDevTier"`
	RequireSLSA   bool   `json:"requireSlsa"`
	RequireSBOM   bool   `json:"requireSbom"`
	RequireSig    bool   `json:"requireSignature"`
	RequireDigest bool   `json:"requireDigest"`
}

type Remediation struct {
	Mode                   string              `json:"mode"`
	ScanDepth              string              `json:"scanDepth"`
	MaxFindingsPerRun      int                 `json:"maxFindingsPerRun"`
	MaxPatchFailuresPerRun int                 `json:"maxPatchFailuresPerRun"`
	IncludeDevOnly         bool                `json:"includeDevOnly"`
	Policy                 RemediationPolicy   `json:"policy,omitempty"`
	Unstable               RemediationUnstable `json:"unstable,omitempty"`
}

// RemediationUnstable is the opt-in policy for sourcing a CVE fix from a newer
// (unstable) nixpkgs when the stable pin lacks it. Default-off: the scan only
// SUGGESTS an unstable fix unless an explicit soft opt-in scopes a single
// package to a pinned ref (the .NET/node22 dedicated-pin pattern), or `hard`
// moves the whole fleet. See docs/analysis/cli-pivot-plan.md.
type RemediationUnstable struct {
	// Mode: off | suggest | soft | hard. Default suggest.
	Mode string `json:"mode,omitempty"`
	// Ref is the default unstable nixpkgs flake ref the scan probes for fixes.
	Ref string `json:"ref,omitempty"`
	// SoftOptIns scope individual packages to a pinned unstable ref for a CVE.
	SoftOptIns []RemediationUnstableOptIn `json:"softOptIns,omitempty"`
}

// RemediationUnstableOptIn pins one package to a newer nixpkgs ref to clear
// specific CVEs, scoped so the rest of the fleet stays on the stable pin.
type RemediationUnstableOptIn struct {
	Package string                   `json:"package"`
	Ref     string                   `json:"ref,omitempty"`
	Reason  string                   `json:"reason,omitempty"`
	Owner   string                   `json:"owner,omitempty"`
	Fixes   []RemediationUnstableFix `json:"fixes,omitempty"`
}

// RemediationUnstableFix records a CVE cleared by the opt-in and the versions.
type RemediationUnstableFix struct {
	CVE              string `json:"cve"`
	InstalledVersion string `json:"installedVersion,omitempty"`
	FixedVersion     string `json:"fixedVersion,omitempty"`
}

// RemediationPolicy is the configurable, risk-based CVE policy. A finding is in
// scope to remediate/block when it is reachable (present in the production
// runtime closure) AND materially risky (KEV, OR EPSS percentile >=
// EPSSPercentile, OR severity >= MinimumSeverity) AND in a production tier;
// fixability then splits must-fix from must-acknowledge. Everything else is
// auto-accepted (recorded, expiring). See docs/analysis/cve-risk-policy-design.md.
type RemediationPolicy struct {
	ProductionTiers []string `json:"productionTiers,omitempty"`
	MinimumSeverity string   `json:"minimumSeverity,omitempty"`
	// Reachability gates on closure presence: "runtime" (only findings in the
	// shipped runtime closure are in scope) or "any". This is closure-presence
	// reachability, NOT exploitability/call-graph reachability.
	Reachability string `json:"reachability,omitempty"`
	// EPSSPercentile is the FIRST EPSS percentile (0..1) at/above which a finding
	// is materially risky. A missing EPSS score falls back to KEV/severity.
	EPSSPercentile float64 `json:"epssPercentile,omitempty"`
	// KEV controls CISA KEV handling: "always" (a KEV finding is always in scope,
	// non-loosenable for crypto) or "off".
	KEV string `json:"kev,omitempty"`
	// RequireFixedVersion governs in-scope but UNFIXABLE findings. true (default):
	// they block until explicitly acknowledged (must_acknowledge) — never a silent
	// pass. false: a non-KEV unfixable finding auto-accepts (recorded as an
	// expiring VEX record), the escape hatch for a line that must run with an
	// unbackported CVE. KEV is non-loosenable either way. A fix always being
	// present is what separates must_fix from must_acknowledge.
	RequireFixedVersion *bool `json:"requireFixedVersion,omitempty"`
	// AcceptedExpiryDays backstops auto-recorded acceptances (re-evaluated each scan).
	AcceptedExpiryDays int `json:"acceptedExpiryDays,omitempty"`
	// CryptoTrust selects how the known-good crypto build (openssl/sqlite) is
	// trusted by the runtime-patch completeness gate and the substitute-first
	// sourcing. "nixpkgs" (default): trust the pin's patched build, substitute it
	// from cache, and VEX the scanner version gap. "reproduce": everything nixpkgs
	// does, plus an independent rebuild of the crypto closure byte-compared against
	// the substituted build (trust AND verify); a divergence fails the release
	// evidence. Both ship only provenance-allowlisted crypto identities, so the
	// gate is identical — only whether a reproducibility compare is also required
	// differs.
	CryptoTrust string `json:"cryptoTrust,omitempty"`

	// Deprecated — retained for back-compat; normalized into the fields above by
	// EffectiveRemediationPolicy. RequireRuntimeLayer -> Reachability,
	// EPSSPercentileBoostAt -> EPSSPercentile, KEVBoost -> KEV.
	RequireRuntimeLayer   *bool   `json:"requireRuntimeLayer,omitempty"`
	EPSSPercentileBoostAt float64 `json:"epssPercentileBoostAt,omitempty"`
	KEVBoost              *bool   `json:"kevBoost,omitempty"`
}

type Templates struct {
	Runtimes []string `json:"runtimes"`
}

type GitHubReleaseCell struct {
	System   string `json:"system"`
	Language string `json:"language"`
	Tier     string `json:"tier"`
}

type GitHubImageCell struct {
	Language string `json:"language"`
	Tier     string `json:"tier"`
}

type GitHubReleaseMatrix struct {
	Include []GitHubReleaseCell `json:"include"`
}

type GitHubImageMatrix struct {
	Include []GitHubImageCell `json:"include"`
}

type GitHubServiceReleaseCell struct {
	System  string `json:"system"`
	Service string `json:"service"`
}

type GitHubServiceImageCell struct {
	Service string `json:"service"`
}

type GitHubServiceReleaseMatrix struct {
	Include []GitHubServiceReleaseCell `json:"include"`
}

type GitHubServiceImageMatrix struct {
	Include []GitHubServiceImageCell `json:"include"`
}

// RuntimeLine is the public runtime identifier accepted in clearcutt.fleet.yaml.
// Nix attributes remain an implementation detail behind these stable IDs.
type RuntimeLine struct {
	ID                 string   `json:"id"`
	Language           string   `json:"language"`
	Version            string   `json:"version"`
	AppTemplateRuntime string   `json:"appTemplateRuntime,omitempty"`
	Description        string   `json:"description"`
	PackageCandidates  []string `json:"packageCandidates,omitempty"`
	DevPackages        []string `json:"devPackages,omitempty"`
	OmitInProduction   bool     `json:"omitInProduction,omitempty"`
	Smoke              []string `json:"smoke,omitempty"`
}

// ServiceImage is the public service-image identifier accepted in
// clearcutt.fleet.yaml. The template/package mapping is expanded by the CLI and
// Nix remains an implementation detail of the build.
type ServiceImage struct {
	ID                string           `json:"id"`
	Template          string           `json:"template"`
	Version           string           `json:"version"`
	Description       string           `json:"description,omitempty"`
	PackageCandidates []string         `json:"packageCandidates,omitempty"`
	Ports             []ServicePort    `json:"ports,omitempty"`
	Stateful          bool             `json:"stateful,omitempty"`
	DataDirs          []string         `json:"dataDirs,omitempty"`
	Env               []string         `json:"env,omitempty"`
	Entrypoint        []string         `json:"entrypoint,omitempty"`
	Cmd               []string         `json:"cmd,omitempty"`
	Smoke             []string         `json:"smoke,omitempty"`
	Lifecycle         ServiceLifecycle `json:"lifecycle,omitempty"`
	ProductionAllowed bool             `json:"productionAllowed,omitempty"`
}

type ServicePort struct {
	Name     string `json:"name,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
}

type ServiceLifecycle struct {
	Status  string `json:"status,omitempty"`
	Support string `json:"support,omitempty"`
	Notes   string `json:"notes,omitempty"`
}

var supportedRuntimeLines = []RuntimeLine{
	{ID: "coreLTS", Language: "core", Version: "LTS", Description: "Core CA certificates, shell, and baseline utilities"},
	{ID: "java21", Language: "java", Version: "21", AppTemplateRuntime: "java", Description: "Java 21 LTS runtime line"},
	{ID: "java25", Language: "java", Version: "25", AppTemplateRuntime: "java", Description: "Java 25 runtime line"},
	{ID: "node22", Language: "node", Version: "22", AppTemplateRuntime: "node", Description: "Node.js 22 runtime line"},
	{ID: "node24", Language: "node", Version: "24", AppTemplateRuntime: "node", Description: "Node.js 24 runtime line"},
	{ID: "python3.13", Language: "python", Version: "3.13", AppTemplateRuntime: "python", Description: "Python 3.13 runtime line"},
	{ID: "python3.14", Language: "python", Version: "3.14", AppTemplateRuntime: "python", Description: "Python 3.14 LTS runtime line"},
	{ID: "go1.25", Language: "go", Version: "1.25", AppTemplateRuntime: "go", Description: "Go 1.25 toolchain line"},
	{ID: "go1.26", Language: "go", Version: "1.26", AppTemplateRuntime: "go", Description: "Go 1.26 LTS toolchain line"},
	{ID: "dotnet8", Language: "dotnet", Version: "8", Description: ".NET 8 runtime line"},
	{ID: "dotnet10", Language: "dotnet", Version: "10", Description: ".NET 10 runtime line"},
	{ID: "rust1.95", Language: "rust", Version: "1.95", Description: "Rust 1.95 toolchain line"},
	{ID: "cc15", Language: "cc", Version: "15", Description: "C/C++ GCC 15 toolchain line"},
}

var supportedServiceTemplates = map[string]ServiceImage{
	"postgres": {
		Template:          "postgres",
		Description:       "Postgres database service image",
		PackageCandidates: []string{"postgresql_16"},
		Ports:             []ServicePort{{Name: "postgres", Port: 5432, Protocol: "tcp"}},
		Stateful:          true,
		DataDirs:          []string{"/var/lib/postgresql/data"},
		Env:               []string{"PGDATA=/var/lib/postgresql/data"},
		Entrypoint:        []string{"clearcutt-postgres-entrypoint"},
		Smoke:             []string{"postgres --version", "initdb --version", "pg_isready --version"},
		Lifecycle:         ServiceLifecycle{Status: "preview", Support: "current"},
	},
	"valkey": {
		Template:          "valkey",
		Description:       "Valkey in-memory data store service image",
		PackageCandidates: []string{"valkey"},
		Ports:             []ServicePort{{Name: "redis", Port: 6379, Protocol: "tcp"}},
		Stateful:          true,
		DataDirs:          []string{"/data"},
		Entrypoint:        []string{"valkey-server"},
		Smoke:             []string{"valkey-server --version", "valkey-cli --version"},
		Lifecycle:         ServiceLifecycle{Status: "preview", Support: "current"},
	},
	"oauth2-proxy": {
		Template:          "oauth2-proxy",
		Description:       "oauth2-proxy authentication gateway service image",
		PackageCandidates: []string{"oauth2-proxy"},
		Ports:             []ServicePort{{Name: "http", Port: 4180, Protocol: "tcp"}},
		Stateful:          false,
		Entrypoint:        []string{"oauth2-proxy"},
		Smoke:             []string{"oauth2-proxy --version"},
		Lifecycle:         ServiceLifecycle{Status: "preview", Support: "current"},
	},
}

var supportedLinuxSystems = map[string]struct{}{
	"x86_64-linux":  {},
	"aarch64-linux": {},
}

// DeriveProductName turns a repository slug into a human product name, e.g.
// "base-images" -> "Base Images". It is the default product identity for a fork
// that does not set branding.productName explicitly.
func DeriveProductName(repo string) string {
	words := strings.FieldsFunc(repo, func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == '/' || r == ' '
	})
	for i, w := range words {
		if w == "" {
			continue
		}
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	name := strings.Join(words, " ")
	if name == "" {
		return repo
	}
	return name
}

func DefaultConfig(owner, repo string) Config {
	owner = firstNonEmpty(owner, ReferenceOwner)
	repo = firstNonEmpty(repo, ReferenceRepo)
	repoPath := owner + "/" + repo
	productName := DeriveProductName(repo)
	return Config{
		APIVersion: "clearcutt.dev/v1",
		Kind:       "FleetConfig",
		Metadata: Metadata{
			Name: "clearcutt-reference-fleet",
		},
		Registry: Registry{
			Host:        "ghcr.io",
			Owner:       owner,
			Repository:  repo,
			ImagePrefix: strings.ToLower(repo),
		},
		Branding: Branding{
			ProductName: productName,
			Vendor:      owner,
			Authors:     productName + " maintainers",
		},
		Site: Site{
			Title:       "ClearCutt Hardened Image Fleet",
			Pages:       true,
			BasePath:    "/" + repo,
			Description: "Forkable hardened base-image catalog with signatures, SBOMs, SLSA Build L3 provenance, vulnerability evidence, and app-team onboarding templates.",
		},
		Matrix: Matrix{
			Systems: []string{
				"x86_64-linux",
				"aarch64-linux",
			},
			Languages: []string{
				"coreLTS",
				"java21",
				"java25",
				"node22",
				"node24",
				"python3.13",
				"python3.14",
				"go1.25",
				"go1.26",
				"dotnet8",
				"dotnet10",
				"rust1.95",
				"cc15",
			},
			Tiers: []string{
				"dev",
				"slim",
				"distroless",
			},
		},
		Release: Release{
			SourceBranch:     "main",
			WorkflowIdentity: fmt.Sprintf("https://github.com/%s/.github/workflows/release.yml@refs/heads/main", repoPath),
			SLSABuilder:      "slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.1.0",
		},
		Rebase: Rebase{
			WorkflowIdentity: fmt.Sprintf("https://github.com/%s/.github/workflows/rebase.yml@refs/heads/main", repoPath),
		},
		Catalog: Catalog{
			ReleaseLimit: 10,
			ScanDepth:    "4",
			ScanAll:      false,
		},
		Admission: Admission{
			Engine:        "kyverno",
			Environment:   "production",
			Namespace:     "apps",
			DenyDevTier:   true,
			RequireSLSA:   true,
			RequireSBOM:   true,
			RequireSig:    true,
			RequireDigest: true,
		},
		Remediation: Remediation{
			Mode:                   "approved-pr",
			ScanDepth:              "1",
			MaxFindingsPerRun:      1,
			MaxPatchFailuresPerRun: 1,
			IncludeDevOnly:         false,
			Policy:                 DefaultRemediationPolicy(),
		},
		Templates: Templates{
			Runtimes: []string{"java", "node", "python", "go"},
		},
	}
}

func Load(path string) (Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg := DefaultConfig("", "")
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid %s: %w", path, err)
	}
	return cfg, nil
}

func Marshal(cfg Config) ([]byte, error) {
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return yaml.Marshal(cfg)
}

func (c *Config) applyDefaults() {
	def := DefaultConfig(c.Registry.Owner, c.Registry.Repository)
	c.APIVersion = firstNonEmpty(c.APIVersion, def.APIVersion)
	c.Kind = firstNonEmpty(c.Kind, def.Kind)
	c.Metadata.Name = firstNonEmpty(c.Metadata.Name, def.Metadata.Name)
	c.Registry.Host = firstNonEmpty(c.Registry.Host, def.Registry.Host)
	c.Registry.Owner = firstNonEmpty(c.Registry.Owner, def.Registry.Owner)
	c.Registry.Repository = firstNonEmpty(c.Registry.Repository, def.Registry.Repository)
	c.Registry.ImagePrefix = firstNonEmpty(c.Registry.ImagePrefix, def.Registry.ImagePrefix)
	c.Branding.ProductName = firstNonEmpty(c.Branding.ProductName, def.Branding.ProductName)
	c.Branding.Vendor = firstNonEmpty(c.Branding.Vendor, def.Branding.Vendor)
	c.Branding.Authors = firstNonEmpty(c.Branding.Authors, c.Branding.ProductName+" maintainers")
	c.Site.Title = firstNonEmpty(c.Site.Title, def.Site.Title)
	c.Site.BasePath = firstNonEmpty(c.Site.BasePath, def.Site.BasePath)
	c.Site.Description = firstNonEmpty(c.Site.Description, def.Site.Description)
	if len(c.Matrix.Systems) == 0 {
		c.Matrix.Systems = def.Matrix.Systems
	}
	if len(c.Matrix.Languages) == 0 {
		c.Matrix.Languages = def.Matrix.Languages
	}
	if len(c.Matrix.Tiers) == 0 {
		c.Matrix.Tiers = def.Matrix.Tiers
	}
	c.Release.SourceBranch = firstNonEmpty(c.Release.SourceBranch, def.Release.SourceBranch)
	c.Release.WorkflowIdentity = firstNonEmpty(c.Release.WorkflowIdentity, def.Release.WorkflowIdentity)
	c.Release.SLSABuilder = firstNonEmpty(c.Release.SLSABuilder, def.Release.SLSABuilder)
	c.Rebase.WorkflowIdentity = firstNonEmpty(c.Rebase.WorkflowIdentity, def.Rebase.WorkflowIdentity)
	if c.Catalog.ReleaseLimit == 0 {
		c.Catalog.ReleaseLimit = def.Catalog.ReleaseLimit
	}
	c.Catalog.ScanDepth = firstNonEmpty(c.Catalog.ScanDepth, def.Catalog.ScanDepth)
	c.Admission.Engine = firstNonEmpty(c.Admission.Engine, def.Admission.Engine)
	c.Admission.Environment = firstNonEmpty(c.Admission.Environment, def.Admission.Environment)
	c.Admission.Namespace = firstNonEmpty(c.Admission.Namespace, def.Admission.Namespace)
	c.Remediation.Mode = firstNonEmpty(c.Remediation.Mode, def.Remediation.Mode)
	c.Remediation.ScanDepth = firstNonEmpty(c.Remediation.ScanDepth, def.Remediation.ScanDepth)
	if c.Remediation.MaxFindingsPerRun == 0 {
		c.Remediation.MaxFindingsPerRun = def.Remediation.MaxFindingsPerRun
	}
	if c.Remediation.MaxPatchFailuresPerRun == 0 {
		c.Remediation.MaxPatchFailuresPerRun = def.Remediation.MaxPatchFailuresPerRun
	}
	c.Remediation.Policy = EffectiveRemediationPolicy(c.Remediation.Policy)
	if len(c.Templates.Runtimes) == 0 {
		c.Templates.Runtimes = def.Templates.Runtimes
	}
	for i := range c.Services {
		c.Services[i].applyDefaults()
	}
}

func (s *ServiceImage) applyDefaults() {
	template, ok := ServiceTemplateDefaults(s.Template, s.Version)
	if !ok {
		return
	}
	s.Template = firstNonEmpty(s.Template, template.Template)
	s.Version = firstNonEmpty(s.Version, template.Version)
	s.Description = firstNonEmpty(s.Description, template.Description)
	if len(s.PackageCandidates) == 0 {
		s.PackageCandidates = append([]string(nil), template.PackageCandidates...)
	}
	if len(s.Ports) == 0 {
		s.Ports = cloneServicePorts(template.Ports)
	}
	if !s.Stateful {
		s.Stateful = template.Stateful
	}
	if len(s.DataDirs) == 0 {
		s.DataDirs = append([]string(nil), template.DataDirs...)
	}
	if len(s.Env) == 0 {
		s.Env = append([]string(nil), template.Env...)
	}
	if len(s.Entrypoint) == 0 {
		s.Entrypoint = append([]string(nil), template.Entrypoint...)
	}
	if len(s.Cmd) == 0 {
		s.Cmd = append([]string(nil), template.Cmd...)
	}
	if len(s.Smoke) == 0 {
		s.Smoke = append([]string(nil), template.Smoke...)
	}
	s.Lifecycle.Status = firstNonEmpty(s.Lifecycle.Status, template.Lifecycle.Status)
	s.Lifecycle.Support = firstNonEmpty(s.Lifecycle.Support, template.Lifecycle.Support)
	s.Lifecycle.Notes = firstNonEmpty(s.Lifecycle.Notes, template.Lifecycle.Notes)
	for i := range s.Ports {
		s.Ports[i].Protocol = strings.ToLower(firstNonEmpty(s.Ports[i].Protocol, "tcp"))
	}
}

func (c Config) Validate() error {
	if c.APIVersion != "clearcutt.dev/v1" {
		return fmt.Errorf("apiVersion must be clearcutt.dev/v1")
	}
	if c.Kind != "FleetConfig" {
		return fmt.Errorf("kind must be FleetConfig")
	}
	if c.Registry.Host == "" || c.Registry.Owner == "" || c.Registry.Repository == "" {
		return fmt.Errorf("registry.host, registry.owner, and registry.repository are required")
	}
	if len(c.Matrix.Systems) == 0 || len(c.Matrix.Languages) == 0 || len(c.Matrix.Tiers) == 0 {
		return fmt.Errorf("matrix.systems, matrix.languages, and matrix.tiers must not be empty")
	}
	seenSystems := map[string]struct{}{}
	for _, system := range c.Matrix.Systems {
		system = strings.TrimSpace(system)
		if system == "" {
			return fmt.Errorf("matrix.systems must not contain empty values")
		}
		if _, ok := supportedLinuxSystems[system]; !ok {
			return fmt.Errorf("unsupported matrix system %q (supported: %s)", system, strings.Join(SupportedSystems(), ", "))
		}
		if _, exists := seenSystems[system]; exists {
			return fmt.Errorf("duplicate matrix system %q", system)
		}
		seenSystems[system] = struct{}{}
	}
	runtimeLines, err := c.runtimeLineMap()
	if err != nil {
		return err
	}
	seenLanguages := map[string]struct{}{}
	for _, language := range c.Matrix.Languages {
		language = strings.TrimSpace(language)
		if language == "" {
			return fmt.Errorf("matrix.languages must not contain empty values")
		}
		if _, ok := runtimeLines[language]; !ok {
			return fmt.Errorf("unsupported matrix language %q (supported: %s)", language, strings.Join(c.SupportedRuntimeLineIDs(), ", "))
		}
		if _, exists := seenLanguages[language]; exists {
			return fmt.Errorf("duplicate matrix language %q", language)
		}
		seenLanguages[language] = struct{}{}
	}
	seenTiers := map[string]struct{}{}
	for _, tier := range c.Matrix.Tiers {
		tier = strings.TrimSpace(tier)
		switch tier {
		case "dev", "slim", "distroless":
		default:
			return fmt.Errorf("unsupported matrix tier %q", tier)
		}
		if _, exists := seenTiers[tier]; exists {
			return fmt.Errorf("duplicate matrix tier %q", tier)
		}
		seenTiers[tier] = struct{}{}
	}
	if c.Catalog.ReleaseLimit < 1 {
		return fmt.Errorf("catalog.releaseLimit must be greater than 0")
	}
	if c.Remediation.Mode != "approved-pr" {
		return fmt.Errorf("remediation.mode currently supports only approved-pr")
	}
	if err := validateRemediationPolicy(c.Remediation.Policy); err != nil {
		return err
	}
	if _, err := c.serviceMap(); err != nil {
		return err
	}
	return nil
}

func boolPtr(value bool) *bool {
	return &value
}

func DefaultRemediationPolicy() RemediationPolicy {
	return RemediationPolicy{
		ProductionTiers:       []string{"slim", "distroless"},
		MinimumSeverity:       "high",
		Reachability:          "runtime",
		EPSSPercentile:        0.90,
		KEV:                   "always",
		RequireFixedVersion:   boolPtr(true),
		AcceptedExpiryDays:    90,
		RequireRuntimeLayer:   boolPtr(true),
		EPSSPercentileBoostAt: 0.90,
		KEVBoost:              boolPtr(true),
		CryptoTrust:           "nixpkgs",
	}
}

// CryptoTrust modes for RemediationPolicy.CryptoTrust.
const (
	CryptoTrustNixpkgs   = "nixpkgs"
	CryptoTrustReproduce = "reproduce"
)

func EffectiveRemediationPolicy(policy RemediationPolicy) RemediationPolicy {
	def := DefaultRemediationPolicy()
	if len(policy.ProductionTiers) == 0 {
		policy.ProductionTiers = append([]string(nil), def.ProductionTiers...)
	}
	if policy.MinimumSeverity == "" {
		policy.MinimumSeverity = def.MinimumSeverity
	}
	if policy.RequireFixedVersion == nil {
		policy.RequireFixedVersion = def.RequireFixedVersion
	}

	// Normalize the gating fields: the new field wins when set, else the
	// deprecated equivalent, else the default. Then mirror the resolved value
	// back onto the deprecated field so existing consumers stay consistent.
	if policy.Reachability == "" {
		if policy.RequireRuntimeLayer != nil {
			policy.Reachability = map[bool]string{true: "runtime", false: "any"}[*policy.RequireRuntimeLayer]
		} else {
			policy.Reachability = def.Reachability
		}
	}
	policy.RequireRuntimeLayer = boolPtr(policy.Reachability == "runtime")

	if policy.EPSSPercentile == 0 {
		if policy.EPSSPercentileBoostAt > 0 {
			policy.EPSSPercentile = policy.EPSSPercentileBoostAt
		} else {
			policy.EPSSPercentile = def.EPSSPercentile
		}
	}
	policy.EPSSPercentileBoostAt = policy.EPSSPercentile

	if policy.KEV == "" {
		if policy.KEVBoost != nil {
			policy.KEV = map[bool]string{true: "always", false: "off"}[*policy.KEVBoost]
		} else {
			policy.KEV = def.KEV
		}
	}
	policy.KEVBoost = boolPtr(policy.KEV == "always")

	if policy.AcceptedExpiryDays == 0 {
		policy.AcceptedExpiryDays = def.AcceptedExpiryDays
	}
	if policy.CryptoTrust == "" {
		policy.CryptoTrust = def.CryptoTrust
	}
	return policy
}

func validateRemediationPolicy(policy RemediationPolicy) error {
	// Validate the raw deprecated bound before normalization so an out-of-range
	// deprecated value is caught even when a new field also takes precedence.
	if policy.EPSSPercentileBoostAt < 0 || policy.EPSSPercentileBoostAt > 1 {
		return fmt.Errorf("remediation.policy.epssPercentileBoostAt must be between 0 and 1")
	}
	policy = EffectiveRemediationPolicy(policy)
	if len(policy.ProductionTiers) == 0 {
		return fmt.Errorf("remediation.policy.productionTiers must not be empty")
	}
	for _, tier := range policy.ProductionTiers {
		switch strings.TrimSpace(tier) {
		case "slim", "distroless":
		default:
			return fmt.Errorf("unsupported remediation.policy.productionTiers value %q", tier)
		}
	}
	switch strings.ToLower(policy.MinimumSeverity) {
	case "critical", "high", "medium", "low", "negligible", "unknown":
	default:
		return fmt.Errorf("unsupported remediation.policy.minimumSeverity %q", policy.MinimumSeverity)
	}
	switch strings.ToLower(policy.Reachability) {
	case "runtime", "any":
	default:
		return fmt.Errorf("unsupported remediation.policy.reachability %q (use runtime or any)", policy.Reachability)
	}
	switch strings.ToLower(policy.KEV) {
	case "always", "off":
	default:
		return fmt.Errorf("unsupported remediation.policy.kev %q (use always or off)", policy.KEV)
	}
	if policy.EPSSPercentile < 0 || policy.EPSSPercentile > 1 {
		return fmt.Errorf("remediation.policy.epssPercentile must be between 0 and 1")
	}
	if policy.AcceptedExpiryDays < 0 {
		return fmt.Errorf("remediation.policy.acceptedExpiryDays must not be negative")
	}
	switch strings.ToLower(policy.CryptoTrust) {
	case CryptoTrustNixpkgs, CryptoTrustReproduce:
	default:
		return fmt.Errorf("unsupported remediation.policy.cryptoTrust %q (use nixpkgs or reproduce)", policy.CryptoTrust)
	}
	return nil
}

func (c Config) RepoPath() string {
	return c.Registry.Owner + "/" + c.Registry.Repository
}

func (c Config) RepoURL() string {
	return "https://github.com/" + c.RepoPath()
}

func (c Config) RegistryBase() string {
	return strings.TrimSuffix(c.Registry.Host, "/") + "/" + c.RepoPath()
}

func (c Config) ImageName(language string) string {
	return c.RegistryBase() + "/" + c.Registry.ImagePrefix + "-" + strings.ToLower(language)
}

func (c Config) ServiceImageName(id string) string {
	return c.RegistryBase() + "/" + c.Registry.ImagePrefix + "-" + strings.ToLower(strings.TrimSpace(id))
}

func SupportedSystems() []string {
	systems := make([]string, 0, len(supportedLinuxSystems))
	for system := range supportedLinuxSystems {
		systems = append(systems, system)
	}
	sort.Strings(systems)
	return systems
}

func SupportedRuntimeLines() []RuntimeLine {
	return sortedRuntimeLines(supportedRuntimeLines)
}

func BuiltInRuntimeLines() []RuntimeLine {
	return SupportedRuntimeLines()
}

func SupportedServiceTemplates() []ServiceImage {
	templates := make([]ServiceImage, 0, len(supportedServiceTemplates))
	for _, template := range supportedServiceTemplates {
		templates = append(templates, cloneServiceImage(template))
	}
	return sortedServiceTemplates(templates)
}

func BuiltInServiceTemplates() []ServiceImage {
	return SupportedServiceTemplates()
}

func (c Config) SupportedRuntimeLines() []RuntimeLine {
	lines := append([]RuntimeLine{}, supportedRuntimeLines...)
	lines = append(lines, c.RuntimeLines...)
	return sortedRuntimeLines(lines)
}

func sortedRuntimeLines(lines []RuntimeLine) []RuntimeLine {
	lines = append([]RuntimeLine(nil), lines...)
	sort.Slice(lines, func(i, j int) bool {
		return lines[i].ID < lines[j].ID
	})
	return lines
}

func sortedServiceTemplates(templates []ServiceImage) []ServiceImage {
	templates = append([]ServiceImage(nil), templates...)
	sort.Slice(templates, func(i, j int) bool {
		return templates[i].Template < templates[j].Template
	})
	return templates
}

func SupportedRuntimeLineIDs() []string {
	lines := SupportedRuntimeLines()
	ids := make([]string, 0, len(lines))
	for _, line := range lines {
		ids = append(ids, line.ID)
	}
	return ids
}

func (c Config) SupportedRuntimeLineIDs() []string {
	lines := c.SupportedRuntimeLines()
	ids := make([]string, 0, len(lines))
	for _, line := range lines {
		ids = append(ids, line.ID)
	}
	return ids
}

func RuntimeLineInfo(id string) (RuntimeLine, bool) {
	id = strings.TrimSpace(id)
	for _, line := range supportedRuntimeLines {
		if line.ID == id {
			return line, true
		}
	}
	return RuntimeLine{}, false
}

func ServiceTemplateInfo(template string) (ServiceImage, bool) {
	template = strings.TrimSpace(template)
	line, ok := supportedServiceTemplates[template]
	if !ok {
		return ServiceImage{}, false
	}
	return cloneServiceImage(line), true
}

func ServiceTemplateDefaults(template, version string) (ServiceImage, bool) {
	defaults, ok := ServiceTemplateInfo(template)
	if !ok {
		return ServiceImage{}, false
	}
	defaults.Version = strings.TrimSpace(version)
	if defaults.Template == "postgres" && defaults.Version != "" {
		defaults.PackageCandidates = []string{"postgresql_" + serviceMajorVersion(defaults.Version)}
	}
	return defaults, true
}

func (c Config) RuntimeLineInfo(id string) (RuntimeLine, bool) {
	id = strings.TrimSpace(id)
	if line, ok := RuntimeLineInfo(id); ok {
		return line, true
	}
	for _, line := range c.RuntimeLines {
		if line.ID == id {
			return line, true
		}
	}
	return RuntimeLine{}, false
}

func (c Config) IsCustomRuntimeLine(id string) bool {
	id = strings.TrimSpace(id)
	for _, line := range c.RuntimeLines {
		if line.ID == id {
			return true
		}
	}
	return false
}

func (c Config) ServiceInfo(id string) (ServiceImage, bool) {
	id = strings.TrimSpace(id)
	for _, service := range c.Services {
		service.applyDefaults()
		if service.ID == id {
			return cloneServiceImage(service), true
		}
	}
	return ServiceImage{}, false
}

func (c Config) ServiceIDs() []string {
	ids := make([]string, 0, len(c.Services))
	for _, service := range c.Services {
		if strings.TrimSpace(service.ID) != "" {
			ids = append(ids, service.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

func (c Config) runtimeLineMap() (map[string]RuntimeLine, error) {
	lines := map[string]RuntimeLine{}
	for _, line := range supportedRuntimeLines {
		lines[line.ID] = line
	}
	seenCustom := map[string]struct{}{}
	for _, line := range c.RuntimeLines {
		line.ID = strings.TrimSpace(line.ID)
		line.Language = strings.TrimSpace(line.Language)
		line.Version = strings.TrimSpace(line.Version)
		if line.ID == "" || line.Language == "" || line.Version == "" {
			return nil, fmt.Errorf("runtimeLines entries require id, language, and version")
		}
		if _, builtin := RuntimeLineInfo(line.ID); builtin {
			return nil, fmt.Errorf("runtimeLines entry %q conflicts with a built-in runtime line", line.ID)
		}
		if _, exists := seenCustom[line.ID]; exists {
			return nil, fmt.Errorf("duplicate runtimeLines entry %q", line.ID)
		}
		if len(line.PackageCandidates) == 0 {
			return nil, fmt.Errorf("runtimeLines entry %q requires at least one packageCandidates value", line.ID)
		}
		lines[line.ID] = line
		seenCustom[line.ID] = struct{}{}
	}
	return lines, nil
}

func (c Config) serviceMap() (map[string]ServiceImage, error) {
	services := map[string]ServiceImage{}
	for _, service := range c.Services {
		service.applyDefaults()
		service.ID = strings.TrimSpace(service.ID)
		service.Template = strings.TrimSpace(service.Template)
		service.Version = strings.TrimSpace(service.Version)
		if service.ID == "" || service.Template == "" || service.Version == "" {
			return nil, fmt.Errorf("services entries require id, template, and version")
		}
		if _, ok := ServiceTemplateInfo(service.Template); !ok {
			return nil, fmt.Errorf("unsupported service template %q (supported: %s)", service.Template, strings.Join(SupportedServiceTemplateNames(), ", "))
		}
		if _, exists := services[service.ID]; exists {
			return nil, fmt.Errorf("duplicate services entry %q", service.ID)
		}
		if len(service.PackageCandidates) == 0 {
			return nil, fmt.Errorf("services entry %q requires at least one packageCandidates value", service.ID)
		}
		if service.Stateful && len(service.DataDirs) == 0 {
			return nil, fmt.Errorf("services entry %q is stateful and requires at least one dataDirs value", service.ID)
		}
		for _, dir := range service.DataDirs {
			if !strings.HasPrefix(strings.TrimSpace(dir), "/") {
				return nil, fmt.Errorf("services entry %q dataDir %q must be absolute", service.ID, dir)
			}
		}
		for _, port := range service.Ports {
			if port.Port < 1 || port.Port > 65535 {
				return nil, fmt.Errorf("services entry %q has invalid port %d", service.ID, port.Port)
			}
			switch strings.ToLower(firstNonEmpty(port.Protocol, "tcp")) {
			case "tcp", "udp":
			default:
				return nil, fmt.Errorf("services entry %q port %d has unsupported protocol %q", service.ID, port.Port, port.Protocol)
			}
		}
		switch service.Lifecycle.Status {
		case "", "preview", "active", "deprecated", "experimental":
		default:
			return nil, fmt.Errorf("services entry %q has unsupported lifecycle.status %q", service.ID, service.Lifecycle.Status)
		}
		services[service.ID] = service
	}
	return services, nil
}

func (c Config) GitHubReleaseMatrix() GitHubReleaseMatrix {
	matrix := GitHubReleaseMatrix{}
	for _, system := range c.Matrix.Systems {
		for _, language := range c.Matrix.Languages {
			for _, tier := range c.Matrix.Tiers {
				matrix.Include = append(matrix.Include, GitHubReleaseCell{
					System:   system,
					Language: language,
					Tier:     tier,
				})
			}
		}
	}
	return matrix
}

func (c Config) GitHubImageMatrix() GitHubImageMatrix {
	matrix := GitHubImageMatrix{}
	for _, language := range c.Matrix.Languages {
		for _, tier := range c.Matrix.Tiers {
			matrix.Include = append(matrix.Include, GitHubImageCell{
				Language: language,
				Tier:     tier,
			})
		}
	}
	return matrix
}

func (c Config) GitHubServiceReleaseMatrix() GitHubServiceReleaseMatrix {
	matrix := GitHubServiceReleaseMatrix{}
	for _, system := range c.Matrix.Systems {
		for _, service := range c.Services {
			if strings.TrimSpace(service.ID) == "" {
				continue
			}
			matrix.Include = append(matrix.Include, GitHubServiceReleaseCell{
				System:  system,
				Service: service.ID,
			})
		}
	}
	return matrix
}

func (c Config) GitHubServiceImageMatrix() GitHubServiceImageMatrix {
	matrix := GitHubServiceImageMatrix{}
	for _, service := range c.Services {
		if strings.TrimSpace(service.ID) == "" {
			continue
		}
		matrix.Include = append(matrix.Include, GitHubServiceImageCell{
			Service: service.ID,
		})
	}
	return matrix
}

func SupportedServiceTemplateNames() []string {
	names := make([]string, 0, len(supportedServiceTemplates))
	for name := range supportedServiceTemplates {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func serviceMajorVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return version
	}
	if idx := strings.IndexAny(version, ".-+"); idx >= 0 {
		return version[:idx]
	}
	return version
}

func cloneServiceImage(service ServiceImage) ServiceImage {
	service.PackageCandidates = append([]string(nil), service.PackageCandidates...)
	service.Ports = cloneServicePorts(service.Ports)
	service.DataDirs = append([]string(nil), service.DataDirs...)
	service.Env = append([]string(nil), service.Env...)
	service.Entrypoint = append([]string(nil), service.Entrypoint...)
	service.Cmd = append([]string(nil), service.Cmd...)
	service.Smoke = append([]string(nil), service.Smoke...)
	return service
}

func cloneServicePorts(ports []ServicePort) []ServicePort {
	if len(ports) == 0 {
		return nil
	}
	out := make([]ServicePort, len(ports))
	copy(out, ports)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
