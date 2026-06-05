package fleet

import (
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/yaml"
)

const DefaultConfigPath = "clearcutt.fleet.yaml"

type Config struct {
	APIVersion  string            `json:"apiVersion"`
	Kind        string            `json:"kind"`
	Metadata    Metadata          `json:"metadata"`
	Registry    Registry          `json:"registry"`
	Site        Site              `json:"site"`
	Matrix      Matrix            `json:"matrix"`
	Release     Release           `json:"release"`
	Rebase      Rebase            `json:"rebase"`
	Catalog     Catalog           `json:"catalog"`
	Admission   Admission         `json:"admission"`
	Remediation Remediation       `json:"remediation"`
	Templates   Templates         `json:"templates"`
	Labels      map[string]string `json:"labels,omitempty"`
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

type Site struct {
	Title       string `json:"title"`
	Pages       bool   `json:"pages"`
	BasePath    string `json:"basePath"`
	Description string `json:"description"`
}

type Matrix struct {
	Systems   []string `json:"systems"`
	Languages []string `json:"languages"`
	Tiers     []string `json:"tiers"`
}

type Release struct {
	SourceBranch     string `json:"sourceBranch"`
	WorkflowIdentity string `json:"workflowIdentity"`
	SLSABuilder      string `json:"slsaBuilder"`
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
	Mode                   string `json:"mode"`
	ScanDepth              string `json:"scanDepth"`
	MaxFindingsPerRun      int    `json:"maxFindingsPerRun"`
	MaxPatchFailuresPerRun int    `json:"maxPatchFailuresPerRun"`
	IncludeDevOnly         bool   `json:"includeDevOnly"`
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

func DefaultConfig(owner, repo string) Config {
	owner = firstNonEmpty(owner, "northcutted")
	repo = firstNonEmpty(repo, "clearcutt")
	repoPath := owner + "/" + repo
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
			ImagePrefix: "clearcutt",
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
	if len(c.Templates.Runtimes) == 0 {
		c.Templates.Runtimes = def.Templates.Runtimes
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
	for _, tier := range c.Matrix.Tiers {
		switch tier {
		case "dev", "slim", "distroless":
		default:
			return fmt.Errorf("unsupported matrix tier %q", tier)
		}
	}
	if c.Catalog.ReleaseLimit < 1 {
		return fmt.Errorf("catalog.releaseLimit must be greater than 0")
	}
	if c.Remediation.Mode != "approved-pr" {
		return fmt.Errorf("remediation.mode currently supports only approved-pr")
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
