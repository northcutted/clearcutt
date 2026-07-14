package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/platformsource"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

const (
	platformProfileCatalogOnly = "catalog-only"
	platformProfileFleet       = "fleet"
	controlPlaneAPIVersion     = "clearcutt.dev/v1"
	catalogSourceInventory     = "inventory"
	catalogSourceGitHubRelease = "github-release"
)

var catalogTargetPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type platformRenderFlags struct {
	dir                 string
	profile             string
	owner               string
	repo                string
	registryBase        string
	registryHost        string
	imagePrefix         string
	visibility          string
	pages               bool
	environment         string
	force               bool
	generatedAt         string
	source              string
	catalogSource       string
	catalogSourceRepo   string
	catalogTargets      string
	catalogReleaseLimit int
}

type PlatformRenderResult struct {
	Profile           string   `json:"profile"`
	Directory         string   `json:"directory"`
	Owner             string   `json:"owner"`
	Repo              string   `json:"repo"`
	RegistryBase      string   `json:"registryBase"`
	CatalogSource     string   `json:"catalogSource,omitempty"`
	CatalogSourceRepo string   `json:"catalogSourceRepo,omitempty"`
	Files             []string `json:"files"`
	NextCommands      []string `json:"nextCommands"`
}

var platformRenderOpts platformRenderFlags

func NewPlatformRenderCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "render [dir]",
		Short: "Render a local ClearCutt control-plane repository",
		Long: `Render a local ClearCutt control-plane repository without calling gh,
initializing git, or pushing anything. The catalog-only profile writes a
lightweight Nix-free repo around images.yaml or selected GitHub release
evidence. The fleet profile delegates to the existing platform new scaffold and
adds control-plane metadata.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := platformRenderOpts
			if len(args) == 1 {
				if cmd.Flags().Changed("dir") {
					return fmt.Errorf("pass either [dir] or --dir, not both")
				}
				opts.dir = args[0]
			}
			result, err := renderPlatformControlPlane(opts)
			if err != nil {
				return err
			}
			return printPlatformRenderResult(result)
		},
	}
	addPlatformRenderFlags(cmd, &platformRenderOpts)
	return cmd
}

func addPlatformRenderFlags(cmd *cobra.Command, opts *platformRenderFlags) {
	cmd.Flags().StringVar(&opts.dir, "dir", "", "Output directory for the rendered control-plane repository")
	cmd.Flags().StringVar(&opts.profile, "profile", platformProfileCatalogOnly, "Control-plane profile: catalog-only or fleet")
	cmd.Flags().StringVar(&opts.owner, "owner", "", "GitHub owner/org for the control-plane repository")
	cmd.Flags().StringVar(&opts.repo, "repo", "", "GitHub repository name for the control plane")
	cmd.Flags().StringVar(&opts.registryBase, "registry-base", "", "OCI registry namespace for catalog records, for example ghcr.io/acme/image-platform")
	cmd.Flags().StringVar(&opts.registryHost, "registry-host", "", "Container registry host for fleet profile (default ghcr.io)")
	cmd.Flags().StringVar(&opts.imagePrefix, "image-prefix", "", "Image name prefix for fleet profile")
	cmd.Flags().StringVar(&opts.visibility, "visibility", "private", "GitHub repository visibility: private, public, or internal")
	cmd.Flags().BoolVar(&opts.pages, "pages", false, "Render desired GitHub Pages settings")
	cmd.Flags().StringVar(&opts.environment, "environment", "production", "GitHub environment name to record")
	cmd.Flags().BoolVar(&opts.force, "force", false, "Allow rendering into a non-empty directory and overwrite generated files")
	cmd.Flags().StringVar(&opts.generatedAt, "generated-at", "", "Override generated timestamp for deterministic tests")
	cmd.Flags().StringVar(&opts.source, "source", "", "Reference source checkout directory or zip archive/URL for fleet profile")
	cmd.Flags().StringVar(&opts.catalogSource, "catalog-source", catalogSourceInventory, "Catalog-only source: inventory or github-release")
	cmd.Flags().StringVar(&opts.catalogSourceRepo, "catalog-source-repo", "", "GitHub release source in OWNER/REPO form for catalog-only mode")
	cmd.Flags().StringVar(&opts.catalogTargets, "catalog-targets", "", "Comma-separated release target allowlist for github-release catalog source")
	cmd.Flags().IntVar(&opts.catalogReleaseLimit, "catalog-release-limit", 1, "Maximum non-draft releases to inspect for github-release catalog source")
}

func renderPlatformControlPlane(opts platformRenderFlags) (PlatformRenderResult, error) {
	normalized, err := normalizePlatformRenderOptions(opts)
	if err != nil {
		return PlatformRenderResult{}, err
	}
	switch normalized.profile {
	case platformProfileCatalogOnly:
		return renderCatalogOnlyControlPlane(normalized)
	case platformProfileFleet:
		return renderFleetControlPlane(normalized)
	default:
		return PlatformRenderResult{}, fmt.Errorf("unsupported profile %q (expected catalog-only or fleet)", normalized.profile)
	}
}

func normalizePlatformRenderOptions(opts platformRenderFlags) (platformRenderFlags, error) {
	opts.profile = strings.TrimSpace(opts.profile)
	if opts.profile == "" {
		opts.profile = platformProfileCatalogOnly
	}
	opts.owner = strings.TrimSpace(opts.owner)
	if opts.owner == "" {
		return opts, fmt.Errorf("--owner is required")
	}
	opts.repo = strings.TrimSpace(opts.repo)
	opts.dir = strings.TrimSpace(opts.dir)
	if opts.repo == "" && opts.dir != "" {
		opts.repo = filepath.Base(filepath.Clean(opts.dir))
	}
	if opts.repo == "" {
		return opts, fmt.Errorf("--repo is required")
	}
	if opts.dir == "" {
		opts.dir = opts.repo
	}
	if !filepath.IsAbs(opts.dir) {
		abs, err := filepath.Abs(opts.dir)
		if err != nil {
			return opts, err
		}
		opts.dir = abs
	}
	opts.visibility = strings.ToLower(strings.TrimSpace(opts.visibility))
	if opts.visibility == "" {
		opts.visibility = "private"
	}
	if opts.visibility != "private" && opts.visibility != "public" && opts.visibility != "internal" {
		return opts, fmt.Errorf("--visibility must be private, public, or internal")
	}
	opts.environment = strings.TrimSpace(opts.environment)
	if opts.environment == "" {
		opts.environment = "production"
	}
	if opts.generatedAt == "" {
		opts.generatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	switch opts.profile {
	case platformProfileCatalogOnly:
		opts.catalogSource = strings.ToLower(strings.TrimSpace(opts.catalogSource))
		if opts.catalogSource == "" {
			opts.catalogSource = catalogSourceInventory
		}
		if opts.catalogSource != catalogSourceInventory && opts.catalogSource != catalogSourceGitHubRelease {
			return opts, fmt.Errorf("--catalog-source must be inventory or github-release")
		}
		opts.catalogSourceRepo = strings.TrimSpace(opts.catalogSourceRepo)
		targets, err := normalizeCatalogTargets(opts.catalogTargets)
		if err != nil {
			return opts, err
		}
		opts.catalogTargets = strings.Join(targets, ",")
		if opts.catalogSource == catalogSourceGitHubRelease {
			if _, _, err := splitCatalogSourceRepo(opts.catalogSourceRepo); err != nil {
				return opts, err
			}
			if len(targets) == 0 {
				return opts, fmt.Errorf("--catalog-targets is required when --catalog-source=github-release")
			}
			if opts.catalogReleaseLimit < 1 {
				return opts, fmt.Errorf("--catalog-release-limit must be at least 1")
			}
		} else if opts.catalogSourceRepo != "" || len(targets) > 0 {
			return opts, fmt.Errorf("--catalog-source-repo and --catalog-targets require --catalog-source=github-release")
		}
		if strings.TrimSpace(opts.registryBase) == "" {
			opts.registryBase = fmt.Sprintf("ghcr.io/%s/%s", strings.ToLower(opts.owner), strings.ToLower(opts.repo))
		}
	case platformProfileFleet:
		if strings.TrimSpace(opts.catalogSource) != "" && strings.TrimSpace(opts.catalogSource) != catalogSourceInventory || strings.TrimSpace(opts.catalogSourceRepo) != "" || strings.TrimSpace(opts.catalogTargets) != "" {
			return opts, fmt.Errorf("catalog source flags are only supported with --profile=catalog-only")
		}
		if strings.TrimSpace(opts.registryHost) == "" {
			opts.registryHost = "ghcr.io"
		}
		if strings.TrimSpace(opts.imagePrefix) == "" {
			opts.imagePrefix = opts.repo
		}
		if strings.TrimSpace(opts.registryBase) == "" {
			opts.registryBase = strings.TrimSuffix(opts.registryHost, "/") + "/" + opts.owner + "/" + opts.repo
		}
	}
	opts.registryBase = strings.TrimSuffix(strings.TrimSpace(opts.registryBase), "/")
	return opts, nil
}

func normalizeCatalogTargets(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return []string{}, nil
	}
	seen := map[string]bool{}
	targets := []string{}
	for _, item := range strings.Split(raw, ",") {
		target := strings.TrimSpace(item)
		if !catalogTargetPattern.MatchString(target) {
			return nil, fmt.Errorf("invalid --catalog-targets entry %q", target)
		}
		if !seen[target] {
			seen[target] = true
			targets = append(targets, target)
		}
	}
	return targets, nil
}

func splitCatalogSourceRepo(raw string) (string, string, error) {
	parts := strings.Split(strings.TrimSpace(raw), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || !catalogTargetPattern.MatchString(parts[0]) || !catalogTargetPattern.MatchString(parts[1]) {
		return "", "", fmt.Errorf("--catalog-source-repo must use OWNER/REPO form")
	}
	return parts[0], parts[1], nil
}

func renderCatalogOnlyControlPlane(opts platformRenderFlags) (PlatformRenderResult, error) {
	if err := ensureScaffoldTarget(opts.dir, opts.force); err != nil {
		return PlatformRenderResult{}, err
	}
	files, err := catalogOnlyControlPlaneFiles(opts)
	if err != nil {
		return PlatformRenderResult{}, err
	}
	written, err := writeControlPlaneFiles(opts.dir, files, opts.force)
	if err != nil {
		return PlatformRenderResult{}, err
	}
	return platformRenderResult(opts, written), nil
}

func renderFleetControlPlane(opts platformRenderFlags) (PlatformRenderResult, error) {
	old := platformOpts
	platformOpts.outputDir = opts.dir
	platformOpts.owner = opts.owner
	platformOpts.repo = opts.repo
	platformOpts.registryHost = opts.registryHost
	platformOpts.imagePrefix = opts.imagePrefix
	platformOpts.source = opts.source
	platformOpts.force = opts.force
	defer func() { platformOpts = old }()
	if err := runPlatformNew(); err != nil {
		return PlatformRenderResult{}, err
	}
	files, err := fleetControlPlaneMetadataFiles(opts)
	if err != nil {
		return PlatformRenderResult{}, err
	}
	written, err := writeControlPlaneFiles(opts.dir, files, true)
	if err != nil {
		return PlatformRenderResult{}, err
	}
	sort.Strings(written)
	return platformRenderResult(opts, written), nil
}

func platformRenderResult(opts platformRenderFlags, written []string) PlatformRenderResult {
	sort.Strings(written)
	return PlatformRenderResult{
		Profile:           opts.profile,
		Directory:         opts.dir,
		Owner:             opts.owner,
		Repo:              opts.repo,
		RegistryBase:      opts.registryBase,
		CatalogSource:     opts.catalogSource,
		CatalogSourceRepo: opts.catalogSourceRepo,
		Files:             written,
		NextCommands: []string{
			fmt.Sprintf("clearcutt platform plan github --dir %s --owner %s --repo %s --profile %s", opts.dir, opts.owner, opts.repo, opts.profile),
			fmt.Sprintf("clearcutt platform bootstrap github --skip-render --dir %s --owner %s --repo %s --profile %s --apply --confirm", opts.dir, opts.owner, opts.repo, opts.profile),
		},
	}
}

func printPlatformRenderResult(result PlatformRenderResult) error {
	if structuredFormat() {
		return printStructured(result)
	}
	fmt.Fprintf(out, "Rendered ClearCutt %s control plane at %s\n", result.Profile, result.Directory)
	fmt.Fprintln(out, "Written files:")
	for _, file := range result.Files {
		fmt.Fprintf(out, "- %s\n", file)
	}
	fmt.Fprintln(out, "\nNext commands:")
	for _, command := range result.NextCommands {
		fmt.Fprintf(out, "- %s\n", command)
	}
	return nil
}

func writeControlPlaneFiles(root string, files map[string][]byte, force bool) ([]string, error) {
	written := make([]string, 0, len(files))
	for rel, raw := range files {
		if filepath.IsAbs(rel) || strings.HasPrefix(filepath.Clean(rel), "..") {
			return written, fmt.Errorf("unsafe generated path %q", rel)
		}
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := writeGeneratedFile(path, raw, force); err != nil {
			return written, err
		}
		written = append(written, filepath.ToSlash(rel))
	}
	sort.Strings(written)
	return written, nil
}

func catalogOnlyControlPlaneFiles(opts platformRenderFlags) (map[string][]byte, error) {
	lock, err := clearcuttLockYAML(opts)
	if err != nil {
		return nil, err
	}
	githubDesired, err := githubDesiredStateYAML(opts)
	if err != nil {
		return nil, err
	}
	state, err := initialBootstrapStateJSON(opts)
	if err != nil {
		return nil, err
	}
	installAction, err := installClearCuttActionYAML()
	if err != nil {
		return nil, err
	}
	siteConfig, err := catalogOnlySiteConfigYAML(opts)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{
		"README.md":                                    []byte(catalogOnlyReadme(opts)),
		".gitignore":                                   []byte("dist/\n.clearcutt/*.plan.json\n"),
		"clearcutt.lock":                               lock,
		".clearcutt/github.yaml":                       githubDesired,
		".clearcutt/state.json":                        state,
		".clearcutt/site.yaml":                         siteConfig,
		".github/workflows/catalog.yml":                []byte(catalogOnlyCatalogWorkflow(opts)),
		".github/workflows/pr-gate.yml":                []byte(catalogOnlyPRGateWorkflow(opts)),
		".github/actions/install-clearcutt/action.yml": installAction,
		"docs/operating-model.md":                      []byte(catalogOnlyOperatingModel(opts)),
		"docs/first-catalog.md":                        []byte(catalogOnlyFirstCatalog(opts)),
		"docs/app-team-onboarding.md":                  []byte(catalogOnlyAppTeamOnboarding(opts)),
		"docs/trust-model.md":                          []byte(catalogOnlyTrustModel(opts)),
		"policies/README.md":                           []byte("# Policies\n\nAdd admission and CI policy examples here as the catalog evidence requirements mature.\n"),
		"catalog/README.md":                            []byte("# Catalog Output\n\nGenerated catalog JSON can be written here or under `dist/catalog` in CI.\n"),
		"evidence/README.md":                           []byte(catalogOnlyEvidenceReadme(opts)),
	}
	if opts.catalogSource == catalogSourceInventory {
		files["images.yaml"] = []byte(catalogOnlyImagesYAML(opts))
	}
	return files, nil
}

func catalogOnlyEvidenceReadme(opts platformRenderFlags) string {
	if opts.catalogSource == catalogSourceGitHubRelease {
		return "# Evidence\n\nThe generated catalog consumes release evidence published by " + opts.catalogSourceRepo + ". Generated artifacts remain under `dist/`; add durable local evidence inputs here only when the control plane intentionally owns them.\n"
	}
	return "# Evidence\n\nStore imported SBOMs, provenance, signatures, scans, and exception records here when your workflow needs durable evidence inputs.\n"
}

func catalogOnlySiteConfigYAML(opts platformRenderFlags) ([]byte, error) {
	catalogMode := "imported"
	sourceRepo := "https://github.com/" + opts.owner + "/" + opts.repo
	title := "Imported Image Catalog"
	description := "Inspect image inventory and evidence gaps without assuming ClearCutt built or verified the images."
	noticeBody := "Observed metadata is not verified evidence. Missing or stale channels remain visible and do not satisfy policy gates."
	quickLinks := []map[string]any{
		{"label": "Browse imported images", "href": "catalog", "description": "Review inventory, origin, and per-channel evidence status."},
		{"label": "Audit evidence", "href": "about?tab=audit", "description": "Understand verification boundaries before enforcing policy."},
		{"label": "Know limits", "href": "limitations", "description": "Review what catalog-only governance does and does not prove."},
	}
	provenance := false
	selectedTargets := []string{}
	if opts.catalogSource == catalogSourceGitHubRelease {
		sourceOwner, sourceName, err := splitCatalogSourceRepo(opts.catalogSourceRepo)
		if err != nil {
			return nil, err
		}
		catalogMode = "fleet"
		sourceRepo = "https://github.com/" + sourceOwner + "/" + sourceName
		title = "Release Evidence Catalog"
		description = "Inspect release evidence published by " + opts.catalogSourceRepo + " without copying its source tree."
		noticeBody = "Verified channels come from published release assets. Missing signatures, scans, or other channels remain explicit."
		quickLinks = []map[string]any{
			{"label": "Browse release images", "href": "catalog", "description": "Review selected targets and their published evidence."},
			{"label": "Audit evidence", "href": "about?tab=audit", "description": "Trace which release artifacts support each status."},
			{"label": "Know limits", "href": "limitations", "description": "Review evidence that remains missing or unverified."},
		}
		provenance = true
		selectedTargets, err = normalizeCatalogTargets(opts.catalogTargets)
		if err != nil {
			return nil, err
		}
	}
	payload := map[string]any{
		"site": map[string]any{
			"title":           opts.repo + " Image Catalog",
			"description":     "Evidence-oriented catalog for OCI images governed by " + opts.owner + "/" + opts.repo + ".",
			"catalogMode":     catalogMode,
			"portalRole":      "generated-control-plane",
			"selectedTargets": selectedTargets,
			"navigation": map[string]any{
				"showHome":           true,
				"showGettingStarted": false,
				"showOperatorDocs":   false,
				"showCliDocs":        true,
				"showAuditGuide":     true,
			},
			"links": map[string]any{
				"sourceRepo": sourceRepo,
				"registry":   opts.registryBase,
			},
			"features": map[string]any{
				"sbomTable":          true,
				"vulnerabilityTable": true,
				"layerExplorer":      false,
				"provenance":         provenance,
				"ociLabels":          true,
				"versionHistory":     true,
				"kyvernoPolicies":    false,
			},
			"home": map[string]any{
				"title":       title,
				"description": description,
				"showNotice":  true,
				"noticeTitle": "Evidence is explicit",
				"noticeBody":  noticeBody,
				"quickLinks":  quickLinks,
				"personas":    []any{},
			},
		},
	}
	return yaml.Marshal(payload)
}

func fleetControlPlaneMetadataFiles(opts platformRenderFlags) (map[string][]byte, error) {
	lock, err := clearcuttLockYAML(opts)
	if err != nil {
		return nil, err
	}
	githubDesired, err := githubDesiredStateYAML(opts)
	if err != nil {
		return nil, err
	}
	state, err := initialBootstrapStateJSON(opts)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		"clearcutt.lock":         lock,
		".clearcutt/github.yaml": githubDesired,
		".clearcutt/state.json":  state,
	}, nil
}

func clearcuttLockYAML(opts platformRenderFlags) ([]byte, error) {
	spec := map[string]any{
		"clearcutt": map[string]any{
			"version":         Version,
			"sourceRepo":      fleet.ReferenceOwner + "/" + fleet.ReferenceRepo,
			"templateVersion": 1,
			"generatedAt":     opts.generatedAt,
		},
		"platform": map[string]any{
			"profile":      opts.profile,
			"owner":        opts.owner,
			"repo":         opts.repo,
			"registryBase": opts.registryBase,
			"pages":        opts.pages,
			"environment":  opts.environment,
		},
	}
	if opts.profile == platformProfileCatalogOnly {
		catalogState := map[string]any{"source": opts.catalogSource}
		if opts.catalogSource == catalogSourceGitHubRelease {
			targets, err := normalizeCatalogTargets(opts.catalogTargets)
			if err != nil {
				return nil, err
			}
			catalogState["sourceRepo"] = opts.catalogSourceRepo
			catalogState["targets"] = targets
			catalogState["releaseLimit"] = opts.catalogReleaseLimit
		} else {
			catalogState["inventoryFile"] = "images.yaml"
		}
		spec["catalog"] = catalogState
	}
	payload := map[string]any{
		"apiVersion": controlPlaneAPIVersion,
		"kind":       "ClearCuttLock",
		"metadata": map[string]any{
			"name": "clearcutt",
		},
		"spec": spec,
	}
	return yaml.Marshal(payload)
}

func githubDesiredStateYAML(opts platformRenderFlags) ([]byte, error) {
	payload := map[string]any{
		"apiVersion": controlPlaneAPIVersion,
		"kind":       "GitHubControlPlane",
		"metadata": map[string]any{
			"name": opts.repo,
		},
		"spec": map[string]any{
			"repository": map[string]any{
				"owner":         opts.owner,
				"name":          opts.repo,
				"visibility":    opts.visibility,
				"defaultBranch": "main",
			},
			"actions": map[string]any{
				"enabled":                    true,
				"defaultWorkflowPermissions": "read",
				"allowGitHubActionsToApprovePullRequests": false,
			},
			"pages": map[string]any{
				"enabled":     opts.pages,
				"buildType":   "workflow",
				"environment": "github-pages",
			},
			"environments": []map[string]any{
				{"name": opts.environment, "protectedBranches": true},
			},
			"variables": map[string]string{
				"CLEARCUTT_CLI_VERSION":      bootstrapCLIVersion(),
				"CLEARCUTT_CLI_REPO":         fleet.ReferenceOwner + "/" + fleet.ReferenceRepo,
				"CLEARCUTT_PLATFORM_PROFILE": opts.profile,
				"CLEARCUTT_REGISTRY_BASE":    opts.registryBase,
			},
		},
	}
	return yaml.Marshal(payload)
}

func initialBootstrapStateJSON(opts platformRenderFlags) ([]byte, error) {
	payload := map[string]any{
		"apiVersion":          controlPlaneAPIVersion,
		"kind":                "ClearCuttBootstrapState",
		"profile":             opts.profile,
		"owner":               opts.owner,
		"repo":                opts.repo,
		"managedResources":    []string{},
		"lastAppliedPlanHash": "",
		"generatedAt":         opts.generatedAt,
	}
	return json.MarshalIndent(payload, "", "  ")
}

func installClearCuttActionYAML() ([]byte, error) {
	if root, ok := findRepoRoot(); ok {
		raw, err := os.ReadFile(filepath.Join(root, ".github", "actions", "install-clearcutt", "action.yml"))
		if err == nil {
			return raw, nil
		}
		return nil, err
	}
	embeddedRoot, cleanup, err := platformsource.Materialize()
	if err != nil {
		return nil, fmt.Errorf("load embedded install-clearcutt action: %w", err)
	}
	defer cleanup()
	actionPath := filepath.Join(embeddedRoot, "clearcutt-source", ".github", "actions", "install-clearcutt", "action.yml")
	raw, err := os.ReadFile(actionPath)
	if err != nil {
		return nil, fmt.Errorf("read embedded install-clearcutt action: %w", err)
	}
	return raw, nil
}

func bootstrapCLIVersion() string {
	version := strings.TrimSpace(Version)
	if version == "" || version == "dev" || !strings.HasPrefix(version, "v") {
		return "latest"
	}
	return version
}

func catalogOnlyReadme(opts platformRenderFlags) string {
	if opts.catalogSource == catalogSourceGitHubRelease {
		return fmt.Sprintf(`# %s

This repository is a ClearCutt catalog-only control plane for release evidence
published by %s. It does not require Nix and does not vendor the upstream
ClearCutt source tree.

## First Catalog

1. Run the generated Catalog workflow or execute the command in docs/first-catalog.md.
2. Validate with clearcutt --catalog dist/catalog catalog validate.
3. Build the static portal with clearcutt catalog site build --catalog dist/catalog --output dist/site --install.
4. Treat missing signatures, scans, or other channels as explicit evidence gaps.

Catalog source state is recorded in clearcutt.lock. GitHub desired state is
recorded in .clearcutt/github.yaml. Bootstrap state is recorded in
.clearcutt/state.json.
`, opts.repo, opts.catalogSourceRepo)
	}
	return fmt.Sprintf(`# %s

This repository is a ClearCutt catalog-only control plane for images.yaml.
It does not require Nix and does not vendor the upstream ClearCutt source tree.

## First Catalog

1. Edit images.yaml with OCI image references your team already owns.
2. Run clearcutt catalog generate --images images.yaml --output dist/catalog --owner %s --repo %s --registry-base %s.
3. Validate with clearcutt --catalog dist/catalog catalog validate.
4. Build the static portal with clearcutt catalog site build --catalog dist/catalog --output dist/site --install.

GitHub desired state is recorded in .clearcutt/github.yaml. Bootstrap state is recorded in .clearcutt/state.json.
`, opts.repo, opts.owner, opts.repo, opts.registryBase)
}

func catalogOnlyImagesYAML(opts platformRenderFlags) string {
	return fmt.Sprintf(`# Generic OCI image inventory for ClearCutt catalog-only mode.
# Add images your platform already publishes. Missing signatures, SBOMs,
# provenance, scans, and tests remain explicit missing-evidence states.
#
# Example:
# images:
#   - id: node22-slim
#     image: %s/node22:slim
#     language:
#       id: node
#       displayName: Node.js
#       version: "22"
#     tier: slim
#     architectures: [amd64, arm64]

images:
  - id: sample-slim
    image: %s/sample:slim
    language:
      id: sample
      displayName: Sample
      version: "1"
    tier: slim
    architectures: [amd64]
`, opts.registryBase, opts.registryBase)
}

func catalogOnlyCatalogWorkflow(opts platformRenderFlags) string {
	steps := fmt.Sprintf(`      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - uses: ./.github/actions/install-clearcutt
        with:
          version: ${{ vars.CLEARCUTT_CLI_VERSION || '%s' }}
          repo: ${{ vars.CLEARCUTT_CLI_REPO || '%s/%s' }}
      - run: %s
      - run: clearcutt --catalog dist/catalog catalog validate
      - run: %s
`, bootstrapCLIVersion(), fleet.ReferenceOwner, fleet.ReferenceRepo, catalogOnlyGenerateCommand(opts), catalogOnlySiteBuildCommand(opts))
	paths := catalogOnlyWorkflowPaths(opts, ".github/workflows/catalog.yml")
	refreshTriggers := ""
	if opts.catalogSource == catalogSourceGitHubRelease {
		refreshTriggers = "  schedule:\n    - cron: '23 6 * * *'\n  repository_dispatch:\n    types: [clearcutt-release]\n"
	}
	if !opts.pages {
		return fmt.Sprintf(`name: Catalog

on:
  workflow_dispatch:
%s  push:
    paths:
%s

permissions:
  contents: read

jobs:
  catalog:
    runs-on: ubuntu-latest
    steps:
%s`, refreshTriggers, paths, steps)
	}
	return fmt.Sprintf(`name: Catalog

on:
  workflow_dispatch:
%s  push:
    paths:
%s

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: false

jobs:
  catalog:
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deploy.outputs.page_url }}
    steps:
%s      - uses: actions/upload-pages-artifact@56afc609e74202658d3ffba0e8f6dda462b719fa # v3.0.1
        with:
          path: dist/site
      - id: deploy
        uses: actions/deploy-pages@cd2ce8fcbc39b97be8ca5fce6e763baed58fa128 # v5.0.0
`, refreshTriggers, paths, steps)
}

func catalogOnlyWorkflowPaths(opts platformRenderFlags, workflow string) string {
	paths := []string{"      - clearcutt.lock", "      - .clearcutt/**", "      - " + workflow}
	if opts.catalogSource == catalogSourceInventory {
		paths = append([]string{"      - images.yaml"}, paths...)
	}
	return strings.Join(paths, "\n")
}

func catalogOnlyGenerateCommand(opts platformRenderFlags) string {
	return catalogOnlyGenerateCommandWithRegistry(opts, catalogRegistryBaseExpression(opts.registryBase))
}

func catalogOnlyLocalGenerateCommand(opts platformRenderFlags) string {
	return catalogOnlyGenerateCommandWithRegistry(opts, strconv.Quote(opts.registryBase))
}

func catalogOnlyGenerateCommandWithRegistry(opts platformRenderFlags, registryArg string) string {
	if opts.catalogSource == catalogSourceGitHubRelease {
		sourceOwner, sourceRepo, _ := splitCatalogSourceRepo(opts.catalogSourceRepo)
		return fmt.Sprintf(
			"clearcutt catalog generate --owner %q --repo %q --registry-base %s --targets %q --limit %s --output dist/catalog",
			sourceOwner,
			sourceRepo,
			registryArg,
			opts.catalogTargets,
			strconv.Itoa(opts.catalogReleaseLimit),
		)
	}
	return fmt.Sprintf(
		"clearcutt catalog generate --images images.yaml --output dist/catalog --owner %q --repo %q --registry-base %s",
		opts.owner,
		opts.repo,
		registryArg,
	)
}

func catalogRegistryBaseExpression(fallback string) string {
	return fmt.Sprintf(`"${{ vars.CLEARCUTT_REGISTRY_BASE || '%s' }}"`, fallback)
}

func catalogOnlySiteBuildCommand(opts platformRenderFlags) string {
	command := "clearcutt catalog site build --catalog dist/catalog --output dist/site --install --clean --site-config .clearcutt/site.yaml"
	if opts.pages {
		command += fmt.Sprintf(" --base-path %q --site-url %q", catalogOnlyPagesBasePath(opts), "https://"+strings.ToLower(opts.owner)+".github.io")
	}
	return command
}

func catalogOnlyPagesBasePath(opts platformRenderFlags) string {
	if strings.EqualFold(opts.repo, opts.owner+".github.io") {
		return "/"
	}
	return "/" + strings.Trim(opts.repo, "/")
}

func catalogOnlyPRGateWorkflow(opts platformRenderFlags) string {
	paths := catalogOnlyWorkflowPaths(opts, ".github/workflows/**")
	return fmt.Sprintf(`name: Catalog PR Gate

on:
  pull_request:
    paths:
%s

permissions:
  contents: read

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - uses: ./.github/actions/install-clearcutt
        with:
          version: ${{ vars.CLEARCUTT_CLI_VERSION || '%s' }}
          repo: ${{ vars.CLEARCUTT_CLI_REPO || '%s/%s' }}
      - run: %s
      - run: clearcutt --catalog dist/catalog catalog validate
      - run: clearcutt --catalog dist/catalog catalog summarize
      - run: %s
`, paths, bootstrapCLIVersion(), fleet.ReferenceOwner, fleet.ReferenceRepo, catalogOnlyGenerateCommand(opts), catalogOnlySiteBuildCommand(opts))
}

func catalogOnlyOperatingModel(opts platformRenderFlags) string {
	if opts.catalogSource == catalogSourceGitHubRelease {
		return fmt.Sprintf(`# Operating Model

This repository is the user-owned GitHub control plane for %s/%s. It consumes
published release evidence from %s while the source repository continues to
own builds, release assets, signatures, attestations, scans, and tests.

This repository owns the selected target view, static catalog, Pages site,
policy examples, and operating decisions. It does not vendor the source tree or
require Nix.

The catalog workflow refreshes daily so new source releases become visible
without a commit. It also accepts the clearcutt-release repository_dispatch
event for an immediate refresh when the source
repository is configured to send one. Manual workflow dispatch remains
available for operators.
`, opts.owner, opts.repo, opts.catalogSourceRepo)
	}
	return fmt.Sprintf(`# Operating Model

This repository is the user-owned GitHub control plane for %s/%s.
It stores catalog inputs, desired GitHub settings, workflows, policies, and
static-site publishing state. The upstream ClearCutt repository remains the CLI
and reference implementation source.

Catalog-only mode is intentionally Nix-free. Use the fleet profile later if
ClearCutt should build and operate the base-image fleet itself.
`, opts.owner, opts.repo)
}

func catalogOnlyFirstCatalog(opts platformRenderFlags) string {
	if opts.catalogSource == catalogSourceGitHubRelease {
		return fmt.Sprintf(`# First Catalog

Generate and validate release-backed catalog data locally:

`+"```bash"+`
%s

clearcutt --catalog dist/catalog catalog validate
clearcutt catalog site build --catalog dist/catalog --output dist/site --install --site-config .clearcutt/site.yaml
`+"```"+`
`, catalogOnlyLocalGenerateCommand(opts))
	}
	return fmt.Sprintf(`# First Catalog

Generate and validate catalog data locally:

`+"```bash"+`
clearcutt catalog generate \
  --images images.yaml \
  --output dist/catalog \
  --owner %s \
  --repo %s \
  --registry-base %s

clearcutt --catalog dist/catalog catalog validate
clearcutt catalog site build --catalog dist/catalog --output dist/site --install
`+"```"+`
`, opts.owner, opts.repo, opts.registryBase)
}

func catalogOnlyAppTeamOnboarding(opts platformRenderFlags) string {
	return fmt.Sprintf(`# App Team Onboarding

App teams consume catalog records and policy examples from %s/%s. They do
not need Nix for catalog-only mode. Start by pointing app CI at the generated
catalog and requiring the evidence channels your platform actually publishes.
`, opts.owner, opts.repo)
}

func catalogOnlyTrustModel(opts platformRenderFlags) string {
	if opts.catalogSource == catalogSourceGitHubRelease {
		return fmt.Sprintf(`# Trust Model

This control plane derives catalog records from release assets published by
%s. A channel is marked verified only when the catalog generator has matching
release evidence. Missing signatures, vulnerability scans, SBOMs, provenance,
or test results remain visible and must not be inferred from image availability.

The source repository owns image production and evidence publication. %s/%s
owns the selected catalog view, Pages publication, and downstream policy.
`, opts.catalogSourceRepo, opts.owner, opts.repo)
	}
	return fmt.Sprintf(`# Trust Model

Catalog-only mode reports evidence for OCI images your team already publishes.
It does not claim that missing signatures, SBOMs, provenance, vulnerability
scans, or tests are present. Missing evidence remains visible in generated
catalog records and should be handled by policy gates appropriate for %s/%s.
`, opts.owner, opts.repo)
}
