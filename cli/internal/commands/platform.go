package commands

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/output"
	"github.com/northcutted/clearcutt/internal/platformsource"
	"github.com/northcutted/clearcutt/internal/platformsource/rules"
	"github.com/spf13/cobra"
)

type platformFlags struct {
	configPath       string
	outputDir        string
	owner            string
	repo             string
	registryHost     string
	imagePrefix      string
	source           string
	githubOutputPath string
	github           bool
	githubRepo       string
	force            bool
}

var platformOpts platformFlags

type PlatformStatus struct {
	Status string                `json:"status"`
	Checks []PlatformStatusCheck `json:"checks"`
}

type PlatformStatusCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type PlatformRegistryEnv struct {
	Host         string `json:"host"`
	RegistryBase string `json:"registryBase"`
	Owner        string `json:"owner"`
	Repository   string `json:"repository"`
	ImagePrefix  string `json:"imagePrefix"`
	Username     string `json:"username"`
	AuthMode     string `json:"authMode"`
}

type PlatformReleasePlan struct {
	Repository           string                    `json:"repository"`
	ProductName          string                    `json:"productName"`
	FleetConfig          string                    `json:"fleetConfig"`
	Registry             PlatformReleaseRegistry   `json:"registry"`
	CLI                  PlatformReleaseCLI        `json:"cli"`
	Builder              PlatformReleaseBuilder    `json:"builder"`
	Matrix               PlatformReleaseMatrix     `json:"matrix"`
	RequiredEnvironment  []string                  `json:"requiredEnvironment"`
	RequiredVariables    []PlatformReleaseSetting  `json:"requiredVariables"`
	RequiredSecrets      []PlatformReleaseSetting  `json:"requiredSecrets"`
	LocalChecks          []PlatformReleaseCommand  `json:"localChecks"`
	ReleaseSteps         []PlatformReleaseCommand  `json:"releaseSteps"`
	VerificationCommands []PlatformReleaseCommand  `json:"verificationCommands"`
	Boundaries           []PlatformReleaseBoundary `json:"boundaries"`
	Status               PlatformStatus            `json:"status"`
}

type PlatformReleaseRegistry struct {
	Host         string `json:"host"`
	RegistryBase string `json:"registryBase"`
	AuthMode     string `json:"authMode"`
	SupportTier  string `json:"supportTier"`
	Note         string `json:"note"`
}

type PlatformReleaseCLI struct {
	InstallAction  string `json:"installAction"`
	DefaultMode    string `json:"defaultMode"`
	DefaultVersion string `json:"defaultVersion"`
	DefaultRepo    string `json:"defaultRepo"`
	Verification   string `json:"verification"`
}

type PlatformReleaseBuilder struct {
	PrimaryCI       string `json:"primaryCi"`
	SLSABuilder     string `json:"slsaBuilder"`
	ReleaseIdentity string `json:"releaseIdentity"`
	RebaseIdentity  string `json:"rebaseIdentity"`
	SourceBranch    string `json:"sourceBranch"`
	ProductionGate  string `json:"productionGate"`
}

type PlatformReleaseMatrix struct {
	RuntimeLines int      `json:"runtimeLines"`
	Tiers        []string `json:"tiers"`
	Systems      []string `json:"systems"`
	Services     int      `json:"services"`
}

type PlatformReleaseSetting struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Reason   string `json:"reason"`
}

type PlatformReleaseCommand struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Command string `json:"command"`
	Reason  string `json:"reason"`
}

type PlatformReleaseBoundary struct {
	Area  string `json:"area"`
	Owner string `json:"owner"`
	Note  string `json:"note"`
}

func NewPlatformCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "platform",
		Short: "Bootstrap and inspect ClearCutt control-plane repositories",
		Long: `Bootstrap and inspect GitHub-native ClearCutt control-plane repositories.
The catalog-only profile renders a lightweight Nix-free repository around an
images.yaml inventory. The fleet profile keeps the existing platform scaffold
path for teams that want ClearCutt to build and operate a base-image fleet.`,
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Write starter fleet config, docs, and app templates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Default --output writes into the repo root, not the cwd, so
			// running from a subdirectory does not scatter nested
			// core/docs/examples trees.
			resolveRepoRootDefault(cmd, "output", &platformOpts.outputDir)
			return runPlatformInit()
		},
	}
	initCmd.Flags().StringVar(&platformOpts.configPath, "fleet-config", fleet.DefaultConfigPath, "Fleet config path to write")
	initCmd.Flags().StringVar(&platformOpts.outputDir, "output", ".", "Repository root/output directory")
	initCmd.Flags().StringVar(&platformOpts.owner, "owner", "", "GitHub owner/org for the fleet (default northcutted)")
	initCmd.Flags().StringVar(&platformOpts.repo, "repo", "", "GitHub repository for the fleet (default clearcutt)")
	initCmd.Flags().StringVar(&platformOpts.registryHost, "registry-host", "", "Container registry host (default ghcr.io)")
	initCmd.Flags().StringVar(&platformOpts.imagePrefix, "image-prefix", "", "Image name prefix (default clearcutt)")
	initCmd.Flags().BoolVar(&platformOpts.force, "force", false, "Overwrite existing generated files")

	newCmd := &cobra.Command{
		Use:   "new [dir]",
		Short: "Scaffold a standalone ClearCutt fleet repository",
		Long: `Scaffold a standalone ClearCutt fleet repository from the reference kit.
The command copies the CLI source, workflows, Nix fleet core, site template,
schemas, docs, and examples from the current ClearCutt checkout when available.
When run from an installed CLI outside a checkout, it uses the embedded
reference source archive. A custom checkout or zip can be supplied with
--source. The command localizes the generated fleet config, app templates,
policy examples, and metadata for the requested owner/repo/registry identity.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := platformOpts.outputDir
			if len(args) == 1 {
				if cmd.Flags().Changed("dir") {
					return fmt.Errorf("pass either [dir] or --dir, not both")
				}
				dir = args[0]
			}
			if strings.TrimSpace(dir) == "" {
				repo := strings.TrimSpace(platformOpts.repo)
				if repo == "" {
					repo = "clearcutt-fleet"
				}
				dir = repo
			}
			if strings.TrimSpace(platformOpts.repo) == "" {
				platformOpts.repo = filepath.Base(filepath.Clean(dir))
			}
			platformOpts.outputDir = dir
			return runPlatformNew()
		},
	}
	newCmd.Flags().StringVar(&platformOpts.outputDir, "dir", "", "Output directory for the new fleet repository (default ./<repo>)")
	newCmd.Flags().StringVar(&platformOpts.owner, "owner", "", "GitHub owner/org for the fleet (default northcutted)")
	newCmd.Flags().StringVar(&platformOpts.repo, "repo", "", "GitHub repository for the fleet (default basename of --dir)")
	newCmd.Flags().StringVar(&platformOpts.registryHost, "registry-host", "", "Container registry host (default ghcr.io)")
	newCmd.Flags().StringVar(&platformOpts.imagePrefix, "image-prefix", "", "Image name prefix (default clearcutt)")
	newCmd.Flags().StringVar(&platformOpts.source, "source", "", "Reference source checkout directory or zip archive/URL (default current checkout, then embedded archive)")
	newCmd.Flags().BoolVar(&platformOpts.force, "force", false, "Allow scaffolding into a non-empty directory and overwrite localized files")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Check whether the platform kit is wired together",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Inspect the same root that platform init writes to by default.
			resolveRepoRootDefault(cmd, "output", &platformOpts.outputDir)
			return runPlatformStatus()
		},
	}
	statusCmd.Flags().StringVar(&platformOpts.configPath, "fleet-config", fleet.DefaultConfigPath, "Fleet config path to inspect")
	statusCmd.Flags().StringVar(&platformOpts.outputDir, "output", ".", "Repository root to inspect")

	doctorCmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run local and optional GitHub readiness checks",
		Long: `Run first-release readiness checks for a ClearCutt fleet repository.
By default this runs the same local wiring checks as platform status. Pass
--github to also inspect the GitHub repository with the gh CLI for Actions,
workflow permissions, production environment, Pages, and registry credential
readiness.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolveRepoRootDefault(cmd, "output", &platformOpts.outputDir)
			return runPlatformDoctor()
		},
	}
	doctorCmd.Flags().StringVar(&platformOpts.configPath, "fleet-config", fleet.DefaultConfigPath, "Fleet config path to inspect")
	doctorCmd.Flags().StringVar(&platformOpts.outputDir, "output", ".", "Repository root to inspect")
	doctorCmd.Flags().BoolVar(&platformOpts.github, "github", false, "Use gh to check GitHub repository readiness")
	doctorCmd.Flags().StringVar(&platformOpts.githubRepo, "repo", "", "GitHub owner/repo to inspect (default from fleet config)")

	releasePlanCmd := &cobra.Command{
		Use:   "release-plan",
		Short: "Print a first-release plan for the configured fleet",
		Long: `Print a first-release plan for a ClearCutt fleet repository.
The plan is generated from clearcutt.fleet.yaml and the local workflow wiring.
It is side-effect free: it does not dispatch workflows, log in to registries, or
modify release state. Use it before the first production release to see the
required GitHub environment, variables, secrets, local checks, release steps,
verification commands, and the current boundary between CLI-owned orchestration
and GitHub Actions/Nix/Sigstore machinery.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolveRepoRootDefault(cmd, "output", &platformOpts.outputDir)
			return runPlatformReleasePlan()
		},
	}
	releasePlanCmd.Flags().StringVar(&platformOpts.configPath, "fleet-config", fleet.DefaultConfigPath, "Fleet config path to inspect")
	releasePlanCmd.Flags().StringVar(&platformOpts.outputDir, "output", ".", "Repository root to inspect")

	registryEnvCmd := &cobra.Command{
		Use:   "registry-env",
		Short: "Emit registry login settings from clearcutt.fleet.yaml",
		Long: `Emit non-secret registry settings for GitHub Actions and local automation.
The registry host and image namespace come from clearcutt.fleet.yaml. The login
username resolves from CLEARCUTT_REGISTRY_USER, then GITHUB_ACTOR, then the fleet
owner as a local fallback. Passwords are never emitted; workflows should keep
using CLEARCUTT_REGISTRY_TOKEN or GITHUB_TOKEN.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolveRepoRootDefault(cmd, "fleet-config", &platformOpts.configPath)
			return runPlatformRegistryEnv()
		},
	}
	registryEnvCmd.Flags().StringVar(&platformOpts.configPath, "fleet-config", fleet.DefaultConfigPath, "Fleet config path to inspect")
	registryEnvCmd.Flags().StringVar(&platformOpts.githubOutputPath, "github-output", "", "Optional GITHUB_OUTPUT file to append host, username, registry_base, owner, repository, image_prefix, and auth_mode")

	cmd.AddCommand(initCmd, newCmd, statusCmd, doctorCmd, releasePlanCmd, registryEnvCmd, NewPlatformSetupNixCmd(), NewPlatformRenderCmd(), NewPlatformPlanCmd(), NewPlatformApplyCmd(), NewPlatformBootstrapCmd())
	return cmd
}

func runPlatformInit() error {
	root := platformOpts.outputDir
	cfgPath := joinRoot(root, platformOpts.configPath)
	cfg := platformConfigFromFlags()
	raw, err := fleet.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := writeGeneratedFile(cfgPath, raw, platformOpts.force); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s\n", cfgPath)

	docsPath := filepath.Join(root, "docs", "platform-kit.md")
	if err := writeGeneratedFile(docsPath, []byte(platformKitDoc(cfg)), platformOpts.force); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s\n", docsPath)

	metadataPath := filepath.Join(root, "core", "lib", "platform-metadata.nix")
	if err := writeGeneratedFile(metadataPath, []byte(platformMetadataNix(cfg)), platformOpts.force); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s\n", metadataPath)

	for _, runtime := range cfg.Templates.Runtimes {
		dir := filepath.Join(root, "examples", "clearcutt-template-"+runtime)
		written, err := writeAppTemplate(cfg, runtime, "clearcutt-template-"+runtime, dir, platformOpts.force)
		if err != nil {
			return err
		}
		for _, path := range written {
			fmt.Fprintf(out, "wrote %s\n", path)
		}
	}

	localized, err := localizeConsumerExamples(root, cfg)
	if err != nil {
		return err
	}
	for _, path := range localized {
		fmt.Fprintf(out, "localized %s\n", path)
	}
	return nil
}

func runPlatformNew() error {
	sourceRoot, cleanup, err := resolvePlatformSkeletonSource()
	if err != nil {
		return err
	}
	defer cleanup()
	targetRoot := platformOpts.outputDir
	if !filepath.IsAbs(targetRoot) {
		abs, err := filepath.Abs(targetRoot)
		if err != nil {
			return err
		}
		targetRoot = abs
	}
	if err := ensureScaffoldTarget(targetRoot, platformOpts.force); err != nil {
		return err
	}
	if err := copyPlatformSkeleton(sourceRoot, targetRoot, platformOpts.force); err != nil {
		return err
	}
	if err := writeEmbeddedPlatformSourceAsset(targetRoot); err != nil {
		return err
	}

	oldOutput := platformOpts.outputDir
	oldConfig := platformOpts.configPath
	oldForce := platformOpts.force
	platformOpts.outputDir = targetRoot
	platformOpts.configPath = fleet.DefaultConfigPath
	platformOpts.force = true
	defer func() {
		platformOpts.outputDir = oldOutput
		platformOpts.configPath = oldConfig
		platformOpts.force = oldForce
	}()
	if err := runPlatformInit(); err != nil {
		return err
	}
	if !GlobalOpts.Quiet {
		fmt.Fprintf(out, "scaffolded ClearCutt fleet repo at %s\n", targetRoot)
		fmt.Fprintln(out, "next: cd into the repo, review clearcutt.fleet.yaml, then run clearcutt platform status")
	}
	return nil
}

func resolvePlatformSkeletonSource() (string, func(), error) {
	if strings.TrimSpace(platformOpts.source) != "" {
		return materializePlatformSkeletonSource(platformOpts.source)
	}
	if sourceRoot, ok := findRepoRoot(); ok {
		return sourceRoot, func() {}, nil
	}
	root, cleanup, err := platformsource.Materialize()
	if err == nil {
		sourceRoot, rootErr := findPlatformSkeletonRoot(root)
		if rootErr != nil {
			cleanup()
			return "", func() {}, rootErr
		}
		return sourceRoot, cleanup, nil
	}
	return materializePlatformSkeletonSource(defaultPlatformSourceArchiveURL())
}

func defaultPlatformSourceArchiveURL() string {
	version := strings.TrimSpace(Version)
	refKind := "heads"
	ref := "main"
	if version != "" && version != "dev" && !strings.Contains(version, "-g") && !strings.Contains(version, "dirty") {
		refKind = "tags"
		ref = version
	}
	return fmt.Sprintf("https://github.com/%s/%s/archive/refs/%s/%s.zip", fleet.ReferenceOwner, fleet.ReferenceRepo, refKind, ref)
}

func materializePlatformSkeletonSource(source string) (string, func(), error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return "", func() {}, fmt.Errorf("platform scaffold source is required")
	}
	if parsed, err := url.Parse(source); err == nil && parsed.Scheme != "" {
		switch parsed.Scheme {
		case "http", "https":
			return materializePlatformSkeletonArchiveURL(source)
		case "file":
			path, err := url.PathUnescape(parsed.Path)
			if err != nil {
				return "", func() {}, err
			}
			return materializePlatformSkeletonSource(path)
		}
	}
	info, err := os.Stat(source)
	if err != nil {
		return "", func() {}, err
	}
	if info.IsDir() {
		root, err := findPlatformSkeletonRoot(source)
		if err != nil {
			return "", func() {}, err
		}
		return root, func() {}, nil
	}
	return materializePlatformSkeletonArchive(source)
}

const maxPlatformSourceArchiveBytes = 200 << 20

func materializePlatformSkeletonArchiveURL(sourceURL string) (string, func(), error) {
	req, err := http.NewRequest(http.MethodGet, sourceURL, nil)
	if err != nil {
		return "", func() {}, err
	}
	client := http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", func() {}, fmt.Errorf("download platform source archive %s: %w", sourceURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", func() {}, fmt.Errorf("download platform source archive %s: HTTP %s", sourceURL, resp.Status)
	}
	tmp, err := os.CreateTemp("", "clearcutt-platform-source-*.zip")
	if err != nil {
		return "", func() {}, err
	}
	tmpPath := tmp.Name()
	cleanupFile := func() { _ = os.Remove(tmpPath) }
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, maxPlatformSourceArchiveBytes+1)); err != nil {
		_ = tmp.Close()
		cleanupFile()
		return "", func() {}, err
	}
	if err := tmp.Close(); err != nil {
		cleanupFile()
		return "", func() {}, err
	}
	info, err := os.Stat(tmpPath)
	if err != nil {
		cleanupFile()
		return "", func() {}, err
	}
	if info.Size() > maxPlatformSourceArchiveBytes {
		cleanupFile()
		return "", func() {}, fmt.Errorf("platform source archive exceeds %d bytes", maxPlatformSourceArchiveBytes)
	}
	root, cleanupDir, err := materializePlatformSkeletonArchive(tmpPath)
	if err != nil {
		cleanupFile()
		cleanupDir()
		return "", func() {}, err
	}
	return root, func() {
		cleanupDir()
		cleanupFile()
	}, nil
}

func materializePlatformSkeletonArchive(path string) (string, func(), error) {
	tmpDir, err := os.MkdirTemp("", "clearcutt-platform-source-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }
	if err := unzipPlatformSkeletonArchive(path, tmpDir); err != nil {
		cleanup()
		return "", func() {}, err
	}
	root, err := findPlatformSkeletonRoot(tmpDir)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	return root, cleanup, nil
}

func unzipPlatformSkeletonArchive(path, dir string) error {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("open platform source archive: %w", err)
	}
	defer reader.Close()
	for _, file := range reader.File {
		clean := filepath.Clean(filepath.FromSlash(file.Name))
		if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("platform source archive contains unsafe path %q", file.Name)
		}
		target := filepath.Join(dir, clean)
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, file.Mode().Perm()); err != nil {
				return err
			}
			continue
		}
		if !file.FileInfo().Mode().IsRegular() {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		src, err := file.Open()
		if err != nil {
			return err
		}
		dst, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, file.Mode().Perm())
		if err != nil {
			_ = src.Close()
			return err
		}
		_, copyErr := io.Copy(dst, src)
		closeErr := dst.Close()
		_ = src.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func findPlatformSkeletonRoot(dir string) (string, error) {
	if isPlatformSkeletonRoot(dir) {
		return dir, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := filepath.Join(dir, entry.Name())
		if isPlatformSkeletonRoot(candidate) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%s does not contain a ClearCutt platform source tree", dir)
}

func isPlatformSkeletonRoot(dir string) bool {
	for _, rel := range []string{"clearcutt.fleet.yaml", "core/flake.nix", ".github/workflows/release.yml"} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			return false
		}
	}
	return true
}

func platformConfigFromFlags() fleet.Config {
	owner := strings.TrimSpace(platformOpts.owner)
	repo := strings.TrimSpace(platformOpts.repo)
	if owner == "" {
		owner = fleet.ReferenceOwner
	}
	if repo == "" {
		repo = fleet.ReferenceRepo
	}
	cfg := fleet.DefaultConfig(owner, repo)
	if host := strings.TrimSuffix(strings.TrimSpace(platformOpts.registryHost), "/"); host != "" {
		cfg.Registry.Host = host
	}
	if prefix := strings.TrimSpace(platformOpts.imagePrefix); prefix != "" {
		cfg.Registry.ImagePrefix = prefix
	}
	return cfg
}

func ensureScaffoldTarget(dir string, force bool) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(dir, 0o755)
	}
	if err != nil {
		return err
	}
	if len(entries) > 0 && !force {
		return fmt.Errorf("%s is not empty; pass --force to scaffold there", dir)
	}
	return nil
}

func copyPlatformSkeleton(sourceRoot, targetRoot string, force bool) error {
	for _, rel := range rules.Entries {
		src := filepath.Join(sourceRoot, rel)
		if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := copyPlatformSkeletonPath(sourceRoot, targetRoot, rel, force); err != nil {
			return err
		}
	}
	return nil
}

func copyPlatformSkeletonPath(sourceRoot, targetRoot, rel string, force bool) error {
	src := filepath.Join(sourceRoot, rel)
	dst := filepath.Join(targetRoot, rel)
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if rules.SkipPath(rel, info) {
		return nil
	}
	if info.IsDir() {
		if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			childRel := filepath.Join(rel, entry.Name())
			if err := copyPlatformSkeletonPath(sourceRoot, targetRoot, childRel, force); err != nil {
				return err
			}
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	if !force {
		if _, err := os.Stat(dst); err == nil {
			return fmt.Errorf("%s already exists; pass --force to overwrite", dst)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, raw, info.Mode().Perm())
}

func writeEmbeddedPlatformSourceAsset(root string) error {
	raw, err := platformsource.Bytes()
	if err != nil {
		// A dev binary built without the generated archive still scaffolds
		// fine: the kit carries archive/README.md so the scaffolded repo
		// compiles, and its own CI regenerates the archive on build.
		if errors.Is(err, platformsource.ErrNotEmbedded) {
			return nil
		}
		return err
	}
	path := platformsource.ArchivePath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

// localizeConsumerExamples rewrites the upstream ClearCutt identity inside the
// consumer-facing example manifests (Kubernetes, OpenShift, Compose, the
// base-image overlay, and framework samples) so a fork does not ship deployment
// manifests that pull upstream images, admission policy that trusts the upstream
// signing identity, or copy that shows the upstream brand. It localizes four
// things, all sourced from the fleet config:
//
//	registry namespace, GitHub OIDC identity, image-name prefix (so admission
//	globs match the fork's actual images), and the product brand word.
//
// Placeholder app-team identities such as ghcr.io/acme/* and the clearcutt.dev
// schema/predicate dialect (no hyphen) are intentionally left untouched. Files
// are edited in place so comments and local customization survive; unchanged
// files are skipped, which makes this a no-op in the upstream repository itself.
func localizeConsumerExamples(root string, cfg fleet.Config) ([]string, error) {
	ref := fleet.DefaultConfig(fleet.ReferenceOwner, fleet.ReferenceRepo)
	if ref.RegistryBase() == cfg.RegistryBase() &&
		ref.RepoPath() == cfg.RepoPath() &&
		ref.Registry.ImagePrefix == cfg.Registry.ImagePrefix &&
		fleet.ReferenceProductName == cfg.Branding.ProductName {
		return nil, nil
	}
	// Order matters: replace the registry base (host + path) before the bare repo
	// path, and use a trailing hyphen on the image prefix so "clearcutt-" image
	// names/globs are localized without touching the "clearcutt.dev" dialect.
	replacer := strings.NewReplacer(
		ref.RegistryBase(), cfg.RegistryBase(),
		ref.RepoPath(), cfg.RepoPath(),
		ref.Registry.ImagePrefix+"-", cfg.Registry.ImagePrefix+"-",
		fleet.ReferenceProductName, cfg.Branding.ProductName,
	)
	var written []string
	walkErr := filepath.WalkDir(filepath.Join(root, "examples"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > 2<<20 {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		updated := replacer.Replace(string(raw))
		if updated == string(raw) {
			return nil
		}
		if err := os.WriteFile(path, []byte(updated), info.Mode().Perm()); err != nil {
			return err
		}
		written = append(written, path)
		return nil
	})
	if walkErr != nil {
		return written, walkErr
	}
	return written, nil
}

func runPlatformStatus() error {
	root := platformOpts.outputDir
	result := collectPlatformStatus(root, platformOpts.configPath)
	if err := printPlatformStatus(result); err != nil {
		return err
	}
	if result.Status == "fail" {
		return ErrCheckFailed
	}
	return nil
}

func runPlatformDoctor() error {
	root := platformOpts.outputDir
	checks := collectPlatformStatus(root, platformOpts.configPath).Checks
	addPlatformDoctorWorkflowChecks(root, func(id, status, msg string) {
		checks = append(checks, PlatformStatusCheck{ID: id, Status: status, Message: msg})
	})
	if platformOpts.github {
		cfg, err := fleet.Load(joinRoot(root, platformOpts.configPath))
		if err != nil {
			checks = append(checks, PlatformStatusCheck{ID: "github.config", Status: "fail", Message: fmt.Sprintf("fleet config missing or invalid: %v", err)})
		} else {
			addGithubDoctorChecks(cfg, platformOpts.githubRepo, func(id, status, msg string) {
				checks = append(checks, PlatformStatusCheck{ID: id, Status: status, Message: msg})
			})
		}
	}
	result := platformStatusFromChecks(checks)
	if err := printPlatformStatus(result); err != nil {
		return err
	}
	if result.Status == "fail" {
		return ErrCheckFailed
	}
	return nil
}

func runPlatformReleasePlan() error {
	root := platformOpts.outputDir
	cfgPath := joinRoot(root, platformOpts.configPath)
	cfg, err := fleet.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	plan := buildPlatformReleasePlan(root, platformOpts.configPath, cfg)
	return printPlatformReleasePlan(plan)
}

func buildPlatformReleasePlan(root, configPath string, cfg fleet.Config) PlatformReleasePlan {
	registryEnv := platformRegistryEnv(cfg)
	supportTier := "ghcr-reference"
	registryNote := "GHCR is the reference path and can use GITHUB_TOKEN when publishing within the configured repository namespace."
	if registryEnv.Host != "ghcr.io" {
		supportTier = "configurable-needs-registry-proof"
		registryNote = "Non-GHCR registries are configurable, but the fork owner must prove login, OCI referrer, signature, attestation, and verifier behavior for that registry."
	}
	defaultCLIVersion := workflowDefaultExpressionValue(root, ".github/workflows/release.yml", "CLEARCUTT_CLI_VERSION", "v0.17.0")
	defaultCLIRepo := workflowDefaultExpressionValue(root, ".github/workflows/release.yml", "CLEARCUTT_CLI_REPO", fleet.ReferenceOwner+"/"+fleet.ReferenceRepo)
	status := collectPlatformStatus(root, configPath)
	requiredSecrets := []PlatformReleaseSetting{
		{Name: "GITHUB_TOKEN", Required: true, Reason: "GitHub-provided token used by the GHCR reference path, releases, Pages, and pull request automation."},
	}
	if registryEnv.Host != "ghcr.io" {
		requiredSecrets = append(requiredSecrets, PlatformReleaseSetting{Name: "CLEARCUTT_REGISTRY_TOKEN", Required: true, Reason: "Token used by workflows to log in to the configured non-GHCR registry."})
	} else {
		requiredSecrets = append(requiredSecrets, PlatformReleaseSetting{Name: "CLEARCUTT_REGISTRY_TOKEN", Required: false, Reason: "Optional override when GHCR publishing cannot use GITHUB_TOKEN."})
	}
	if strings.TrimSpace(cfg.Release.NixCache.SigningKeyName) != "" || strings.TrimSpace(cfg.Release.NixCache.Bucket) != "" {
		requiredSecrets = append(requiredSecrets, PlatformReleaseSetting{Name: cfg.Release.NixCache.SigningKeyName, Required: true, Reason: "Private key for signing the fork-owned Nix binary cache."})
	}
	requiredSecrets = append(requiredSecrets, PlatformReleaseSetting{Name: "OPENROUTER_API_KEY", Required: false, Reason: "Only needed when manual remediation runs allow LLM escalation; scheduled deterministic drafting runs with LLM off."})

	requiredVars := []PlatformReleaseSetting{
		{Name: "CLEARCUTT_CLI_MODE=release", Required: true, Reason: "Fleet workflows should install the verified released CLI. Use local only for deliberate dogfooding."},
		{Name: "CLEARCUTT_CLI_VERSION=" + defaultCLIVersion, Required: true, Reason: "Pin the ClearCutt CLI release that owns workflow orchestration."},
		{Name: "CLEARCUTT_CLI_REPO=" + defaultCLIRepo, Required: false, Reason: "Set when the fleet consumes a forked CLI publisher instead of upstream ClearCutt."},
		{Name: "CLEARCUTT_REGISTRY_USER", Required: registryEnv.Host != "ghcr.io", Reason: "Registry login username; GHCR can fall back to github.actor."},
		{Name: "CLEARCUTT_SCHEDULED_REMEDIATION_DRAFTS", Required: false, Reason: "Set true only after accepting deterministic scheduled PR drafting."},
	}

	releaseRef := "refs/heads/" + cfg.Release.SourceBranch
	return PlatformReleasePlan{
		Repository:  cfg.RepoPath(),
		ProductName: cfg.Branding.ProductName,
		FleetConfig: configPath,
		Registry: PlatformReleaseRegistry{
			Host:         registryEnv.Host,
			RegistryBase: registryEnv.RegistryBase,
			AuthMode:     registryEnv.AuthMode,
			SupportTier:  supportTier,
			Note:         registryNote,
		},
		CLI: PlatformReleaseCLI{
			InstallAction:  ".github/actions/install-clearcutt",
			DefaultMode:    "release",
			DefaultVersion: defaultCLIVersion,
			DefaultRepo:    defaultCLIRepo,
			Verification:   "release binaries are checked against SHA256SUMS.txt and cosign verify-blob before workflow use",
		},
		Builder: PlatformReleaseBuilder{
			PrimaryCI:       "GitHub Actions",
			SLSABuilder:     cfg.Release.SLSABuilder,
			ReleaseIdentity: cfg.Release.WorkflowIdentity,
			RebaseIdentity:  cfg.Rebase.WorkflowIdentity,
			SourceBranch:    cfg.Release.SourceBranch,
			ProductionGate:  "GitHub environment: production",
		},
		Matrix: PlatformReleaseMatrix{
			RuntimeLines: len(cfg.Matrix.Languages),
			Tiers:        append([]string(nil), cfg.Matrix.Tiers...),
			Systems:      append([]string(nil), cfg.Matrix.Systems...),
			Services:     len(cfg.Services),
		},
		RequiredEnvironment: []string{"production"},
		RequiredVariables:   requiredVars,
		RequiredSecrets:     requiredSecrets,
		LocalChecks: []PlatformReleaseCommand{
			{ID: "status", Title: "Check scaffold wiring", Command: "clearcutt platform status --output . --fleet-config " + configPath, Reason: "Confirms workflows, registry naming, release identity, app templates, and catalog wiring are present."},
			{ID: "doctor", Title: "Check GitHub readiness", Command: "clearcutt platform doctor --github --output . --fleet-config " + configPath, Reason: "Checks repository settings, Actions permissions, production environment, Pages, and optional secrets."},
			{ID: "registry", Title: "Resolve registry login settings", Command: "clearcutt platform registry-env --fleet-config " + configPath, Reason: "Shows the non-secret registry host, namespace, username, and auth mode workflows will use."},
			{ID: "nix", Title: "Prepare build host Nix config", Command: "clearcutt platform setup-nix --fleet-config " + configPath + " --skip-warm", Reason: "Validates fork-specific Nix cache/client settings before release runners build the fleet without warming the dev shell."},
		},
		ReleaseSteps: []PlatformReleaseCommand{
			{ID: "push", Title: "Merge release source", Command: "git push origin " + cfg.Release.SourceBranch, Reason: "The release workflow identity is pinned to " + releaseRef + "."},
			{ID: "release", Title: "Run the release workflow", Command: "gh workflow run release.yml --ref " + cfg.Release.SourceBranch + " -f custom_version=vX.Y.Z", Reason: "Publishes images, signs, attests, verifies release evidence, exports provenance, and finalizes release assets."},
			{ID: "catalog", Title: "Publish the evidence catalog", Command: "gh workflow run publish-pages.yml --ref " + cfg.Release.SourceBranch, Reason: "Builds the catalog/operator portal from released artifacts, SBOMs, signatures, provenance, and scans."},
			{ID: "remediation", Title: "Keep scheduled remediation conservative", Command: "gh variable set CLEARCUTT_SCHEDULED_REMEDIATION_DRAFTS --body false", Reason: "Leave scheduled patch drafting off until deterministic evidence-backed fixes are acceptable for the fork."},
		},
		VerificationCommands: []PlatformReleaseCommand{
			{ID: "catalog", Title: "Validate generated catalog", Command: "clearcutt catalog validate --catalog site/src/data/catalog", Reason: "Checks the catalog shape after release ingestion."},
			{ID: "policy", Title: "Run catalog policy gate", Command: "clearcutt verify image java21-distroless --require-signature --require-sbom --require-provenance --allow-preview", Reason: "Exercises the catalog policy gate; this is not the live registry cryptographic verifier."},
			{ID: "release-evidence", Title: "Verify live release evidence", Command: "clearcutt verify release-evidence --ref " + cfg.ImageName("java21") + ":distroless --repo " + cfg.RepoPath() + " --workflow-identity " + cfg.Release.WorkflowIdentity + " --source-ref " + releaseRef + " --source-branch " + cfg.Release.SourceBranch + " --core-dir core", Reason: "Verifies registry-side signature, SBOM, provenance, and workflow identity for a published image using the scaffolded Nix-backed verifier toolchain."},
		},
		Boundaries: []PlatformReleaseBoundary{
			{Area: "CLI orchestration", Owner: "ClearCutt CLI", Note: "Scaffolds fleet repos, derives matrices, resolves registry settings, runs platform checks, owns reusable publish/assemble/verify/finalize commands, and emits this release plan."},
			{Area: "Trusted builder", Owner: "GitHub Actions plus SLSA generator", Note: "SLSA Build L3 provenance depends on the GitHub-hosted trusted builder identity configured in release.workflowIdentity and release.slsaBuilder."},
			{Area: "Image construction", Owner: "Nix backend invoked by CLI/workflows", Note: "Nix remains the platform-owner backend for reproducible image closures and also supplies pinned SBOM, scan, and Cosign release tools to the Go-owned paths."},
			{Area: "Signing and referrers", Owner: "Cosign, registry APIs, and core-pinned verifier tools", Note: "The CLI owns image push, multi-arch index assembly, and verifier sequencing in the Go paths. Cosign, SLSA verifier, and GitHub attestation verification run from the core Nix environment when --core-dir is used."},
			{Area: "Remediation", Owner: "ClearCutt CLI; retained Python/LLM backend only for fallback campaigns", Note: "Scheduled drafting is deterministic and LLM-off by default, but remediation still produces gated PRs rather than silent production mutation."},
		},
		Status: status,
	}
}

func workflowDefaultExpressionValue(root, workflowPath, varName, fallback string) string {
	raw, err := os.ReadFile(filepath.Join(root, workflowPath))
	if err != nil {
		return fallback
	}
	needle := varName + " || '"
	body := string(raw)
	idx := strings.Index(body, needle)
	if idx < 0 {
		return fallback
	}
	start := idx + len(needle)
	end := strings.Index(body[start:], "'")
	if end < 0 {
		return fallback
	}
	value := strings.TrimSpace(body[start : start+end])
	if value == "" {
		return fallback
	}
	return value
}

func printPlatformReleasePlan(plan PlatformReleasePlan) error {
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, plan)
	case "yaml", "yml":
		return output.PrintYAML(out, plan)
	default:
		fmt.Fprintf(out, "ClearCutt release plan for %s\n\n", plan.Repository)
		fmt.Fprintf(out, "Registry: %s (%s)\n", plan.Registry.RegistryBase, plan.Registry.SupportTier)
		fmt.Fprintf(out, "CLI: %s@%s via %s (%s)\n", plan.CLI.DefaultRepo, plan.CLI.DefaultVersion, plan.CLI.InstallAction, plan.CLI.DefaultMode)
		fmt.Fprintf(out, "Builder: %s, SLSA builder %s\n", plan.Builder.PrimaryCI, plan.Builder.SLSABuilder)
		fmt.Fprintf(out, "Release identity: %s\n", plan.Builder.ReleaseIdentity)
		fmt.Fprintf(out, "Matrix: %d runtime lines x %d tiers x %d systems; %d service images\n\n", plan.Matrix.RuntimeLines, len(plan.Matrix.Tiers), len(plan.Matrix.Systems), plan.Matrix.Services)
		printReleasePlanSettings("Required GitHub variables", plan.RequiredVariables)
		printReleasePlanSettings("Required GitHub secrets", plan.RequiredSecrets)
		printReleasePlanCommands("Local checks", plan.LocalChecks)
		printReleasePlanCommands("Release steps", plan.ReleaseSteps)
		printReleasePlanCommands("Verification commands", plan.VerificationCommands)
		fmt.Fprintln(out, "Boundaries:")
		for _, boundary := range plan.Boundaries {
			fmt.Fprintf(out, "- %s: %s owns this. %s\n", boundary.Area, boundary.Owner, boundary.Note)
		}
		fmt.Fprintf(out, "\nCurrent platform status: %s\n", plan.Status.Status)
		return nil
	}
}

func printReleasePlanSettings(title string, settings []PlatformReleaseSetting) {
	fmt.Fprintln(out, title+":")
	for _, setting := range settings {
		req := "optional"
		if setting.Required {
			req = "required"
		}
		fmt.Fprintf(out, "- %s (%s): %s\n", setting.Name, req, setting.Reason)
	}
	fmt.Fprintln(out)
}

func printReleasePlanCommands(title string, commands []PlatformReleaseCommand) {
	fmt.Fprintln(out, title+":")
	for _, command := range commands {
		fmt.Fprintf(out, "- %s: %s\n  %s\n", command.Title, command.Command, command.Reason)
	}
	fmt.Fprintln(out)
}

func addPlatformDoctorWorkflowChecks(root string, add func(string, string, string)) {
	checkFileContainsAll(
		root,
		".github/workflows/release.yml",
		[]string{"contents: write", "packages: write", "id-token: write"},
		"release.permissions",
		"release workflow can tag releases, push packages, and mint OIDC attestations",
		add,
	)
	checkFileContainsAll(
		root,
		".github/workflows/publish-pages.yml",
		[]string{"packages: read", "pages: write", "id-token: write"},
		"catalog.permissions",
		"catalog workflow can read package evidence and deploy Pages with OIDC",
		add,
	)
}

func collectPlatformStatus(root, configPath string) PlatformStatus {
	cfg, err := fleet.Load(joinRoot(root, configPath))
	checks := []PlatformStatusCheck{}
	add := func(id, status, msg string) {
		checks = append(checks, PlatformStatusCheck{ID: id, Status: status, Message: msg})
	}

	if err != nil {
		add("fleet.config", "fail", fmt.Sprintf("fleet config missing or invalid: %v", err))
	} else {
		add("fleet.config", "pass", fmt.Sprintf("loaded %s for %s", configPath, cfg.RepoPath()))
		if len(cfg.Matrix.Languages) > 0 && len(cfg.Matrix.Tiers) > 0 && len(cfg.Matrix.Systems) > 0 {
			add("fleet.matrix", "pass", fmt.Sprintf("%d languages x %d tiers x %d systems", len(cfg.Matrix.Languages), len(cfg.Matrix.Tiers), len(cfg.Matrix.Systems)))
			add("fleet.matrix.runtime-lines", "pass", "selected runtime lines are supported by the ClearCutt fleet config contract")
		} else {
			add("fleet.matrix", "fail", "matrix languages, tiers, and systems are required")
		}
		checkRegistrySupportContract(cfg, add)
		checkFileContains(root, "core/lib/platform-metadata.nix", cfg.RepoURL(), "fleet.metadata", "Nix image labels use the fork-local GitHub source URL", add)
		if strings.EqualFold(cfg.Admission.Engine, "kyverno") {
			checkFileContains(root, "examples/k8s-deployment/kyverno-policy.yaml", cfg.RegistryBase(), "admission.identity", "admission policy pins the fork image namespace and signing identity", add)
		}
		checkReleaseIdentityContract(root, cfg, add)
	}

	checkFileContains(root, ".github/workflows/release.yml", "clearcutt fleet workflow-matrices", "release.workflow", "release workflow derives its matrices from clearcutt.fleet.yaml through the CLI", add)
	checkFileNotContains(root, ".github/workflows/release.yml", "matrix export --source fleet", "release.no-inline-matrix-jq", "release workflow no longer shapes matrix outputs with inline jq", add)
	checkFileContains(root, ".github/workflows/release.yml", "clearcutt platform setup-nix", "release.nix", "release workflow delegates fork-specific Nix setup to the CLI", add)
	checkFileContains(root, ".github/workflows/release.yml", "clearcutt fleet publish-target", "release.publish", "release workflow delegates single-arch fleet publication to the CLI", add)
	checkFileContains(root, ".github/workflows/release.yml", "clearcutt fleet assemble-target", "release.assemble", "release workflow delegates multi-arch assembly, signing, and OCI attestations to the CLI", add)
	checkFileContains(root, ".github/workflows/release.yml", "fleet build-cli-assets", "release.cli-assets", "release workflow delegates CLI binary matrix, signing, and checksums to the CLI", add)
	checkFileNotContains(root, ".github/workflows/release.yml", "platforms=(", "release.no-inline-cli-matrix", "release workflow no longer owns the CLI binary platform matrix in inline shell", add)
	checkFileNotContains(root, ".github/workflows/release.yml", "cosign sign-blob --yes \"$file\"", "release.no-inline-cli-signing-loop", "release workflow no longer owns the CLI binary signing loop in inline shell", add)
	checkFileNotContains(root, ".github/workflows/release.yml", "sha256sum clearcutt-*", "release.no-inline-cli-checksums", "release workflow no longer owns CLI checksum generation in inline shell", add)
	checkFileContains(root, ".github/workflows/release.yml", "clearcutt fleet finalize-release", "release.finalize", "release workflow delegates release assets and notes to the CLI", add)
	checkFileContains(root, ".github/workflows/release.yml", "clearcutt platform registry-env", "release.registry", "release workflow resolves registry login host from the fleet config", add)
	checkFileContains(root, ".github/workflows/release.yml", "./.github/actions/install-clearcutt", "release.cli-install", "release workflow installs the configured ClearCutt CLI instead of rebuilding it in fleet jobs", add)
	checkFileContains(root, ".github/workflows/release.yml", "slsa-github-generator", "release.slsa", "release workflow keeps SLSA Build L3 generator provenance", add)
	checkFileContains(root, ".github/workflows/seed-nix-cache.yml", "clearcutt fleet seed-cache-plan", "seed-cache.plan", "seed cache workflow delegates dry-run planning to the CLI", add)
	checkFileContains(root, ".github/workflows/seed-nix-cache.yml", "clearcutt fleet publish-cache", "seed-cache.publish", "seed cache workflow delegates cache publication to the CLI", add)
	checkFileNotContains(root, ".github/workflows/seed-nix-cache.yml", "jq -c '.include[]'", "seed-cache.no-inline-jq-loop", "seed cache workflow no longer owns matrix iteration with inline jq", add)
	checkFileContains(root, ".github/actions/install-clearcutt/action.yml", "cosign verify-blob", "cli.install-action", "ClearCutt CLI install action verifies released binaries before use", add)
	checkFileContains(root, ".github/actions/setup-nix/action.yml", "clearcutt platform setup-nix applies fork-specific fleet cache config", "nix.install", "Nix installer action is generic and leaves fork-specific setup to the CLI", add)
	checkFileNotContains(root, "core/flake.nix", "nix-cache.clearcutt.dev", "nix.flake", "core flake does not hardcode the upstream Nix cache", add)
	checkFileContains(root, ".github/workflows/pr-gate.yml", "clearcutt fleet certify-target", "pr.certify", "PR gate delegates fleet target certification to the CLI", add)
	checkFileContains(root, ".github/workflows/pr-gate.yml", "clearcutt platform setup-nix", "pr.nix", "PR gate delegates fork-specific Nix setup to the CLI", add)
	checkFileContains(root, ".github/workflows/pr-gate.yml", "clearcutt fleet workflow-matrices", "pr.matrix", "PR gate derives its matrices from clearcutt.fleet.yaml through the CLI", add)
	checkFileNotContains(root, ".github/workflows/pr-gate.yml", "matrix export --source fleet", "pr.no-inline-matrix-jq", "PR gate no longer shapes matrix outputs with inline jq", add)
	checkFileContains(root, ".github/workflows/pr-gate.yml", "./.github/actions/install-clearcutt", "pr.cli-install", "PR fleet and integration jobs install the configured ClearCutt CLI", add)
	checkFileContains(root, ".github/workflows/pr-gate.yml", "clearcutt verify boundary-suite", "pr.boundary-suite", "PR gate delegates representative image-security boundary gates to the CLI", add)
	checkFileContains(root, ".github/workflows/publish-pages.yml", "clearcutt catalog build", "catalog.workflow", "catalog workflow uses the canonical catalog build command", add)
	checkFileContains(root, ".github/workflows/publish-pages.yml", "clearcutt catalog workflow-params", "catalog.workflow-params", "catalog workflow derives release limit and scan depth through the CLI", add)
	checkFileNotContains(root, ".github/workflows/publish-pages.yml", "matrix export --source fleet", "catalog.no-inline-param-jq", "catalog workflow no longer parses fleet catalog settings with inline jq", add)
	checkFileContains(root, ".github/workflows/publish-pages.yml", "clearcutt catalog site build", "catalog.site-build", "catalog workflow delegates site packaging to the CLI", add)
	checkFileContains(root, ".github/workflows/publish-pages.yml", "--generate-vex", "catalog.vex", "catalog workflow delegates OpenVEX publication to the CLI", add)
	checkFileNotContains(root, ".github/workflows/publish-pages.yml", "jq -r '.images[].id'", "catalog.no-inline-vex-jq", "catalog workflow no longer loops over catalog image ids with inline jq", add)
	checkFileContains(root, ".github/workflows/publish-pages.yml", "clearcutt platform setup-nix", "catalog.nix", "catalog workflow delegates fork-specific Nix setup to the CLI", add)
	checkFileContains(root, ".github/workflows/publish-pages.yml", "--core-dir core", "catalog.scan.nix", "catalog workflow runs scanner tooling through the Nix backend", add)
	checkFileContains(root, ".github/workflows/publish-pages.yml", "--update-db", "catalog.scan.update-db", "catalog workflow asks the CLI to refresh the Grype database", add)
	checkFileNotContains(root, ".github/workflows/publish-pages.yml", "GRYPE_TARBALL", "catalog.no-grype-install-shell", "catalog workflow no longer installs Grype with inline shell", add)
	checkFileNotContains(root, ".github/workflows/publish-pages.yml", "if [[ \"${FORCE_REFRESH_ALL}\"", "catalog.no-force-branch-shell", "catalog workflow no longer branches around force-refresh in shell", add)
	checkFileContains(root, ".github/workflows/publish-pages.yml", "clearcutt platform registry-env", "catalog.registry", "catalog workflow resolves registry login host from the fleet config", add)
	checkFileContains(root, ".github/workflows/publish-pages.yml", "./.github/actions/install-clearcutt", "catalog.cli-install", "catalog workflow installs the configured ClearCutt CLI", add)
	checkPath(root, ".github/actions/certify-app/action.yml", "certify.action", "composite certify action is available for app teams", add)
	for _, runtime := range []string{"java", "node", "python", "go"} {
		checkPath(root, filepath.Join("examples", "clearcutt-template-"+runtime, "Dockerfile"), "template."+runtime, "app template exists for "+runtime, add)
	}

	return platformStatusFromChecks(checks)
}

func platformStatusFromChecks(checks []PlatformStatusCheck) PlatformStatus {
	hasFail := false
	hasWarn := false
	for _, check := range checks {
		if check.Status == "fail" {
			hasFail = true
		}
		if check.Status == "warn" {
			hasWarn = true
		}
	}
	status := "pass"
	if hasFail {
		status = "fail"
	} else if hasWarn {
		status = "warn"
	}
	return PlatformStatus{Status: status, Checks: checks}
}

func printPlatformStatus(result PlatformStatus) error {
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		if err := output.PrintJSON(out, result); err != nil {
			return err
		}
	case "yaml", "yml":
		if err := output.PrintYAML(out, result); err != nil {
			return err
		}
	default:
		tp := output.NewTablePrinter("CHECK", "STATUS", "MESSAGE")
		for _, check := range result.Checks {
			tp.AddRow(check.ID, check.Status, check.Message)
		}
		if err := tp.Print(out); err != nil {
			return err
		}
	}
	return nil
}

func addGithubDoctorChecks(cfg fleet.Config, repoOverride string, add func(string, string, string)) {
	repo := strings.TrimSpace(repoOverride)
	if repo == "" {
		repo = cfg.RepoPath()
	}

	var repoView struct {
		NameWithOwner    string `json:"nameWithOwner"`
		DefaultBranchRef struct {
			Name string `json:"name"`
		} `json:"defaultBranchRef"`
	}
	if err := ghJSON(&repoView, "repo", "view", repo, "--json", "nameWithOwner,defaultBranchRef"); err != nil {
		add("github.repo", "fail", fmt.Sprintf("gh repo view %s failed: %v", repo, err))
		return
	}
	if repoView.NameWithOwner == cfg.RepoPath() {
		add("github.repo", "pass", fmt.Sprintf("GitHub repository %s is reachable", repoView.NameWithOwner))
	} else {
		add("github.repo", "fail", fmt.Sprintf("GitHub repository is %s, expected %s", repoView.NameWithOwner, cfg.RepoPath()))
	}
	if repoView.DefaultBranchRef.Name == cfg.Release.SourceBranch {
		add("github.defaultBranch", "pass", fmt.Sprintf("default branch is %s", repoView.DefaultBranchRef.Name))
	} else {
		add("github.defaultBranch", "fail", fmt.Sprintf("default branch is %s, expected %s", repoView.DefaultBranchRef.Name, cfg.Release.SourceBranch))
	}

	repoAPI := "repos/" + repo
	var actionsPerms struct {
		Enabled        bool   `json:"enabled"`
		AllowedActions string `json:"allowed_actions"`
	}
	if err := ghJSON(&actionsPerms, "api", repoAPI+"/actions/permissions"); err != nil {
		add("github.actions", "fail", fmt.Sprintf("read Actions permissions: %v", err))
	} else if actionsPerms.Enabled {
		add("github.actions", "pass", "GitHub Actions is enabled")
		if actionsPerms.AllowedActions == "all" || actionsPerms.AllowedActions == "local_only" || actionsPerms.AllowedActions == "selected" {
			addGithubActionsPolicyCheck(repoAPI, actionsPerms.AllowedActions, add)
		}
	} else {
		add("github.actions", "fail", "GitHub Actions is disabled")
	}

	var workflowPerms struct {
		DefaultWorkflowPermissions string `json:"default_workflow_permissions"`
		CanApprovePRReviews        bool   `json:"can_approve_pull_request_reviews"`
	}
	if err := ghJSON(&workflowPerms, "api", repoAPI+"/actions/permissions/workflow"); err != nil {
		add("github.workflowPermissions", "fail", fmt.Sprintf("read workflow permissions: %v", err))
	} else if workflowPerms.DefaultWorkflowPermissions == "write" {
		add("github.workflowPermissions", "pass", "workflow permissions allow read/write tokens")
	} else {
		add("github.workflowPermissions", "fail", fmt.Sprintf("workflow permissions are %q, expected write", workflowPerms.DefaultWorkflowPermissions))
	}

	var environment struct {
		Name            string `json:"name"`
		ProtectionRules []struct {
			Type string `json:"type"`
		} `json:"protection_rules"`
	}
	if err := ghJSON(&environment, "api", repoAPI+"/environments/production"); err != nil {
		add("github.environment.production", "fail", fmt.Sprintf("production environment is missing or inaccessible: %v", err))
	} else if environment.Name == "production" {
		add("github.environment.production", "pass", "production environment exists")
		if len(environment.ProtectionRules) > 0 {
			add("github.environment.protection", "pass", "production environment has protection rules")
		} else {
			add("github.environment.protection", "warn", "production environment has no protection rules; first releases will not require reviewer approval")
		}
	} else {
		add("github.environment.production", "fail", fmt.Sprintf("unexpected production environment response %q", environment.Name))
	}

	var pages struct {
		BuildType string `json:"build_type"`
	}
	if err := ghJSON(&pages, "api", repoAPI+"/pages"); err != nil {
		add("github.pages", "fail", fmt.Sprintf("GitHub Pages is not configured for Actions: %v", err))
	} else if pages.BuildType == "workflow" {
		add("github.pages", "pass", "GitHub Pages is configured for Actions")
	} else {
		add("github.pages", "fail", fmt.Sprintf("GitHub Pages build_type is %q, expected workflow", pages.BuildType))
	}

	var secrets []githubName
	secretErr := ghJSON(&secrets, "secret", "list", "--repo", repo, "--json", "name")
	checkGithubOptionalSecretReadiness(cfg, secrets, secretErr, add)

	if cfg.Registry.Host == "ghcr.io" {
		add("github.registryCredentials", "pass", "GHCR path can use GITHUB_TOKEN unless a fork overrides registry credentials")
		return
	}
	checkGithubRegistryCredentialNames(repo, secrets, secretErr, add)
}

func addGithubActionsPolicyCheck(repoAPI, allowedActions string, add func(string, string, string)) {
	switch allowedActions {
	case "all":
		add("github.actionsPolicy", "pass", "GitHub Actions policy allows required third-party and reusable actions")
	case "local_only":
		add("github.actionsPolicy", "fail", "GitHub Actions policy allows only local actions; release requires third-party and reusable actions")
	case "selected":
		add("github.actionsPolicy", "warn", "GitHub Actions policy is selected; confirm checkout, setup-go, cosign, docker, nix, upload/download artifact, Pages, and SLSA generator actions are allowed")
	}
}

func checkGithubOptionalSecretReadiness(cfg fleet.Config, secrets []githubName, secretErr error, add func(string, string, string)) {

	cache := cfg.Release.NixCache
	if cache.Bucket == "" && cache.PublicBaseURL == "" && cache.SigningKeyName == "" {
		return
	}
	if secretErr != nil {
		add("github.nixCacheSecrets", "warn", fmt.Sprintf("configured release.nixCache could not be checked against GitHub secrets: %v", secretErr))
		return
	}
	required := []string{"NIX_CACHE_SECRET_KEY", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "CLOUDFLARE_ACCOUNT_ID"}
	var missing []string
	for _, name := range required {
		if !githubNameListContains(secrets, name) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		add("github.nixCacheSecrets", "warn", "configured release.nixCache is missing GitHub secrets: "+strings.Join(missing, ", "))
		return
	}
	add("github.nixCacheSecrets", "pass", "configured release.nixCache has required GitHub secret names")
}

func checkGithubRegistryCredentialNames(repo string, secrets []githubName, secretErr error, add func(string, string, string)) {
	var variables []githubName
	varErr := ghJSON(&variables, "variable", "list", "--repo", repo, "--json", "name")
	if varErr != nil || secretErr != nil {
		add("github.registryCredentials", "fail", fmt.Sprintf("non-GHCR registry requires CLEARCUTT_REGISTRY_USER/TOKEN; read failed: variables=%v secrets=%v", varErr, secretErr))
		return
	}
	if !githubNameListContains(variables, "CLEARCUTT_REGISTRY_USER") || !githubNameListContains(secrets, "CLEARCUTT_REGISTRY_TOKEN") {
		add("github.registryCredentials", "fail", "non-GHCR registry requires CLEARCUTT_REGISTRY_USER variable and CLEARCUTT_REGISTRY_TOKEN secret")
		return
	}
	add("github.registryCredentials", "pass", "non-GHCR registry credentials are configured")
}

func ghJSON(target any, args ...string) error {
	raw, err := captureExternalOutput(externalCommand{Name: "gh", Args: args})
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(raw), target); err != nil {
		return fmt.Errorf("parse gh JSON: %w", err)
	}
	return nil
}

type githubName struct {
	Name string `json:"name"`
}

func githubNameListContains(items []githubName, name string) bool {
	for _, item := range items {
		if item.Name == name {
			return true
		}
	}
	return false
}

func checkRegistrySupportContract(cfg fleet.Config, add func(string, string, string)) {
	if strings.TrimSpace(cfg.Registry.Host) == "" {
		add("registry.host", "fail", "registry.host is required")
		return
	}
	if strings.TrimSpace(cfg.Registry.Owner) == "" || strings.TrimSpace(cfg.Registry.Repository) == "" || strings.TrimSpace(cfg.Registry.ImagePrefix) == "" {
		add("registry.naming", "fail", "registry.owner, registry.repository, and registry.imagePrefix are required")
	} else {
		add("registry.naming", "pass", fmt.Sprintf("image names resolve under %s", cfg.RegistryBase()))
	}
	if cfg.Registry.Host == "ghcr.io" {
		add("registry.support", "pass", "GHCR reference path can use registry.host plus GITHUB_TOKEN when registry credentials are unset")
		return
	}
	add(
		"registry.support",
		"warn",
		fmt.Sprintf("non-GHCR host %q requires CLEARCUTT_REGISTRY_USER/TOKEN plus registry-specific proof for referrers and SLSA verification", cfg.Registry.Host),
	)
}

func runPlatformRegistryEnv() error {
	cfg, err := fleet.Load(platformOpts.configPath)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	env := platformRegistryEnv(cfg)
	if platformOpts.githubOutputPath != "" {
		if err := appendGitHubOutputs(platformOpts.githubOutputPath, map[string]string{
			"auth_mode":     env.AuthMode,
			"host":          env.Host,
			"image_prefix":  env.ImagePrefix,
			"owner":         env.Owner,
			"registry_base": env.RegistryBase,
			"repository":    env.Repository,
			"username":      env.Username,
		}); err != nil {
			return err
		}
	}
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, env)
	case "yaml", "yml":
		return output.PrintYAML(out, env)
	default:
		tp := output.NewTablePrinter("SETTING", "VALUE")
		tp.AddRow("host", env.Host)
		tp.AddRow("registryBase", env.RegistryBase)
		tp.AddRow("username", env.Username)
		tp.AddRow("authMode", env.AuthMode)
		return tp.Print(out)
	}
}

func platformRegistryEnv(cfg fleet.Config) PlatformRegistryEnv {
	host := strings.TrimSuffix(strings.TrimSpace(cfg.Registry.Host), "/")
	username := firstNonEmptyString(os.Getenv("CLEARCUTT_REGISTRY_USER"), os.Getenv("GITHUB_ACTOR"), cfg.Registry.Owner)
	authMode := "generic-token"
	if host == "ghcr.io" {
		authMode = "github-token"
	}
	return PlatformRegistryEnv{
		Host:         host,
		RegistryBase: strings.TrimSuffix(cfg.RegistryBase(), "/"),
		Owner:        cfg.Registry.Owner,
		Repository:   cfg.Registry.Repository,
		ImagePrefix:  cfg.Registry.ImagePrefix,
		Username:     username,
		AuthMode:     authMode,
	}
}

func checkReleaseIdentityContract(root string, cfg fleet.Config, add func(string, string, string)) {
	if cfg.Release.SourceBranch == "" {
		add("release.sourceBranch", "fail", "release.sourceBranch is required")
		return
	}
	expectedReleaseIdentity := fmt.Sprintf("https://github.com/%s/.github/workflows/release.yml@refs/heads/%s", cfg.RepoPath(), cfg.Release.SourceBranch)
	if cfg.Release.WorkflowIdentity != expectedReleaseIdentity {
		add("release.workflowIdentity", "fail", fmt.Sprintf("release.workflowIdentity must be %q for this repo/sourceBranch", expectedReleaseIdentity))
	} else {
		add("release.workflowIdentity", "pass", "release workflow identity matches fleet repo and source branch")
	}
	releaseRef := "refs/heads/" + cfg.Release.SourceBranch
	checkFileContains(root, ".github/workflows/release.yml", fmt.Sprintf("github.ref != '%s'", releaseRef), "release.sourceBranch.guard", "release workflow guard matches release.sourceBranch", add)
	checkFileContains(root, ".github/workflows/release.yml", "@${{ github.ref }}", "release.identity.dynamic", "release verifier derives workflow identity from the actual GitHub ref", add)

	// A rebase workflow is optional: `clearcutt app rebase` runs from any CI or a
	// developer machine, and a fleet that does not publish one has nothing to check.
	if strings.TrimSpace(cfg.Rebase.WorkflowIdentity) != "" {
		rebasePath, rebaseRef, ok := workflowIdentityPathAndRef(cfg.Rebase.WorkflowIdentity)
		if !ok {
			add("rebase.workflowIdentity", "fail", "rebase.workflowIdentity must be an exact workflow identity in this repo")
		} else if rebaseRef != releaseRef {
			add("rebase.workflowIdentity", "fail", fmt.Sprintf("rebase.workflowIdentity uses %s, expected %s", rebaseRef, releaseRef))
		} else {
			add("rebase.workflowIdentity", "pass", "rebase workflow identity matches fleet repo and source branch")
			checkPath(root, rebasePath, "rebase.workflowIdentity.path", "configured rebase workflow file exists", add)
		}
	}
}

func workflowIdentityPathAndRef(identity string) (string, string, bool) {
	const marker = "/.github/workflows/"
	i := strings.Index(identity, marker)
	if i < 0 {
		return "", "", false
	}
	relAndRef := identity[i+1:]
	parts := strings.SplitN(relAndRef, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func checkPath(root, rel, id, msg string, add func(string, string, string)) {
	if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
		add(id, "pass", msg)
	} else if errors.Is(err, os.ErrNotExist) {
		add(id, "fail", rel+" is missing")
	} else {
		add(id, "fail", err.Error())
	}
}

func checkFileContains(root, rel, needle, id, msg string, add func(string, string, string)) {
	raw, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		add(id, "fail", rel+" is missing")
		return
	}
	if strings.Contains(string(raw), needle) {
		add(id, "pass", msg)
		return
	}
	add(id, "fail", fmt.Sprintf("%s does not contain %q", rel, needle))
}

func checkFileContainsAll(root, rel string, needles []string, id, msg string, add func(string, string, string)) {
	raw, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		add(id, "fail", rel+" is missing")
		return
	}
	body := string(raw)
	var missing []string
	for _, needle := range needles {
		if !strings.Contains(body, needle) {
			missing = append(missing, needle)
		}
	}
	if len(missing) == 0 {
		add(id, "pass", msg)
		return
	}
	add(id, "fail", fmt.Sprintf("%s is missing %s", rel, strings.Join(missing, ", ")))
}

func checkFileNotContains(root, rel, needle, id, msg string, add func(string, string, string)) {
	raw, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		add(id, "fail", rel+" is missing")
		return
	}
	if strings.Contains(string(raw), needle) {
		add(id, "fail", fmt.Sprintf("%s still contains %q", rel, needle))
		return
	}
	add(id, "pass", msg)
}

func joinRoot(root, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}

func platformMetadataNix(cfg fleet.Config) string {
	return fmt.Sprintf(`# Generated by clearcutt platform init.
# Keep this aligned with clearcutt.fleet.yaml when operating a fork.

{
  repoPath = "%s";
  sourceURL = "%s";
  productName = "%s";
  imagePrefix = "%s";
  vendor = "%s";
  authors = "%s";
}
`, nixString(cfg.RepoPath()), nixString(cfg.RepoURL()), nixString(cfg.Branding.ProductName), nixString(cfg.Registry.ImagePrefix), nixString(cfg.Branding.Vendor), nixString(cfg.Branding.Authors))
}

func nixString(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func platformKitDoc(cfg fleet.Config) string {
	return fmt.Sprintf(`# ClearCutt Platform Fleet Kit

This repository is configured as a platform-owned ClearCutt fleet kit. Platform
teams own the GitHub repository, registry namespace, OIDC release identity,
catalog site, admission policies, and remediation review loop.

For the extension model, see docs/extending-clearcutt.md: app teams use
templates and devcontainers, fleet owners edit %[1]s, and Nix stays in the
backend authoring path.

## Golden Path

1. Review and edit %[1]s. Use clearcutt matrix explain java21 and clearcutt matrix add java25 for built-in runtime lines; use clearcutt runtime scaffold ruby3.4 plus clearcutt runtime validate ruby3.4 for new runtime families. Unsupported IDs fail at the fleet config layer before the Nix backend runs.
2. Create and protect the GitHub Environment named production, then enable GitHub Pages from Actions.
3. Keep the scaffolded workflow default of installing a verified ClearCutt release
   with .github/actions/install-clearcutt. Set CLEARCUTT_CLI_VERSION to pin a
   newer release, CLEARCUTT_CLI_REPO for a forked CLI publisher, or
   CLEARCUTT_CLI_MODE=local only when intentionally dogfooding local source.
4. Keep the weekly remediation scan in plan/report mode by default. Set
   CLEARCUTT_SCHEDULED_REMEDIATION_DRAFTS=true only when deterministic,
   evidence-backed fixes should draft the single rolling remediation PR on
   schedule; scheduled drafting runs with LLM escalation off and still requires
   PR review before merge.
5. Run clearcutt platform registry-env to confirm the registry host and login
   username resolve from %[1]s and the runner environment.
6. Run clearcutt platform status before the first release.
7. Run clearcutt platform release-plan to print the generated first-release
   runbook, including registry support tier, required GitHub variables/secrets,
   local checks, release steps, verification commands, and the boundary between
   CLI-owned orchestration, GitHub Actions/SLSA, Nix, Sigstore tooling, and
   remediation PR drafting.
8. Run clearcutt platform doctor --github after pushing the repo to verify GitHub Actions, workflow token permissions, the production environment, Pages, default branch, registry credential readiness, local workflow permissions, and optional remediation/cache prerequisites.
10. Run clearcutt platform setup-nix only on machines or runners that will build the fleet. It reads %[1]s, writes optional nix.conf/GitHub NIX_CONFIG state, and warms or runs the core dev shell.
11. Run the release workflow to publish the configured fleet to %[2]s. The workflow is a GitHub identity runner; clearcutt platform setup-nix owns fork-specific Nix client setup, and clearcutt fleet certify-target, publish-target, assemble-target, verify-target, export-provenance, and finalize-release own the reusable release mechanics.
12. Let the catalog workflow run %[3]d-release ingestion with vulnerability scan depth %[4]s.
13. Give app teams the templates under %[5]s.
14. Gate on required signature, SBOM, provenance, and rebase-attestation evidence at CI and admission.

## Trust Story

- SLSA Build L3 provenance is produced by %[6]s.
- Release identity is pinned to %[7]s.
- Rebase identity is pinned to %[8]s.
- Vulnerability findings are gated by remediation.policy in %[1]s; ClearCutt reports and gates, it does not mutate published images.
`, fleet.DefaultConfigPath, cfg.RegistryBase(), cfg.Catalog.ReleaseLimit, cfg.Catalog.ScanDepth, "examples/clearcutt-template-*", cfg.Release.SLSABuilder, cfg.Release.WorkflowIdentity, cfg.Rebase.WorkflowIdentity)
}
