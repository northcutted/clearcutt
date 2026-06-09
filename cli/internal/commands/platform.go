package commands

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
)

type platformFlags struct {
	configPath string
	outputDir  string
	owner      string
	repo       string
	force      bool
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

func NewPlatformCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "platform",
		Short: "Initialize and inspect a forkable ClearCutt platform kit",
		Long: `Initialize and inspect the forkable ClearCutt platform kit. The kit ties
fleet config, release workflows, catalog publishing, app templates, policy
generation, and approved remediation into one operator-facing product surface.`,
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Write starter fleet config, docs, and app templates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlatformInit()
		},
	}
	initCmd.Flags().StringVar(&platformOpts.configPath, "fleet-config", fleet.DefaultConfigPath, "Fleet config path to write")
	initCmd.Flags().StringVar(&platformOpts.outputDir, "output", ".", "Repository root/output directory")
	initCmd.Flags().StringVar(&platformOpts.owner, "owner", "", "GitHub owner/org for the fleet (default northcutted)")
	initCmd.Flags().StringVar(&platformOpts.repo, "repo", "", "GitHub repository for the fleet (default clearcutt)")
	initCmd.Flags().BoolVar(&platformOpts.force, "force", false, "Overwrite existing generated files")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Check whether the platform kit is wired together",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlatformStatus()
		},
	}
	statusCmd.Flags().StringVar(&platformOpts.configPath, "fleet-config", fleet.DefaultConfigPath, "Fleet config path to inspect")
	statusCmd.Flags().StringVar(&platformOpts.outputDir, "output", ".", "Repository root to inspect")

	cmd.AddCommand(initCmd, statusCmd, NewPlatformSetupNixCmd())
	return cmd
}

func runPlatformInit() error {
	root := platformOpts.outputDir
	cfgPath := joinRoot(root, platformOpts.configPath)
	owner := platformOpts.owner
	repo := platformOpts.repo
	if owner == "" {
		owner = fleet.ReferenceOwner
	}
	if repo == "" {
		repo = fleet.ReferenceRepo
	}
	cfg := fleet.DefaultConfig(owner, repo)
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
	cfg, err := fleet.Load(joinRoot(root, platformOpts.configPath))
	checks := []PlatformStatusCheck{}
	hasFail := false
	add := func(id, status, msg string) {
		checks = append(checks, PlatformStatusCheck{ID: id, Status: status, Message: msg})
		if status == "fail" {
			hasFail = true
		}
	}

	if err != nil {
		add("fleet.config", "fail", fmt.Sprintf("fleet config missing or invalid: %v", err))
	} else {
		add("fleet.config", "pass", fmt.Sprintf("loaded %s for %s", platformOpts.configPath, cfg.RepoPath()))
		if len(cfg.Matrix.Languages) > 0 && len(cfg.Matrix.Tiers) > 0 && len(cfg.Matrix.Systems) > 0 {
			add("fleet.matrix", "pass", fmt.Sprintf("%d languages x %d tiers x %d systems", len(cfg.Matrix.Languages), len(cfg.Matrix.Tiers), len(cfg.Matrix.Systems)))
			add("fleet.matrix.runtime-lines", "pass", "selected runtime lines are supported by the ClearCutt fleet config contract")
		} else {
			add("fleet.matrix", "fail", "matrix languages, tiers, and systems are required")
		}
		if cfg.Remediation.Mode == "approved-pr" {
			add("remediation.mode", "pass", "approved automated remediation is configured as gated PR drafting")
		} else {
			add("remediation.mode", "fail", "remediation mode must be approved-pr")
		}
		checkFileContains(root, "core/lib/platform-metadata.nix", cfg.RepoURL(), "fleet.metadata", "Nix image labels use the fork-local GitHub source URL", add)
		if strings.EqualFold(cfg.Admission.Engine, "kyverno") {
			checkFileContains(root, "examples/k8s-deployment/kyverno-policy.yaml", cfg.RegistryBase(), "admission.identity", "admission policy pins the fork image namespace and signing identity", add)
		}
		checkReleaseIdentityContract(root, cfg, add)
	}

	checkFileContains(root, ".github/workflows/release.yml", "matrix export --source fleet", "release.workflow", "release workflow derives its matrix from clearcutt.fleet.yaml", add)
	checkFileContains(root, ".github/workflows/release.yml", "clearcutt platform setup-nix", "release.nix", "release workflow delegates fork-specific Nix setup to the CLI", add)
	checkFileContains(root, ".github/workflows/release.yml", "clearcutt fleet publish-target", "release.publish", "release workflow delegates single-arch fleet publication to the CLI", add)
	checkFileContains(root, ".github/workflows/release.yml", "clearcutt fleet assemble-target", "release.assemble", "release workflow delegates multi-arch assembly, signing, and OCI attestations to the CLI", add)
	checkFileContains(root, ".github/workflows/release.yml", "clearcutt fleet finalize-release", "release.finalize", "release workflow delegates release assets and notes to the CLI", add)
	checkFileContains(root, ".github/workflows/release.yml", "slsa-github-generator", "release.slsa", "release workflow keeps SLSA Build L3 generator provenance", add)
	checkFileContains(root, ".github/actions/setup-nix/action.yml", "clearcutt platform setup-nix applies fork-specific fleet cache config", "nix.install", "Nix installer action is generic and leaves fork-specific setup to the CLI", add)
	checkFileNotContains(root, "core/flake.nix", "nix-cache.clearcutt.dev", "nix.flake", "core flake does not hardcode the upstream Nix cache", add)
	checkFileContains(root, ".github/workflows/pr-gate.yml", "clearcutt fleet certify-target", "pr.certify", "PR gate delegates fleet target certification to the CLI", add)
	checkFileContains(root, ".github/workflows/pr-gate.yml", "clearcutt platform setup-nix", "pr.nix", "PR gate delegates fork-specific Nix setup to the CLI", add)
	checkFileContains(root, ".github/workflows/pr-gate.yml", "matrix export --source fleet", "pr.matrix", "PR gate derives its matrix from clearcutt.fleet.yaml", add)
	checkFileContains(root, ".github/workflows/rebase.yml", "app rebase", "rebase.workflow", "rebase workflow exists for the configured platform OIDC identity", add)
	checkFileContains(root, ".github/workflows/publish-pages.yml", "clearcutt catalog build", "catalog.workflow", "catalog workflow uses the canonical catalog build command", add)
	checkPath(root, ".github/actions/certify-app/action.yml", "certify.action", "composite certify action is available for app teams", add)
	for _, runtime := range []string{"java", "node", "python", "go"} {
		checkPath(root, filepath.Join("examples", "clearcutt-template-"+runtime, "Dockerfile"), "template."+runtime, "app template exists for "+runtime, add)
	}

	status := "pass"
	if hasFail {
		status = "fail"
	}
	result := PlatformStatus{Status: status, Checks: checks}
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
		for _, check := range checks {
			tp.AddRow(check.ID, check.Status, check.Message)
		}
		if err := tp.Print(out); err != nil {
			return err
		}
	}
	if hasFail {
		return ErrCheckFailed
	}
	return nil
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

	rebasePath, rebaseRef, ok := workflowIdentityPathAndRef(cfg.Rebase.WorkflowIdentity)
	if !ok || !strings.HasPrefix(cfg.Rebase.WorkflowIdentity, "https://github.com/"+cfg.RepoPath()+"/.github/workflows/") {
		add("rebase.workflowIdentity", "fail", "rebase.workflowIdentity must be an exact workflow identity in this repo")
	} else if rebaseRef != releaseRef {
		add("rebase.workflowIdentity", "fail", fmt.Sprintf("rebase.workflowIdentity uses %s, expected %s", rebaseRef, releaseRef))
	} else {
		add("rebase.workflowIdentity", "pass", "rebase workflow identity matches fleet repo and source branch")
		checkPath(root, rebasePath, "rebase.workflowIdentity.path", "configured rebase workflow file exists", add)
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
	return fmt.Sprintf(`# ClearCutt Forkable Platform Kit

This repository is configured as a forkable platform kit. Platform teams own the
GitHub repository, GHCR namespace, OIDC release identity, catalog site, admission
policies, and remediation review loop.

For the extension model, see docs/extending-clearcutt.md: app teams use
templates and devcontainers, fleet owners edit %[1]s, and Nix stays in the
backend authoring path.

## Golden Path

1. Review and edit %[1]s. Use clearcutt matrix explain java21 and clearcutt matrix add java25 for built-in runtime lines; use clearcutt runtime scaffold ruby3.4 plus clearcutt runtime validate ruby3.4 for new runtime families. Unsupported IDs fail at the fleet config layer before the Nix backend runs.
2. Create and protect the GitHub Environment named production, then enable GitHub Pages from Actions.
3. Run clearcutt platform status before the first release.
4. Run clearcutt platform setup-nix only on machines or runners that will build the fleet. It reads %[1]s, writes optional nix.conf/GitHub NIX_CONFIG state, and warms or runs the core dev shell.
5. Run the release workflow to publish the configured fleet to %[2]s. The workflow is a GitHub identity runner; clearcutt platform setup-nix owns fork-specific Nix client setup, and clearcutt fleet certify-target, publish-target, assemble-target, verify-target, export-provenance, and finalize-release own the reusable release mechanics.
6. Let the catalog workflow run %[3]d-release ingestion with vulnerability scan depth %[4]s.
7. Give app teams the templates under %[5]s.
8. Gate on required signature, SBOM, provenance, and rebase-attestation evidence at CI and admission.

## Trust Story

- SLSA Build L3 provenance is produced by %[6]s.
- Release identity is pinned to %[7]s.
- Rebase identity is pinned to %[8]s.
- Remediation mode is %[9]s: the agent drafts bounded PRs for review, not silent production mutation.
`, fleet.DefaultConfigPath, cfg.RegistryBase(), cfg.Catalog.ReleaseLimit, cfg.Catalog.ScanDepth, "examples/clearcutt-template-*", cfg.Release.SLSABuilder, cfg.Release.WorkflowIdentity, cfg.Rebase.WorkflowIdentity, cfg.Remediation.Mode)
}
