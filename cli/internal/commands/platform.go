package commands

import (
	"errors"
	"fmt"
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

	cmd.AddCommand(initCmd, statusCmd)
	return cmd
}

func runPlatformInit() error {
	root := platformOpts.outputDir
	cfgPath := joinRoot(root, platformOpts.configPath)
	owner := platformOpts.owner
	repo := platformOpts.repo
	if owner == "" {
		owner = "northcutted"
	}
	if repo == "" {
		repo = "clearcutt"
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
	return nil
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
		} else {
			add("fleet.matrix", "fail", "matrix languages, tiers, and systems are required")
		}
		if cfg.Remediation.Mode == "approved-pr" {
			add("remediation.mode", "pass", "approved automated remediation is configured as gated PR drafting")
		} else {
			add("remediation.mode", "fail", "remediation mode must be approved-pr")
		}
		checkFileContains(root, "core/lib/platform-metadata.nix", cfg.RepoURL(), "fleet.metadata", "Nix image labels use the fork-local GitHub source URL", add)
	}

	checkFileContains(root, ".github/workflows/release.yml", "matrix export --source fleet", "release.workflow", "release workflow derives its matrix from clearcutt.fleet.yaml", add)
	checkFileContains(root, ".github/workflows/release.yml", "slsa-github-generator", "release.slsa", "release workflow keeps SLSA Build L3 generator provenance", add)
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
  vendor = "%s";
  authors = "%s";
}
`, nixString(cfg.RepoPath()), nixString(cfg.RepoURL()), nixString(cfg.Registry.Owner), nixString(cfg.Registry.Owner+" platform team"))
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

## Golden Path

1. Review and edit %[1]s.
2. Create and protect the GitHub Environment named production, then enable GitHub Pages from Actions.
3. Run clearcutt platform status before the first release.
4. Run the release workflow to publish the configured fleet to %[2]s.
5. Let the catalog workflow run %[3]d-release ingestion with vulnerability scan depth %[4]s.
6. Give app teams the templates under %[5]s.
7. Enforce signatures, SBOMs, SLSA Build L3 provenance, and rebase attestations at CI and admission.

## Trust Story

- SLSA Build L3 provenance is produced by %[6]s.
- Release identity is pinned to %[7]s.
- Rebase identity is pinned to %[8]s.
- Remediation mode is %[9]s: the agent drafts bounded PRs for review, not silent production mutation.
`, fleet.DefaultConfigPath, cfg.RegistryBase(), cfg.Catalog.ReleaseLimit, cfg.Catalog.ScanDepth, "examples/clearcutt-template-*", cfg.Release.SLSABuilder, cfg.Release.WorkflowIdentity, cfg.Rebase.WorkflowIdentity, cfg.Remediation.Mode)
}
