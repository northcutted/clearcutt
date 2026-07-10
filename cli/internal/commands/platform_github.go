package commands

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

type CommandRunner interface {
	Run(ctx context.Context, name string, args []string, stdin []byte) (stdout string, stderr string, err error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, name string, args []string, stdin []byte) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = strings.NewReader(string(stdin))
	}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

var platformCommandRunner CommandRunner = execCommandRunner{}

type platformPlanFlags struct {
	dir          string
	owner        string
	repo         string
	profile      string
	visibility   string
	registryBase string
	pages        bool
	environment  string
	output       string
	generatedAt  string
}

type platformApplyFlags struct {
	plan    string
	confirm bool
}

type platformBootstrapFlags struct {
	render     platformRenderFlags
	output     string
	dryRun     bool
	apply      bool
	confirm    bool
	skipRender bool
}

type renderedControlPlanePlanState struct {
	profile      string
	owner        string
	repo         string
	visibility   string
	registryBase string
	pages        *bool
	environment  string
}

type renderedControlPlaneLock struct {
	Kind string `json:"kind"`
	Spec struct {
		Platform struct {
			Profile      string `json:"profile"`
			Owner        string `json:"owner"`
			Repo         string `json:"repo"`
			RegistryBase string `json:"registryBase"`
			Pages        *bool  `json:"pages"`
			Environment  string `json:"environment"`
		} `json:"platform"`
		Catalog struct {
			Source        string   `json:"source"`
			InventoryFile string   `json:"inventoryFile"`
			SourceRepo    string   `json:"sourceRepo"`
			Targets       []string `json:"targets"`
			ReleaseLimit  int      `json:"releaseLimit"`
		} `json:"catalog"`
	} `json:"spec"`
}

type PlatformGitHubPlan struct {
	APIVersion                    string                  `json:"apiVersion"`
	Kind                          string                  `json:"kind"`
	Profile                       string                  `json:"profile"`
	Owner                         string                  `json:"owner"`
	Repo                          string                  `json:"repo"`
	Repository                    string                  `json:"repository"`
	LocalDirectory                string                  `json:"localDirectory"`
	Visibility                    string                  `json:"visibility"`
	RegistryBase                  string                  `json:"registryBase"`
	Pages                         bool                    `json:"pages"`
	Environment                   string                  `json:"environment"`
	Operations                    []PlatformGitHubOp      `json:"operations"`
	RequiredUserPermissions       []string                `json:"requiredUserPermissions"`
	RequiredVariables             []PlatformGitHubSetting `json:"requiredVariables"`
	RequiredSecrets               []PlatformGitHubSetting `json:"requiredSecrets"`
	ManualSteps                   []string                `json:"manualSteps"`
	Commands                      []PlatformGitHubCommand `json:"commands"`
	RemoteMutationsRequireConfirm bool                    `json:"remoteMutationsRequireConfirm"`
}

type PlatformGitHubOp struct {
	ID              string `json:"id"`
	Summary         string `json:"summary"`
	Destructive     bool   `json:"destructive"`
	Remote          bool   `json:"remote"`
	RequiresConfirm bool   `json:"requiresConfirm"`
}

type PlatformGitHubSetting struct {
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
	Reason string `json:"reason"`
}

type PlatformGitHubCommand struct {
	OperationID string   `json:"operationId"`
	Name        string   `json:"-"`
	Args        []string `json:"-"`
	Command     string   `json:"command"`
}

var (
	platformPlanOpts      platformPlanFlags
	platformApplyOpts     platformApplyFlags
	platformBootstrapOpts platformBootstrapFlags
)

func NewPlatformPlanCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "plan", Short: "Plan remote control-plane changes"}
	githubCmd := &cobra.Command{
		Use:   "github",
		Short: "Plan GitHub repository setup for a rendered control plane",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := buildGitHubPlan(platformPlanOpts)
			if err != nil {
				return err
			}
			if platformPlanOpts.output != "" {
				if err := writePlanJSON(platformPlanOpts.output, plan); err != nil {
					return err
				}
				if !structuredFormat() {
					fmt.Fprintf(out, "wrote GitHub bootstrap plan to %s\n", platformPlanOpts.output)
					return printGitHubPlanHuman(plan)
				}
			}
			if structuredFormat() || platformPlanOpts.output != "" {
				return output.PrintJSON(out, plan)
			}
			return printGitHubPlanHuman(plan)
		},
	}
	addPlatformPlanGitHubFlags(githubCmd, &platformPlanOpts)
	cmd.AddCommand(githubCmd)
	return cmd
}

func NewPlatformApplyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "apply", Short: "Apply a confirmed control-plane plan"}
	githubCmd := &cobra.Command{
		Use:   "github",
		Short: "Apply a GitHub bootstrap plan",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !platformApplyOpts.confirm {
				return fmt.Errorf("refusing to mutate GitHub without --confirm")
			}
			plan, err := loadGitHubPlan(platformApplyOpts.plan)
			if err != nil {
				return err
			}
			return applyGitHubPlan(cmd.Context(), plan, platformCommandRunner)
		},
	}
	githubCmd.Flags().StringVar(&platformApplyOpts.plan, "plan", "", "Path to clearcutt platform plan github JSON")
	githubCmd.Flags().BoolVar(&platformApplyOpts.confirm, "confirm", false, "Confirm remote GitHub and local git mutations")
	_ = githubCmd.MarkFlagRequired("plan")
	cmd.AddCommand(githubCmd)
	return cmd
}

func NewPlatformBootstrapCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "bootstrap", Short: "Render and optionally apply a control-plane bootstrap"}
	githubCmd := &cobra.Command{
		Use:   "github",
		Short: "Render, plan, and optionally apply GitHub control-plane setup",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlatformBootstrapGitHub(cmd.Context(), platformBootstrapOpts)
		},
	}
	addPlatformRenderFlags(githubCmd, &platformBootstrapOpts.render)
	githubCmd.Flags().StringVar(&platformBootstrapOpts.output, "output", "", "Optional path for the generated plan JSON")
	githubCmd.Flags().BoolVar(&platformBootstrapOpts.dryRun, "dry-run", false, "Render and plan without calling gh or git")
	githubCmd.Flags().BoolVar(&platformBootstrapOpts.apply, "apply", false, "Apply the generated plan")
	githubCmd.Flags().BoolVar(&platformBootstrapOpts.confirm, "confirm", false, "Confirm remote GitHub and local git mutations")
	githubCmd.Flags().BoolVar(&platformBootstrapOpts.skipRender, "skip-render", false, "Plan/apply against an already rendered directory")
	cmd.AddCommand(githubCmd)
	return cmd
}

func addPlatformPlanGitHubFlags(cmd *cobra.Command, opts *platformPlanFlags) {
	cmd.Flags().StringVar(&opts.dir, "dir", "", "Rendered control-plane directory")
	cmd.Flags().StringVar(&opts.owner, "owner", "", "GitHub owner/org")
	cmd.Flags().StringVar(&opts.repo, "repo", "", "GitHub repository name")
	cmd.Flags().StringVar(&opts.profile, "profile", platformProfileCatalogOnly, "Control-plane profile: catalog-only or fleet")
	cmd.Flags().StringVar(&opts.visibility, "visibility", "private", "GitHub repository visibility: private, public, or internal")
	cmd.Flags().StringVar(&opts.registryBase, "registry-base", "", "OCI registry namespace")
	cmd.Flags().BoolVar(&opts.pages, "pages", false, "Plan GitHub Pages setup")
	cmd.Flags().StringVar(&opts.environment, "environment", "production", "GitHub environment name")
	cmd.Flags().StringVar(&opts.output, "output", "", "Write JSON plan to this path")
	cmd.Flags().StringVar(&opts.generatedAt, "generated-at", "", "Override generated timestamp for deterministic tests")
	_ = cmd.MarkFlagRequired("dir")
	_ = cmd.MarkFlagRequired("owner")
	_ = cmd.MarkFlagRequired("repo")
}

func buildGitHubPlan(opts platformPlanFlags) (PlatformGitHubPlan, error) {
	renderOpts, err := normalizePlatformRenderOptions(platformRenderFlags{
		dir:          opts.dir,
		profile:      opts.profile,
		owner:        opts.owner,
		repo:         opts.repo,
		registryBase: opts.registryBase,
		visibility:   opts.visibility,
		pages:        opts.pages,
		environment:  opts.environment,
		generatedAt:  opts.generatedAt,
	})
	if err != nil {
		return PlatformGitHubPlan{}, err
	}
	if err := validateRenderedControlPlane(renderOpts.dir, renderOpts.profile); err != nil {
		return PlatformGitHubPlan{}, err
	}
	renderedState, err := loadRenderedControlPlanePlanState(renderOpts.dir)
	if err != nil {
		return PlatformGitHubPlan{}, err
	}
	if err := applyRenderedControlPlanePlanState(&renderOpts, opts, renderedState); err != nil {
		return PlatformGitHubPlan{}, err
	}
	repository := renderOpts.owner + "/" + renderOpts.repo
	ops := []PlatformGitHubOp{
		{ID: "github.auth.check", Summary: "Verify gh is installed and authenticated", Remote: true, RequiresConfirm: false},
		{ID: "git.init", Summary: "Initialize local git repository if needed"},
		{ID: "github.repo.create", Summary: "Create GitHub repository if it does not exist", Remote: true, RequiresConfirm: true},
		{ID: "git.remote.set", Summary: "Create or replace the origin remote", Destructive: true, RequiresConfirm: true},
		{ID: "github.variables.set", Summary: "Configure non-secret repository variables", Remote: true, RequiresConfirm: true},
		{ID: "github.environment.ensure", Summary: "Create or update requested GitHub environment", Remote: true, RequiresConfirm: true},
	}
	if renderOpts.pages {
		ops = append(ops, PlatformGitHubOp{ID: "github.pages.ensure", Summary: "Configure GitHub Pages for workflow deployment", Remote: true, RequiresConfirm: true})
	}
	ops = append(ops,
		PlatformGitHubOp{ID: "github.actions.permissions.ensure", Summary: "Set default workflow token permissions to read", Destructive: true, Remote: true, RequiresConfirm: true},
		PlatformGitHubOp{ID: "git.commit", Summary: "Commit rendered control-plane files and applied state"},
		PlatformGitHubOp{ID: "git.push", Summary: "Push main branch to GitHub", Remote: true, RequiresConfirm: true},
		PlatformGitHubOp{ID: "github.secrets.manual", Summary: "Print required secrets for manual configuration", Remote: false, RequiresConfirm: false},
	)
	vars := []PlatformGitHubSetting{
		{Name: "CLEARCUTT_CLI_VERSION", Value: bootstrapCLIVersion(), Reason: "Pins workflow CLI installation; source builds use the latest verified release."},
		{Name: "CLEARCUTT_CLI_REPO", Value: "northcutted/clearcutt", Reason: "Repository that publishes ClearCutt CLI release assets."},
		{Name: "CLEARCUTT_PLATFORM_PROFILE", Value: renderOpts.profile, Reason: "Records the generated control-plane profile."},
		{Name: "CLEARCUTT_REGISTRY_BASE", Value: renderOpts.registryBase, Reason: "Registry namespace used by catalog generation."},
	}
	secrets := requiredBootstrapSecrets(renderOpts)
	if secrets == nil {
		secrets = []PlatformGitHubSetting{}
	}
	manual := []string{
		"Review .clearcutt/github.yaml before applying.",
		"Set required secrets manually; ClearCutt does not write repository secrets.",
	}
	if len(secrets) == 0 {
		manual = append(manual, "No repository secrets are required by default for catalog-only.")
	}
	commands := gitHubPlanCommands(renderOpts, repository, vars)
	return PlatformGitHubPlan{
		APIVersion:                    controlPlaneAPIVersion,
		Kind:                          "GitHubBootstrapPlan",
		Profile:                       renderOpts.profile,
		Owner:                         renderOpts.owner,
		Repo:                          renderOpts.repo,
		Repository:                    repository,
		LocalDirectory:                renderOpts.dir,
		Visibility:                    renderOpts.visibility,
		RegistryBase:                  renderOpts.registryBase,
		Pages:                         renderOpts.pages,
		Environment:                   renderOpts.environment,
		Operations:                    ops,
		RequiredUserPermissions:       []string{"GitHub repo administration for " + repository, "GitHub Actions and Pages settings access"},
		RequiredVariables:             vars,
		RequiredSecrets:               secrets,
		ManualSteps:                   manual,
		Commands:                      commands,
		RemoteMutationsRequireConfirm: true,
	}, nil
}

func validateRenderedControlPlane(dir, profile string) error {
	required := []string{"README.md", "clearcutt.lock", ".clearcutt/github.yaml", ".clearcutt/state.json"}
	if profile == platformProfileCatalogOnly {
		required = append(required, ".clearcutt/site.yaml", ".github/workflows/catalog.yml", ".github/workflows/pr-gate.yml", ".github/actions/install-clearcutt/action.yml")
	}
	for _, rel := range required {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("%s is not a rendered ClearCutt %s control plane: missing %s", dir, profile, rel)
			}
			return err
		}
	}
	lock, err := loadRenderedControlPlaneLock(dir)
	if err != nil {
		return err
	}
	if lock.Kind != "ClearCuttLock" || strings.TrimSpace(lock.Spec.Platform.Profile) != profile {
		return fmt.Errorf("%s clearcutt.lock does not match profile %q", dir, profile)
	}
	if profile == platformProfileCatalogOnly {
		source := strings.TrimSpace(lock.Spec.Catalog.Source)
		if source == "" || source == catalogSourceInventory {
			inventoryFile := strings.TrimSpace(lock.Spec.Catalog.InventoryFile)
			if inventoryFile == "" {
				inventoryFile = "images.yaml"
			}
			if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(inventoryFile))); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("%s is not a rendered ClearCutt %s control plane: missing %s", dir, profile, inventoryFile)
				}
				return err
			}
		} else if source == catalogSourceGitHubRelease {
			if _, _, err := splitCatalogSourceRepo(lock.Spec.Catalog.SourceRepo); err != nil {
				return fmt.Errorf("invalid release-backed clearcutt.lock: %w", err)
			}
			if len(lock.Spec.Catalog.Targets) == 0 || lock.Spec.Catalog.ReleaseLimit < 1 {
				return fmt.Errorf("invalid release-backed clearcutt.lock: targets and releaseLimit are required")
			}
			if _, err := normalizeCatalogTargets(strings.Join(lock.Spec.Catalog.Targets, ",")); err != nil {
				return fmt.Errorf("invalid release-backed clearcutt.lock: %w", err)
			}
		} else {
			return fmt.Errorf("unsupported catalog source %q in clearcutt.lock", source)
		}
	}
	return nil
}

func loadRenderedControlPlaneLock(dir string) (renderedControlPlaneLock, error) {
	var lock renderedControlPlaneLock
	raw, err := os.ReadFile(filepath.Join(dir, "clearcutt.lock"))
	if err != nil {
		return lock, err
	}
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		return lock, fmt.Errorf("parse clearcutt.lock: %w", err)
	}
	return lock, nil
}

func loadRenderedControlPlanePlanState(dir string) (renderedControlPlanePlanState, error) {
	var state renderedControlPlanePlanState
	lock, err := loadRenderedControlPlaneLock(dir)
	if err != nil {
		return state, err
	}
	state.profile = strings.TrimSpace(lock.Spec.Platform.Profile)
	state.owner = strings.TrimSpace(lock.Spec.Platform.Owner)
	state.repo = strings.TrimSpace(lock.Spec.Platform.Repo)
	state.registryBase = strings.TrimSpace(lock.Spec.Platform.RegistryBase)
	state.pages = lock.Spec.Platform.Pages
	state.environment = strings.TrimSpace(lock.Spec.Platform.Environment)

	githubRaw, err := os.ReadFile(filepath.Join(dir, ".clearcutt", "github.yaml"))
	if err != nil {
		return state, err
	}
	var desired struct {
		Spec struct {
			Repository struct {
				Owner      string `json:"owner"`
				Name       string `json:"name"`
				Visibility string `json:"visibility"`
			} `json:"repository"`
			Pages struct {
				Enabled *bool `json:"enabled"`
			} `json:"pages"`
			Environments []struct {
				Name string `json:"name"`
			} `json:"environments"`
			Variables map[string]string `json:"variables"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal(githubRaw, &desired); err != nil {
		return state, fmt.Errorf("parse .clearcutt/github.yaml: %w", err)
	}
	if owner := strings.TrimSpace(desired.Spec.Repository.Owner); owner != "" {
		state.owner = owner
	}
	if repo := strings.TrimSpace(desired.Spec.Repository.Name); repo != "" {
		state.repo = repo
	}
	state.visibility = strings.TrimSpace(desired.Spec.Repository.Visibility)
	if desired.Spec.Pages.Enabled != nil {
		state.pages = desired.Spec.Pages.Enabled
	}
	if len(desired.Spec.Environments) > 0 {
		if env := strings.TrimSpace(desired.Spec.Environments[0].Name); env != "" {
			state.environment = env
		}
	}
	if state.registryBase == "" {
		state.registryBase = strings.TrimSpace(desired.Spec.Variables["CLEARCUTT_REGISTRY_BASE"])
	}
	return state, nil
}

func applyRenderedControlPlanePlanState(renderOpts *platformRenderFlags, raw platformPlanFlags, state renderedControlPlanePlanState) error {
	if err := requireRenderedPlanMatch("--profile", raw.profile, state.profile, renderOpts.profile); err != nil {
		return err
	}
	if err := requireRenderedPlanMatch("--owner", raw.owner, state.owner, renderOpts.owner); err != nil {
		return err
	}
	if err := requireRenderedPlanMatch("--repo", raw.repo, state.repo, renderOpts.repo); err != nil {
		return err
	}
	if state.profile != "" {
		renderOpts.profile = state.profile
	}
	if state.owner != "" {
		renderOpts.owner = state.owner
	}
	if state.repo != "" {
		renderOpts.repo = state.repo
	}
	if state.visibility != "" {
		renderOpts.visibility = state.visibility
	}
	if state.registryBase != "" {
		if raw.registryBase != "" && raw.registryBase != state.registryBase {
			return fmt.Errorf("--registry-base %q does not match rendered control plane %q", raw.registryBase, state.registryBase)
		}
		renderOpts.registryBase = state.registryBase
	}
	if state.pages != nil {
		if raw.pages && !*state.pages {
			return fmt.Errorf("--pages was requested, but rendered control plane has pages disabled")
		}
		renderOpts.pages = *state.pages
	}
	if state.environment != "" {
		if raw.environment != "" && raw.environment != "production" && raw.environment != state.environment {
			return fmt.Errorf("--environment %q does not match rendered control plane %q", raw.environment, state.environment)
		}
		renderOpts.environment = state.environment
	}
	return nil
}

func requireRenderedPlanMatch(flag, raw, rendered, normalized string) error {
	if rendered == "" {
		return nil
	}
	if raw != "" && normalized != rendered {
		return fmt.Errorf("%s %q does not match rendered control plane %q", flag, raw, rendered)
	}
	return nil
}

func requiredBootstrapSecrets(opts platformRenderFlags) []PlatformGitHubSetting {
	if opts.profile == platformProfileCatalogOnly {
		return nil
	}
	secrets := []PlatformGitHubSetting{
		{Name: "CLEARCUTT_REGISTRY_TOKEN", Reason: "Required when the configured fleet registry cannot publish with the GitHub-provided token."},
		{Name: "OPENROUTER_API_KEY", Reason: "Optional; only needed for manual remediation escalation."},
	}
	return secrets
}

func gitHubPlanCommands(opts platformRenderFlags, repository string, vars []PlatformGitHubSetting) []PlatformGitHubCommand {
	visibilityFlag := "--private"
	if opts.visibility == "public" {
		visibilityFlag = "--public"
	} else if opts.visibility == "internal" {
		visibilityFlag = "--internal"
	}
	commands := []PlatformGitHubCommand{
		cmdSpec("github.auth.check", "gh", "auth", "status"),
		cmdSpec("git.init", "git", "-C", opts.dir, "init", "-b", "main"),
		cmdSpec("github.repo.create", "gh", "repo", "create", repository, visibilityFlag, "--source", opts.dir, "--remote", "origin"),
		cmdSpec("git.remote.set", "git", "-C", opts.dir, "remote", "set-url", "origin", "https://github.com/"+repository+".git"),
	}
	for _, variable := range vars {
		commands = append(commands, cmdSpec("github.variables.set", "gh", "variable", "set", variable.Name, "--repo", repository, "--body", variable.Value))
	}
	commands = append(commands,
		cmdSpec("github.environment.ensure", "gh", "api", "--method", "PUT", "repos/"+repository+"/environments/"+opts.environment),
	)
	if opts.pages {
		commands = append(commands, cmdSpec("github.pages.ensure", "gh", "api", "--method", "POST", "repos/"+repository+"/pages", "-f", "build_type=workflow"))
	}
	commands = append(commands,
		cmdSpec("github.actions.permissions.ensure", "gh", "api", "--method", "PUT", "repos/"+repository+"/actions/permissions/workflow", "-f", "default_workflow_permissions=read", "-F", "can_approve_pull_request_reviews=false"),
		cmdSpec("git.commit", "git", "-C", opts.dir, "add", "-A", "--", ".", ":(exclude).clearcutt/*.plan.json"),
		cmdSpec("git.commit", "git", "-C", opts.dir, "commit", "-m", "Bootstrap ClearCutt control plane"),
		cmdSpec("git.push", "git", "-C", opts.dir, "push", "-u", "origin", "main"),
	)
	return commands
}

func cmdSpec(operationID, name string, args ...string) PlatformGitHubCommand {
	all := append([]string{name}, args...)
	return PlatformGitHubCommand{OperationID: operationID, Name: name, Args: args, Command: strings.Join(all, " ")}
}

func printGitHubPlanHuman(plan PlatformGitHubPlan) error {
	fmt.Fprintf(out, "GitHub bootstrap plan for %s\n", plan.Repository)
	fmt.Fprintf(out, "Profile: %s\nDirectory: %s\nRegistry: %s\nRemote mutations require --confirm: %t\n\n", plan.Profile, plan.LocalDirectory, plan.RegistryBase, plan.RemoteMutationsRequireConfirm)
	fmt.Fprintln(out, "Operations:")
	for _, op := range plan.Operations {
		scope := "local"
		if op.Remote {
			scope = "remote"
		}
		fmt.Fprintf(out, "- %s (%s, destructive=%t): %s\n", op.ID, scope, op.Destructive, op.Summary)
	}
	fmt.Fprintln(out, "\nRequired variables:")
	for _, setting := range plan.RequiredVariables {
		fmt.Fprintf(out, "- %s=%s: %s\n", setting.Name, setting.Value, setting.Reason)
	}
	fmt.Fprintln(out, "\nRequired secrets:")
	if len(plan.RequiredSecrets) == 0 {
		fmt.Fprintln(out, "- none by default")
	} else {
		for _, setting := range plan.RequiredSecrets {
			fmt.Fprintf(out, "- %s: %s\n", setting.Name, setting.Reason)
		}
	}
	fmt.Fprintln(out, "\nCommands that would run:")
	for _, command := range plan.Commands {
		fmt.Fprintf(out, "- [%s] %s\n", command.OperationID, command.Command)
	}
	return nil
}

func writePlanJSON(path string, plan PlatformGitHubPlan) error {
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func loadGitHubPlan(path string) (PlatformGitHubPlan, error) {
	if strings.TrimSpace(path) == "" {
		return PlatformGitHubPlan{}, fmt.Errorf("--plan is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return PlatformGitHubPlan{}, err
	}
	var plan PlatformGitHubPlan
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return PlatformGitHubPlan{}, fmt.Errorf("parse GitHub plan: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return PlatformGitHubPlan{}, fmt.Errorf("parse GitHub plan: trailing JSON content")
	}
	if plan.APIVersion != controlPlaneAPIVersion {
		return PlatformGitHubPlan{}, fmt.Errorf("plan apiVersion %q is not supported (expected %s)", plan.APIVersion, controlPlaneAPIVersion)
	}
	if plan.Kind != "GitHubBootstrapPlan" {
		return PlatformGitHubPlan{}, fmt.Errorf("plan kind %q is not GitHubBootstrapPlan", plan.Kind)
	}
	expected, err := buildGitHubPlan(platformPlanFlags{
		dir:          plan.LocalDirectory,
		owner:        plan.Owner,
		repo:         plan.Repo,
		profile:      plan.Profile,
		visibility:   plan.Visibility,
		registryBase: plan.RegistryBase,
		pages:        plan.Pages,
		environment:  plan.Environment,
	})
	if err != nil {
		return PlatformGitHubPlan{}, fmt.Errorf("validate GitHub plan against rendered control plane: %w", err)
	}
	if !reflect.DeepEqual(planWithoutExecutableFields(plan), planWithoutExecutableFields(expected)) {
		return PlatformGitHubPlan{}, fmt.Errorf("GitHub plan does not match the rendered control plane or current CLI; regenerate it before applying")
	}
	return expected, nil
}

func planWithoutExecutableFields(plan PlatformGitHubPlan) PlatformGitHubPlan {
	plan.Commands = append([]PlatformGitHubCommand(nil), plan.Commands...)
	for i := range plan.Commands {
		plan.Commands[i].Name = ""
		plan.Commands[i].Args = nil
	}
	return plan
}

func applyGitHubPlan(ctx context.Context, plan PlatformGitHubPlan, runner CommandRunner) error {
	if plan.APIVersion != controlPlaneAPIVersion || plan.Kind != "GitHubBootstrapPlan" {
		return fmt.Errorf("refusing to apply invalid GitHub bootstrap plan %q/%q", plan.APIVersion, plan.Kind)
	}
	if runner == nil {
		runner = execCommandRunner{}
	}
	if _, stderr, err := runner.Run(ctx, "gh", []string{"auth", "status"}, nil); err != nil {
		return fmt.Errorf("github.auth.check failed: gh auth status failed: %v: %s", err, strings.TrimSpace(stderr))
	}
	stateUpdated := false
	for _, command := range plan.Commands {
		if command.OperationID == "github.auth.check" {
			continue
		}
		if command.OperationID == "git.init" {
			if info, err := os.Stat(filepath.Join(plan.LocalDirectory, ".git")); err == nil && info.IsDir() {
				continue
			}
		}
		if command.OperationID == "github.repo.create" {
			if _, _, err := runner.Run(ctx, "gh", []string{"repo", "view", plan.Repository}, nil); err == nil {
				continue
			}
		}
		if command.OperationID == "git.remote.set" {
			remoteURL := "https://github.com/" + plan.Repository + ".git"
			args := []string{"-C", plan.LocalDirectory, "remote", "set-url", "origin", remoteURL}
			if _, _, err := runner.Run(ctx, "git", []string{"-C", plan.LocalDirectory, "remote", "get-url", "origin"}, nil); err != nil {
				args = []string{"-C", plan.LocalDirectory, "remote", "add", "origin", remoteURL}
			}
			if _, stderr, err := runner.Run(ctx, "git", args, nil); err != nil {
				return fmt.Errorf("git.remote.set failed: %v: %s", err, strings.TrimSpace(stderr))
			}
			continue
		}
		if command.OperationID == "github.pages.ensure" {
			endpoint := "repos/" + plan.Repository + "/pages"
			method := "POST"
			if _, _, err := runner.Run(ctx, "gh", []string{"api", endpoint}, nil); err == nil {
				method = "PUT"
			}
			args := []string{"api", "--method", method, endpoint, "-f", "build_type=workflow"}
			if _, stderr, err := runner.Run(ctx, "gh", args, nil); err != nil {
				return fmt.Errorf("github.pages.ensure failed: %v: %s", err, strings.TrimSpace(stderr))
			}
			continue
		}
		if command.OperationID == "git.commit" && !stateUpdated {
			if err := updateBootstrapState(plan); err != nil {
				return err
			}
			stateUpdated = true
		}
		if command.OperationID == "git.commit" && len(command.Args) >= 3 && command.Args[2] == "commit" {
			if _, _, err := runner.Run(ctx, "git", []string{"-C", plan.LocalDirectory, "diff", "--cached", "--quiet"}, nil); err == nil {
				continue
			}
		}
		_, stderr, err := runner.Run(ctx, command.Name, command.Args, nil)
		if err != nil {
			return fmt.Errorf("%s failed: %v: %s", command.OperationID, err, strings.TrimSpace(stderr))
		}
	}
	if !stateUpdated {
		return fmt.Errorf("GitHub bootstrap plan did not contain a state commit operation")
	}
	fmt.Fprintf(out, "applied GitHub bootstrap plan for %s\n", plan.Repository)
	if len(plan.RequiredSecrets) == 0 {
		fmt.Fprintln(out, "required secrets: none by default")
	} else {
		fmt.Fprintln(out, "set these secrets manually:")
		for _, secret := range plan.RequiredSecrets {
			fmt.Fprintf(out, "- %s: %s\n", secret.Name, secret.Reason)
		}
	}
	return nil
}

func updateBootstrapState(plan PlatformGitHubPlan) error {
	statePath := filepath.Join(plan.LocalDirectory, ".clearcutt", "state.json")
	raw, _ := os.ReadFile(statePath)
	var state map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &state)
	}
	if state == nil {
		state = map[string]any{}
	}
	state["apiVersion"] = controlPlaneAPIVersion
	state["kind"] = "ClearCuttBootstrapState"
	state["profile"] = plan.Profile
	state["owner"] = plan.Owner
	state["repo"] = plan.Repo
	state["managedResources"] = []string{plan.Repository}
	state["lastAppliedPlanHash"] = planHash(plan)
	return writeJSONFile(statePath, state)
}

func planHash(plan PlatformGitHubPlan) string {
	raw, _ := json.Marshal(plan)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func runPlatformBootstrapGitHub(ctx context.Context, opts platformBootstrapFlags) error {
	applyMode := opts.apply
	if opts.confirm && !opts.apply {
		return fmt.Errorf("--confirm requires --apply")
	}
	if !applyMode {
		opts.dryRun = true
	}
	if applyMode && !opts.confirm {
		return fmt.Errorf("refusing to mutate GitHub without --confirm")
	}
	renderOpts := opts.render
	if !opts.skipRender {
		if _, err := renderPlatformControlPlane(renderOpts); err != nil {
			return err
		}
	}
	normalized, err := normalizePlatformRenderOptions(renderOpts)
	if err != nil {
		return err
	}
	plan, err := buildGitHubPlan(platformPlanFlags{
		dir:          normalized.dir,
		owner:        normalized.owner,
		repo:         normalized.repo,
		profile:      normalized.profile,
		visibility:   normalized.visibility,
		registryBase: normalized.registryBase,
		pages:        normalized.pages,
		environment:  normalized.environment,
		generatedAt:  normalized.generatedAt,
	})
	if err != nil {
		return err
	}
	planPath := opts.output
	if planPath != "" {
		if err := writePlanJSON(planPath, plan); err != nil {
			return err
		}
	}
	if opts.dryRun {
		if structuredFormat() {
			return output.PrintJSON(out, plan)
		}
		return printGitHubPlanHuman(plan)
	}
	if err := applyGitHubPlan(ctx, plan, platformCommandRunner); err != nil {
		return err
	}
	fmt.Fprintln(out, "next commands:")
	fmt.Fprintf(out, "- clearcutt platform doctor --github --output %s --repo %s\n", normalized.dir, plan.Repository)
	fmt.Fprintf(out, "- gh workflow run catalog.yml --repo %s\n", plan.Repository)
	return nil
}
