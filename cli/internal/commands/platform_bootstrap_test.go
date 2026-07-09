package commands

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlatformRenderFleetCreatesScaffoldAndPrintsResults(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "image-fleet")
	oldOut, oldFormat := out, GlobalOpts.Format
	defer func() {
		out = oldOut
		GlobalOpts.Format = oldFormat
	}()
	out = io.Discard
	result, err := renderPlatformControlPlane(platformRenderFlags{
		dir: dir, profile: platformProfileFleet, owner: "acme", repo: "image-fleet",
		registryHost: "ghcr.io", source: root, generatedAt: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("render fleet: %v", err)
	}
	if result.Profile != platformProfileFleet || result.RegistryBase != "ghcr.io/acme/image-fleet" {
		t.Fatalf("unexpected render result: %#v", result)
	}
	for _, rel := range []string{"clearcutt.fleet.yaml", "core/flake.nix", "site/package.json", "clearcutt.lock", ".clearcutt/github.yaml", ".clearcutt/state.json"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("fleet render missing %s: %v", rel, err)
		}
	}
	var rendered bytes.Buffer
	out = &rendered
	GlobalOpts.Format = "json"
	if err := printPlatformRenderResult(result); err != nil || !strings.Contains(rendered.String(), `"profile": "fleet"`) {
		t.Fatalf("structured render output: err=%v output=%s", err, rendered.String())
	}
	rendered.Reset()
	GlobalOpts.Format = "table"
	if err := printPlatformRenderResult(result); err != nil || !strings.Contains(rendered.String(), "Rendered ClearCutt fleet control plane") {
		t.Fatalf("human render output: err=%v output=%s", err, rendered.String())
	}
}

func TestNormalizePlatformRenderOptionsValidationAndDefaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts platformRenderFlags
		want string
	}{
		{name: "owner", opts: platformRenderFlags{repo: "repo"}, want: "--owner is required"},
		{name: "repo", opts: platformRenderFlags{owner: "acme"}, want: "--repo is required"},
		{name: "visibility", opts: platformRenderFlags{owner: "acme", repo: "repo", visibility: "secret"}, want: "--visibility must be"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := normalizePlatformRenderOptions(tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
	normalized, err := normalizePlatformRenderOptions(platformRenderFlags{
		owner: " Acme ", dir: filepath.Join(t.TempDir(), "Derived-Repo"), profile: platformProfileFleet,
	})
	if err != nil {
		t.Fatal(err)
	}
	if normalized.repo != "Derived-Repo" || normalized.registryHost != "ghcr.io" || normalized.imagePrefix != "Derived-Repo" || normalized.registryBase != "ghcr.io/Acme/Derived-Repo" || normalized.visibility != "private" || normalized.environment != "production" || normalized.generatedAt == "" {
		t.Fatalf("unexpected normalized options: %#v", normalized)
	}
	if _, err := renderPlatformControlPlane(platformRenderFlags{owner: "acme", repo: "repo", profile: "unknown", dir: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "unsupported profile") {
		t.Fatalf("unsupported profile error = %v", err)
	}
}

type recordingRunner struct {
	calls []string
}

type convergentBootstrapRunner struct {
	calls      []string
	repoExists bool
	pages      bool
}

func (r *convergentBootstrapRunner) Run(ctx context.Context, name string, args []string, stdin []byte) (string, string, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, call)
	if name == "git" {
		if len(args) >= 3 && args[2] == "push" {
			return "", "", nil
		}
		cmd := exec.CommandContext(ctx, name, args...)
		if stdin != nil {
			cmd.Stdin = strings.NewReader(string(stdin))
		}
		stdout, err := cmd.Output()
		if exitErr, ok := err.(*exec.ExitError); ok {
			return string(stdout), string(exitErr.Stderr), err
		}
		return string(stdout), "", err
	}
	if call == "gh auth status" {
		return "", "", nil
	}
	if strings.HasPrefix(call, "gh repo view ") {
		if r.repoExists {
			return "", "", nil
		}
		return "", "not found", errors.New("not found")
	}
	if strings.HasPrefix(call, "gh repo create ") {
		r.repoExists = true
		return "", "", nil
	}
	if strings.HasPrefix(call, "gh api repos/") && strings.HasSuffix(call, "/pages") {
		if r.pages {
			return "", "", nil
		}
		return "", "not found", errors.New("not found")
	}
	if strings.Contains(call, "/pages -f build_type=workflow") {
		r.pages = true
	}
	return "", "", nil
}

func (r *recordingRunner) Run(ctx context.Context, name string, args []string, stdin []byte) (string, string, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, call)
	if call == "gh repo view acme/image-platform" {
		return "", "not found", errors.New("not found")
	}
	if call == "gh api repos/acme/image-platform/pages" {
		return "", "not found", errors.New("not found")
	}
	if strings.Contains(call, " remote get-url origin") {
		return "", "missing origin", errors.New("missing origin")
	}
	if strings.Contains(call, " diff --cached --quiet") {
		return "", "changes staged", errors.New("changes staged")
	}
	return "", "", nil
}

func withPlatformRunner(t *testing.T, runner CommandRunner) {
	t.Helper()
	old := platformCommandRunner
	platformCommandRunner = runner
	t.Cleanup(func() { platformCommandRunner = old })
}

func renderCatalogOnlyForTest(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "image-platform")
	_, err := renderPlatformControlPlane(platformRenderFlags{
		dir:          dir,
		profile:      platformProfileCatalogOnly,
		owner:        "acme",
		repo:         "image-platform",
		registryBase: "ghcr.io/acme/image-platform",
		visibility:   "private",
		pages:        true,
		environment:  "production",
		force:        true,
		generatedAt:  "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("render catalog-only: %v", err)
	}
	return dir
}

func TestPlatformRenderCatalogOnlyCreatesExpectedFiles(t *testing.T) {
	dir := renderCatalogOnlyForTest(t)
	for _, rel := range []string{
		"README.md",
		"images.yaml",
		"clearcutt.lock",
		".clearcutt/github.yaml",
		".clearcutt/state.json",
		".clearcutt/site.yaml",
		".github/workflows/catalog.yml",
		".github/workflows/pr-gate.yml",
		".github/actions/install-clearcutt/action.yml",
		"docs/operating-model.md",
		"docs/first-catalog.md",
		"docs/app-team-onboarding.md",
		"docs/trust-model.md",
		"policies/README.md",
		"catalog/README.md",
		"evidence/README.md",
	} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("expected %s: %v", rel, err)
		}
	}
	for _, rel := range []string{"cli", "core", "site"} {
		if _, err := os.Stat(filepath.Join(dir, rel)); !os.IsNotExist(err) {
			t.Fatalf("catalog-only render must not copy %s, stat err=%v", rel, err)
		}
	}
	workflow, err := os.ReadFile(filepath.Join(dir, ".github", "workflows", "catalog.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
		"actions/upload-pages-artifact@56afc609e74202658d3ffba0e8f6dda462b719fa",
		"actions/deploy-pages@cd2ce8fcbc39b97be8ca5fce6e763baed58fa128",
		`--base-path "/image-platform"`,
		`--site-url "https://acme.github.io"`,
		"--site-config .clearcutt/site.yaml",
		"version: ${{ vars.CLEARCUTT_CLI_VERSION || 'latest' }}",
	} {
		if !strings.Contains(string(workflow), want) {
			t.Fatalf("generated Pages workflow missing %q:\n%s", want, workflow)
		}
	}
	if strings.Contains(string(workflow), "actions/configure-pages@v") || strings.Contains(string(workflow), "actions/checkout@v") {
		t.Fatalf("generated workflow contains mutable action tags:\n%s", workflow)
	}
	action, err := os.ReadFile(filepath.Join(dir, ".github", "actions", "install-clearcutt", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(action), "GITHUB_PATH") || !strings.Contains(string(action), "releases/latest/download") {
		t.Fatalf("generated installer must expose the binary and support latest releases:\n%s", action)
	}
	siteConfig, err := os.ReadFile(filepath.Join(dir, ".clearcutt", "site.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(siteConfig), "catalogMode: imported") {
		t.Fatalf("catalog-only site must use imported profile:\n%s", siteConfig)
	}
}

func TestPlatformRenderWithoutPagesDoesNotDeployPages(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "inventory")
	_, err := renderPlatformControlPlane(platformRenderFlags{
		dir: dir, profile: platformProfileCatalogOnly, owner: "acme", repo: "inventory",
		registryBase: "ghcr.io/acme/inventory", generatedAt: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := os.ReadFile(filepath.Join(dir, ".github", "workflows", "catalog.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"pages: write", "id-token: write", "github-pages", "upload-pages-artifact", "deploy-pages", "--base-path"} {
		if strings.Contains(string(workflow), forbidden) {
			t.Fatalf("Pages-disabled workflow contains %q:\n%s", forbidden, workflow)
		}
	}
	if !strings.Contains(string(workflow), "catalog site build") {
		t.Fatalf("Pages-disabled workflow should still validate the site build:\n%s", workflow)
	}
}

func TestPlatformPlanGitHubEmitsDeterministicOperations(t *testing.T) {
	dir := renderCatalogOnlyForTest(t)
	plan, err := buildGitHubPlan(platformPlanFlags{
		dir:          dir,
		owner:        "acme",
		repo:         "image-platform",
		profile:      platformProfileCatalogOnly,
		visibility:   "private",
		registryBase: "ghcr.io/acme/image-platform",
		pages:        true,
		environment:  "production",
		generatedAt:  "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if plan.Repository != "acme/image-platform" || !plan.Pages || plan.RegistryBase != "ghcr.io/acme/image-platform" {
		t.Fatalf("unexpected plan identity: %#v", plan)
	}
	gotIDs := make([]string, 0, len(plan.Operations))
	for _, op := range plan.Operations {
		gotIDs = append(gotIDs, op.ID)
	}
	want := "github.auth.check,git.init,github.repo.create,git.remote.set,github.variables.set,github.environment.ensure,github.pages.ensure,github.actions.permissions.ensure,git.commit,git.push,github.secrets.manual"
	if strings.Join(gotIDs, ",") != want {
		t.Fatalf("operation ids = %s", strings.Join(gotIDs, ","))
	}
	if len(plan.RequiredSecrets) != 0 {
		t.Fatalf("catalog-only should not require secrets: %#v", plan.RequiredSecrets)
	}
}

func TestPlatformPlanGitHubUsesRenderedDesiredState(t *testing.T) {
	dir := renderCatalogOnlyForTest(t)
	plan, err := buildGitHubPlan(platformPlanFlags{
		dir:     dir,
		owner:   "acme",
		repo:    "image-platform",
		profile: platformProfileCatalogOnly,
	})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if !plan.Pages {
		t.Fatalf("plan should use pages=true from rendered .clearcutt/github.yaml: %#v", plan)
	}
	if plan.RegistryBase != "ghcr.io/acme/image-platform" {
		t.Fatalf("plan should use registryBase from rendered clearcutt.lock, got %q", plan.RegistryBase)
	}
	gotPagesOp := false
	for _, op := range plan.Operations {
		if op.ID == "github.pages.ensure" {
			gotPagesOp = true
		}
	}
	if !gotPagesOp {
		t.Fatalf("plan with rendered pages=true should include github.pages.ensure: %#v", plan.Operations)
	}
}

func TestPlatformApplyGitHubRefusesWithoutConfirm(t *testing.T) {
	dir := renderCatalogOnlyForTest(t)
	plan, err := buildGitHubPlan(platformPlanFlags{dir: dir, owner: "acme", repo: "image-platform", profile: platformProfileCatalogOnly, registryBase: "ghcr.io/acme/image-platform"})
	if err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(t.TempDir(), "clearcutt.plan.json")
	if err := writePlanJSON(planPath, plan); err != nil {
		t.Fatal(err)
	}
	stdout, err := runCLI(t, "platform", "apply", "github", "--plan", planPath)
	if err == nil || !strings.Contains(err.Error(), "without --confirm") {
		t.Fatalf("expected confirm refusal, got err=%v stdout=%s", err, stdout)
	}
}

func TestPlatformApplyGitHubUsesFakeRunner(t *testing.T) {
	dir := renderCatalogOnlyForTest(t)
	plan, err := buildGitHubPlan(platformPlanFlags{dir: dir, owner: "acme", repo: "image-platform", profile: platformProfileCatalogOnly, registryBase: "ghcr.io/acme/image-platform", pages: true})
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	if err := applyGitHubPlan(context.Background(), plan, runner); err != nil {
		t.Fatalf("apply plan: %v", err)
	}
	joined := strings.Join(runner.calls, "\n")
	for _, needle := range []string{
		"gh auth status",
		"git -C " + dir + " init -b main",
		"gh repo view acme/image-platform",
		"gh repo create acme/image-platform --private --source " + dir + " --remote origin",
		"git -C " + dir + " remote add origin https://github.com/acme/image-platform.git",
		"gh variable set CLEARCUTT_REGISTRY_BASE --repo acme/image-platform --body ghcr.io/acme/image-platform",
		"gh api --method POST repos/acme/image-platform/pages -f build_type=workflow",
	} {
		if !strings.Contains(joined, needle) {
			t.Fatalf("runner calls missing %q:\n%s", needle, joined)
		}
	}
	state, err := os.ReadFile(filepath.Join(dir, ".clearcutt", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(state), `"lastAppliedPlanHash"`) || !strings.Contains(string(state), "acme/image-platform") {
		t.Fatalf("state not updated:\n%s", state)
	}
}

func TestPlatformApplyGitHubConvergesOnSecondRun(t *testing.T) {
	dir := renderCatalogOnlyForTest(t)
	for _, args := range [][]string{
		{"-C", dir, "init", "-b", "main"},
		{"-C", dir, "config", "user.name", "ClearCutt Test"},
		{"-C", dir, "config", "user.email", "clearcutt@example.invalid"},
	} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	plan, err := buildGitHubPlan(platformPlanFlags{dir: dir, owner: "acme", repo: "image-platform", profile: platformProfileCatalogOnly, registryBase: "ghcr.io/acme/image-platform", pages: true})
	if err != nil {
		t.Fatal(err)
	}
	runner := &convergentBootstrapRunner{}
	if err := applyGitHubPlan(context.Background(), plan, runner); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := applyGitHubPlan(context.Background(), plan, runner); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	joined := strings.Join(runner.calls, "\n")
	if got := strings.Count(joined, "gh repo create acme/image-platform"); got != 1 {
		t.Fatalf("repository should be created once, got %d:\n%s", got, joined)
	}
	if got := strings.Count(joined, "git -C "+dir+" commit -m Bootstrap ClearCutt control plane"); got != 1 {
		t.Fatalf("no-op second apply should not commit, got %d:\n%s", got, joined)
	}
	if !strings.Contains(joined, "gh api --method POST repos/acme/image-platform/pages") || !strings.Contains(joined, "gh api --method PUT repos/acme/image-platform/pages") {
		t.Fatalf("Pages should create then update idempotently:\n%s", joined)
	}
}

func TestPlatformApplyRejectsTamperedPlanCommands(t *testing.T) {
	dir := renderCatalogOnlyForTest(t)
	plan, err := buildGitHubPlan(platformPlanFlags{dir: dir, owner: "acme", repo: "image-platform", profile: platformProfileCatalogOnly, registryBase: "ghcr.io/acme/image-platform"})
	if err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(t.TempDir(), "clearcutt.plan.json")
	if err := writePlanJSON(planPath, plan); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"name": "gh"`) || strings.Contains(string(raw), `"args":`) {
		t.Fatalf("serialized plan must not contain executable fields:\n%s", raw)
	}
	tampered := strings.Replace(string(raw), `"command": "gh auth status"`, `"command": "sh -c malicious"`, 1)
	if err := os.WriteFile(planPath, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadGitHubPlan(planPath); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("tampered plan should be rejected, got %v", err)
	}
}

func TestPlatformBootstrapDryRunDoesNotCallRunner(t *testing.T) {
	runner := &recordingRunner{}
	withPlatformRunner(t, runner)
	dir := filepath.Join(t.TempDir(), "image-platform")
	stdout, err := runCLI(t,
		"platform", "bootstrap", "github",
		"--owner", "acme",
		"--repo", "image-platform",
		"--profile", platformProfileCatalogOnly,
		"--registry-base", "ghcr.io/acme/image-platform",
		"--pages",
		"--environment", "production",
		"--dir", dir,
		"--dry-run",
		"--force",
		"--generated-at", "2026-01-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("bootstrap dry-run: %v\n%s", err, stdout)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("dry-run should not call runner: %#v", runner.calls)
	}
	if !strings.Contains(stdout, "GitHub bootstrap plan for acme/image-platform") {
		t.Fatalf("unexpected dry-run output:\n%s", stdout)
	}
}

func TestPlatformBootstrapConfirmWithoutApplyDoesNotMutate(t *testing.T) {
	runner := &recordingRunner{}
	withPlatformRunner(t, runner)
	dir := filepath.Join(t.TempDir(), "image-platform")
	stdout, err := runCLI(t,
		"platform", "bootstrap", "github",
		"--owner", "acme",
		"--repo", "image-platform",
		"--dir", dir,
		"--confirm",
	)
	if err == nil || !strings.Contains(err.Error(), "--confirm requires --apply") {
		t.Fatalf("confirm-only bootstrap should fail, got err=%v stdout=%s", err, stdout)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("confirm-only bootstrap must not call runner: %#v", runner.calls)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatalf("confirm-only bootstrap must not render, stat err=%v", statErr)
	}
}

func TestPlatformBootstrapApplyCallsRenderPlanApply(t *testing.T) {
	runner := &recordingRunner{}
	withPlatformRunner(t, runner)
	dir := filepath.Join(t.TempDir(), "image-platform")
	stdout, err := runCLI(t,
		"platform", "bootstrap", "github",
		"--owner", "acme",
		"--repo", "image-platform",
		"--profile", platformProfileCatalogOnly,
		"--registry-base", "ghcr.io/acme/image-platform",
		"--pages",
		"--environment", "production",
		"--dir", dir,
		"--apply",
		"--confirm",
		"--force",
		"--generated-at", "2026-01-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("bootstrap apply: %v\n%s", err, stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, "images.yaml")); err != nil {
		t.Fatalf("bootstrap should render first: %v", err)
	}
	joined := strings.Join(runner.calls, "\n")
	if !strings.Contains(joined, "gh auth status") || !strings.Contains(joined, "git -C "+dir+" push -u origin main") {
		t.Fatalf("bootstrap apply did not call apply runner:\n%s", joined)
	}
	if !strings.Contains(stdout, "gh workflow run catalog.yml --repo acme/image-platform") {
		t.Fatalf("missing next command:\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, ".clearcutt", "clearcutt.plan.json")); !os.IsNotExist(err) {
		t.Fatalf("bootstrap should not write a transient plan by default, stat err=%v", err)
	}
}
