package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

type remediationRunFlags struct {
	vulnRoot       string
	vulnDir        string
	includeDevOnly bool
	limit          int
	maxFailures    int
	coreDir        string
	planOut        string
	agentScript    string
	baseBranch     string
	skipPR         bool
	policyJSON     string
}

type remediationOpenPRFlags struct {
	branch           string
	packageName      string
	cve              string
	installedVersion string
	summaryPath      string
	baseBranch       string
	dryRun           bool
}

var remediationRunOpts remediationRunFlags
var remediationOpenPROpts remediationOpenPRFlags

func NewRemediationRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run planned CVE remediation drafting and PR creation",
		Long: `Builds a remediation campaign plan, dispatches the retained CVE draft
agent for each selected campaign, and opens draft pull requests for produced
cve-remediation/* branches. The AI/Nix patch-authoring agent remains in Python;
the CI orchestration, branch detection, and PR creation live here.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemediationRun()
		},
	}
	cmd.Flags().StringVar(&remediationRunOpts.vulnRoot, "vuln-root", envOr("VULN_ROOT", remediationDefaultVulnRoot), "Root directory containing versioned vulnerability scan outputs")
	cmd.Flags().StringVar(&remediationRunOpts.vulnDir, "vuln-dir", os.Getenv("REMEDIATION_VULN_DIR"), "Specific vulnerability scan directory to read")
	cmd.Flags().BoolVar(&remediationRunOpts.includeDevOnly, "include-dev-only", parseScanBool(os.Getenv("INCLUDE_DEV_ONLY_REMEDIATION")), "Include dev-tier-only campaigns")
	cmd.Flags().IntVar(&remediationRunOpts.limit, "limit", envIntValue("MAX_FINDINGS_PER_RUN", 0), "Maximum campaigns to attempt")
	cmd.Flags().IntVar(&remediationRunOpts.maxFailures, "max-failures", envIntValue("MAX_PATCH_FAILURES_PER_RUN", 1), "Stop after this many failed patch attempts (0 disables the cap)")
	cmd.Flags().StringVar(&remediationRunOpts.coreDir, "core-dir", "", "Core workspace directory (auto-detected when omitted)")
	cmd.Flags().StringVar(&remediationRunOpts.planOut, "plan-out", "", "Write the generated plan JSON to this path")
	cmd.Flags().StringVar(&remediationRunOpts.agentScript, "agent-script", envOr("CVE_DRAFT_AGENT", "./scripts/cve-draft-agent.py"), "Drafting agent path, relative to --core-dir unless absolute")
	cmd.Flags().StringVar(&remediationRunOpts.baseBranch, "base-branch", envOr("REMEDIATION_BASE_BRANCH", "main"), "Base branch for draft PRs and checkout reset")
	cmd.Flags().StringVar(&remediationRunOpts.policyJSON, "policy-json", os.Getenv("REMEDIATION_POLICY_JSON"), "Effective remediation policy JSON from clearcutt.fleet.yaml")
	cmd.Flags().BoolVar(&remediationRunOpts.skipPR, "skip-pr", false, "Run the drafting agent but do not push or open pull requests")
	return cmd
}

func NewRemediationOpenPRCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "open-pr",
		Short: "Push a remediation branch and open its draft pull request",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemediationOpenPR()
		},
	}
	cmd.Flags().StringVar(&remediationOpenPROpts.branch, "branch", "", "Remediation branch name (defaults to current branch)")
	cmd.Flags().StringVar(&remediationOpenPROpts.packageName, "package", "", "Remediated package name")
	cmd.Flags().StringVar(&remediationOpenPROpts.cve, "cve", "", "CVE identifier")
	cmd.Flags().StringVar(&remediationOpenPROpts.installedVersion, "installed-version", "unknown", "Installed vulnerable package version")
	cmd.Flags().StringVar(&remediationOpenPROpts.summaryPath, "summary", "", "Remediation summary JSON path")
	cmd.Flags().StringVar(&remediationOpenPROpts.baseBranch, "base-branch", envOr("REMEDIATION_BASE_BRANCH", "main"), "Base branch for the pull request")
	cmd.Flags().BoolVar(&remediationOpenPROpts.dryRun, "dry-run", false, "Render the PR title/body without pushing or creating a PR")
	return cmd
}

func envIntValue(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func runRemediationRun() error {
	logRemediationRun("Initializing AI CVE Triage & Auto-Patch Dispatcher...")

	coreDir, err := resolveCoreDir(remediationRunOpts.coreDir)
	if err != nil {
		return err
	}
	planPath := remediationRunOpts.planOut
	if planPath == "" {
		planPath = filepath.Join(coreDir, "build-outputs", "remediation-plan.json")
	}

	vulnDir, err := resolveRemediationVulnDir(remediationRunOpts.vulnRoot, remediationRunOpts.vulnDir)
	if err != nil {
		return err
	}
	policy := remediationPolicyFromJSON(remediationRunOpts.policyJSON)
	plan, err := buildRemediationPlanWithPolicy(vulnDir, remediationRunOpts.limit, remediationRunOpts.includeDevOnly, policy)
	if err != nil {
		return err
	}
	if err := writeRemediationPlanFile(planPath, plan); err != nil {
		return err
	}
	printRemediationRunPlanSummary(plan)

	if len(plan.Campaigns) == 0 {
		return nil
	}

	successCount := 0
	failureCount := 0
	for _, campaign := range plan.Campaigns {
		ok := executeRemediationCampaign(coreDir, campaign)
		if ok {
			successCount++
		} else {
			failureCount++
			if remediationRunOpts.maxFailures > 0 && failureCount >= remediationRunOpts.maxFailures {
				remaining := len(plan.Campaigns) - successCount - failureCount
				warnRemediationRun(
					"Stopping after %d failed patch attempt(s); %d campaign(s) remain queued for a later run.",
					failureCount,
					remaining,
				)
				break
			}
		}
	}

	attempted := successCount + failureCount
	passRemediationRun("Auto-Patch Dispatcher complete. Drafted %d/%d attempted remediation PR(s).", successCount, attempted)
	return nil
}

func printRemediationRunPlanSummary(plan *RemediationPlan) {
	if len(plan.Campaigns) == 0 {
		summary := plan.Summary
		if summary.DevOnlyCampaignCount > 0 {
			passRemediationRun(
				"No fixable production runtime remediation campaigns selected; %d dev-tier-only campaign(s) deferred by policy.",
				summary.DevOnlyCampaignCount,
			)
			logRemediationRun("Set INCLUDE_DEV_ONLY_REMEDIATION=1, or use --include-dev-only, for an explicit dev-tier remediation run.")
		} else {
			passRemediationRun("Zero fixable, materially-risky runtime vulnerabilities selected for automated remediation.")
		}
		if len(summary.ProductionDeferredReasonCounts) > 0 {
			logRemediationRun("Production findings outside auto-remediation policy: %s.", sortedReasonSummary(summary.ProductionDeferredReasonCounts))
		}
		return
	}

	logRemediationRun("Planner selected %d remediation campaign(s) from %s.", len(plan.Campaigns), plan.SourceDir)
	if plan.Summary.DeferredCount > 0 {
		warnRemediationRun("Planner deferred %d finding occurrence(s) outside auto-remediation policy.", plan.Summary.DeferredCount)
	}
	for i, campaign := range plan.Campaigns {
		logRemediationRun(
			"Campaign %d: %s %s %s -> %s targets=%d prod_targets=%d",
			i+1,
			campaign.Package,
			campaign.CVE,
			fallbackString(campaign.InstalledVersion, "?"),
			fallbackString(campaign.FixedVersion, "?"),
			campaign.TargetCount,
			campaign.ProductionTargetCount,
		)
	}
}

func executeRemediationCampaign(coreDir string, campaign RemediationCampaign) bool {
	logRemediationRun(
		"Dispatching AI Patching Agent for: %s (%s) -> %s...",
		campaign.Package,
		campaign.InstalledVersion,
		campaign.CVE,
	)

	summaryRel := filepath.Join("build-outputs", fmt.Sprintf("remediation-summary-%s.json", campaignSlug(campaign)))
	env, err := remediationAgentEnv(campaign, summaryRel)
	if err != nil {
		warnRemediationRun("Failed to encode campaign environment for %s (%s): %v", campaign.Package, campaign.CVE, err)
		return false
	}

	agent := remediationRunOpts.agentScript
	if !filepath.IsAbs(agent) && !strings.Contains(agent, string(filepath.Separator)) {
		if found, err := exec.LookPath(agent); err == nil {
			agent = found
		}
	}
	cmd := exec.Command(agent)
	cmd.Dir = coreDir
	cmd.Env = env
	cmd.Stdout = out
	cmd.Stderr = errOut
	if err := cmd.Run(); err != nil {
		warnRemediationRun("AI Patching Agent failed to draft a patch for %s (%s): %v", campaign.Package, campaign.CVE, err)
		return false
	}

	passRemediationRun("AI Patching Agent drafted a patch for %s (%s); checking for branch...", campaign.Package, campaign.CVE)
	branchName, err := currentGitBranch(coreDir)
	if err != nil {
		warnRemediationRun("Could not read current git branch: %v", err)
		return false
	}
	if !strings.HasPrefix(branchName, "cve-remediation/") {
		warnRemediationRun("No remediation branch produced by the agent - skipping PR.")
		return false
	}
	if remediationRunOpts.skipPR {
		logRemediationRun("--skip-pr set; leaving remediation branch %s in place.", branchName)
		return true
	}

	summaryPath := filepath.Join(coreDir, summaryRel)
	if err := openRemediationPR(openRemediationPROptions{
		Branch:           branchName,
		PackageName:      campaign.Package,
		CVE:              campaign.CVE,
		InstalledVersion: campaign.InstalledVersion,
		SummaryPath:      summaryPath,
		BaseBranch:       remediationRunOpts.baseBranch,
	}); err != nil {
		warnRemediationRun("PR open failed for %s (%s) - branch is still pushed: %v", campaign.Package, campaign.CVE, err)
	}
	_ = runCommand(coreDir, "git", "checkout", remediationRunOpts.baseBranch)
	return true
}

func remediationAgentEnv(campaign RemediationCampaign, summaryPath string) ([]string, error) {
	campaignJSON, err := json.Marshal(campaign)
	if err != nil {
		return nil, err
	}
	targetsJSON, err := json.Marshal(campaign.AffectedTargets)
	if err != nil {
		return nil, err
	}
	env := os.Environ()
	env = append(env,
		"CVE_ID="+campaign.CVE,
		"PACKAGE_NAME="+campaign.Package,
		"INSTALLED_VERSION="+campaign.InstalledVersion,
		"FIXED_VERSION="+campaign.FixedVersion,
		"REMEDIATION_CAMPAIGN="+string(campaignJSON),
		"AFFECTED_TARGETS="+string(targetsJSON),
		"REMEDIATION_SUMMARY_PATH="+summaryPath,
	)
	return env, nil
}

func runRemediationOpenPR() error {
	branch := remediationOpenPROpts.branch
	if branch == "" {
		current, err := currentGitBranch(".")
		if err != nil {
			return err
		}
		branch = current
	}
	return openRemediationPR(openRemediationPROptions{
		Branch:           branch,
		PackageName:      remediationOpenPROpts.packageName,
		CVE:              remediationOpenPROpts.cve,
		InstalledVersion: remediationOpenPROpts.installedVersion,
		SummaryPath:      remediationOpenPROpts.summaryPath,
		BaseBranch:       remediationOpenPROpts.baseBranch,
		DryRun:           remediationOpenPROpts.dryRun,
	})
}

type openRemediationPROptions struct {
	Branch           string
	PackageName      string
	CVE              string
	InstalledVersion string
	SummaryPath      string
	BaseBranch       string
	DryRun           bool
}

func openRemediationPR(opts openRemediationPROptions) error {
	if !strings.HasPrefix(opts.Branch, "cve-remediation/") {
		return fmt.Errorf("refusing to PR non-remediation branch: %s", opts.Branch)
	}
	if opts.PackageName == "" {
		return fmt.Errorf("--package is required")
	}
	if opts.CVE == "" {
		return fmt.Errorf("--cve is required")
	}
	if opts.InstalledVersion == "" {
		opts.InstalledVersion = "unknown"
	}
	if opts.BaseBranch == "" {
		opts.BaseBranch = "main"
	}

	title := fmt.Sprintf("chore: automated CVE patch remediation for %s (%s)", opts.PackageName, opts.CVE)
	body, err := remediationPRBody(opts.PackageName, opts.CVE, opts.InstalledVersion, opts.SummaryPath)
	if err != nil {
		return err
	}
	if opts.DryRun {
		fmt.Fprintf(out, "Title: %s\n\n%s\n", title, body)
		return nil
	}

	fmt.Fprintf(out, "Pushing %s to origin...\n", opts.Branch)
	// Remediation branches are created locally by the drafting agent, so a fresh
	// CI checkout has no remote-tracking ref for them. Bare --force-with-lease
	// then rejects re-pushing a branch that already exists on origin ("stale
	// info"), which happens whenever the same top campaign is re-attempted before
	// its PR merges. Read the current remote tip and lease against that exact
	// value: a re-push succeeds, while a push that races in during this run is
	// still refused. A brand-new branch has no remote tip and is simply created.
	_ = runCommand(".", "git", "fetch", "origin",
		fmt.Sprintf("+refs/heads/%s:refs/remotes/origin/%s", opts.Branch, opts.Branch))
	pushArgs := []string{"push", "origin", opts.Branch}
	if remoteTip, _ := gitCapture(".", "rev-parse", "--verify", "--quiet", "refs/remotes/origin/"+opts.Branch); remoteTip != "" {
		pushArgs = append(pushArgs, "--force-with-lease="+opts.Branch+":"+remoteTip)
	}
	if err := runCommand(".", "git", pushArgs...); err != nil {
		return err
	}

	fmt.Fprintln(out, "Opening draft PR...")
	if err := runCommand(".", "gh", "pr", "create", "--title", title, "--body", body, "--head", opts.Branch, "--base", opts.BaseBranch, "--draft"); err != nil {
		return err
	}
	fmt.Fprintf(out, "Done. PR created against %s.\n", opts.Branch)
	return nil
}

func remediationPRBody(packageName, cve, installedVersion, summaryPath string) (string, error) {
	summarySection, err := remediationSummarySection(summaryPath)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`This Pull Request was automatically drafted by the **ClearCutt CVE Patch Drafting Agent**.

### Details
- **Package:** %s
- **Installed version:** %s
- **CVE:** %s
- **Overlay file:** %s

%s

### Verification
The agent verified the patch against the planner-selected affected target set
and required the original CVE/package pair to disappear from rebuilt Grype
scan output. The full 13-language x 3-tier x 2-arch matrix runs in this PR's pr-gate job;
**do not merge until that suite is green.**

### Rollback
To revert, delete the new file under core/overlays/cve/ and re-merge to main.`,
		codeQuote(packageName),
		codeQuote(installedVersion),
		codeQuote(cve),
		codeQuote("core/overlays/cve/"),
		summarySection,
	), nil
}

func remediationSummarySection(summaryPath string) (string, error) {
	if summaryPath == "" {
		return "", nil
	}
	info, err := os.Stat(summaryPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if info.Size() == 0 {
		return "", nil
	}
	raw, err := os.ReadFile(summaryPath)
	if err != nil {
		return "", err
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", fmt.Errorf("failed to parse remediation summary %s: %w", summaryPath, err)
	}

	recipe := mapValue(data, "recipe")
	policyDecision := firstMapValue(data, "policy_decision", "policyDecision")
	riskFactors := firstMapValue(data, "risk_factors", "riskFactors")
	expectedRemoved := firstSliceValue(data, "expected_removed", "expectedRemoved")
	validation := sliceValue(data, "validation")
	affected := sliceValue(data, "affected_targets")

	var b strings.Builder
	b.WriteString("### Planner campaign\n")
	b.WriteString(fmt.Sprintf("- **Route:** %s\n", codeQuote(firstNonEmpty(stringValue(recipe, "route"), stringValue(data, "remediation_route"), "unknown"))))
	if attr := stringValue(recipe, "package_attribute"); attr != "" {
		b.WriteString(fmt.Sprintf("- **Nix package attribute:** %s\n", codeQuote(attr)))
	}
	if fixed := stringValue(data, "fixed_version"); fixed != "" {
		b.WriteString(fmt.Sprintf("- **Expected fixed version:** %s\n", codeQuote(fixed)))
	}
	if reason := stringValue(policyDecision, "reason"); reason != "" {
		b.WriteString(fmt.Sprintf("- **Policy decision:** %s\n", codeQuote(reason)))
	}
	if known := boolValue(riskFactors, "knownExploited"); known {
		b.WriteString("- **Known exploited:** `true`\n")
	}
	if epss := numberStringValue(riskFactors, "epssPercentile"); epss != "" {
		b.WriteString(fmt.Sprintf("- **EPSS percentile:** %s\n", codeQuote(epss)))
	}
	b.WriteString(fmt.Sprintf("- **Affected target fanout:** %s\n", codeQuote(fmt.Sprintf("%d", len(affected)))))
	prodCount := 0
	labels := []string{}
	for _, item := range affected {
		tier := stringValue(item, "tier")
		if productionRemediationTiers[tier] {
			prodCount++
		}
		if len(labels) < 8 {
			target := stringValue(item, "target")
			arch := stringValue(item, "arch")
			if target != "" || arch != "" {
				labels = append(labels, target+":"+arch)
			}
		}
	}
	b.WriteString(fmt.Sprintf("- **Production target fanout:** %s\n", codeQuote(fmt.Sprintf("%d", prodCount))))
	if len(labels) > 0 {
		extra := ""
		if len(affected) > 8 {
			extra = fmt.Sprintf(" (+%d more)", len(affected)-8)
		}
		b.WriteString(fmt.Sprintf("- **Affected targets:** %s\n", codeQuote(strings.Join(labels, ", ")+extra)))
	}
	if len(expectedRemoved) > 0 {
		pairs := []string{}
		for _, item := range expectedRemoved {
			pair := firstNonEmpty(stringValue(item, "cve"), stringValue(item, "id"))
			pkg := firstNonEmpty(stringValue(item, "package"), stringValue(item, "packageName"))
			if pair != "" || pkg != "" {
				pairs = append(pairs, pair+"/"+pkg)
			}
		}
		if len(pairs) > 0 {
			b.WriteString(fmt.Sprintf("- **Expected removed findings:** %s\n", codeQuote(strings.Join(pairs, ", "))))
		}
	}

	b.WriteString("\n### Before/after validation\n")
	if len(validation) == 0 {
		b.WriteString("- No validation summary was attached by the drafting agent.\n")
		return b.String(), nil
	}
	for _, item := range validation {
		status := firstNonEmpty(stringValue(item, "status"), "unknown")
		target := firstNonEmpty(stringValue(item, "target"), "unknown")
		reason := stringValue(item, "reason")
		b.WriteString(fmt.Sprintf("- %s: **%s** - %s\n", codeQuote(target), status, reason))
		if scanPath := stringValue(item, "scanPath"); scanPath != "" {
			b.WriteString(fmt.Sprintf("  - Grype scan: %s\n", codeQuote(scanPath)))
		}
		if sbomPath := stringValue(item, "sbomPath"); sbomPath != "" {
			b.WriteString(fmt.Sprintf("  - SBOM: %s\n", codeQuote(sbomPath)))
		}
	}
	return b.String(), nil
}

func resolveCoreDir(value string) (string, error) {
	if value != "" {
		return value, nil
	}
	if _, err := os.Stat(filepath.Join("scripts", "cve-draft-agent.py")); err == nil {
		return ".", nil
	}
	if _, err := os.Stat(filepath.Join("core", "scripts", "cve-draft-agent.py")); err == nil {
		return "core", nil
	}
	return "", fmt.Errorf("could not locate core/scripts/cve-draft-agent.py; pass --core-dir")
}

func currentGitBranch(dir string) (string, error) {
	var stdout bytes.Buffer
	cmd := exec.Command("git", "branch", "--show-current")
	cmd.Dir = dir
	cmd.Stdout = &stdout
	cmd.Stderr = errOut
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout.String()), nil
}

func runCommand(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = out
	cmd.Stderr = errOut
	return cmd.Run()
}

// gitCapture runs git and returns trimmed stdout. stderr is discarded so callers
// can probe optional refs (e.g. rev-parse --quiet) without noise on the miss.
func gitCapture(dir string, args ...string) (string, error) {
	var stdout bytes.Buffer
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout.String()), nil
}

func logRemediationRun(format string, args ...any) {
	fmt.Fprintf(out, "[remediation-run] "+format+"\n", args...)
}

func warnRemediationRun(format string, args ...any) {
	fmt.Fprintf(errOut, "[remediation-run] warning: "+format+"\n", args...)
}

func passRemediationRun(format string, args ...any) {
	fmt.Fprintf(out, "[remediation-run] ok: "+format+"\n", args...)
}

func campaignSlug(campaign RemediationCampaign) string {
	safe := strings.ToLower(campaign.CVE + "-" + campaign.Package)
	parts := strings.FieldsFunc(safe, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	return strings.Join(parts, "-")
}

func sortedReasonSummary(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	return strings.Join(parts, ", ")
}

func fallbackString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func codeQuote(value string) string {
	return "`" + strings.ReplaceAll(value, "`", "'") + "`"
}

func mapValue(data map[string]any, key string) map[string]any {
	value, _ := data[key].(map[string]any)
	if value == nil {
		return map[string]any{}
	}
	return value
}

func firstMapValue(data map[string]any, keys ...string) map[string]any {
	for _, key := range keys {
		if value := mapValue(data, key); len(value) > 0 {
			return value
		}
	}
	return map[string]any{}
}

func sliceValue(data map[string]any, key string) []map[string]any {
	raw, _ := data[key].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if mapped, ok := item.(map[string]any); ok {
			out = append(out, mapped)
		}
	}
	return out
}

func firstSliceValue(data map[string]any, keys ...string) []map[string]any {
	for _, key := range keys {
		if value := sliceValue(data, key); len(value) > 0 {
			return value
		}
	}
	return nil
}

func stringValue(data map[string]any, key string) string {
	value, _ := data[key].(string)
	return value
}

func boolValue(data map[string]any, key string) bool {
	value, _ := data[key].(bool)
	return value
}

func numberStringValue(data map[string]any, key string) string {
	switch value := data[key].(type) {
	case float64:
		return fmt.Sprintf("%.3f", value)
	case int:
		return fmt.Sprintf("%d", value)
	default:
		return ""
	}
}
