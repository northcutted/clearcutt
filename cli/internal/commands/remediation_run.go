package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type remediationRunFlags struct {
	vulnRoot              string
	vulnDir               string
	includeDevOnly        bool
	limit                 int
	maxFailures           int
	coreDir               string
	planOut               string
	agentScript           string
	baseBranch            string
	rollingBranch         string
	llmMode               string
	deterministicEvidence string
	skipPR                bool
	policyJSON            string
	manualPackage         string
	manualCVE             string
	manualInstalled       string
	manualFixed           string
	manualDownloadURL     string
	manualSHA256          string
	manualPatchURL        string
	manualPatchSHA256     string
	requireLLMKey         bool
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
		Long: `Builds a remediation campaign plan and accumulates produced overlays
onto one cve-remediation/* rolling branch. Deterministic evidence-backed fixes
are drafted natively by the Go CLI from direct route+overlay_expression recipes
or explicit source/patch URL+hash evidence. With --llm off, campaigns that still
need hash iteration or build probing are skipped. With --llm auto, only those
unresolved campaigns may route to the retained drafting backend. The command
opens or updates one aggregated draft PR unless --skip-pr is set.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemediationRun()
		},
	}
	cmd.Flags().StringVar(&remediationRunOpts.vulnRoot, "vuln-root", envOr("VULN_ROOT", remediationDefaultVulnRoot), "Root directory containing versioned vulnerability scan outputs")
	cmd.Flags().StringVar(&remediationRunOpts.vulnDir, "vuln-dir", os.Getenv("REMEDIATION_VULN_DIR"), "Specific vulnerability scan directory to read")
	cmd.Flags().BoolVar(&remediationRunOpts.includeDevOnly, "include-dev-only", remediationRunIncludeDevOnlyDefault(), "Include dev-tier-only campaigns")
	cmd.Flags().IntVar(&remediationRunOpts.limit, "limit", remediationRunLimitDefault(), "Maximum campaigns to attempt")
	cmd.Flags().IntVar(&remediationRunOpts.maxFailures, "max-failures", envIntValue("MAX_PATCH_FAILURES_PER_RUN", 1), "Stop after this many failed patch attempts (0 disables the cap)")
	cmd.Flags().StringVar(&remediationRunOpts.coreDir, "core-dir", "", "Core workspace directory (auto-detected when omitted)")
	cmd.Flags().StringVar(&remediationRunOpts.planOut, "plan-out", "", "Write the generated plan JSON to this path")
	cmd.Flags().StringVar(&remediationRunOpts.agentScript, "agent-script", envOr("CVE_DRAFT_AGENT", "./scripts/cve-draft-agent.py"), "Retained drafting backend path, relative to --core-dir unless absolute")
	cmd.Flags().StringVar(&remediationRunOpts.baseBranch, "base-branch", envOr("REMEDIATION_BASE_BRANCH", "main"), "Base branch for draft PRs and checkout reset")
	cmd.Flags().StringVar(&remediationRunOpts.rollingBranch, "rolling-branch", envOr("REMEDIATION_ROLLING_BRANCH", "cve-remediation/auto"), "Single rolling branch all campaign overlays land on, backing ONE aggregated draft PR")
	cmd.Flags().StringVar(&remediationRunOpts.llmMode, "llm", envOr("REMEDIATION_LLM_MODE", envOr("CLEARCUTT_REMEDIATION_LLM", "auto")), "LLM escalation policy: auto or off. off attempts only deterministic evidence-backed campaigns")
	cmd.Flags().StringVar(&remediationRunOpts.deterministicEvidence, "deterministic-evidence", envOr("REMEDIATION_EVIDENCE_FILE", filepath.Join("overlays", "remediation-evidence.json")), "Evidence file used to decide which campaigns are safe for --llm off")
	cmd.Flags().StringVar(&remediationRunOpts.policyJSON, "policy-json", os.Getenv("REMEDIATION_POLICY_JSON"), "Effective remediation policy JSON from clearcutt.fleet.yaml")
	cmd.Flags().StringVar(&remediationRunOpts.manualPackage, "package", os.Getenv("PACKAGE_NAME"), "Manual single-campaign package name; when set, scan planning is bypassed")
	cmd.Flags().StringVar(&remediationRunOpts.manualCVE, "cve", os.Getenv("CVE_ID"), "Manual single-campaign CVE id; required with --package")
	cmd.Flags().StringVar(&remediationRunOpts.manualInstalled, "installed-version", os.Getenv("INSTALLED_VERSION"), "Manual single-campaign installed vulnerable version")
	cmd.Flags().StringVar(&remediationRunOpts.manualFixed, "fixed-version", os.Getenv("FIXED_VERSION"), "Manual single-campaign fixed version, when known")
	cmd.Flags().StringVar(&remediationRunOpts.manualDownloadURL, "download-url", os.Getenv("DOWNLOAD_URL"), "Manual deterministic source archive URL for a version-bump recipe")
	cmd.Flags().StringVar(&remediationRunOpts.manualSHA256, "sha256", os.Getenv("SHA256"), "Manual deterministic source archive sha256 for a version-bump recipe")
	cmd.Flags().StringVar(&remediationRunOpts.manualPatchURL, "patch-url", os.Getenv("PATCH_URL"), "Manual deterministic patch URL for a fetchpatch recipe")
	cmd.Flags().StringVar(&remediationRunOpts.manualPatchSHA256, "patch-sha256", os.Getenv("PATCH_SHA256"), "Manual deterministic patch sha256 for a fetchpatch recipe")
	cmd.Flags().BoolVar(&remediationRunOpts.skipPR, "skip-pr", false, "Draft remediation overlays locally but do not push or open pull requests")
	cmd.Flags().BoolVar(&remediationRunOpts.requireLLMKey, "require-llm-key", parseScanBool(os.Getenv("REMEDIATION_REQUIRE_LLM_KEY")), "Fail before drafting when LLM mode is enabled but OPENROUTER_API_KEY is not configured")
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

func remediationRunLimitDefault() int {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("GITHUB_EVENT_NAME")), "schedule") {
		if limit := envIntValue("SCHEDULED_REMEDIATION_LIMIT", 0); limit > 0 {
			return limit
		}
	}
	return envIntValue("MAX_FINDINGS_PER_RUN", 0)
}

func remediationRunIncludeDevOnlyDefault() bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("GITHUB_EVENT_NAME")), "schedule") {
		return false
	}
	return parseScanBool(os.Getenv("INCLUDE_DEV_ONLY_REMEDIATION"))
}

func runRemediationRun() error {
	logRemediationRun("Initializing ClearCutt remediation dispatcher...")
	if remediationRunOpts.requireLLMKey &&
		!strings.EqualFold(strings.TrimSpace(remediationRunOpts.llmMode), "off") &&
		strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) == "" {
		return fmt.Errorf("draft_patches=true requires OPENROUTER_API_KEY when --llm is not off")
	}

	coreDir, err := resolveCoreDir(remediationRunOpts.coreDir)
	if err != nil {
		return err
	}
	planPath := remediationRunOpts.planOut
	if planPath == "" {
		planPath = filepath.Join(coreDir, "build-outputs", "remediation-plan.json")
	}

	policy := remediationPolicyFromJSON(remediationRunOpts.policyJSON)
	var plan *RemediationPlan
	if remediationRunManualInputSet() {
		plan, err = buildManualRemediationPlan()
		if err != nil {
			return err
		}
		plan.Policy = policy
	} else {
		vulnDir, err := resolveRemediationVulnDir(remediationRunOpts.vulnRoot, remediationRunOpts.vulnDir)
		if err != nil {
			return err
		}
		plan, err = buildRemediationPlanWithPolicy(vulnDir, remediationRunOpts.limit, remediationRunOpts.includeDevOnly, policy)
		if err != nil {
			return err
		}
		enrichPlanRoutesBestEffort(plan, coreDir)
	}
	if strings.EqualFold(strings.TrimSpace(remediationRunOpts.llmMode), "off") {
		evidencePath := remediationRunOpts.deterministicEvidence
		if !filepath.IsAbs(evidencePath) {
			evidencePath = filepath.Join(coreDir, evidencePath)
		}
		selected, skipped, err := filterDeterministicRemediationCampaigns(plan.Campaigns, evidencePath)
		if err != nil {
			return err
		}
		if skipped > 0 {
			warnRemediationRun(
				"LLM escalation is off; skipped %d campaign(s) without deterministic source/patch evidence.",
				skipped,
			)
		}
		updatePlanCampaignSelection(plan, selected)
	}
	if err := writeRemediationPlanFile(planPath, plan); err != nil {
		return err
	}
	printRemediationRunPlanSummary(plan)

	if len(plan.Campaigns) == 0 {
		return nil
	}

	rolling := remediationRunOpts.rollingBranch
	base := remediationRunOpts.baseBranch
	runner := execRunner{}

	// Every campaign overlay lands on ONE rolling branch backing a single
	// aggregated draft PR (instead of a PR per CVE). The branch is recreated
	// from base each run so that one PR always reflects the current scan.
	if err := resetRollingBranch(runner, coreDir, rolling, base); err != nil {
		return fmt.Errorf("could not initialize rolling remediation branch %s: %w", rolling, err)
	}

	successCount := 0
	failureCount := 0
	landed := make([]RemediationCampaign, 0, len(plan.Campaigns))
	for _, campaign := range plan.Campaigns {
		ok, branch := executeRemediationCampaign(coreDir, campaign)
		if !ok {
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
			continue
		}
		successCount++
		if branch == "" {
			continue
		}
		if err := foldIntoRolling(runner, coreDir, rolling, branch); err != nil {
			warnRemediationRun("Could not fold %s into rolling branch %s: %v", branch, rolling, err)
			continue
		}
		landed = append(landed, campaign)
	}

	if len(landed) == 0 {
		passRemediationRun("Auto-Patch Dispatcher complete. No overlays landed on %s.", rolling)
		return nil
	}
	if remediationRunOpts.skipPR {
		passRemediationRun("--skip-pr set; %d overlay(s) accumulated on local branch %s (not pushed).", len(landed), rolling)
		return nil
	}
	if err := openOrUpdateAggregatedPR(runner, coreDir, rolling, base, landed); err != nil {
		return fmt.Errorf("aggregated PR open/update failed after pushing branch %s: %w", rolling, err)
	}

	passRemediationRun(
		"Auto-Patch Dispatcher complete. %d overlay(s) on one aggregated PR (%d/%d campaigns succeeded).",
		len(landed), successCount, successCount+failureCount,
	)
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

func remediationRunManualInputSet() bool {
	for _, value := range []string{
		remediationRunOpts.manualPackage,
		remediationRunOpts.manualCVE,
		remediationRunOpts.manualInstalled,
		remediationRunOpts.manualFixed,
		remediationRunOpts.manualDownloadURL,
		remediationRunOpts.manualSHA256,
		remediationRunOpts.manualPatchURL,
		remediationRunOpts.manualPatchSHA256,
	} {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func buildManualRemediationPlan() (*RemediationPlan, error) {
	pkg := strings.TrimSpace(remediationRunOpts.manualPackage)
	cve := strings.TrimSpace(remediationRunOpts.manualCVE)
	installed := strings.TrimSpace(remediationRunOpts.manualInstalled)
	if pkg == "" {
		return nil, fmt.Errorf("--package is required for manual remediation dispatch")
	}
	if cve == "" {
		return nil, fmt.Errorf("--cve is required for manual remediation dispatch")
	}
	if installed == "" {
		return nil, fmt.Errorf("--installed-version is required for manual remediation dispatch")
	}
	fixed := strings.TrimSpace(remediationRunOpts.manualFixed)
	evidence := manualRemediationEvidence()
	route := manualRemediationRoute(evidence, fixed)
	fixedAvailable := fixed != ""
	fixState := "unknown"
	if fixedAvailable {
		fixState = "fixed"
	}
	campaign := RemediationCampaign{
		Package:             pkg,
		CVE:                 cve,
		PrimaryCVE:          cve,
		CVEs:                []string{cve},
		InstalledVersion:    installed,
		FixedVersion:        fixed,
		FixState:            fixState,
		Severity:            "manual",
		Layer:               "runtime",
		RecommendedRoute:    route,
		RouteReason:         "manual workflow_dispatch input",
		RemediationEvidence: evidence,
		RiskFactors: RemediationRiskFactors{
			Severity:              "manual",
			FixedVersionAvailable: fixedAvailable,
			ProductionTargetCount: 1,
			TargetCount:           1,
		},
		PolicyDecision: RemediationPolicyDecision{
			Selected: true,
			Reason:   "manual_dispatch",
			Summary:  "Selected from explicit workflow_dispatch remediation input.",
		},
		ExpectedRemoved: []RemediationExpectedFinding{{
			CVE:              cve,
			Package:          pkg,
			InstalledVersion: installed,
		}},
		AffectedTargets: []RemediationTarget{{
			Target: "manual-dispatch",
			Tier:   "manual",
			Arch:   "manual",
		}},
		ProductionTargetCount: 1,
		TargetCount:           1,
		Score:                 1,
	}
	now := time.Now().UTC().Format(time.RFC3339)
	plan := &RemediationPlan{
		GeneratedAt: now,
		SourceDir:   "manual-dispatch",
		ScanSource: RemediationScanSource{
			Directory: "manual-dispatch",
		},
		Campaigns: []RemediationCampaign{campaign},
		Deferred:  []RemediationDeferred{},
		Metrics: RemediationMetrics{
			SelectedCampaigns:       1,
			CandidateCampaigns:      1,
			AutomationCoverage:      1,
			RootCauseClusterCount:   1,
			KnownExploitedCampaigns: 0,
		},
		Summary: RemediationPlanSummary{
			CampaignCount:           1,
			CandidateCampaignCount:  1,
			ProductionCampaignCount: 1,
			DeferredReasonCounts:    map[string]int{},
		},
	}
	plan.Clusters = remediationClusters(plan.Campaigns)
	return plan, nil
}

func manualRemediationEvidence() map[string]any {
	evidence := map[string]any{}
	add := func(key, value string) {
		if strings.TrimSpace(value) != "" {
			evidence[key] = strings.TrimSpace(value)
		}
	}
	add("fixedVersion", remediationRunOpts.manualFixed)
	add("download_url", remediationRunOpts.manualDownloadURL)
	add("source_url", remediationRunOpts.manualDownloadURL)
	add("sha256", remediationRunOpts.manualSHA256)
	add("source_sha256", remediationRunOpts.manualSHA256)
	add("patch_url", remediationRunOpts.manualPatchURL)
	add("patch_sha256", remediationRunOpts.manualPatchSHA256)
	return evidence
}

func manualRemediationRoute(evidence map[string]any, fixed string) string {
	if strings.TrimSpace(stringValue(evidence, "patch_url")) != "" {
		return RouteFetchpatchRebuild
	}
	if strings.TrimSpace(stringValue(evidence, "download_url")) != "" || strings.TrimSpace(fixed) != "" {
		return RouteVersionBump
	}
	return "manual_triage"
}

func filterDeterministicRemediationCampaigns(campaigns []RemediationCampaign, evidencePath string) ([]RemediationCampaign, int, error) {
	entries, err := loadDeterministicRemediationEvidence(evidencePath)
	if err != nil {
		return nil, 0, err
	}
	selected := make([]RemediationCampaign, 0, len(campaigns))
	for _, campaign := range campaigns {
		if campaignHasDeterministicRecipe(campaign) {
			selected = append(selected, campaign)
			continue
		}
		if evidence := matchingDeterministicEvidence(campaign, entries); evidence != nil {
			selected = append(selected, campaignWithDeterministicEvidence(campaign, evidence))
		}
	}
	return selected, len(campaigns) - len(selected), nil
}

func loadDeterministicRemediationEvidence(path string) ([]map[string]any, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read deterministic remediation evidence %s: %w", path, err)
	}
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var wrapped struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, fmt.Errorf("parse deterministic remediation evidence %s: %w", path, err)
	}
	return wrapped.Entries, nil
}

func campaignHasDeterministicRecipe(campaign RemediationCampaign) bool {
	for _, recipe := range []map[string]any{campaign.DeterministicRecipe, mapValue(campaign.DeterministicRemediation, "recipe")} {
		if evidenceHasDeterministicRecipe(recipe) {
			return true
		}
	}
	return evidenceHasDeterministicRecipe(campaign.RemediationEvidence)
}

func matchingDeterministicEvidence(campaign RemediationCampaign, entries []map[string]any) map[string]any {
	for _, entry := range entries {
		if !remediationEvidenceEntryMatches(entry, campaign) {
			continue
		}
		if evidenceHasDeterministicRecipe(entry) {
			return entry
		}
	}
	return nil
}

func campaignWithDeterministicEvidence(campaign RemediationCampaign, evidence map[string]any) RemediationCampaign {
	if len(campaign.RemediationEvidence) == 0 {
		campaign.RemediationEvidence = evidence
	} else {
		merged := make(map[string]any, len(campaign.RemediationEvidence)+len(evidence))
		for key, value := range campaign.RemediationEvidence {
			merged[key] = value
		}
		for key, value := range evidence {
			if _, exists := merged[key]; !exists {
				merged[key] = value
			}
		}
		campaign.RemediationEvidence = merged
	}
	if recipe := mapValue(evidence, "recipe"); len(recipe) > 0 {
		campaign.DeterministicRecipe = recipe
	} else if strings.TrimSpace(stringValue(evidence, "route")) != "" && strings.TrimSpace(stringValue(evidence, "overlay_expression")) != "" {
		campaign.DeterministicRecipe = evidence
	} else if evidenceHasDeterministicRecipe(evidence) {
		campaign.DeterministicRecipe = evidence
	}
	return campaign
}

func remediationEvidenceEntryMatches(entry map[string]any, campaign RemediationCampaign) bool {
	if !strings.EqualFold(strings.TrimSpace(stringValue(entry, "package")), strings.TrimSpace(campaign.Package)) {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(stringValue(entry, "cve")), strings.TrimSpace(campaign.CVE)) {
		return false
	}
	if installed := firstNonEmpty(stringValue(entry, "installedVersion"), stringValue(entry, "installed_version")); installed != "" && installed != campaign.InstalledVersion {
		return false
	}
	if fixed := firstNonEmpty(stringValue(entry, "fixedVersion"), stringValue(entry, "fixed_version")); fixed != "" && fixed != campaign.FixedVersion {
		return false
	}
	return true
}

func evidenceHasDeterministicRecipe(entry map[string]any) bool {
	if len(entry) == 0 {
		return false
	}
	recipe := mapValue(entry, "recipe")
	if strings.TrimSpace(stringValue(recipe, "route")) != "" && strings.TrimSpace(stringValue(recipe, "overlay_expression")) != "" {
		return true
	}
	if strings.TrimSpace(stringValue(entry, "overlay_expression")) != "" {
		return true
	}
	sourceURL := firstNonEmpty(stringValue(entry, "download_url"), stringValue(entry, "downloadUrl"), stringValue(entry, "source_url"), stringValue(entry, "sourceUrl"))
	sourceHash := firstNonEmpty(stringValue(entry, "sha256"), stringValue(entry, "source_sha256"), stringValue(entry, "sourceSha256"))
	patchURL := firstNonEmpty(stringValue(entry, "patch_url"), stringValue(entry, "patchUrl"))
	patchHash := firstNonEmpty(stringValue(entry, "patch_sha256"), stringValue(entry, "patchSha256"))
	return (sourceURL != "" && sourceHash != "") || (patchURL != "" && patchHash != "")
}

func updatePlanCampaignSelection(plan *RemediationPlan, campaigns []RemediationCampaign) {
	if plan == nil {
		return
	}
	plan.Campaigns = campaigns
	plan.Clusters = remediationClusters(campaigns)
	plan.Summary.CampaignCount = len(campaigns)
	plan.Summary.ProductionCampaignCount = 0
	plan.Metrics.SelectedCampaigns = len(campaigns)
	plan.Metrics.KnownExploitedCampaigns = 0
	for _, campaign := range campaigns {
		if campaign.ProductionTargetCount > 0 {
			plan.Summary.ProductionCampaignCount++
		}
		if campaign.RiskFactors.KnownExploited {
			plan.Metrics.KnownExploitedCampaigns++
		}
	}
	denominator := plan.Summary.CandidateCampaignCount + plan.Summary.DeferredCount
	if denominator > 0 {
		plan.Metrics.AutomationCoverage = roundRemediationScore(float64(len(campaigns)) / float64(denominator))
	} else {
		plan.Metrics.AutomationCoverage = 0
	}
}

// executeRemediationCampaign drafts one campaign natively when deterministic
// evidence is sufficient, otherwise it invokes the retained drafting backend.
// Both paths produce a cve-remediation/* branch from the current rolling HEAD,
// so the caller folds that branch into ONE aggregated PR for the whole run.
func executeRemediationCampaign(coreDir string, campaign RemediationCampaign) (bool, string) {
	ok, branch, attempted := executeNativeDeterministicRemediation(coreDir, campaign)
	if attempted {
		return ok, branch
	}
	if strings.EqualFold(strings.TrimSpace(remediationRunOpts.llmMode), "off") {
		warnRemediationRun(
			"LLM escalation is off and no deterministic recipe is available for %s (%s); skipping campaign.",
			campaign.Package,
			campaign.CVE,
		)
		return false, ""
	}
	logRemediationRun(
		"Dispatching retained CVE drafting backend for: %s (%s) -> %s...",
		campaign.Package,
		campaign.InstalledVersion,
		campaign.CVE,
	)

	summaryRel := filepath.Join("build-outputs", fmt.Sprintf("remediation-summary-%s.json", campaignSlug(campaign)))
	env, err := remediationAgentEnv(campaign, summaryRel)
	if err != nil {
		warnRemediationRun("Failed to encode campaign environment for %s (%s): %v", campaign.Package, campaign.CVE, err)
		return false, ""
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
		warnRemediationRun("Retained CVE drafting backend failed to draft a patch for %s (%s): %v", campaign.Package, campaign.CVE, err)
		return false, ""
	}

	passRemediationRun("Retained CVE drafting backend drafted a patch for %s (%s); checking for branch...", campaign.Package, campaign.CVE)
	branchName, err := currentGitBranch(coreDir)
	if err != nil {
		warnRemediationRun("Could not read current git branch: %v", err)
		return false, ""
	}
	if !strings.HasPrefix(branchName, "cve-remediation/") {
		warnRemediationRun("No remediation branch produced by the drafting backend - skipping campaign.")
		return false, ""
	}
	return true, branchName
}

func executeNativeDeterministicRemediation(coreDir string, campaign RemediationCampaign) (bool, string, bool) {
	recipe := deterministicRecipeForCampaign(campaign)
	if len(recipe) == 0 {
		return false, "", false
	}
	logRemediationRun(
		"Drafting deterministic remediation natively for: %s (%s) -> %s...",
		campaign.Package,
		campaign.InstalledVersion,
		campaign.CVE,
	)
	expression, err := validateNativeRemediationRecipe(recipe, campaign)
	if err != nil {
		warnRemediationRun("Deterministic recipe rejected for %s (%s): %v", campaign.Package, campaign.CVE, err)
		return false, "", true
	}
	overlayPath, err := writeNativeCVEOverlay(coreDir, campaign.CVE, campaign.Package, expression)
	if err != nil {
		warnRemediationRun("Could not write deterministic overlay for %s (%s): %v", campaign.Package, campaign.CVE, err)
		return false, "", true
	}
	status := "drafted_unvalidated"
	validation := []map[string]any{{
		"status":  "pending",
		"reason":  "native deterministic draft; pr-gate rebuild and scan must pass before merge",
		"command": "clearcutt remediation validate-overlays --overlay-dir core/overlays/cve",
	}}
	if ok, syntaxErr := checkNativeOverlaySyntax(overlayPath); ok {
		status = "draft_compiled"
		validation = []map[string]any{{
			"status":  "passed",
			"reason":  "nix-instantiate --parse accepted the generated overlay",
			"command": "nix-instantiate --parse " + filepath.ToSlash(overlayPath),
		}}
	} else if syntaxErr != "" {
		_ = removeNativeCVEOverlay(coreDir, campaign.CVE, campaign.Package)
		warnRemediationRun("Deterministic overlay syntax check failed for %s (%s): %s", campaign.Package, campaign.CVE, syntaxErr)
		return false, "", true
	}
	summaryRel := filepath.Join("build-outputs", fmt.Sprintf("remediation-summary-%s.json", campaignSlug(campaign)))
	summary := nativeDeterministicSummary(campaign, recipe, status, validation)
	summaryPath := filepath.Join(coreDir, summaryRel)
	if err := writeRemediationJSONFile(summaryPath, summary); err != nil {
		warnRemediationRun("Could not write deterministic remediation summary for %s (%s): %v", campaign.Package, campaign.CVE, err)
		return false, "", true
	}
	if err := writeNativeCVEOverlayEvidence(coreDir, campaign.CVE, campaign.Package, summary, summaryRel); err != nil {
		warnRemediationRun("Could not write deterministic overlay evidence for %s (%s): %v", campaign.Package, campaign.CVE, err)
		return false, "", true
	}
	branch, err := createNativeRemediationBranch(coreDir, campaign)
	if err != nil {
		warnRemediationRun("Could not create deterministic remediation branch for %s (%s): %v", campaign.Package, campaign.CVE, err)
		return false, "", true
	}
	passRemediationRun("Native deterministic remediation drafted a patch for %s (%s).", campaign.Package, campaign.CVE)
	return true, branch, true
}

func deterministicRecipeForCampaign(campaign RemediationCampaign) map[string]any {
	sources := []map[string]any{
		campaign.DeterministicRecipe,
		mapValue(campaign.DeterministicRemediation, "recipe"),
		mapValue(campaign.RemediationEvidence, "recipe"),
		campaign.RemediationEvidence,
		campaign.DeterministicRemediation,
	}
	for _, recipe := range sources {
		if strings.TrimSpace(stringValue(recipe, "route")) != "" && strings.TrimSpace(stringValue(recipe, "overlay_expression")) != "" {
			return recipe
		}
	}
	return synthesizeDeterministicRecipe(campaign, sources)
}

var nixAttributePathPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_'-]*(\.[A-Za-z_][A-Za-z0-9_'-]*)*$`)

func synthesizeDeterministicRecipe(campaign RemediationCampaign, sources []map[string]any) map[string]any {
	packageAttr := safeNixAttributePath(firstNonEmpty(
		firstStringValue(sources, "package_attribute", "packageAttribute", "nix_attribute", "nixAttribute"),
		campaign.Package,
	))
	if packageAttr == "" {
		return nil
	}
	fixedVersion := firstNonEmpty(
		campaign.FixedVersion,
		firstStringValue(sources, "fixed_version", "fixedVersion"),
	)
	sourceURL := firstStringValue(sources, "download_url", "downloadUrl", "source_url", "sourceUrl")
	sourceHash := firstStringValue(sources, "sha256", "source_sha256", "sourceSha256")
	patchURL := firstStringValue(sources, "patch_url", "patchUrl")
	patchHash := firstStringValue(sources, "patch_sha256", "patchSha256")
	advisoryURL := firstStringValue(sources, "advisory_url", "advisoryUrl")
	upstreamCommit := firstStringValue(sources, "upstream_commit", "upstreamCommit")

	if fixedVersion != "" && sourceURL != "" && sourceHash != "" {
		expression := fmt.Sprintf(
			"%s =\n"+
				"  if prev.lib.versionOlder prev.%s.version %s\n"+
				"  then prev.%s.overrideAttrs (old: {\n"+
				"    version = %s;\n"+
				"    src = prev.fetchurl {\n"+
				"      url = %s;\n"+
				"      sha256 = %s;\n"+
				"    };\n"+
				"    # The fixed-output source hash pins the release archive; CI rebuild and rescan gates remain required.\n"+
				"    doCheck = false;\n"+
				"  })\n"+
				"  else prev.%s;",
			packageAttr,
			packageAttr,
			nixStringLiteral(fixedVersion),
			packageAttr,
			nixStringLiteral(fixedVersion),
			nixStringLiteral(sourceURL),
			nixStringLiteral(sourceHash),
			packageAttr,
		)
		return nativeRecipeMap("version_bump", expression, map[string]string{
			"package_attribute": packageAttr,
			"fixed_version":     fixedVersion,
			"source_url":        sourceURL,
			"source_sha256":     sourceHash,
			"advisory_url":      advisoryURL,
			"upstream_commit":   upstreamCommit,
		})
	}

	if patchURL != "" && patchHash != "" {
		expression := fmt.Sprintf(
			"%s = prev.%s.overrideAttrs (old: {\n"+
				"  patches = (old.patches or []) ++ [\n"+
				"    (prev.fetchpatch {\n"+
				"      url = %s;\n"+
				"      sha256 = %s;\n"+
				"    })\n"+
				"  ];\n"+
				"});",
			packageAttr,
			packageAttr,
			nixStringLiteral(patchURL),
			nixStringLiteral(patchHash),
		)
		return nativeRecipeMap("fetchpatch", expression, map[string]string{
			"package_attribute": packageAttr,
			"patch_url":         patchURL,
			"patch_sha256":      patchHash,
			"advisory_url":      advisoryURL,
			"upstream_commit":   upstreamCommit,
		})
	}
	return nil
}

func firstStringValue(sources []map[string]any, keys ...string) string {
	for _, source := range sources {
		for _, key := range keys {
			if value := strings.TrimSpace(stringValue(source, key)); value != "" {
				return value
			}
		}
	}
	return ""
}

func safeNixAttributePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !nixAttributePathPattern.MatchString(value) {
		return ""
	}
	return value
}

func nixStringLiteral(value string) string {
	return strconv.Quote(value)
}

func nativeRecipeMap(route, expression string, fields map[string]string) map[string]any {
	recipe := map[string]any{
		"route":              route,
		"overlay_expression": expression,
	}
	for key, value := range fields {
		if strings.TrimSpace(value) != "" {
			recipe[key] = value
		}
	}
	return recipe
}

func nativeDeterministicSummary(campaign RemediationCampaign, recipe map[string]any, status string, validation []map[string]any) map[string]any {
	remediationRoute := "deterministic_" + strings.TrimSpace(stringValue(recipe, "route"))
	switch strings.TrimSpace(stringValue(recipe, "route")) {
	case "version_bump":
		remediationRoute = "tier1_pin_bump"
	case "fetchpatch":
		remediationRoute = "tier2_patch_file"
	}
	return map[string]any{
		"status":            status,
		"generated_at":      time.Now().UTC().Format(time.RFC3339),
		"package":           campaign.Package,
		"cve":               campaign.CVE,
		"installed_version": campaign.InstalledVersion,
		"fixed_version":     firstNonEmpty(stringValue(recipe, "fixed_version"), stringValue(recipe, "fixedVersion"), campaign.FixedVersion),
		"remediation_route": remediationRoute,
		"recipe":            recipe,
		"affected_targets":  campaign.AffectedTargets,
		"expected_removed":  campaign.ExpectedRemoved,
		"policy_decision":   campaign.PolicyDecision,
		"risk_factors":      campaign.RiskFactors,
		"validation":        validation,
		"drafted_by":        "clearcutt-go-native-deterministic",
		"human_review_note": "Generated without LLM escalation. Merge remains gated by PR review and CI rebuild/rescan gates.",
	}
}

func writeRemediationJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func nativeCVEOverlayPath(coreDir, cveID, packageName string) string {
	return filepath.Join(coreDir, "overlays", "cve", campaignSlug(RemediationCampaign{CVE: cveID, Package: packageName})+".nix")
}

func nativeCVEOverlayEvidencePath(coreDir, cveID, packageName string) string {
	return strings.TrimSuffix(nativeCVEOverlayPath(coreDir, cveID, packageName), ".nix") + ".evidence.json"
}

func writeNativeCVEOverlay(coreDir, cveID, packageName, expression string) (string, error) {
	path := nativeCVEOverlayPath(coreDir, cveID, packageName)
	body := strings.TrimSpace(expression)
	if strings.Contains(body, "final: prev:") || strings.HasPrefix(body, "final:") {
		if open := strings.Index(body, "{"); open >= 0 {
			if close := strings.LastIndex(body, "}"); close > open {
				body = strings.TrimSpace(body[open+1 : close])
			}
		}
	}
	body = strings.TrimRight(strings.TrimSpace(body), ";")
	content := fmt.Sprintf(`# %s - %s
# Generated by clearcutt remediation run --llm off - safe to delete to roll back.
#
# This deterministic overlay was rendered by the Go CLI from explicit
# remediation evidence. PR review and CI rebuild/rescan gates must pass before
# merge.
final: prev: {
  %s;
}
`, cveID, packageName, body)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return "", err
	}
	return path, os.Rename(tmp, path)
}

func writeNativeCVEOverlayEvidence(coreDir, cveID, packageName string, summary map[string]any, summaryPath string) error {
	evidence := map[string]any{
		"schemaVersion":   "clearcutt.remediation.evidence/v1",
		"status":          summary["status"],
		"cve":             cveID,
		"package":         packageName,
		"generatedAt":     summary["generated_at"],
		"policyDecision":  summary["policy_decision"],
		"riskFactors":     summary["risk_factors"],
		"expectedRemoved": summary["expected_removed"],
		"recipe":          summary["recipe"],
		"validation":      summary["validation"],
		"summaryPath":     summaryPath,
		"generatedBy":     "clearcutt remediation run --llm off",
	}
	return writeRemediationJSONFile(nativeCVEOverlayEvidencePath(coreDir, cveID, packageName), evidence)
}

func removeNativeCVEOverlay(coreDir, cveID, packageName string) error {
	var firstErr error
	for _, path := range []string{nativeCVEOverlayPath(coreDir, cveID, packageName), nativeCVEOverlayEvidencePath(coreDir, cveID, packageName)} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func createNativeRemediationBranch(coreDir string, campaign RemediationCampaign) (string, error) {
	branch := "cve-remediation/" + campaignSlug(campaign)
	if err := runCommand(coreDir, "git", "checkout", "-b", branch); err != nil {
		warnRemediationRun("git checkout -b %s failed; trying existing branch", branch)
		if checkoutErr := runCommand(coreDir, "git", "checkout", branch); checkoutErr != nil {
			return "", checkoutErr
		}
	}
	for _, path := range []string{
		nativeCVEOverlayPath(coreDir, campaign.CVE, campaign.Package),
		nativeCVEOverlayEvidencePath(coreDir, campaign.CVE, campaign.Package),
	} {
		if _, err := os.Stat(path); err == nil {
			if err := runCommand(coreDir, "git", "add", path); err != nil {
				return "", err
			}
		}
	}
	if err := runCommand(coreDir, "git", "commit", "-m", fmt.Sprintf("chore: deterministic CVE remediation for %s (%s)", campaign.Package, campaign.CVE)); err != nil {
		warnRemediationRun("git commit warning/error for deterministic remediation branch %s: %v", branch, err)
	}
	return branch, nil
}

func checkNativeOverlaySyntax(path string) (bool, string) {
	if _, err := exec.LookPath("nix-instantiate"); err != nil {
		return false, ""
	}
	var stderr bytes.Buffer
	cmd := exec.Command("nix-instantiate", "--parse", path)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return false, strings.TrimSpace(stderr.String())
	}
	return true, ""
}

var nativeRouteAllowedOverrideAttrs = map[string]map[string]bool{
	"version_bump": {"version": true, "src": true, "doCheck": true},
	"fetchpatch":   {"patches": true},
}

func validateNativeRemediationRecipe(recipe map[string]any, campaign RemediationCampaign) (string, error) {
	route := strings.TrimSpace(stringValue(recipe, "route"))
	allowedAttrs, ok := nativeRouteAllowedOverrideAttrs[route]
	if !ok {
		return "", fmt.Errorf("recipe route must be one of fetchpatch, version_bump; got %q", route)
	}
	expression := strings.TrimSpace(stringValue(recipe, "overlay_expression"))
	if expression == "" {
		return "", fmt.Errorf("recipe must include overlay_expression")
	}
	packageAttr := firstNonEmpty(stringValue(recipe, "package_attribute"), stringValue(recipe, "packageAttribute"), campaign.Package)
	assignRe := regexp.MustCompile(`(?m)(^|\n)\s*` + regexp.QuoteMeta(packageAttr) + `\s*=`)
	if !assignRe.MatchString(expression) {
		return "", fmt.Errorf("overlay_expression must assign the %q package attribute", packageAttr)
	}
	for _, attr := range disallowedOverlayAttrs {
		attrRe := regexp.MustCompile(`(?im)["']?\b` + regexp.QuoteMeta(attr) + `\b["']?\s*=`)
		if attrRe.MatchString(expression) {
			return "", fmt.Errorf("%s overrides are not valid automated remediations", attr)
		}
	}
	overrideAttrs := nativeTopLevelOverrideAttrs(expression)
	if len(overrideAttrs) == 0 {
		return "", fmt.Errorf("overlay_expression must set at least one override attribute")
	}
	disallowed := make([]string, 0)
	for attr := range overrideAttrs {
		if !allowedAttrs[attr] {
			disallowed = append(disallowed, attr)
		}
	}
	sort.Strings(disallowed)
	if len(disallowed) > 0 {
		return "", fmt.Errorf("%s recipes may set only allowed override attributes; found %v", route, disallowed)
	}
	decommented := stripNixComments(expression)
	doCheckRe := regexp.MustCompile(`(?im)\bdoCheck\s*=\s*([^;]+);`)
	for _, match := range doCheckRe.FindAllStringSubmatch(decommented, -1) {
		if strings.TrimSpace(match[1]) != "false" {
			return "", fmt.Errorf("doCheck may only be set to the literal false in a CVE overlay")
		}
	}
	hasEvidence := firstNonEmpty(
		stringValue(recipe, "fixed_version"),
		stringValue(recipe, "fixedVersion"),
		stringValue(recipe, "source_url"),
		stringValue(recipe, "sourceUrl"),
		stringValue(recipe, "patch_url"),
		stringValue(recipe, "patchUrl"),
		stringValue(recipe, "upstream_commit"),
		stringValue(recipe, "upstreamCommit"),
		stringValue(recipe, "advisory_url"),
		stringValue(recipe, "advisoryUrl"),
	) != ""
	if !hasEvidence {
		return "", fmt.Errorf("recipe must include fixed-version, source, patch, or advisory evidence")
	}
	return expression, nil
}

func nativeTopLevelOverrideAttrs(expression string) map[string]bool {
	attrs := map[string]bool{}
	searchFrom := 0
	for {
		idx := strings.Index(expression[searchFrom:], "overrideAttrs")
		if idx < 0 {
			break
		}
		idx += searchFrom
		bodyStart := strings.Index(expression[idx:], "{")
		if bodyStart < 0 {
			break
		}
		for attr := range nativeOverrideBodyAttrs(expression, idx+bodyStart) {
			attrs[attr] = true
		}
		searchFrom = idx + len("overrideAttrs")
	}
	return attrs
}

func nativeOverrideBodyAttrs(expression string, bodyStart int) map[string]bool {
	attrs := map[string]bool{}
	depth := 1
	i := bodyStart + 1
	for i < len(expression) && depth > 0 {
		ch := expression[i]
		if ch == '"' {
			content, next := consumeDoubleQuotedString(expression, i)
			if depth == 1 && content != "" {
				j := skipSpaces(expression, next)
				if j < len(expression) && expression[j] == '=' && (j+1 >= len(expression) || expression[j+1] != '=') {
					attrs[content] = true
					i = j
					continue
				}
			}
			i = next
			continue
		}
		switch {
		case ch == '{':
			depth++
			i++
		case ch == '}':
			depth--
			i++
		case depth == 1 && isNixIdentStart(ch):
			start := i
			i++
			for i < len(expression) && isNixIdentPart(expression[i]) {
				i++
			}
			name := expression[start:i]
			j := skipSpaces(expression, i)
			if j < len(expression) && expression[j] == '=' && (j+1 >= len(expression) || expression[j+1] != '=') {
				attrs[name] = true
			}
		default:
			i++
		}
	}
	return attrs
}

func stripNixComments(expression string) string {
	var b strings.Builder
	for i := 0; i < len(expression); {
		ch := expression[i]
		if ch == '"' {
			next := copyDoubleQuotedString(&b, expression, i)
			i = next
			continue
		}
		if ch == '#' {
			next := strings.IndexByte(expression[i:], '\n')
			if next < 0 {
				break
			}
			i += next
			continue
		}
		if ch == '/' && i+1 < len(expression) && expression[i+1] == '*' {
			close := strings.Index(expression[i+2:], "*/")
			if close < 0 {
				break
			}
			i += close + 4
			continue
		}
		b.WriteByte(ch)
		i++
	}
	return b.String()
}

func consumeDoubleQuotedString(expression string, start int) (string, int) {
	var b strings.Builder
	escape := false
	for i := start + 1; i < len(expression); i++ {
		ch := expression[i]
		if escape {
			b.WriteByte(ch)
			escape = false
			continue
		}
		if ch == '\\' {
			escape = true
			continue
		}
		if ch == '"' {
			return b.String(), i + 1
		}
		b.WriteByte(ch)
	}
	return "", len(expression)
}

func copyDoubleQuotedString(b *strings.Builder, expression string, start int) int {
	b.WriteByte(expression[start])
	escape := false
	for i := start + 1; i < len(expression); i++ {
		ch := expression[i]
		b.WriteByte(ch)
		if escape {
			escape = false
			continue
		}
		if ch == '\\' {
			escape = true
			continue
		}
		if ch == '"' {
			return i + 1
		}
	}
	return len(expression)
}

func skipSpaces(value string, start int) int {
	for start < len(value) && (value[start] == ' ' || value[start] == '\n' || value[start] == '\t' || value[start] == '\r') {
		start++
	}
	return start
}

func isNixIdentStart(ch byte) bool {
	return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '_'
}

func isNixIdentPart(ch byte) bool {
	return isNixIdentStart(ch) || (ch >= '0' && ch <= '9') || ch == '\'' || ch == '-' || ch == '_'
}

// cmdRunner abstracts git/gh execution so the rolling-branch accumulation and
// aggregated-PR dedup are unit-testable with a fake.
type cmdRunner interface {
	Run(dir, name string, args ...string) error
	Output(dir, name string, args ...string) (string, error)
}

type execRunner struct{}

func (execRunner) Run(dir, name string, args ...string) error {
	return runCommand(dir, name, args...)
}

func (execRunner) Output(dir, name string, args ...string) (string, error) {
	var stdout bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout.String()), nil
}

// resetRollingBranch recreates the rolling remediation branch at base so the
// single aggregated PR reflects the current scan rather than accumulating stale
// overlays across runs.
func resetRollingBranch(r cmdRunner, dir, rolling, base string) error {
	if err := r.Run(dir, "git", "checkout", base); err != nil {
		return err
	}
	return r.Run(dir, "git", "checkout", "-B", rolling)
}

// foldIntoRolling fast-forwards the rolling branch to a per-CVE branch produced
// by either the native path or retained backend, accumulating that overlay,
// then returns HEAD to the rolling branch for the next campaign and deletes the
// now-redundant branch.
func foldIntoRolling(r cmdRunner, dir, rolling, branch string) error {
	if err := r.Run(dir, "git", "branch", "-f", rolling, branch); err != nil {
		return err
	}
	if err := r.Run(dir, "git", "checkout", rolling); err != nil {
		return err
	}
	_ = r.Run(dir, "git", "branch", "-D", branch)
	return nil
}

// openOrUpdateAggregatedPR pushes the rolling branch and opens its single draft
// PR, or refreshes the existing one. The `gh pr list --head` dedup guard is what
// keeps remediation to ONE continuously-updated PR instead of many.
func openOrUpdateAggregatedPR(r cmdRunner, dir, rolling, base string, campaigns []RemediationCampaign) error {
	// The rolling branch is recreated from base each run, so its remote ref
	// diverges; lease against the fetched remote tip to force-update safely, or
	// create it when there is no remote ref yet.
	_ = r.Run(dir, "git", "fetch", "origin",
		fmt.Sprintf("+refs/heads/%s:refs/remotes/origin/%s", rolling, rolling))
	pushArgs := []string{"push", "origin", rolling}
	if tip, _ := r.Output(dir, "git", "rev-parse", "--verify", "--quiet", "refs/remotes/origin/"+rolling); tip != "" {
		pushArgs = append(pushArgs, "--force-with-lease="+rolling+":"+tip)
	}
	if err := r.Run(dir, "git", pushArgs...); err != nil {
		return err
	}

	title := aggregatedPRTitle(campaigns)
	body := aggregatedPRBody(campaigns)

	count, _ := r.Output(dir, "gh", "pr", "list", "--head", rolling, "--state", "open", "--json", "number", "--jq", "length")
	if trimmed := strings.TrimSpace(count); trimmed == "" || trimmed == "0" {
		fmt.Fprintf(out, "Opening aggregated draft PR for %s...\n", rolling)
		return r.Run(dir, "gh", "pr", "create", "--title", title, "--body", body, "--head", rolling, "--base", base, "--draft")
	}
	fmt.Fprintf(out, "Updating existing aggregated PR for %s...\n", rolling)
	return r.Run(dir, "gh", "pr", "edit", rolling, "--title", title, "--body", body)
}

func aggregatedPRTitle(campaigns []RemediationCampaign) string {
	if len(campaigns) == 1 {
		return fmt.Sprintf("chore(cve): automated remediation for %s (%s)", campaigns[0].Package, campaigns[0].CVE)
	}
	return fmt.Sprintf("chore(cve): automated remediation for %d CVEs", len(campaigns))
}

func aggregatedPRBody(campaigns []RemediationCampaign) string {
	var b strings.Builder
	b.WriteString("This Pull Request was automatically drafted by the **ClearCutt remediation workflow**.\n\n")
	b.WriteString(fmt.Sprintf("It aggregates **%d** CVE remediation overlay(s) onto a single rolling branch; the workflow refreshes this one PR as new scans run instead of opening a PR per CVE.\n\n", len(campaigns)))
	b.WriteString("### Remediations\n")
	b.WriteString("| Package | CVE | Installed | Fixed | Route |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, c := range campaigns {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			codeQuote(c.Package), codeQuote(c.CVE),
			codeQuote(fallbackString(c.InstalledVersion, "?")),
			codeQuote(fallbackString(c.FixedVersion, "?")),
			codeQuote(fallbackString(c.RecommendedRoute, RouteVersionBump))))
	}
	b.WriteString("\n_Route legend: `substitute_vex` = ship the provenance-allowlisted patched crypto + VEX the version gap; `unstable_optin` = source the fix from a scoped newer nixpkgs pin; `version_bump` = a fixed version in the pinned channel; `fetchpatch_rebuild` = bespoke crypto rebuild (no upstream fix yet); `scanner_ignore` = narrow expiring suppression._\n")
	b.WriteString("\n### Verification\n")
	b.WriteString("Review each overlay evidence sidecar and any attached validation summary. Native deterministic drafts may include syntax validation only; retained backend summaries may include build/rescan evidence for selected targets. ")
	b.WriteString("The full matrix runs in this PR's pr-gate job; **do not merge until that suite rebuilds and rescans successfully.**\n\n")
	b.WriteString("### Rollback\n")
	b.WriteString("To drop a single remediation, delete its file under `core/overlays/cve/` and re-run the scan; the next run rebuilds this PR without it.\n")
	return b.String()
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
	evidence := campaign.RemediationEvidence
	env = append(env,
		"CVE_ID="+campaign.CVE,
		"PACKAGE_NAME="+campaign.Package,
		"INSTALLED_VERSION="+campaign.InstalledVersion,
		"FIXED_VERSION="+campaign.FixedVersion,
		"DOWNLOAD_URL="+firstNonEmpty(stringValue(evidence, "download_url"), stringValue(evidence, "downloadUrl"), stringValue(evidence, "source_url"), stringValue(evidence, "sourceUrl")),
		"SHA256="+firstNonEmpty(stringValue(evidence, "sha256"), stringValue(evidence, "source_sha256"), stringValue(evidence, "sourceSha256")),
		"PATCH_URL="+firstNonEmpty(stringValue(evidence, "patch_url"), stringValue(evidence, "patchUrl")),
		"PATCH_SHA256="+firstNonEmpty(stringValue(evidence, "patch_sha256"), stringValue(evidence, "patchSha256")),
		"REMEDIATION_CAMPAIGN="+string(campaignJSON),
		"AFFECTED_TARGETS="+string(targetsJSON),
		"REMEDIATION_SUMMARY_PATH="+summaryPath,
		"CLEARCUTT_REMEDIATION_LLM="+strings.ToLower(strings.TrimSpace(remediationRunOpts.llmMode)),
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
	// Remediation branches are created locally, so a fresh CI checkout has no
	// remote-tracking ref for them. Bare --force-with-lease then rejects
	// re-pushing a branch that already exists on origin ("stale info"), which
	// happens whenever the same top campaign is re-attempted before its PR
	// merges. Read the current remote tip and lease against that exact value:
	// a re-push succeeds, while a push that races in during this run is still
	// refused. A brand-new branch has no remote tip and is simply created.
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
	return fmt.Sprintf(`This Pull Request was automatically drafted by the **ClearCutt remediation workflow**.

### Details
- **Package:** %s
- **Installed version:** %s
- **CVE:** %s
- **Overlay file:** %s

%s

### Verification
Review the attached validation summary when present. Native deterministic drafts
may include syntax validation only; retained backend summaries may include
build/rescan evidence for selected targets. The full 13-language x 3-tier x
2-arch matrix runs in this PR's pr-gate job; **do not merge until that suite
rebuilds and rescans successfully.**

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
		b.WriteString("- No validation summary was attached by the remediation backend.\n")
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
	for _, candidate := range []string{".", "core"} {
		if isClearCuttCoreWorkspace(candidate) {
			return candidate, nil
		}
	}
	if _, err := os.Stat(filepath.Join("scripts", "cve-draft-agent.py")); err == nil {
		return ".", nil
	}
	if _, err := os.Stat(filepath.Join("core", "scripts", "cve-draft-agent.py")); err == nil {
		return "core", nil
	}
	return "", fmt.Errorf("could not locate ClearCutt core workspace; pass --core-dir")
}

func isClearCuttCoreWorkspace(dir string) bool {
	if !remediationFileExists(filepath.Join(dir, "flake.nix")) {
		return false
	}
	return remediationFileExists(filepath.Join(dir, "lib", "registry.nix")) ||
		remediationFileExists(filepath.Join(dir, "overlays", "cve-remediation.nix"))
}

func remediationFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
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
