package commands

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/northcutted/clearcutt/internal/catalog"
	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
)

const (
	remediationDefaultVulnRoot = "site/src/data/vulnerabilities"
)

var productionRemediationTiers = map[string]bool{
	"slim":       true,
	"distroless": true,
}

var remediationTargetFileRe = regexp.MustCompile(`^(.+)-(amd64|arm64)\.json$`)

type remediationFlags struct {
	vulnRoot       string
	vulnDir        string
	includeDevOnly bool
	limit          int
	out            string
	policyJSON     string
}

var remediationOpts remediationFlags

type RemediationPlan struct {
	GeneratedAt string                       `json:"generatedAt"`
	SourceDir   string                       `json:"sourceDir"`
	Policy      fleet.RemediationPolicy      `json:"policy"`
	ScanSource  RemediationScanSource        `json:"scanSource"`
	Campaigns   []RemediationCampaign        `json:"campaigns"`
	Clusters    []RemediationCluster         `json:"clusters"`
	Deferred    []RemediationDeferred        `json:"deferred"`
	TopDeferred []RemediationDeferredSummary `json:"topDeferred"`
	Metrics     RemediationMetrics           `json:"metrics"`
	Summary     RemediationPlanSummary       `json:"summary"`
}

type RemediationPlanSummary struct {
	CampaignCount                  int            `json:"campaignCount"`
	CandidateCampaignCount         int            `json:"candidateCampaignCount"`
	DeferredCount                  int            `json:"deferredCount"`
	DeferredReasonCounts           map[string]int `json:"deferredReasonCounts"`
	ProductionDeferredReasonCounts map[string]int `json:"productionDeferredReasonCounts"`
	DevOnlyCampaignCount           int            `json:"devOnlyCampaignCount"`
	IncludeDevOnly                 bool           `json:"includeDevOnly"`
	ProductionCampaignCount        int            `json:"productionCampaignCount"`
}

type RemediationCampaign struct {
	Package                  string                       `json:"package"`
	CVE                      string                       `json:"cve"`
	PrimaryCVE               string                       `json:"primaryCve"`
	CVEs                     []string                     `json:"cves"`
	InstalledVersion         string                       `json:"installedVersion"`
	FixedVersion             string                       `json:"fixedVersion"`
	FixState                 string                       `json:"fixState"`
	Severity                 string                       `json:"severity"`
	Layer                    string                       `json:"layer"`
	CVSSScore                *float64                     `json:"cvssScore,omitempty"`
	CVSSVector               *string                      `json:"cvssVector,omitempty"`
	EPSSScore                *float64                     `json:"epssScore,omitempty"`
	EPSSPercentile           *float64                     `json:"epssPercentile,omitempty"`
	RiskScore                *float64                     `json:"riskScore,omitempty"`
	DataSource               *string                      `json:"dataSource,omitempty"`
	Namespace                *string                      `json:"namespace,omitempty"`
	Description              *string                      `json:"description,omitempty"`
	RecommendedRoute         string                       `json:"recommendedRoute"`
	RouteReason              string                       `json:"routeReason,omitempty"`
	RemediationEvidence      map[string]any               `json:"remediationEvidence,omitempty"`
	DeterministicRemediation map[string]any               `json:"deterministicRemediation,omitempty"`
	DeterministicRecipe      map[string]any               `json:"deterministicRecipe,omitempty"`
	RiskFactors              RemediationRiskFactors       `json:"riskFactors"`
	PolicyDecision           RemediationPolicyDecision    `json:"policyDecision"`
	ExpectedRemoved          []RemediationExpectedFinding `json:"expectedRemoved"`
	AffectedTargets          []RemediationTarget          `json:"affectedTargets"`
	ProductionTargetCount    int                          `json:"productionTargetCount"`
	TargetCount              int                          `json:"targetCount"`
	Score                    float64                      `json:"score"`
}

type RemediationScanSource struct {
	Directory         string  `json:"directory"`
	FileCount         int     `json:"fileCount"`
	Scanner           *string `json:"scanner,omitempty"`
	DBBuiltAt         *string `json:"dbBuiltAt,omitempty"`
	ScannedAt         *string `json:"scannedAt,omitempty"`
	KEVStatus         string  `json:"kevStatus"`
	KEVCatalogVersion *string `json:"kevCatalogVersion,omitempty"`
}

type RemediationRiskFactors struct {
	Severity              string   `json:"severity"`
	CVSSScore             *float64 `json:"cvssScore,omitempty"`
	EPSSScore             *float64 `json:"epssScore,omitempty"`
	EPSSPercentile        *float64 `json:"epssPercentile,omitempty"`
	RiskScore             *float64 `json:"riskScore,omitempty"`
	KnownExploited        bool     `json:"knownExploited"`
	FixedVersionAvailable bool     `json:"fixedVersionAvailable"`
	ProductionTargetCount int      `json:"productionTargetCount"`
	TargetCount           int      `json:"targetCount"`
}

type RemediationPolicyDecision struct {
	Selected bool   `json:"selected"`
	Reason   string `json:"reason"`
	Summary  string `json:"summary"`
}

type RemediationExpectedFinding struct {
	CVE              string `json:"cve"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installedVersion"`
}

type RemediationCluster struct {
	Package               string   `json:"package"`
	InstalledVersion      string   `json:"installedVersion"`
	FixedVersion          string   `json:"fixedVersion"`
	PrimaryCVE            string   `json:"primaryCve"`
	CVEs                  []string `json:"cves"`
	TargetCount           int      `json:"targetCount"`
	ProductionTargetCount int      `json:"productionTargetCount"`
	KnownExploited        bool     `json:"knownExploited"`
	Score                 float64  `json:"score"`
}

type RemediationDeferredSummary struct {
	Reason          string `json:"reason"`
	Package         string `json:"package"`
	CVE             string `json:"cve"`
	Target          string `json:"target"`
	Tier            string `json:"tier"`
	Count           int    `json:"count"`
	ProductionCount int    `json:"productionCount"`
}

type RemediationMetrics struct {
	SelectedCampaigns          int     `json:"selectedCampaigns"`
	CandidateCampaigns         int     `json:"candidateCampaigns"`
	DeferredFindings           int     `json:"deferredFindings"`
	ProductionDeferredFindings int     `json:"productionDeferredFindings"`
	AutomationCoverage         float64 `json:"automationCoverage"`
	KnownExploitedCampaigns    int     `json:"knownExploitedCampaigns"`
	RootCauseClusterCount      int     `json:"rootCauseClusterCount"`
}

type RemediationTarget struct {
	Target     string `json:"target"`
	Language   string `json:"language"`
	Tier       string `json:"tier"`
	Arch       string `json:"arch"`
	SourceFile string `json:"sourceFile"`
}

type RemediationDeferred struct {
	Reason   string `json:"reason"`
	CVE      string `json:"cve"`
	Package  string `json:"package"`
	Severity string `json:"severity"`
	Layer    string `json:"layer"`
	Target   string `json:"target"`
	Tier     string `json:"tier"`
	Arch     string `json:"arch"`
	FixState string `json:"fixState"`
}

type remediationScanFile struct {
	ScannedAt         string                 `json:"scannedAt"`
	Scanner           string                 `json:"scanner"`
	DBBuiltAt         *string                `json:"dbBuiltAt"`
	KEVStatus         string                 `json:"kevStatus"`
	KEVCatalogVersion *string                `json:"kevCatalogVersion"`
	CountsBySeverity  catalog.SeverityCounts `json:"countsBySeverity"`
	Findings          []catalog.FindingInfo  `json:"findings"`
}

type campaignKey struct {
	Package          string
	InstalledVersion string
	FixedVersion     string
}

func NewRemediationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remediation",
		Short: "Plan ClearCutt CVE remediation campaigns",
	}

	planCmd := &cobra.Command{
		Use:   "plan",
		Short: "Rank fixable vulnerability scan findings into remediation campaigns",
		Long:  `Builds the same dry-run remediation campaign plan used by CI, without invoking AI agents, creating branches, or opening pull requests.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemediationPlan()
		},
	}

	planCmd.Flags().StringVar(&remediationOpts.vulnRoot, "vuln-root", envOr("VULN_ROOT", remediationDefaultVulnRoot), "Root directory containing versioned vulnerability scan outputs")
	planCmd.Flags().StringVar(&remediationOpts.vulnDir, "vuln-dir", "", "Specific vulnerability scan directory to read")
	planCmd.Flags().BoolVar(&remediationOpts.includeDevOnly, "include-dev-only", parseScanBool(os.Getenv("INCLUDE_DEV_ONLY_REMEDIATION")), "Include dev-tier-only campaigns")
	planCmd.Flags().IntVar(&remediationOpts.limit, "limit", envIntValue("MAX_FINDINGS_PER_RUN", 0), "Maximum campaigns to emit")
	planCmd.Flags().StringVar(&remediationOpts.out, "out", "", "Write the plan JSON to this path (in addition to stdout output)")
	planCmd.Flags().StringVar(&remediationOpts.policyJSON, "policy-json", os.Getenv("REMEDIATION_POLICY_JSON"), "Effective remediation policy JSON from clearcutt.fleet.yaml")

	cmd.AddCommand(planCmd)
	cmd.AddCommand(NewRemediationTriageCmd())
	cmd.AddCommand(NewRemediationStatusCmd())
	cmd.AddCommand(NewRemediationReportCmd())
	cmd.AddCommand(NewRemediationValidateOverlaysCmd())
	cmd.AddCommand(NewRemediationRunCmd())
	cmd.AddCommand(NewRemediationOpenPRCmd())
	cmd.AddCommand(NewRemediationGenerateFloorCmd())
	cmd.AddCommand(NewRemediationIgnoreCmd())
	cmd.AddCommand(NewRemediationVexCryptoCmd())
	cmd.AddCommand(NewRemediationWorkflowParamsCmd())
	return cmd
}

func runRemediationPlan() error {
	vulnDir, err := resolveRemediationVulnDir(remediationOpts.vulnRoot, remediationOpts.vulnDir)
	if err != nil {
		return err
	}
	policy := remediationPolicyFromJSON(remediationOpts.policyJSON)
	plan, err := buildRemediationPlanWithPolicy(vulnDir, remediationOpts.limit, remediationOpts.includeDevOnly, policy)
	if err != nil {
		return err
	}
	enrichPlanRoutesBestEffort(plan, "")

	if remediationOpts.out != "" {
		if err := writeRemediationPlanFile(remediationOpts.out, plan); err != nil {
			return err
		}
	}

	// --quiet collapses the plan to a single machine-greppable summary line so
	// callers that consume --out (e.g. the auto-patch dispatcher) keep clean
	// logs instead of the full JSON payload.
	if GlobalOpts.Quiet {
		s := plan.Summary
		fmt.Fprintf(
			out,
			"[remediation] campaigns=%d candidates=%d production=%d dev_only=%d deferred=%d criteria=reachable-materially-risky-fixable source=%s\n",
			s.CampaignCount, s.CandidateCampaignCount, s.ProductionCampaignCount,
			s.DevOnlyCampaignCount, s.DeferredCount, plan.SourceDir,
		)
		return nil
	}

	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, plan)
	case "yaml", "yml":
		return output.PrintYAML(out, plan)
	default:
		return printRemediationPlanTable(plan)
	}
}

func writeRemediationPlanFile(path string, plan *RemediationPlan) error {
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode remediation plan: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create plan output directory %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		return fmt.Errorf("failed to write remediation plan to %s: %w", path, err)
	}
	return nil
}

func resolveRemediationVulnDir(vulnRoot, vulnDir string) (string, error) {
	if vulnDir != "" {
		info, err := os.Stat(vulnDir)
		if err != nil || !info.IsDir() {
			return "", fmt.Errorf("vulnerability directory does not exist: %s (%s)", vulnDir, describeRemediationVulnRoot(vulnRoot))
		}
		return vulnDir, nil
	}
	latest, err := latestRemediationVulnDir(vulnRoot)
	if err != nil {
		return "", err
	}
	return latest, nil
}

func latestRemediationVulnDir(root string) (string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("no vulnerability scan directory found (%s): %w", describeRemediationVulnRoot(root), err)
	}
	dirs := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry.Name())
		}
	}
	if len(dirs) == 0 {
		return "", fmt.Errorf("no vulnerability scan directory found (%s)", describeRemediationVulnRoot(root))
	}
	sort.Slice(dirs, func(i, j int) bool {
		return compareVersionLike(dirs[i], dirs[j]) > 0
	})
	return filepath.Join(root, dirs[0]), nil
}

func describeRemediationVulnRoot(root string) string {
	abs, _ := filepath.Abs(root)
	cwd, _ := os.Getwd()
	versionDirs := 0
	scanFiles := 0
	if entries, err := os.ReadDir(root); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				versionDirs++
				matches, _ := filepath.Glob(filepath.Join(root, entry.Name(), "*.json"))
				scanFiles += len(matches)
			}
		}
		if scanFiles == 0 {
			matches, _ := filepath.Glob(filepath.Join(root, "*.json"))
			scanFiles = len(matches)
		}
	}
	return fmt.Sprintf("cwd=%s checked_vuln_root=%s absolute_vuln_root=%s version_dir_count=%d scan_json_count=%d", cwd, root, abs, versionDirs, scanFiles)
}

func buildRemediationPlan(vulnDir string, limit int, includeDevOnly bool) (*RemediationPlan, error) {
	return buildRemediationPlanWithPolicy(vulnDir, limit, includeDevOnly, fleet.DefaultRemediationPolicy())
}

func buildRemediationPlanWithPolicy(vulnDir string, limit int, includeDevOnly bool, policy fleet.RemediationPolicy) (*RemediationPlan, error) {
	policy = fleet.EffectiveRemediationPolicy(policy)
	campaigns, deferred, scanSource, err := normalizeRemediationCampaigns(vulnDir, policy)
	if err != nil {
		return nil, err
	}

	candidateCampaignCount := len(campaigns)
	devOnlyCampaignCount := 0
	for _, campaign := range campaigns {
		if campaign.ProductionTargetCount == 0 {
			devOnlyCampaignCount++
		}
	}

	deferredReasonCounts := map[string]int{}
	productionDeferredReasonCounts := map[string]int{}
	for _, item := range deferred {
		deferredReasonCounts[item.Reason]++
		if productionTier(policy, item.Tier) {
			productionDeferredReasonCounts[item.Reason]++
		}
	}

	if !includeDevOnly {
		filtered := []RemediationCampaign{}
		for _, campaign := range campaigns {
			if campaign.ProductionTargetCount > 0 {
				filtered = append(filtered, campaign)
			}
		}
		campaigns = filtered
	}
	if limit > 0 && len(campaigns) > limit {
		campaigns = campaigns[:limit]
	}

	productionCampaignCount := 0
	knownExploitedCampaignCount := 0
	for _, campaign := range campaigns {
		if campaign.ProductionTargetCount > 0 {
			productionCampaignCount++
		}
		if campaign.RiskFactors.KnownExploited {
			knownExploitedCampaignCount++
		}
	}

	clusters := remediationClusters(campaigns)
	productionDeferred := 0
	for _, item := range deferred {
		if productionTier(policy, item.Tier) {
			productionDeferred++
		}
	}
	coverageDenominator := candidateCampaignCount + len(deferred)
	automationCoverage := 0.0
	if coverageDenominator > 0 {
		automationCoverage = roundRemediationScore(float64(len(campaigns)) / float64(coverageDenominator))
	}

	return &RemediationPlan{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		SourceDir:   vulnDir,
		Policy:      policy,
		ScanSource:  scanSource,
		Campaigns:   campaigns,
		Clusters:    clusters,
		Deferred:    deferred,
		TopDeferred: topDeferredSummaries(deferred, policy, 10),
		Metrics: RemediationMetrics{
			SelectedCampaigns:          len(campaigns),
			CandidateCampaigns:         candidateCampaignCount,
			DeferredFindings:           len(deferred),
			ProductionDeferredFindings: productionDeferred,
			AutomationCoverage:         automationCoverage,
			KnownExploitedCampaigns:    knownExploitedCampaignCount,
			RootCauseClusterCount:      len(clusters),
		},
		Summary: RemediationPlanSummary{
			CampaignCount:                  len(campaigns),
			CandidateCampaignCount:         candidateCampaignCount,
			DeferredCount:                  len(deferred),
			DeferredReasonCounts:           deferredReasonCounts,
			ProductionDeferredReasonCounts: productionDeferredReasonCounts,
			DevOnlyCampaignCount:           devOnlyCampaignCount,
			IncludeDevOnly:                 includeDevOnly,
			ProductionCampaignCount:        productionCampaignCount,
		},
	}, nil
}

func normalizeRemediationCampaigns(vulnDir string, policy fleet.RemediationPolicy) ([]RemediationCampaign, []RemediationDeferred, RemediationScanSource, error) {
	files, err := filepath.Glob(filepath.Join(vulnDir, "*.json"))
	if err != nil {
		return nil, nil, RemediationScanSource{}, fmt.Errorf("failed to list vulnerability scan files: %w", err)
	}
	sort.Strings(files)

	campaigns := map[campaignKey]*RemediationCampaign{}
	deferred := []RemediationDeferred{}
	scanSource := RemediationScanSource{Directory: vulnDir, KEVStatus: "unavailable"}
	for _, filePath := range files {
		target, ok := splitRemediationTargetFile(filePath)
		if !ok {
			continue
		}
		raw, err := os.ReadFile(filePath)
		if err != nil {
			return nil, nil, scanSource, fmt.Errorf("failed to read vulnerability scan file %s: %w", filePath, err)
		}
		var scan remediationScanFile
		if err := json.Unmarshal(raw, &scan); err != nil {
			return nil, nil, scanSource, fmt.Errorf("failed to parse vulnerability scan file %s: %w", filePath, err)
		}
		mergeScanSource(&scanSource, scan)
		scanSource.FileCount++

		for _, finding := range scan.Findings {
			if finding.PackageName == "" || finding.ID == "" {
				continue
			}
			fix := fixedVersionString(finding.FixedIn)
			// One risk policy decides scope here — the same fleet.Materiality
			// the release gate (verify) and the crypto floor consume. It
			// promotes EPSS/KEV from ranking boosts to gates (a medium finding
			// with EPSS >= the floor or a KEV listing is now in scope), and
			// splits an in-scope finding on fixability. ProductionTier is forced
			// true: the planner ranks across every tier and the dev/prod split
			// is applied downstream (devOnly filtering + ProductionTargetCount),
			// so gating on tier here would drop --include-dev-only campaigns.
			decision := fleet.Materiality(fleet.MaterialityInput{
				Severity:       finding.Severity,
				EPSSPercentile: finding.EpssPercentile,
				KEV:            finding.KEV != nil && finding.KEV.KnownExploited,
				Layer:          finding.Layer,
				HasFix:         fix != "",
				ProductionTier: true,
			}, policy)

			if decision.Disposition != fleet.DispositionMustFix {
				deferred = append(deferred, RemediationDeferred{
					Reason:   plannerDeferredReason(decision),
					CVE:      finding.ID,
					Package:  finding.PackageName,
					Severity: finding.Severity,
					Layer:    finding.Layer,
					Target:   target.Target,
					Tier:     target.Tier,
					Arch:     target.Arch,
					FixState: finding.FixState,
				})
				continue
			}

			key := campaignKey{
				Package:          finding.PackageName,
				InstalledVersion: finding.PackageVersion,
				FixedVersion:     fix,
			}
			campaign, exists := campaigns[key]
			if !exists {
				campaign = &RemediationCampaign{
					Package:          finding.PackageName,
					CVE:              finding.ID,
					PrimaryCVE:       finding.ID,
					CVEs:             []string{},
					InstalledVersion: finding.PackageVersion,
					FixedVersion:     fix,
					FixState:         finding.FixState,
					Severity:         finding.Severity,
					Layer:            finding.Layer,
					CVSSScore:        finding.CvssScore,
					CVSSVector:       finding.CvssVector,
					EPSSScore:        finding.EpssScore,
					EPSSPercentile:   finding.EpssPercentile,
					RiskScore:        finding.RiskScore,
					DataSource:       finding.DataSource,
					Namespace:        finding.Namespace,
					Description:      finding.Description,
					RecommendedRoute: "version_bump",
					RiskFactors:      remediationRiskFactors(finding, fix, 0, 0),
					PolicyDecision: RemediationPolicyDecision{
						Selected: true,
						Reason:   "eligible",
						Summary:  "Finding matches the configured automated remediation policy.",
					},
					ExpectedRemoved: []RemediationExpectedFinding{},
					AffectedTargets: []RemediationTarget{},
				}
				campaigns[key] = campaign
			}
			addCampaignCVE(campaign, finding.ID)
			addExpectedRemoved(campaign, finding)
			if campaign.CVSSScore == nil && finding.CvssScore != nil {
				campaign.CVSSScore = finding.CvssScore
			}
			if campaign.EPSSScore == nil && finding.EpssScore != nil {
				campaign.EPSSScore = finding.EpssScore
			}
			if campaign.EPSSPercentile == nil && finding.EpssPercentile != nil {
				campaign.EPSSPercentile = finding.EpssPercentile
			}
			if campaign.RiskScore == nil && finding.RiskScore != nil {
				campaign.RiskScore = finding.RiskScore
			}
			if finding.KEV != nil && finding.KEV.KnownExploited {
				campaign.RiskFactors.KnownExploited = true
			}
			addAffectedTarget(campaign, target)
		}
	}

	normalized := make([]RemediationCampaign, 0, len(campaigns))
	for _, campaign := range campaigns {
		sort.Slice(campaign.AffectedTargets, func(i, j int) bool {
			left := campaign.AffectedTargets[i]
			right := campaign.AffectedTargets[j]
			if productionTier(policy, left.Tier) != productionTier(policy, right.Tier) {
				return productionTier(policy, left.Tier)
			}
			if left.Target != right.Target {
				return left.Target < right.Target
			}
			return left.Arch < right.Arch
		})
		campaign.TargetCount = len(campaign.AffectedTargets)
		for _, target := range campaign.AffectedTargets {
			if productionTier(policy, target.Tier) {
				campaign.ProductionTargetCount++
			}
		}
		campaign.RiskFactors = remediationRiskFactorsFromCampaign(*campaign)
		campaign.Score = roundRemediationScore(remediationFindingScore(*campaign))
		normalized = append(normalized, *campaign)
	}

	sort.Slice(normalized, func(i, j int) bool {
		left := normalized[i]
		right := normalized[j]
		if (left.ProductionTargetCount == 0) != (right.ProductionTargetCount == 0) {
			return left.ProductionTargetCount > 0
		}
		if left.Score != right.Score {
			return left.Score > right.Score
		}
		if left.Package != right.Package {
			return left.Package < right.Package
		}
		if left.CVE != right.CVE {
			return left.CVE < right.CVE
		}
		return left.InstalledVersion < right.InstalledVersion
	})

	return normalized, deferred, scanSource, nil
}

func splitRemediationTargetFile(path string) (RemediationTarget, bool) {
	name := filepath.Base(path)
	matches := remediationTargetFileRe.FindStringSubmatch(name)
	if matches == nil {
		return RemediationTarget{}, false
	}
	target := matches[1]
	idx := strings.LastIndex(target, "-")
	if idx == -1 {
		return RemediationTarget{}, false
	}
	return RemediationTarget{
		Target:     target,
		Language:   target[:idx],
		Tier:       target[idx+1:],
		Arch:       matches[2],
		SourceFile: path,
	}, true
}

func fixedVersionString(value *string) string {
	if value == nil {
		return ""
	}
	parts := strings.SplitN(*value, ",", 2)
	return strings.TrimSpace(parts[0])
}

func remediationFindingScore(campaign RemediationCampaign) float64 {
	severityWeights := map[string]float64{
		"critical":   1000,
		"high":       700,
		"medium":     300,
		"low":        100,
		"negligible": 10,
		"unknown":    0,
	}
	score := severityWeights[strings.ToLower(campaign.Severity)]
	score += float64(campaign.ProductionTargetCount * 40)
	score += float64(campaign.TargetCount * 5)
	if campaign.FixedVersion != "" {
		score += 150
	}
	if campaign.RiskScore != nil {
		score += *campaign.RiskScore
	}
	if campaign.EPSSScore != nil {
		score += *campaign.EPSSScore * 100
	}
	if campaign.EPSSPercentile != nil && *campaign.EPSSPercentile >= 0.90 {
		score += 100
	}
	if campaign.RiskFactors.KnownExploited {
		score += 500
	}
	return score
}

func roundRemediationScore(value float64) float64 {
	return math.Round(value*1000) / 1000
}

func parseVersionParts(value string) []int {
	value = strings.TrimPrefix(value, "v")
	parts := strings.Split(value, ".")
	out := make([]int, len(parts))
	for i, part := range parts {
		parsed, err := strconv.Atoi(part)
		if err != nil {
			return []int{0, 0, 0}
		}
		out[i] = parsed
	}
	return out
}

func compareVersionLike(left, right string) int {
	l := parseVersionParts(left)
	r := parseVersionParts(right)
	maxLen := len(l)
	if len(r) > maxLen {
		maxLen = len(r)
	}
	for i := 0; i < maxLen; i++ {
		lv := 0
		rv := 0
		if i < len(l) {
			lv = l[i]
		}
		if i < len(r) {
			rv = r[i]
		}
		if lv > rv {
			return 1
		}
		if lv < rv {
			return -1
		}
	}
	return strings.Compare(left, right)
}

func remediationPolicyFromJSON(raw string) fleet.RemediationPolicy {
	if strings.TrimSpace(raw) == "" || strings.TrimSpace(raw) == "null" {
		return fleet.DefaultRemediationPolicy()
	}
	var policy fleet.RemediationPolicy
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		return fleet.DefaultRemediationPolicy()
	}
	return fleet.EffectiveRemediationPolicy(policy)
}

// plannerDeferredReason maps a risk decision onto the planner's deferral
// vocabulary. A must_acknowledge finding (reachable + materially risky, but
// unfixable) gets its own reason so it is never silently folded into a benign
// "below threshold" deferral — it is surfaced for an explicit, owned
// acknowledgement. The planner only ranks; the release gate (verify) is what
// actually blocks on it.
func plannerDeferredReason(decision fleet.RiskDecision) string {
	if decision.Disposition == fleet.DispositionMustAcknowledge {
		return "requires_acknowledgement"
	}
	switch decision.Reason {
	case "not_reachable_base_layer":
		return "base_layer"
	case "no_fix_unrequired":
		// In scope and unfixable, but the policy does not require a fix
		// (requireFixedVersion:false): a benign no-fix deferral.
		return "no_fixed_version"
	default:
		// below_risk_threshold (and any future auto-accept reason). non_production
		// cannot occur on the planner path: it forces ProductionTier:true.
		return "below_priority_threshold"
	}
}

// findingHasFix is the single fixability predicate shared by the planner and the
// release gate so they never disagree on a finding's disposition. It keys on a
// usable fixed version (the first comma-delimited candidate), matching what the
// campaign actually bumps to — not merely a non-empty FixedIn string.
func findingHasFix(fixedIn *string) bool {
	return fixedVersionString(fixedIn) != ""
}

func productionTier(policy fleet.RemediationPolicy, tier string) bool {
	policy = fleet.EffectiveRemediationPolicy(policy)
	for _, item := range policy.ProductionTiers {
		if item == tier {
			return true
		}
	}
	return false
}

func mergeScanSource(source *RemediationScanSource, scan remediationScanFile) {
	if source.Scanner == nil && scan.Scanner != "" {
		source.Scanner = &scan.Scanner
	}
	if source.DBBuiltAt == nil && scan.DBBuiltAt != nil {
		source.DBBuiltAt = scan.DBBuiltAt
	}
	if source.ScannedAt == nil && scan.ScannedAt != "" {
		source.ScannedAt = &scan.ScannedAt
	}
	if scan.KEVStatus != "" {
		if source.KEVStatus == "" || source.KEVStatus == "unavailable" || scan.KEVStatus == "available" {
			source.KEVStatus = scan.KEVStatus
		}
	}
	if source.KEVCatalogVersion == nil && scan.KEVCatalogVersion != nil {
		source.KEVCatalogVersion = scan.KEVCatalogVersion
	}
}

func addCampaignCVE(campaign *RemediationCampaign, cve string) {
	for _, existing := range campaign.CVEs {
		if existing == cve {
			return
		}
	}
	campaign.CVEs = append(campaign.CVEs, cve)
	sort.Strings(campaign.CVEs)
	if campaign.PrimaryCVE == "" || cve < campaign.PrimaryCVE {
		campaign.PrimaryCVE = cve
		campaign.CVE = cve
	}
}

func addExpectedRemoved(campaign *RemediationCampaign, finding catalog.FindingInfo) {
	item := RemediationExpectedFinding{
		CVE:              finding.ID,
		Package:          finding.PackageName,
		InstalledVersion: finding.PackageVersion,
	}
	for _, existing := range campaign.ExpectedRemoved {
		if existing == item {
			return
		}
	}
	campaign.ExpectedRemoved = append(campaign.ExpectedRemoved, item)
	sort.Slice(campaign.ExpectedRemoved, func(i, j int) bool {
		left := campaign.ExpectedRemoved[i]
		right := campaign.ExpectedRemoved[j]
		if left.CVE != right.CVE {
			return left.CVE < right.CVE
		}
		if left.Package != right.Package {
			return left.Package < right.Package
		}
		return left.InstalledVersion < right.InstalledVersion
	})
}

func addAffectedTarget(campaign *RemediationCampaign, target RemediationTarget) {
	for _, existing := range campaign.AffectedTargets {
		if existing.Target == target.Target && existing.Arch == target.Arch {
			return
		}
	}
	campaign.AffectedTargets = append(campaign.AffectedTargets, target)
}

func remediationRiskFactors(finding catalog.FindingInfo, fixedVersion string, productionTargets, targets int) RemediationRiskFactors {
	return RemediationRiskFactors{
		Severity:              finding.Severity,
		CVSSScore:             finding.CvssScore,
		EPSSScore:             finding.EpssScore,
		EPSSPercentile:        finding.EpssPercentile,
		RiskScore:             finding.RiskScore,
		KnownExploited:        finding.KEV != nil && finding.KEV.KnownExploited,
		FixedVersionAvailable: fixedVersion != "",
		ProductionTargetCount: productionTargets,
		TargetCount:           targets,
	}
}

func remediationRiskFactorsFromCampaign(campaign RemediationCampaign) RemediationRiskFactors {
	return RemediationRiskFactors{
		Severity:              campaign.Severity,
		CVSSScore:             campaign.CVSSScore,
		EPSSScore:             campaign.EPSSScore,
		EPSSPercentile:        campaign.EPSSPercentile,
		RiskScore:             campaign.RiskScore,
		KnownExploited:        campaign.RiskFactors.KnownExploited,
		FixedVersionAvailable: campaign.FixedVersion != "",
		ProductionTargetCount: campaign.ProductionTargetCount,
		TargetCount:           campaign.TargetCount,
	}
}

func remediationClusters(campaigns []RemediationCampaign) []RemediationCluster {
	clusters := make([]RemediationCluster, 0, len(campaigns))
	for _, campaign := range campaigns {
		clusters = append(clusters, RemediationCluster{
			Package:               campaign.Package,
			InstalledVersion:      campaign.InstalledVersion,
			FixedVersion:          campaign.FixedVersion,
			PrimaryCVE:            campaign.PrimaryCVE,
			CVEs:                  append([]string(nil), campaign.CVEs...),
			TargetCount:           campaign.TargetCount,
			ProductionTargetCount: campaign.ProductionTargetCount,
			KnownExploited:        campaign.RiskFactors.KnownExploited,
			Score:                 campaign.Score,
		})
	}
	return clusters
}

func topDeferredSummaries(deferred []RemediationDeferred, policy fleet.RemediationPolicy, limit int) []RemediationDeferredSummary {
	type key struct {
		reason, pkg, cve, target, tier string
	}
	grouped := map[key]*RemediationDeferredSummary{}
	for _, item := range deferred {
		k := key{reason: item.Reason, pkg: item.Package, cve: item.CVE, target: item.Target, tier: item.Tier}
		summary := grouped[k]
		if summary == nil {
			summary = &RemediationDeferredSummary{
				Reason:  item.Reason,
				Package: item.Package,
				CVE:     item.CVE,
				Target:  item.Target,
				Tier:    item.Tier,
			}
			grouped[k] = summary
		}
		summary.Count++
		if productionTier(policy, item.Tier) {
			summary.ProductionCount++
		}
	}
	out := make([]RemediationDeferredSummary, 0, len(grouped))
	for _, summary := range grouped {
		out = append(out, *summary)
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i]
		right := out[j]
		if left.ProductionCount != right.ProductionCount {
			return left.ProductionCount > right.ProductionCount
		}
		if left.Count != right.Count {
			return left.Count > right.Count
		}
		if left.Reason != right.Reason {
			return left.Reason < right.Reason
		}
		if left.Package != right.Package {
			return left.Package < right.Package
		}
		return left.CVE < right.CVE
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func printRemediationPlanTable(plan *RemediationPlan) error {
	fmt.Fprintf(out, "Remediation Plan\n")
	fmt.Fprintf(out, "Source: %s\n", plan.SourceDir)
	fmt.Fprintf(
		out,
		"Campaigns: %d selected, %d candidate, %d production, %d dev-only, %d deferred\n",
		plan.Summary.CampaignCount,
		plan.Summary.CandidateCampaignCount,
		plan.Summary.ProductionCampaignCount,
		plan.Summary.DevOnlyCampaignCount,
		plan.Summary.DeferredCount,
	)
	if len(plan.Campaigns) == 0 {
		fmt.Fprintln(out, "No remediation campaigns selected.")
		return nil
	}

	tp := output.NewTablePrinter("PACKAGE", "CVE", "INSTALLED", "FIXED", "SEVERITY", "PROD", "TARGETS")
	for _, campaign := range plan.Campaigns {
		tp.AddRow(
			campaign.Package,
			campaign.CVE,
			campaign.InstalledVersion,
			campaign.FixedVersion,
			campaign.Severity,
			fmt.Sprintf("%d", campaign.ProductionTargetCount),
			fmt.Sprintf("%d", campaign.TargetCount),
		)
	}
	return tp.Print(out)
}
