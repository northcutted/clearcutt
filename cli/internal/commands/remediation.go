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
}

var remediationOpts remediationFlags

type RemediationPlan struct {
	GeneratedAt string                 `json:"generatedAt"`
	SourceDir   string                 `json:"sourceDir"`
	Campaigns   []RemediationCampaign  `json:"campaigns"`
	Deferred    []RemediationDeferred  `json:"deferred"`
	Summary     RemediationPlanSummary `json:"summary"`
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
	Package               string              `json:"package"`
	CVE                   string              `json:"cve"`
	InstalledVersion      string              `json:"installedVersion"`
	FixedVersion          string              `json:"fixedVersion"`
	FixState              string              `json:"fixState"`
	Severity              string              `json:"severity"`
	Layer                 string              `json:"layer"`
	CVSSScore             *float64            `json:"cvssScore,omitempty"`
	CVSSVector            *string             `json:"cvssVector,omitempty"`
	EPSSScore             *float64            `json:"epssScore,omitempty"`
	EPSSPercentile        *float64            `json:"epssPercentile,omitempty"`
	RiskScore             *float64            `json:"riskScore,omitempty"`
	DataSource            *string             `json:"dataSource,omitempty"`
	Namespace             *string             `json:"namespace,omitempty"`
	Description           *string             `json:"description,omitempty"`
	RecommendedRoute      string              `json:"recommendedRoute"`
	AffectedTargets       []RemediationTarget `json:"affectedTargets"`
	ProductionTargetCount int                 `json:"productionTargetCount"`
	TargetCount           int                 `json:"targetCount"`
	Score                 float64             `json:"score"`
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
	Findings []catalog.FindingInfo `json:"findings"`
}

type campaignKey struct {
	Package          string
	CVE              string
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

	planCmd.Flags().StringVar(&remediationOpts.vulnRoot, "vuln-root", remediationDefaultVulnRoot, "Root directory containing versioned vulnerability scan outputs")
	planCmd.Flags().StringVar(&remediationOpts.vulnDir, "vuln-dir", "", "Specific vulnerability scan directory to read")
	planCmd.Flags().BoolVar(&remediationOpts.includeDevOnly, "include-dev-only", false, "Include dev-tier-only campaigns")
	planCmd.Flags().IntVar(&remediationOpts.limit, "limit", 0, "Maximum campaigns to emit")

	cmd.AddCommand(planCmd)
	return cmd
}

func runRemediationPlan() error {
	vulnDir, err := resolveRemediationVulnDir(remediationOpts.vulnRoot, remediationOpts.vulnDir)
	if err != nil {
		return err
	}
	plan, err := buildRemediationPlan(vulnDir, remediationOpts.limit, remediationOpts.includeDevOnly)
	if err != nil {
		return err
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
	campaigns, deferred, err := normalizeRemediationCampaigns(vulnDir)
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
		if productionRemediationTiers[item.Tier] {
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
	for _, campaign := range campaigns {
		if campaign.ProductionTargetCount > 0 {
			productionCampaignCount++
		}
	}

	return &RemediationPlan{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		SourceDir:   vulnDir,
		Campaigns:   campaigns,
		Deferred:    deferred,
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

func normalizeRemediationCampaigns(vulnDir string) ([]RemediationCampaign, []RemediationDeferred, error) {
	files, err := filepath.Glob(filepath.Join(vulnDir, "*.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list vulnerability scan files: %w", err)
	}
	sort.Strings(files)

	campaigns := map[campaignKey]*RemediationCampaign{}
	deferred := []RemediationDeferred{}
	for _, filePath := range files {
		target, ok := splitRemediationTargetFile(filePath)
		if !ok {
			continue
		}
		raw, err := os.ReadFile(filePath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read vulnerability scan file %s: %w", filePath, err)
		}
		var scan remediationScanFile
		if err := json.Unmarshal(raw, &scan); err != nil {
			return nil, nil, fmt.Errorf("failed to parse vulnerability scan file %s: %w", filePath, err)
		}

		for _, finding := range scan.Findings {
			if finding.PackageName == "" || finding.ID == "" {
				continue
			}
			severityKey := strings.ToLower(finding.Severity)
			fix := fixedVersionString(finding.FixedIn)
			reason := ""
			switch {
			case finding.Layer != "runtime":
				reason = "base_layer"
			case severityKey != "critical" && severityKey != "high":
				reason = "below_priority_threshold"
			case fix == "":
				reason = "no_fixed_version"
			}

			if reason != "" {
				deferred = append(deferred, RemediationDeferred{
					Reason:   reason,
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
				CVE:              finding.ID,
				InstalledVersion: finding.PackageVersion,
				FixedVersion:     fix,
			}
			campaign, exists := campaigns[key]
			if !exists {
				campaign = &RemediationCampaign{
					Package:          finding.PackageName,
					CVE:              finding.ID,
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
					AffectedTargets:  []RemediationTarget{},
				}
				campaigns[key] = campaign
			}
			campaign.AffectedTargets = append(campaign.AffectedTargets, target)
		}
	}

	normalized := make([]RemediationCampaign, 0, len(campaigns))
	for _, campaign := range campaigns {
		sort.Slice(campaign.AffectedTargets, func(i, j int) bool {
			left := campaign.AffectedTargets[i]
			right := campaign.AffectedTargets[j]
			if productionRemediationTiers[left.Tier] != productionRemediationTiers[right.Tier] {
				return productionRemediationTiers[left.Tier]
			}
			if left.Target != right.Target {
				return left.Target < right.Target
			}
			return left.Arch < right.Arch
		})
		campaign.TargetCount = len(campaign.AffectedTargets)
		for _, target := range campaign.AffectedTargets {
			if productionRemediationTiers[target.Tier] {
				campaign.ProductionTargetCount++
			}
		}
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

	return normalized, deferred, nil
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
