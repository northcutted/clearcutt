package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type remediationReportFlags struct {
	planPath   string
	outPath    string
	summaryDir string
}

type remediationValidateOverlaysFlags struct {
	overlayDir string
}

var remediationReportOpts remediationReportFlags
var remediationValidateOverlaysOpts remediationValidateOverlaysFlags

func NewRemediationReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render a remediation operations report from a plan",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemediationReport()
		},
	}
	cmd.Flags().StringVar(&remediationReportOpts.planPath, "plan", filepath.Join("core", "build-outputs", "remediation-plan.json"), "Remediation plan JSON path")
	cmd.Flags().StringVar(&remediationReportOpts.outPath, "out", "", "Write remediation report JSON to this path")
	cmd.Flags().StringVar(&remediationReportOpts.summaryDir, "summary-dir", "", "Directory containing remediation-summary-*.json files")
	return cmd
}

func NewRemediationValidateOverlaysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate-overlays",
		Short: "Validate generated CVE remediation overlays and evidence",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemediationValidateOverlays()
		},
	}
	cmd.Flags().StringVar(&remediationValidateOverlaysOpts.overlayDir, "overlay-dir", filepath.Join("core", "overlays", "cve"), "Directory containing per-CVE remediation overlays")
	return cmd
}

type RemediationReport struct {
	GeneratedAt          string                       `json:"generatedAt"`
	PlanGeneratedAt      string                       `json:"planGeneratedAt"`
	Policy               any                          `json:"policy"`
	ScanSource           RemediationScanSource        `json:"scanSource"`
	Metrics              RemediationMetrics           `json:"metrics"`
	SelectedCampaigns    []RemediationCampaign        `json:"selectedCampaigns"`
	RootCauseClusters    []RemediationCluster         `json:"rootCauseClusters"`
	TopDeferred          []RemediationDeferredSummary `json:"topDeferred"`
	ResidualOwnerActions []RemediationOwnerAction     `json:"residualOwnerActions"`
	DraftResults         RemediationDraftResults      `json:"draftResults"`
}

type RemediationOwnerAction struct {
	Reason          string `json:"reason"`
	Owner           string `json:"owner"`
	Summary         string `json:"summary"`
	Count           int    `json:"count"`
	ProductionCount int    `json:"productionCount"`
}

type RemediationDraftResults struct {
	SummaryDir string `json:"summaryDir,omitempty"`
	Drafted    int    `json:"drafted"`
	Failed     int    `json:"failed"`
	Unknown    int    `json:"unknown"`
}

func runRemediationReport() error {
	raw, err := os.ReadFile(remediationReportOpts.planPath)
	if err != nil {
		return fmt.Errorf("failed to read remediation plan %s: %w", remediationReportOpts.planPath, err)
	}
	var plan RemediationPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return fmt.Errorf("failed to parse remediation plan %s: %w", remediationReportOpts.planPath, err)
	}
	summaryDir := remediationReportOpts.summaryDir
	if summaryDir == "" {
		summaryDir = filepath.Dir(remediationReportOpts.planPath)
	}
	report := RemediationReport{
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
		PlanGeneratedAt:      plan.GeneratedAt,
		Policy:               plan.Policy,
		ScanSource:           plan.ScanSource,
		Metrics:              plan.Metrics,
		SelectedCampaigns:    plan.Campaigns,
		RootCauseClusters:    plan.Clusters,
		TopDeferred:          plan.TopDeferred,
		ResidualOwnerActions: residualOwnerActions(plan.TopDeferred),
		DraftResults:         remediationDraftResults(summaryDir),
	}
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode remediation report: %w", err)
	}
	payload = append(payload, '\n')
	if remediationReportOpts.outPath != "" {
		if dir := filepath.Dir(remediationReportOpts.outPath); dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("failed to create report output directory %s: %w", dir, err)
			}
		}
		if err := os.WriteFile(remediationReportOpts.outPath, payload, 0o644); err != nil {
			return fmt.Errorf("failed to write remediation report %s: %w", remediationReportOpts.outPath, err)
		}
	}
	_, err = out.Write(payload)
	return err
}

func residualOwnerActions(deferred []RemediationDeferredSummary) []RemediationOwnerAction {
	grouped := map[string]*RemediationOwnerAction{}
	for _, item := range deferred {
		owner := "platform"
		summary := "Review deferred finding and decide whether to patch, document an exception, or hand off upstream."
		switch item.Reason {
		case "base_layer":
			owner = "base-image-owner"
			summary = "Inherited base-layer finding requires base image update or documented exception."
		case "requires_acknowledgement":
			owner = "security"
			summary = "Reachable and materially risky with no upstream fix; requires an explicit, owned acknowledgement and a documented, expiring VEX exception (it blocks the release gate until then)."
		case "no_fixed_version":
			owner = "security"
			summary = "No upstream fixed version is available; monitor advisory and consider a temporary VEX exception."
		case "below_priority_threshold":
			owner = "security"
			summary = "Below automated threshold; keep visible for SLA and trend monitoring."
		}
		key := item.Reason + "::" + owner
		action := grouped[key]
		if action == nil {
			action = &RemediationOwnerAction{Reason: item.Reason, Owner: owner, Summary: summary}
			grouped[key] = action
		}
		action.Count += item.Count
		action.ProductionCount += item.ProductionCount
	}
	actions := make([]RemediationOwnerAction, 0, len(grouped))
	for _, action := range grouped {
		actions = append(actions, *action)
	}
	sort.Slice(actions, func(i, j int) bool {
		if actions[i].ProductionCount != actions[j].ProductionCount {
			return actions[i].ProductionCount > actions[j].ProductionCount
		}
		if actions[i].Count != actions[j].Count {
			return actions[i].Count > actions[j].Count
		}
		return actions[i].Reason < actions[j].Reason
	})
	return actions
}

func remediationDraftResults(summaryDir string) RemediationDraftResults {
	results := RemediationDraftResults{SummaryDir: summaryDir}
	matches, _ := filepath.Glob(filepath.Join(summaryDir, "remediation-summary-*.json"))
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			results.Unknown++
			continue
		}
		var data map[string]any
		if err := json.Unmarshal(raw, &data); err != nil {
			results.Unknown++
			continue
		}
		switch strings.ToLower(fmt.Sprint(data["status"])) {
		case "draft_compiled":
			results.Drafted++
		case "failed":
			results.Failed++
		default:
			results.Unknown++
		}
	}
	return results
}

var overlayAssignmentRe = regexp.MustCompile(`(?m)^  ([A-Za-z_][A-Za-z0-9_'.-]*)\s*=`)

// Kept in sync with DANGEROUS_OVERRIDE_ATTRS in core/scripts/cve-draft-agent.py.
var disallowedOverlayAttrs = []string{
	"prePatch",
	"postPatch",
	"patchPhase",
	"unpackPhase",
	"preConfigure",
	"configurePhase",
	"preBuild",
	"buildPhase",
	"postBuild",
	"buildCommand",
	"preInstall",
	"installPhase",
	"postInstall",
	"preFixup",
	"fixupPhase",
	"postFixup",
	"checkPhase",
	"installCheckPhase",
	"shellHook",
	"setupHook",
	"builder",
}

func runRemediationValidateOverlays() error {
	files, err := filepath.Glob(filepath.Join(remediationValidateOverlaysOpts.overlayDir, "*.nix"))
	if err != nil {
		return fmt.Errorf("failed to list remediation overlays: %w", err)
	}
	sort.Strings(files)
	attrOwners := map[string]string{}
	problems := []string{}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: read failed: %v", path, err))
			continue
		}
		text := string(raw)
		attrs := overlayAssignmentRe.FindAllStringSubmatch(text, -1)
		for _, match := range attrs {
			attr := match[1]
			if previous := attrOwners[attr]; previous != "" && previous != path {
				problems = append(problems, fmt.Sprintf("%s: package attribute %s also overridden by %s", path, attr, previous))
			} else {
				attrOwners[attr] = path
			}
		}
		evidencePath := strings.TrimSuffix(path, ".nix") + ".evidence.json"
		status, err := validateOverlayEvidence(evidencePath)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", path, err))
		}
		if status != "manual_accepted" {
			for _, attr := range disallowedOverlayAttrs {
				// Also match the quoted key form ("postInstall" = ...), which
				// Nix applies identically to the bareword assignment.
				if regexp.MustCompile(`(?m)["']?\b` + regexp.QuoteMeta(attr) + `\b["']?\s*=`).MatchString(text) {
					problems = append(problems, fmt.Sprintf("%s: disallowed generated remediation hook %s", path, attr))
				}
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("remediation overlay governance failed:\n%s", strings.Join(problems, "\n"))
	}
	fmt.Fprintf(out, "Validated %d remediation overlay(s) under %s.\n", len(files), remediationValidateOverlaysOpts.overlayDir)
	return nil
}

func validateOverlayEvidence(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("missing evidence file %s", path)
		}
		return "", fmt.Errorf("failed to read evidence file %s: %w", path, err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", fmt.Errorf("failed to parse evidence file %s: %w", path, err)
	}
	if data["policyDecision"] == nil {
		return "", fmt.Errorf("evidence file %s missing policyDecision", path)
	}
	status := strings.ToLower(fmt.Sprint(data["status"]))
	if status == "manual_accepted" {
		if strings.TrimSpace(fmt.Sprint(data["owner"])) == "" || strings.TrimSpace(fmt.Sprint(data["reason"])) == "" {
			return status, fmt.Errorf("manual evidence file %s requires owner and reason", path)
		}
		return status, nil
	}
	if data["validation"] == nil {
		return status, fmt.Errorf("generated evidence file %s missing validation", path)
	}
	return status, nil
}
