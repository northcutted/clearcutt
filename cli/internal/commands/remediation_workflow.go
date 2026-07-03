package commands

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
)

type remediationWorkflowFlags struct {
	fleetConfig      string
	githubOutputPath string
}

var remediationWorkflowOpts remediationWorkflowFlags

type RemediationWorkflowParams struct {
	ScanDepth              string                  `json:"scanDepth"`
	MaxFindingsPerRun      int                     `json:"maxFindingsPerRun"`
	MaxPatchFailuresPerRun int                     `json:"maxPatchFailuresPerRun"`
	IncludeDevOnly         bool                    `json:"includeDevOnly"`
	Policy                 fleet.RemediationPolicy `json:"policy"`
	PolicyJSON             string                  `json:"policyJson"`
}

func NewRemediationWorkflowParamsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workflow-params",
		Short: "Emit scheduled remediation workflow parameters from clearcutt.fleet.yaml",
		Long: `Reads clearcutt.fleet.yaml and emits the scheduled remediation parameters
used by GitHub Actions: scan depth, campaign/failure limits, dev-tier inclusion,
and compact remediation policy JSON. Use --github-output in workflows to append
the same values to GITHUB_OUTPUT without jq.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolveRepoRootDefault(cmd, "fleet-config", &remediationWorkflowOpts.fleetConfig)
			return runRemediationWorkflowParams()
		},
	}
	cmd.Flags().StringVar(&remediationWorkflowOpts.fleetConfig, "fleet-config", fleet.DefaultConfigPath, "Path to clearcutt fleet config")
	cmd.Flags().StringVar(&remediationWorkflowOpts.githubOutputPath, "github-output", "", "Optional GITHUB_OUTPUT file to append scan_depth, max_findings, max_failures, include_dev_only, and policy")
	return cmd
}

func runRemediationWorkflowParams() error {
	params, err := buildRemediationWorkflowParams(remediationWorkflowOpts.fleetConfig)
	if err != nil {
		return err
	}
	if remediationWorkflowOpts.githubOutputPath != "" {
		if err := appendGitHubOutputs(remediationWorkflowOpts.githubOutputPath, map[string]string{
			"include_dev_only": strconv.FormatBool(params.IncludeDevOnly),
			"max_failures":     strconv.Itoa(params.MaxPatchFailuresPerRun),
			"max_findings":     strconv.Itoa(params.MaxFindingsPerRun),
			"policy":           params.PolicyJSON,
			"scan_depth":       params.ScanDepth,
		}); err != nil {
			return err
		}
	}
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, params)
	case "yaml", "yml":
		return output.PrintYAML(out, params)
	default:
		tp := output.NewTablePrinter("SETTING", "VALUE")
		tp.AddRow("scanDepth", params.ScanDepth)
		tp.AddRow("maxFindingsPerRun", strconv.Itoa(params.MaxFindingsPerRun))
		tp.AddRow("maxPatchFailuresPerRun", strconv.Itoa(params.MaxPatchFailuresPerRun))
		tp.AddRow("includeDevOnly", strconv.FormatBool(params.IncludeDevOnly))
		return tp.Print(out)
	}
}

func buildRemediationWorkflowParams(configPath string) (RemediationWorkflowParams, error) {
	cfg, err := fleet.Load(configPath)
	if err != nil {
		return RemediationWorkflowParams{}, fmt.Errorf("failed to load fleet config: %w", err)
	}
	policy := fleet.EffectiveRemediationPolicy(cfg.Remediation.Policy)
	rawPolicy, err := json.Marshal(policy)
	if err != nil {
		return RemediationWorkflowParams{}, fmt.Errorf("marshal remediation policy: %w", err)
	}
	return RemediationWorkflowParams{
		ScanDepth:              cfg.Remediation.ScanDepth,
		MaxFindingsPerRun:      cfg.Remediation.MaxFindingsPerRun,
		MaxPatchFailuresPerRun: cfg.Remediation.MaxPatchFailuresPerRun,
		IncludeDevOnly:         cfg.Remediation.IncludeDevOnly,
		Policy:                 policy,
		PolicyJSON:             string(rawPolicy),
	}, nil
}
