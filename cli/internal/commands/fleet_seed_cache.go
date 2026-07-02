package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/output"
)

type fleetSeedCachePlan struct {
	HasWork bool                      `json:"hasWork"`
	Count   int                       `json:"count"`
	Matrix  fleet.GitHubReleaseMatrix `json:"matrix"`
}

func runFleetSeedCachePlan() error {
	cfg, err := fleet.Load(fleetOpts.configPath)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	matrix := cfg.GitHubReleaseMatrix()
	needed := make([]fleet.GitHubReleaseCell, 0, len(matrix.Include))
	failures := []string{}

	for _, cell := range matrix.Include {
		fleetSeedCacheLogf("[seed-cache-plan] dry-run %s %s %s\n", cell.System, cell.Language, cell.Tier)
		needsBuild, err := dryRunFleetSeedCell(fleetOpts.coreDir, cell)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s %s %s: %v", cell.System, cell.Language, cell.Tier, err))
			continue
		}
		if needsBuild {
			fleetSeedCacheLogf("[seed-cache-plan] needs build: %s %s %s\n", cell.System, cell.Language, cell.Tier)
			needed = append(needed, cell)
			continue
		}
		fleetSeedCacheLogf("[seed-cache-plan] cached: %s %s %s\n", cell.System, cell.Language, cell.Tier)
	}
	if len(failures) > 0 {
		return fmt.Errorf("%d cell(s) failed to evaluate; refusing to emit a partial seed set: %s", len(failures), strings.Join(failures, "; "))
	}

	result := fleetSeedCachePlan{
		HasWork: len(needed) > 0,
		Count:   len(needed),
		Matrix:  fleet.GitHubReleaseMatrix{Include: needed},
	}
	if err := writeFleetSeedCacheOutputs(result); err != nil {
		return err
	}

	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, result)
	case "yaml", "yml":
		return output.PrintYAML(out, result)
	default:
		fmt.Fprintf(out, "[seed-cache-plan] cells needing a seed build: %d\n", result.Count)
		for _, cell := range result.Matrix.Include {
			fmt.Fprintf(out, "  - %s %s %s\n", cell.System, cell.Language, cell.Tier)
		}
		return nil
	}
}

func dryRunFleetSeedCell(coreDir string, cell fleet.GitHubReleaseCell) (bool, error) {
	attr := fmt.Sprintf(".#packages.%s.%q", cell.System, fleetTarget(cell.Language, cell.Tier))
	raw, err := captureExternalOutput(externalCommand{
		Name: "nix",
		Dir:  coreDir,
		Args: []string{
			"build",
			"--dry-run",
			attr,
			"--extra-experimental-features",
			"nix-command flakes",
			"--accept-flake-config",
		},
	})
	if err != nil {
		return false, fmt.Errorf("nix dry-run failed for %s: %w", attr, err)
	}
	return strings.Contains(raw, "will be built"), nil
}

func fleetSeedCacheLogf(format string, args ...any) {
	switch strings.ToLower(GlobalOpts.Format) {
	case "json", "yaml", "yml":
		return
	default:
		fmt.Fprintf(out, format, args...)
	}
}

func writeFleetSeedCacheOutputs(result fleetSeedCachePlan) error {
	matrixRaw, err := json.Marshal(result.Matrix)
	if err != nil {
		return err
	}
	if strings.TrimSpace(fleetOpts.githubOutputPath) != "" {
		if err := appendGitHubOutputs(fleetOpts.githubOutputPath, map[string]string{
			"has_work":    fmt.Sprintf("%t", result.HasWork),
			"seed_matrix": string(matrixRaw),
		}); err != nil {
			return err
		}
	}
	return nil
}
