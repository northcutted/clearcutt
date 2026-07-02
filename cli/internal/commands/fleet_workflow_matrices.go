package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/output"
)

type fleetWorkflowMatrices struct {
	ReleaseMatrix        fleet.GitHubReleaseMatrix        `json:"releaseMatrix"`
	ImageMatrix          fleet.GitHubImageMatrix          `json:"imageMatrix"`
	ServiceReleaseMatrix fleet.GitHubServiceReleaseMatrix `json:"serviceReleaseMatrix"`
	ServiceImageMatrix   fleet.GitHubServiceImageMatrix   `json:"serviceImageMatrix"`
}

func runFleetWorkflowMatrices() error {
	cfg, err := fleet.Load(fleetOpts.configPath)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	matrices := fleetWorkflowMatrices{
		ReleaseMatrix:        cfg.GitHubReleaseMatrix(),
		ImageMatrix:          cfg.GitHubImageMatrix(),
		ServiceReleaseMatrix: cfg.GitHubServiceReleaseMatrix(),
		ServiceImageMatrix:   cfg.GitHubServiceImageMatrix(),
	}
	if err := writeFleetWorkflowMatrixOutputs(matrices); err != nil {
		return err
	}

	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, matrices)
	case "yaml", "yml":
		return output.PrintYAML(out, matrices)
	default:
		tp := output.NewTablePrinter("MATRIX", "CELLS")
		tp.AddRow("release", fmt.Sprint(len(matrices.ReleaseMatrix.Include)))
		tp.AddRow("image", fmt.Sprint(len(matrices.ImageMatrix.Include)))
		tp.AddRow("service-release", fmt.Sprint(len(matrices.ServiceReleaseMatrix.Include)))
		tp.AddRow("service-image", fmt.Sprint(len(matrices.ServiceImageMatrix.Include)))
		return tp.Print(out)
	}
}

func writeFleetWorkflowMatrixOutputs(matrices fleetWorkflowMatrices) error {
	if strings.TrimSpace(fleetOpts.githubOutputPath) == "" {
		return nil
	}
	values := map[string]string{}
	encoded := []struct {
		key   string
		value any
	}{
		{key: "release_matrix", value: matrices.ReleaseMatrix},
		{key: "image_matrix", value: matrices.ImageMatrix},
		{key: "service_release_matrix", value: matrices.ServiceReleaseMatrix},
		{key: "service_image_matrix", value: matrices.ServiceImageMatrix},
	}
	for _, item := range encoded {
		raw, err := json.Marshal(item.value)
		if err != nil {
			return err
		}
		values[item.key] = string(raw)
	}
	return appendGitHubOutputs(fleetOpts.githubOutputPath, values)
}
