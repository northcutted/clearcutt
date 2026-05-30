package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/northcutted/clearcutt/internal/catalog"
	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
)

type MatrixExport struct {
	GeneratedAt  string               `json:"generatedAt"`
	RegistryBase string               `json:"registryBase"`
	Images       []MatrixImageSummary `json:"images"`
}

type MatrixImageSummary struct {
	ID            string   `json:"id"`
	Runtime       string   `json:"runtime"`
	Version       string   `json:"version"`
	Tier          string   `json:"tier"`
	Architectures []string `json:"architectures"`
}

func NewMatrixCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "matrix",
		Short: "Manage base-image matrices",
	}

	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export the runtime matrix as JSON or YAML",
		Long:  `Gathers and outputs all published language runtimes, tiers, and multi-architecture metadata into a single machine-readable contract. Honors the global --format flag (json or yaml); json is the default.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMatrixExport()
		},
	}

	cmd.AddCommand(exportCmd)

	return cmd
}

func runMatrixExport() error {
	idx, err := catalog.LoadCatalogIndex(GlobalOpts.CatalogPath)
	if err != nil {
		return fmt.Errorf("failed to load catalog index: %w", err)
	}

	images := []MatrixImageSummary{}

	for _, img := range idx.Images {
		images = append(images, MatrixImageSummary{
			ID:            img.ID,
			Runtime:       img.Language,
			Version:       img.LanguageVersion,
			Tier:          img.Tier,
			Architectures: img.Architectures,
		})
	}

	export := MatrixExport{
		GeneratedAt:  idx.GeneratedAt,
		RegistryBase: idx.RegistryBase,
		Images:       images,
	}

	switch strings.ToLower(GlobalOpts.Format) {
	case "yaml", "yml":
		return output.PrintYAML(out, export)
	default:
		// matrix has no tabular form; "table" (the global default) falls through to JSON.
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(export); err != nil {
			return fmt.Errorf("failed to output JSON: %w", err)
		}
		return nil
	}
}
