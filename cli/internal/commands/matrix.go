package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/northcutted/clearcutt/internal/catalog"
	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
)

type matrixFlags struct {
	source        string
	fleetConfig   string
	githubActions bool
	matrixKind    string
}

var matrixOpts matrixFlags

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
		Long: `Exports runtime matrix metadata from either the generated catalog or the
forkable fleet configuration. Honors the global --format flag: table (default),
json, or yaml. Use --source fleet --github-actions inside GitHub Actions to emit
an include-matrix derived from clearcutt.fleet.yaml.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMatrixExport()
		},
	}
	exportCmd.Flags().StringVar(&matrixOpts.source, "source", "catalog", "Matrix source: catalog or fleet")
	exportCmd.Flags().StringVar(&matrixOpts.fleetConfig, "fleet-config", fleet.DefaultConfigPath, "Path to clearcutt fleet config")
	exportCmd.Flags().BoolVar(&matrixOpts.githubActions, "github-actions", false, "Emit a GitHub Actions include matrix")
	exportCmd.Flags().StringVar(&matrixOpts.matrixKind, "matrix", "release", "GitHub Actions matrix kind: release or image")

	cmd.AddCommand(exportCmd)

	return cmd
}

func runMatrixExport() error {
	if strings.EqualFold(matrixOpts.source, "fleet") {
		return runFleetMatrixExport()
	}

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
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(export); err != nil {
			return fmt.Errorf("failed to output JSON: %w", err)
		}
		return nil
	default:
		// Render the matrix as an aligned table for the default --format=table.
		tp := output.NewTablePrinter("IMAGE", "RUNTIME", "VERSION", "TIER", "ARCHES")
		for _, img := range export.Images {
			tp.AddRow(img.ID, img.Runtime, img.Version, img.Tier, strings.Join(img.Architectures, ","))
		}
		return tp.Print(out)
	}
}

func runFleetMatrixExport() error {
	cfg, err := fleet.Load(matrixOpts.fleetConfig)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}

	if matrixOpts.githubActions {
		switch strings.ToLower(matrixOpts.matrixKind) {
		case "release":
			return output.PrintJSON(out, cfg.GitHubReleaseMatrix())
		case "image":
			return output.PrintJSON(out, cfg.GitHubImageMatrix())
		default:
			return fmt.Errorf("--matrix must be release or image")
		}
	}

	export := struct {
		RegistryBase string            `json:"registryBase"`
		Registry     fleet.Registry    `json:"registry"`
		Branding     fleet.Branding    `json:"branding"`
		Systems      []string          `json:"systems"`
		Languages    []string          `json:"languages"`
		Tiers        []string          `json:"tiers"`
		Catalog      fleet.Catalog     `json:"catalog"`
		Remediation  fleet.Remediation `json:"remediation"`
	}{
		RegistryBase: cfg.RegistryBase(),
		Registry:     cfg.Registry,
		Branding:     cfg.Branding,
		Systems:      cfg.Matrix.Systems,
		Languages:    cfg.Matrix.Languages,
		Tiers:        cfg.Matrix.Tiers,
		Catalog:      cfg.Catalog,
		Remediation:  cfg.Remediation,
	}

	switch strings.ToLower(GlobalOpts.Format) {
	case "yaml", "yml":
		return output.PrintYAML(out, export)
	case "json":
		return output.PrintJSON(out, export)
	default:
		tp := output.NewTablePrinter("SOURCE", "REGISTRY", "SYSTEMS", "LANGUAGES", "TIERS")
		tp.AddRow("fleet", export.RegistryBase, strings.Join(export.Systems, ","), strings.Join(export.Languages, ","), strings.Join(export.Tiers, ","))
		return tp.Print(out)
	}
}
