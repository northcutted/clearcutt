package commands

import (
	"encoding/json"
	"fmt"
	"os"
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
	tiers         string
	systems       string
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

type MatrixRuntimeExplanation struct {
	ID                 string   `json:"id"`
	Language           string   `json:"language"`
	Version            string   `json:"version"`
	Description        string   `json:"description"`
	ImageIDs           []string `json:"imageIds"`
	AppTemplateRuntime string   `json:"appTemplateRuntime,omitempty"`
	FleetConfig        string   `json:"fleetConfig,omitempty"`
	FleetConfigFound   bool     `json:"fleetConfigFound"`
	SelectedInFleet    bool     `json:"selectedInFleet"`
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

	explainCmd := &cobra.Command{
		Use:   "explain <runtime-line>",
		Short: "Explain a fleet runtime line without opening Nix files",
		Long: `Explains a supported runtime line from the public fleet configuration
surface. Use this before editing clearcutt.fleet.yaml to see the runtime,
version, generated image IDs, app-template support, and whether the runtime is
selected in the current fleet config.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMatrixExplain(args[0])
		},
	}
	explainCmd.Flags().StringVar(&matrixOpts.fleetConfig, "fleet-config", fleet.DefaultConfigPath, "Path to clearcutt fleet config")

	addCmd := &cobra.Command{
		Use:   "add <runtime-line>",
		Short: "Add a supported runtime line to clearcutt.fleet.yaml",
		Long: `Adds a supported runtime line to matrix.languages in clearcutt.fleet.yaml.
Use runtime scaffold first when the runtime line is not built in.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMatrixAdd(args[0])
		},
	}
	addCmd.Flags().StringVar(&matrixOpts.fleetConfig, "fleet-config", fleet.DefaultConfigPath, "Path to clearcutt fleet config")
	addCmd.Flags().StringVar(&matrixOpts.tiers, "tiers", "", "Optional comma-separated tiers to ensure: dev,slim,distroless")
	addCmd.Flags().StringVar(&matrixOpts.systems, "systems", "", "Optional comma-separated systems to ensure, for example x86_64-linux,aarch64-linux")

	removeCmd := &cobra.Command{
		Use:   "remove <runtime-line>",
		Short: "Remove a runtime line from clearcutt.fleet.yaml",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMatrixRemove(args[0])
		},
	}
	removeCmd.Flags().StringVar(&matrixOpts.fleetConfig, "fleet-config", fleet.DefaultConfigPath, "Path to clearcutt fleet config")

	cmd.AddCommand(exportCmd, explainCmd, addCmd, removeCmd)

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

func runMatrixExplain(runtimeLine string) error {
	runtimeLine = strings.TrimSpace(runtimeLine)
	var cfg fleet.Config
	cfgFound := false
	line, ok := fleet.RuntimeLineInfo(runtimeLine)
	cfg, err := fleet.Load(matrixOpts.fleetConfig)
	if err == nil {
		cfgFound = true
		line, ok = cfg.RuntimeLineInfo(runtimeLine)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	if !ok {
		supported := fleet.SupportedRuntimeLineIDs()
		if cfgFound {
			supported = cfg.SupportedRuntimeLineIDs()
		}
		return fmt.Errorf("unsupported runtime line %q (supported: %s)", runtimeLine, strings.Join(supported, ", "))
	}

	explanation := MatrixRuntimeExplanation{
		ID:                 line.ID,
		Language:           line.Language,
		Version:            line.Version,
		Description:        line.Description,
		ImageIDs:           runtimeLineImageIDs(line.ID),
		AppTemplateRuntime: line.AppTemplateRuntime,
		FleetConfig:        matrixOpts.fleetConfig,
	}

	if cfgFound {
		explanation.FleetConfigFound = true
		for _, selected := range cfg.Matrix.Languages {
			if selected == line.ID {
				explanation.SelectedInFleet = true
				break
			}
		}
	}

	switch strings.ToLower(GlobalOpts.Format) {
	case "yaml", "yml":
		return output.PrintYAML(out, explanation)
	case "json":
		return output.PrintJSON(out, explanation)
	default:
		selected := "unknown"
		if explanation.FleetConfigFound {
			selected = "no"
			if explanation.SelectedInFleet {
				selected = "yes"
			}
		}
		template := explanation.AppTemplateRuntime
		if template == "" {
			template = "-"
		}
		tp := output.NewTablePrinter("RUNTIME", "LANGUAGE", "VERSION", "IMAGES", "TEMPLATE", "SELECTED")
		tp.AddRow(explanation.ID, explanation.Language, explanation.Version, strings.Join(explanation.ImageIDs, ","), template, selected)
		return tp.Print(out)
	}
}

func runtimeLineImageIDs(runtimeLine string) []string {
	return []string{
		runtimeLine + "-dev",
		runtimeLine + "-slim",
		runtimeLine + "-distroless",
	}
}

func runMatrixAdd(runtimeLine string) error {
	cfg, err := fleet.Load(matrixOpts.fleetConfig)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	runtimeLine = strings.TrimSpace(runtimeLine)
	if _, ok := cfg.RuntimeLineInfo(runtimeLine); !ok {
		return fmt.Errorf("unsupported runtime line %q (supported: %s)", runtimeLine, strings.Join(cfg.SupportedRuntimeLineIDs(), ", "))
	}
	cfg.Matrix.Languages = appendUnique(cfg.Matrix.Languages, runtimeLine)
	if values := splitCSVList(matrixOpts.tiers); len(values) > 0 {
		cfg.Matrix.Tiers = appendUniqueMany(cfg.Matrix.Tiers, values)
	}
	if values := splitCSVList(matrixOpts.systems); len(values) > 0 {
		cfg.Matrix.Systems = appendUniqueMany(cfg.Matrix.Systems, values)
	}
	if err := writeFleetConfigFile(matrixOpts.fleetConfig, cfg); err != nil {
		return err
	}
	if !GlobalOpts.Quiet {
		fmt.Fprintf(out, "added %s to %s\n", runtimeLine, matrixOpts.fleetConfig)
	}
	return nil
}

func runMatrixRemove(runtimeLine string) error {
	cfg, err := fleet.Load(matrixOpts.fleetConfig)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	runtimeLine = strings.TrimSpace(runtimeLine)
	next, removed := removeString(cfg.Matrix.Languages, runtimeLine)
	if !removed {
		return fmt.Errorf("runtime line %q is not selected in %s", runtimeLine, matrixOpts.fleetConfig)
	}
	cfg.Matrix.Languages = next
	if err := writeFleetConfigFile(matrixOpts.fleetConfig, cfg); err != nil {
		return err
	}
	if !GlobalOpts.Quiet {
		fmt.Fprintf(out, "removed %s from %s\n", runtimeLine, matrixOpts.fleetConfig)
	}
	return nil
}

func writeFleetConfigFile(path string, cfg fleet.Config) error {
	raw, err := fleet.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("invalid fleet config update: %w", err)
	}
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(path, raw, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func splitCSVList(raw string) []string {
	parts := strings.Split(raw, ",")
	values := []string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueMany(values, additions []string) []string {
	for _, value := range additions {
		values = appendUnique(values, value)
	}
	return values
}

func removeString(values []string, value string) ([]string, bool) {
	next := values[:0]
	removed := false
	for _, existing := range values {
		if existing == value {
			removed = true
			continue
		}
		next = append(next, existing)
	}
	return next, removed
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
