package commands

import (
	"github.com/northcutted/clearcutt/internal/catalog"
	"github.com/spf13/cobra"
)

// Version is the CLI version, overridable at build time via -ldflags.
var Version = "dev"

// GlobalOptions stores the CLI flags shared across commands.
type GlobalOptions struct {
	CatalogPath string
	Format      string
	Quiet       bool
	Verbose     bool
}

// GlobalOpts holds the active parsed global options.
var GlobalOpts GlobalOptions

// NewRootCmd initializes the Cobra root command hierarchy.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "clearcutt",
		Short: "ClearCutt base-image platform engineering governance CLI",
		Long: `ClearCutt is a platform-engineering CLI to list, inspect, verify,
and manage hardened multi-architecture platform-owned base images.`,
		Version: Version,
		// Returned errors are already actionable; don't dump usage text on every
		// failure, and let main own error/exit-code presentation.
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.PersistentFlags().StringVar(&GlobalOpts.CatalogPath, "catalog", "site/src/data/catalog", "Path to local catalog JSON data directory")
	rootCmd.PersistentFlags().StringVar(&GlobalOpts.Format, "format", "table", "Output formatting format: table, json, or yaml")
	rootCmd.PersistentFlags().BoolVar(&GlobalOpts.Quiet, "quiet", false, "Suppress non-essential console outputs")
	rootCmd.PersistentFlags().BoolVar(&GlobalOpts.Verbose, "verbose", false, "Enable verbose debug outputs")
	rootCmd.PersistentFlags().BoolVar(&catalog.Strict, "strict", false, "Reject catalog JSON containing fields unknown to the CLI data model")

	// The CLI help is a tool map, not a marketing funnel. Several commands span
	// multiple SDLC phases, so group them by operator job while the README/site
	// explain the higher-level lifecycle story.
	rootCmd.AddGroup(
		&cobra.Group{ID: "platform", Title: "Platform Kit:"},
		&cobra.Group{ID: "catalog", Title: "Catalog & Release Evidence:"},
		&cobra.Group{ID: "browse", Title: "Catalog Discovery:"},
		&cobra.Group{ID: "apps", Title: "App Team Workflow:"},
		&cobra.Group{ID: "govern", Title: "Governance Gates:"},
		&cobra.Group{ID: "secure", Title: "Security Operations:"},
	)

	add := func(groupID string, cmd *cobra.Command) {
		cmd.GroupID = groupID
		rootCmd.AddCommand(cmd)
	}

	// Configure and inspect the forkable product kit.
	add("platform", NewPlatformCmd())
	add("platform", NewFleetCmd())
	add("platform", NewRuntimeCmd())
	add("platform", NewServiceCmd())

	// Build catalog data and publish release evidence.
	add("catalog", NewCatalogCmd())
	add("catalog", NewReleaseCmd())
	add("catalog", NewMatrixCmd())
	add("catalog", NewOverlayCmd())

	// Browse published catalog contents.
	add("browse", NewListCmd())
	add("browse", NewInspectCmd())
	add("browse", NewDiffCmd())

	// Give app teams matching dev, build, rebase, mirroring, and admission tools.
	add("apps", NewDevCmd())
	add("apps", NewAppCmd())
	add("apps", NewMirrorCmd())
	add("apps", NewPolicyCmd())

	// Gate image releases and cluster admission decisions.
	add("govern", NewCertifyCmd())
	add("govern", NewVerifyCmd())
	add("govern", NewConformanceCmd())

	// Operate security remediation, exceptions, and VEX flows.
	add("secure", NewScanCmd())
	add("secure", NewRemediationCmd())
	add("secure", NewExceptionsCmd())
	add("secure", NewVexCmd())

	return rootCmd
}
