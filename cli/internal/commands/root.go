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
and manage hardened multi-architecture enterprise base images.`,
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

	// Add subcommands
	rootCmd.AddCommand(NewListCmd())
	rootCmd.AddCommand(NewInspectCmd())
	rootCmd.AddCommand(NewVerifyCmd())
	rootCmd.AddCommand(NewDiffCmd())
	rootCmd.AddCommand(NewCertifyCmd())
	rootCmd.AddCommand(NewVexCmd())
	rootCmd.AddCommand(NewPolicyCmd())
	rootCmd.AddCommand(NewMirrorCmd())
	rootCmd.AddCommand(NewMatrixCmd())
	rootCmd.AddCommand(NewExceptionsCmd())
	rootCmd.AddCommand(NewOverlayCmd())
	rootCmd.AddCommand(NewReleaseCmd())
	rootCmd.AddCommand(NewConformanceCmd())
	rootCmd.AddCommand(NewRemediationCmd())
	rootCmd.AddCommand(NewAppCmd())

	return rootCmd
}
