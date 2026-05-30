package commands

import (
	"os"

	"github.com/spf13/cobra"
)

// osExit is overridden in tests to prevent exiting the test process.
var osExit = os.Exit

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
	}

	rootCmd.PersistentFlags().StringVar(&GlobalOpts.CatalogPath, "catalog", "site/src/data/catalog", "Path to local catalog JSON data directory")
	rootCmd.PersistentFlags().StringVar(&GlobalOpts.Format, "format", "table", "Output formatting format: table, json, or yaml")
	rootCmd.PersistentFlags().BoolVar(&GlobalOpts.Quiet, "quiet", false, "Suppress non-essential console outputs")
	rootCmd.PersistentFlags().BoolVar(&GlobalOpts.Verbose, "verbose", false, "Enable verbose debug outputs")

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

	return rootCmd
}
