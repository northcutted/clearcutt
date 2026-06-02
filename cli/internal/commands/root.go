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

	// Command groups map the CLI surface to ClearCutt's pillars so `clearcutt
	// --help` reads as one cohesive toolchain. Every command also stands alone —
	// use one piece (e.g. just build base images) or adopt the whole lifecycle.
	rootCmd.AddGroup(
		&cobra.Group{ID: "build", Title: "Build Your Catalog:"},
		&cobra.Group{ID: "secure", Title: "Keep It Secure:"},
		&cobra.Group{ID: "verify", Title: "Verify It:"},
		&cobra.Group{ID: "certify", Title: "Certify New Images:"},
		&cobra.Group{ID: "apps", Title: "Manage Applications:"},
		&cobra.Group{ID: "develop", Title: "Develop Locally:"},
		&cobra.Group{ID: "browse", Title: "Browse The Catalog:"},
	)

	add := func(groupID string, cmd *cobra.Command) {
		cmd.GroupID = groupID
		rootCmd.AddCommand(cmd)
	}

	// Build your catalog
	add("build", NewCatalogCmd())
	add("build", NewReleaseCmd())
	add("build", NewMatrixCmd())
	add("build", NewOverlayCmd())
	// Keep it secure
	add("secure", NewScanCmd())
	add("secure", NewRemediationCmd())
	add("secure", NewExceptionsCmd())
	add("secure", NewVexCmd())
	// Verify it (verify groups image/catalog/release-evidence as subcommands)
	add("verify", NewVerifyCmd())
	add("verify", NewConformanceCmd())
	// Certify new images
	add("certify", NewCertifyCmd())
	// Manage applications via rebasing
	add("apps", NewAppCmd())
	add("apps", NewMirrorCmd())
	add("apps", NewPolicyCmd())
	// Develop locally
	add("develop", NewDevCmd())
	// Browse the catalog
	add("browse", NewListCmd())
	add("browse", NewInspectCmd())
	add("browse", NewDiffCmd())

	return rootCmd
}
