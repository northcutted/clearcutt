package commands

import "github.com/spf13/cobra"

func newCatalogInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect <image-id>",
		Short: "Inspect a specific image record in a generated catalog",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInspect(args[0])
		},
	}
	cmd.Flags().StringVar(&inspectOpts.tag, "tag", "", "Inspect details for a specific versioned release tag")
	return cmd
}
