package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/northcutted/clearcutt/internal/commands"
)

func main() {
	rootCmd := commands.NewRootCmd()
	if err := rootCmd.Execute(); err != nil {
		// Gating failures (verify/certify/conformance/exceptions) already printed a
		// detailed report; exit non-zero without an extra, redundant error line.
		if !errors.Is(err, commands.ErrCheckFailed) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}
