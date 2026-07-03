package main

import (
	"fmt"
	"os"

	"github.com/northcutted/clearcutt/internal/platformsource"
)

func main() {
	wd, err := os.Getwd()
	if err != nil {
		fatal(err)
	}
	dest, err := run(wd)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s\n", dest)
}

func run(wd string) (string, error) {
	root, ok := platformsource.FindRepoRoot(wd)
	if !ok {
		return "", fmt.Errorf("repo root not found (no clearcutt.fleet.yaml + go.work above %s)", wd)
	}
	return platformsource.WriteArchive(root)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
