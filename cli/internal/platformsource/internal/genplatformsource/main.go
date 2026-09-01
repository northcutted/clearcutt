package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/northcutted/clearcutt/internal/platformsource"
)

func main() {
	check := flag.Bool("check", false, "Check whether the embedded platform source archive matches the live tree")
	flag.Parse()
	wd, err := os.Getwd()
	if err != nil {
		fatal(err)
	}
	dest, err := run(wd, *check)
	if err != nil {
		fatal(err)
	}
	if *check {
		fmt.Printf("platform source archive is current: %s\n", dest)
	} else {
		fmt.Printf("wrote %s\n", dest)
	}
}

func run(wd string, check bool) (string, error) {
	root, ok := platformsource.FindRepoRoot(wd)
	if !ok {
		return "", fmt.Errorf("repo root not found (no clearcutt.yaml + go.work above %s)", wd)
	}
	if check {
		if err := platformsource.CheckArchiveFresh(root); err != nil {
			return "", fmt.Errorf("%w\nrun: go -C cli run ./internal/platformsource/internal/genplatformsource", err)
		}
		return platformsource.ArchivePath(root), nil
	}
	return platformsource.WriteArchive(root)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
