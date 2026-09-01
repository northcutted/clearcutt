package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt/internal/estate"
	"github.com/spf13/cobra"
)

type estateFlags struct {
	dir         string
	files       []string
	generatedAt string
	insecure    bool
	output      string
}

var estateOpts estateFlags

// estateDefaultFiles are the artifacts a governance snapshot is made of. They
// are the outputs of `import observe`, `graph build` and `graph layers`.
var estateDefaultFiles = []string{"observations.json", "graph.json", "layers.json"}

// NewEstateCmd builds the `clearcutt estate` command group: persist a
// governance snapshot to a registry, and read one back.
func NewEstateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "estate",
		Short: "Persist and retrieve estate snapshots as OCI artifacts",
		Long: `Store a governance snapshot — observations, base graph, layer graph — in a
registry as an OCI artifact.

The registry is a deliberate backing store, not a convenient one. The evidence
lives under the same auth boundary, replication and retention as the images it
describes; digests make each snapshot immutable; tags give history, so estate
drift is a diff between two tags; and a mirror carries its own evidence into an
air gap. Nothing new has to be operated.

Snapshots are deterministic: identical inputs produce an identical digest, so a
nightly push of an unchanged estate does not create a new version.`,
	}
	cmd.AddCommand(newEstatePushCmd(), newEstatePullCmd())
	return cmd
}

func newEstatePushCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "push <reference>",
		Short: "Push an estate snapshot to a registry as an OCI artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runEstatePush(args[0])
		},
	}
	cmd.Flags().StringVar(&estateOpts.dir, "dir", ".", "Directory holding the snapshot files")
	cmd.Flags().StringSliceVar(&estateOpts.files, "file", nil, "Snapshot file(s) to store (default: observations.json, graph.json, layers.json)")
	cmd.Flags().StringVar(&estateOpts.generatedAt, "generated-at", "", "Snapshot timestamp recorded as a manifest annotation")
	cmd.Flags().BoolVar(&estateOpts.insecure, "insecure", false, "Use plain HTTP without auth (test registries only)")
	return cmd
}

func newEstatePullCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pull <reference>",
		Short: "Pull an estate snapshot out of a registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runEstatePull(args[0])
		},
	}
	cmd.Flags().StringVar(&estateOpts.output, "output", ".", "Directory to write the snapshot files into")
	cmd.Flags().BoolVar(&estateOpts.insecure, "insecure", false, "Use plain HTTP without auth (test registries only)")
	return cmd
}

func estateClient() *estate.Client {
	if estateOpts.insecure {
		return estate.NewInsecureClient()
	}
	return estate.NewClient()
}

func runEstatePush(ref string) error {
	wanted := nonEmptyStrings(estateOpts.files)
	if len(wanted) == 0 {
		wanted = estateDefaultFiles
	}
	snapshot := estate.Snapshot{
		GeneratedAt: strings.TrimSpace(estateOpts.generatedAt),
		Files:       map[string][]byte{},
	}
	var missing []string
	for _, fileName := range wanted {
		path := fileName
		if !filepath.IsAbs(path) {
			path = filepath.Join(estateOpts.dir, fileName)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) && len(estateOpts.files) == 0 {
				// Defaults are a convenience, not a contract: a fleet that has
				// not run `graph layers` yet should still be able to push what
				// it does have. An explicitly requested file is different — the
				// operator asked for it by name, so its absence is an error.
				missing = append(missing, fileName)
				continue
			}
			return fmt.Errorf("reading estate file %s: %w", path, err)
		}
		snapshot.Files[filepath.Base(fileName)] = body
	}
	if len(snapshot.Files) == 0 {
		return fmt.Errorf("no estate files found in %s (looked for %s); run `clearcutt import observe` and `clearcutt graph build` first",
			estateOpts.dir, strings.Join(wanted, ", "))
	}
	for _, fileName := range missing {
		fmt.Fprintf(out, "[estate] %s not present; pushing without it\n", fileName)
	}

	digest, err := estateClient().Push(ref, snapshot)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(snapshot.Files))
	for fileName := range snapshot.Files {
		names = append(names, fileName)
	}
	sort.Strings(names)
	fmt.Fprintf(out, "[estate] pushed %d file(s) to %s\n", len(names), ref)
	for _, fileName := range names {
		fmt.Fprintf(out, "[estate]   %s (%d bytes)\n", fileName, len(snapshot.Files[fileName]))
	}
	fmt.Fprintf(out, "[estate] digest %s\n", digest)
	fmt.Fprintf(out, "[estate] this digest is stable for identical content, so an unchanged estate re-pushes to the same version\n")
	return nil
}

func runEstatePull(ref string) error {
	snapshot, digest, err := estateClient().Pull(ref)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(estateOpts.output, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(snapshot.Files))
	for fileName := range snapshot.Files {
		names = append(names, fileName)
	}
	sort.Strings(names)
	for _, fileName := range names {
		// The file name comes off a registry annotation, which is attacker
		// controllable. Take only the base name so a crafted artifact cannot
		// write outside the output directory.
		safe := filepath.Base(filepath.Clean(fileName))
		if safe == "." || safe == string(filepath.Separator) || safe == ".." {
			return fmt.Errorf("estate artifact contains an unusable file name %q", fileName)
		}
		path := filepath.Join(estateOpts.output, safe)
		if err := os.WriteFile(path, snapshot.Files[fileName], 0o644); err != nil {
			return err
		}
		fmt.Fprintf(out, "[estate] wrote %s (%d bytes)\n", path, len(snapshot.Files[fileName]))
	}
	if snapshot.GeneratedAt != "" {
		fmt.Fprintf(out, "[estate] snapshot generated at %s\n", snapshot.GeneratedAt)
	}
	fmt.Fprintf(out, "[estate] pulled %s\n", digest)
	return nil
}
