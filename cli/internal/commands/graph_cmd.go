package commands

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt/internal/importedfleet"
	"github.com/spf13/cobra"
)

type graphBuildFlags struct {
	observations  string
	output        string
	report        string
	basePatterns  []string
	minConfidence string
	maxShared     int
	generatedAt   string
	failOnStale   bool
	failOnUnknown bool
	force         bool
}

var graphBuildOpts graphBuildFlags

// NewGraphCmd builds the `clearcutt graph` command group.
func NewGraphCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "graph",
		Short: "Map which images are built on which, and how stale each one is",
		Long: `Derive the base-image dependency graph for an observed estate.

Where 'rebase discover' checks a relationship someone declared, 'graph build'
discovers relationships nobody wrote down: it compares observed images and reports
which are built on which, how that was established, and how far behind each consumer
is from the newest version of its base.

Only layer-digest matching is proof. Label- and history-based matches are reported as
claims made by whoever built the image, and labelled as such.`,
	}
	cmd.AddCommand(newGraphBuildCmd())
	return cmd
}

func newGraphBuildCmd() *cobra.Command {
	graphBuildOpts = graphBuildFlags{}
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build the base-image dependency graph from observations",
		Args:  cobra.NoArgs,
		Example: `  # Full path from a registry to an auditable inventory
  clearcutt registry scan --registry ghcr.io --namespace acme/platform \
    --repository base-java21 --repository payments --output images.yaml
  clearcutt import observe --images images.yaml --output observations.json
  clearcutt graph build --observations observations.json \
    --output graph.json --report inventory.md

  # Gate CI on proof, and fail when anything is on a stale base
  clearcutt graph build --observations observations.json --output graph.json \
    --min-confidence verified --fail-on-stale`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGraphBuild()
		},
	}
	f := cmd.Flags()
	f.StringVar(&graphBuildOpts.observations, "observations", "", "Observations JSON from `clearcutt import observe`")
	f.StringVar(&graphBuildOpts.output, "output", "", "Output graph JSON path")
	f.StringVar(&graphBuildOpts.report, "report", "", "Also write a Markdown governance inventory to this path")
	f.StringArrayVar(&graphBuildOpts.basePatterns, "base-repository", nil, "Only this repository glob may act as a base (repeatable; default: infer from layering)")
	f.StringVar(&graphBuildOpts.minConfidence, "min-confidence", "", "Drop edges weaker than this: verified, declared, assisted, weak")
	f.IntVar(&graphBuildOpts.maxShared, "max-shared-layers", 100, "Cap shared layers retained for blast-radius analysis, widest reach first (-1 keeps all)")
	f.StringVar(&graphBuildOpts.generatedAt, "generated-at", "", "Deterministic generated timestamp")
	f.BoolVar(&graphBuildOpts.failOnStale, "fail-on-stale", false, "Exit 2 when any consumer sits on a stale base version")
	f.BoolVar(&graphBuildOpts.failOnUnknown, "fail-on-unknown", false, "Exit 2 when any image's base could not be determined")
	f.BoolVar(&graphBuildOpts.force, "force", false, "Overwrite existing output files")
	_ = cmd.MarkFlagRequired("observations")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func runGraphBuild() error {
	opts := graphBuildOpts
	for _, path := range []string{opts.output, opts.report} {
		if path == "" || opts.force {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; pass --force to overwrite", path)
		}
	}
	observations, err := importedfleet.ReadObservations(opts.observations)
	if err != nil {
		return fmt.Errorf("read observations: %w", err)
	}
	graph, err := importedfleet.BuildGraph(observations, importedfleet.GraphOptions{
		GeneratedAt:     opts.generatedAt,
		BasePatterns:    opts.basePatterns,
		MinConfidence:   opts.minConfidence,
		MaxSharedLayers: opts.maxShared,
	})
	if err != nil {
		return err
	}
	if err := writeAlongside(opts.output, func(path string) error {
		return importedfleet.WriteGraph(path, graph)
	}); err != nil {
		return err
	}
	if opts.report != "" {
		if err := writeAlongside(opts.report, func(path string) error {
			return os.WriteFile(path, []byte(importedfleet.GraphMarkdown(graph)), 0o644)
		}); err != nil {
			return err
		}
	}

	if structuredFormat() {
		if err := printStructured(graph); err != nil {
			return err
		}
		return graphGateResult(graph, opts)
	}
	printGraphSummary(graph, opts)
	return graphGateResult(graph, opts)
}

// graphGateResult turns the requested gates into the shared check-failure sentinel so
// `graph build` can be used as a CI gate with the same exit-code contract as the
// other ClearCutt gates.
func graphGateResult(graph importedfleet.Graph, opts graphBuildFlags) error {
	failures := []string{}
	if opts.failOnStale && graph.Summary.StaleConsumers > 0 {
		failures = append(failures, fmt.Sprintf("%d consumer(s) sit on a stale base version", graph.Summary.StaleConsumers))
	}
	if opts.failOnUnknown && graph.Summary.UnresolvedConsumers > 0 {
		failures = append(failures, fmt.Sprintf("%d image(s) have an undetermined base", graph.Summary.UnresolvedConsumers))
	}
	if len(failures) == 0 {
		return nil
	}
	for _, failure := range failures {
		fmt.Fprintf(errOut, "[graph] FAIL: %s\n", failure)
	}
	return ErrCheckFailed
}

// printGraphSummary renders the terminal pane of glass: what is stale, what is
// unknown, and how much of the graph rests on proof rather than on a label.
func printGraphSummary(graph importedfleet.Graph, opts graphBuildFlags) {
	s := graph.Summary
	fmt.Fprintf(out, "[graph] %d image(s) observed: %d base famil(ies), %d consumer(s), %d root(s)\n",
		s.ObservedImages, s.BaseFamilies, s.Consumers, s.RootImages)
	fmt.Fprintf(out, "[graph] resolved %d consumer(s): %d on the current base, %d stale, %d undetermined\n",
		s.ResolvedConsumers, s.CurrentConsumers, s.StaleConsumers, s.UnresolvedConsumers)

	proven := s.EdgesByConfidence["verified"]
	if s.ResolvedConsumers > 0 {
		fmt.Fprintf(out, "[graph] %d of %d relationship(s) are proven by layer digests; the rest rest on labels the image author supplied\n",
			proven, s.ResolvedConsumers)
	}

	if len(graph.Bases) > 0 {
		fmt.Fprintf(out, "\n%-44s %9s %10s %8s\n", "BASE REPOSITORY", "VERSIONS", "CONSUMERS", "STALE")
		for _, base := range graph.Bases {
			fmt.Fprintf(out, "%-44s %9d %10d %8d\n", truncate(base.Repository, 44), base.Versions, base.Consumers, base.StaleConsumers)
		}
	}

	stale := []importedfleet.GraphEdge{}
	for _, edge := range graph.Edges {
		if edge.Drift == "stale" {
			stale = append(stale, edge)
		}
	}
	if len(stale) > 0 {
		sort.SliceStable(stale, func(i, j int) bool {
			if stale[i].VersionsBehind != stale[j].VersionsBehind {
				return stale[i].VersionsBehind > stale[j].VersionsBehind
			}
			return stale[i].ConsumerRef < stale[j].ConsumerRef
		})
		fmt.Fprintf(out, "\nStale consumers (rebase candidates):\n")
		fmt.Fprintf(out, "%-50s %-30s %8s %7s\n", "CONSUMER", "BASE", "BEHIND", "DAYS")
		for _, edge := range stale {
			fmt.Fprintf(out, "%-50s %-30s %8d %7d\n",
				truncate(edge.ConsumerRef, 50), truncate(edge.BaseRepository, 30), edge.VersionsBehind, edge.DaysBehind)
		}
	}

	if len(graph.SharedLayers) > 0 {
		fmt.Fprintf(out, "\nShared layers (blast radius): %d of %d distinct layers are in more than one image; the widest is in %d\n",
			s.SharedLayers, s.DistinctLayers, s.WidestLayerReach)
		fmt.Fprintf(out, "%-30s %8s\n", "LAYER", "IMAGES")
		for i, layer := range graph.SharedLayers {
			if i >= 5 {
				fmt.Fprintf(out, "... %d more (see the graph JSON or --report)\n", len(graph.SharedLayers)-5)
				break
			}
			fmt.Fprintf(out, "%-30s %8d\n", truncate(layer.Digest, 30), layer.ImageCount)
		}
	}

	if len(graph.Unresolved) > 0 {
		fmt.Fprintf(out, "\nBase could not be determined for %d image(s):\n", len(graph.Unresolved))
		for _, entry := range graph.Unresolved {
			fmt.Fprintf(out, "  %s\n    %s\n", entry.ConsumerRef, strings.Join(entry.Reasons, "; "))
		}
	}
	for _, warning := range graph.Warnings {
		fmt.Fprintf(errOut, "[graph] %s\n", warning)
	}
	fmt.Fprintf(out, "\n[graph] wrote %s\n", opts.output)
	if opts.report != "" {
		fmt.Fprintf(out, "[graph] wrote %s\n", opts.report)
	}
}

func truncate(value string, width int) string {
	if len(value) <= width {
		return value
	}
	if width <= 1 {
		return value[:width]
	}
	return "…" + value[len(value)-width+1:]
}
