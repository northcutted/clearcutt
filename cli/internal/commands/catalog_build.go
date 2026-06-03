package commands

import (
	"os"

	"github.com/spf13/cobra"
)

type catalogBuildFlags struct {
	limit           int
	targets         string
	forceRefreshAll bool
	scanDepth       string
	scanAll         bool
	lenientEvidence bool
}

var catalogBuildOpts catalogBuildFlags

func newCatalogBuildCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Run the full catalog gather, enrich, scan, fold, and verify pipeline",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogBuild()
		},
	}
	cmd.Flags().IntVar(&catalogBuildOpts.limit, "limit", envIntValue("RELEASE_LIMIT", 10), "Maximum releases to inspect")
	cmd.Flags().StringVar(&catalogBuildOpts.targets, "targets", os.Getenv("CATALOG_TARGETS"), "Comma-separated target allowlist")
	cmd.Flags().BoolVar(&catalogBuildOpts.forceRefreshAll, "force-refresh-all", parseScanBool(os.Getenv("FORCE_REFRESH_ALL")), "Refresh enrichment and SBOMs for every release")
	cmd.Flags().StringVar(&catalogBuildOpts.scanDepth, "scan-depth", envOr("SCAN_TAG_DEPTH", "4"), "Newest cached tag count to scan")
	cmd.Flags().BoolVar(&catalogBuildOpts.scanAll, "scan-all", parseScanBool(os.Getenv("SCAN_ALL_TAGS")), "Scan every cached SBOM tag")
	cmd.Flags().BoolVar(&catalogBuildOpts.lenientEvidence, "lenient-evidence", false, "Run verify-catalog without requiring signature/provenance/tests")
	return cmd
}

func runCatalogBuild() error {
	catalogGatherOpts.limit = catalogBuildOpts.limit
	catalogGatherOpts.targets = catalogBuildOpts.targets
	catalogGatherOpts.forceRefreshAll = catalogBuildOpts.forceRefreshAll
	catalogGatherOpts.forceRefreshTags = os.Getenv("FORCE_REFRESH_TAGS")
	if err := runCatalogGather(); err != nil {
		return err
	}

	catalogEnrichOpts.limit = catalogBuildOpts.limit
	catalogEnrichOpts.targets = catalogBuildOpts.targets
	catalogEnrichOpts.forceRefreshAll = catalogBuildOpts.forceRefreshAll
	catalogEnrichOpts.forceRefreshTags = os.Getenv("FORCE_REFRESH_TAGS")
	if err := runCatalogEnrich(); err != nil {
		return err
	}

	scanOpts.mode = "catalog"
	scanOpts.sbomDir = catalogGatherOpts.sbomCacheDir
	scanOpts.outDir = catalogGatherOpts.vulnDir
	scanOpts.depth = catalogBuildOpts.scanDepth
	scanOpts.tags = os.Getenv("SCAN_TAGS")
	scanOpts.all = catalogBuildOpts.scanAll || catalogBuildOpts.forceRefreshAll
	scanOpts.concurrency = 0
	if err := runScan(); err != nil {
		return err
	}

	// Second gather folds enrichment and vulnerability JSON into image records;
	// do not force SBOM downloads again because the first gather already populated
	// the cache for this build.
	catalogGatherOpts.forceRefreshAll = false
	catalogGatherOpts.forceRefreshTags = ""
	if err := runCatalogGather(); err != nil {
		return err
	}

	verifyCatalogOpts.lenientEvidence = catalogBuildOpts.lenientEvidence
	return runVerifyCatalog()
}
