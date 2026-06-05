package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/northcutted/clearcutt/internal/catalog"
	"github.com/northcutted/clearcutt/internal/catalogbuild"
	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/spf13/cobra"
)

type catalogGatherFlags struct {
	config           string
	imagesFile       string
	limit            int
	owner            string
	repo             string
	registryBase     string
	outDir           string
	enrichmentDir    string
	sbomCacheDir     string
	vulnDir          string
	targets          string
	forceRefreshAll  bool
	forceRefreshTags string
	generatedAt      string
	pretty           bool
}

var catalogGatherOpts catalogGatherFlags

func NewCatalogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Build and enrich the site catalog data",
	}
	cmd.AddCommand(newCatalogGenerateCmd())
	cmd.AddCommand(newCatalogGatherCmd())
	cmd.AddCommand(newCatalogEnrichCmd())
	cmd.AddCommand(newCatalogBuildCmd())
	cmd.AddCommand(newCatalogValidateCmd())
	cmd.AddCommand(newCatalogSummarizeCmd())
	cmd.AddCommand(newCatalogInspectCmd())
	cmd.AddCommand(newCatalogDiffCmd())
	cmd.AddCommand(newCatalogSiteCmd())
	return cmd
}

func newCatalogGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate portable catalog JSON from ClearCutt release evidence",
		Long: `Generate the site-compatible catalog JSON used by ClearCutt discovery
commands and Astro catalog pages. This first public generator path reuses the
ClearCutt-native GitHub release evidence pipeline by default. Pass --images to
build a minimal Nix-free catalog from a generic OCI image inventory; unavailable
evidence channels are preserved as explicit missing-evidence states.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogGenerate(cmd)
		},
	}
	addCatalogGatherFlags(cmd)
	cmd.Flags().StringVar(&catalogGatherOpts.config, "config", fleet.DefaultConfigPath, "ClearCutt fleet config used for owner/repo/registry/target defaults")
	cmd.Flags().StringVar(&catalogGatherOpts.imagesFile, "images", "", "Generic OCI images.yaml inventory to convert into catalog data")
	cmd.Flags().StringVar(&catalogGatherOpts.outDir, "output", "", "Catalog output directory")
	cmd.Flags().BoolVar(&catalogGatherOpts.pretty, "pretty", true, "Write indented JSON output")
	return cmd
}

func newCatalogGatherCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gather",
		Short: "Gather GitHub release assets into catalog image records",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogGather()
		},
	}
	addCatalogGatherFlags(cmd)
	return cmd
}

func addCatalogGatherFlags(cmd *cobra.Command) {
	cmd.Flags().IntVar(&catalogGatherOpts.limit, "limit", envIntValue("RELEASE_LIMIT", 10), "Maximum non-draft releases to inspect")
	cmd.Flags().StringVar(&catalogGatherOpts.owner, "owner", os.Getenv("GH_OWNER"), "GitHub owner (defaults to GH_OWNER, GITHUB_REPOSITORY, fleet config, or git remote)")
	cmd.Flags().StringVar(&catalogGatherOpts.repo, "repo", os.Getenv("GH_REPO"), "GitHub repository (defaults to GH_REPO, GITHUB_REPOSITORY, fleet config, or git remote)")
	cmd.Flags().StringVar(&catalogGatherOpts.registryBase, "registry-base", "", "Registry namespace (defaults to fleet config or ghcr.io/<owner>/<repo>)")
	cmd.Flags().StringVar(&catalogGatherOpts.outDir, "out-dir", "", "Catalog output directory (defaults to --catalog)")
	cmd.Flags().StringVar(&catalogGatherOpts.enrichmentDir, "enrichment-dir", envOr("ENRICHMENT_DIR", filepath.Join("site", "src", "data", "enrichment")), "Directory of registry enrichment JSON")
	cmd.Flags().StringVar(&catalogGatherOpts.sbomCacheDir, "sbom-cache-dir", envOr("SBOM_CACHE_DIR", filepath.Join("site", "src", "data", "sboms")), "Directory to cache downloaded SBOM assets")
	cmd.Flags().StringVar(&catalogGatherOpts.vulnDir, "vuln-dir", envOr("VULN_DIR", filepath.Join("site", "src", "data", "vulnerabilities")), "Directory of vulnerability scan JSON")
	cmd.Flags().StringVar(&catalogGatherOpts.targets, "targets", os.Getenv("CATALOG_TARGETS"), "Comma-separated target allowlist")
	cmd.Flags().BoolVar(&catalogGatherOpts.forceRefreshAll, "force-refresh-all", parseScanBool(os.Getenv("FORCE_REFRESH_ALL")), "Refresh every release asset instead of reusing the SBOM cache")
	cmd.Flags().StringVar(&catalogGatherOpts.forceRefreshTags, "force-refresh-tags", os.Getenv("FORCE_REFRESH_TAGS"), "Comma-separated release tags to refresh")
	cmd.Flags().StringVar(&catalogGatherOpts.generatedAt, "generated-at", "", "Override index generatedAt timestamp (tests/reproducibility)")
}

func runCatalogGenerate(cmd *cobra.Command) error {
	return runCatalogGenerateWithConfig(cmd.Flags().Changed("config"), cmd.Flags().Changed("limit"))
}

func runCatalogGenerateWithConfig(explicitConfig, limitChanged bool) error {
	if catalogGatherOpts.imagesFile != "" {
		return runCatalogGenerateFromImages()
	}
	if catalogGatherOpts.config != "" {
		cfg, err := fleet.Load(catalogGatherOpts.config)
		if err != nil {
			if explicitConfig || !os.IsNotExist(err) {
				return err
			}
		} else {
			if catalogGatherOpts.owner == "" {
				catalogGatherOpts.owner = cfg.Registry.Owner
			}
			if catalogGatherOpts.repo == "" {
				catalogGatherOpts.repo = cfg.Registry.Repository
			}
			if catalogGatherOpts.registryBase == "" {
				catalogGatherOpts.registryBase = cfg.RegistryBase()
			}
			if catalogGatherOpts.targets == "" {
				catalogGatherOpts.targets = fleetTargets(cfg)
			}
			if !limitChanged && cfg.Catalog.ReleaseLimit > 0 {
				catalogGatherOpts.limit = cfg.Catalog.ReleaseLimit
			}
		}
	}
	if catalogGatherOpts.outDir != "" {
		GlobalOpts.CatalogPath = catalogGatherOpts.outDir
	}
	if err := runCatalogGather(); err != nil {
		return err
	}
	outDir := catalogbuild.FirstNonEmptyStr(catalogGatherOpts.outDir, GlobalOpts.CatalogPath, filepath.Join("site", "src", "data", "catalog"))
	return finalizeGeneratedCatalog(outDir)
}

func finalizeGeneratedCatalog(outDir string) error {
	if err := stampCatalogIndexMetadata(outDir); err != nil {
		return err
	}
	if err := ensureRawEvidenceDirs(outDir); err != nil {
		return err
	}
	if err := writeCatalogSummaryFile(outDir); err != nil {
		return err
	}
	fmt.Fprintf(out, "[generate] wrote summary.json\n")
	if err := writeCatalogSchemaFiles(outDir); err != nil {
		return err
	}
	fmt.Fprintf(out, "[generate] wrote schemas/\n")
	return nil
}

func ensureRawEvidenceDirs(outDir string) error {
	for _, rel := range []string{
		filepath.Join("raw", "sbom"),
		filepath.Join("raw", "provenance"),
		filepath.Join("raw", "scans"),
		filepath.Join("raw", "test-results"),
	} {
		if err := os.MkdirAll(filepath.Join(outDir, rel), 0o755); err != nil {
			return err
		}
	}
	return nil
}

func stampCatalogIndexMetadata(outDir string) error {
	index, err := catalog.LoadCatalogIndex(outDir)
	if err != nil {
		return err
	}
	index.Generator = &catalog.CatalogGenerator{
		Name:    "clearcutt",
		Version: catalogbuild.FirstNonEmptyStr(Version, "dev"),
		Commit:  "unknown",
	}
	index.Source = &catalog.CatalogSource{
		Owner:        index.Owner,
		Repo:         index.Repo,
		RepoURL:      index.RepoURL,
		RegistryBase: index.RegistryBase,
	}
	index.Summary = catalogIndexSummary(index)
	return writeJSONFile(filepath.Join(outDir, "index.json"), index)
}

func catalogIndexSummary(index *catalog.CatalogIndex) *catalog.CatalogSummary {
	if index == nil {
		return nil
	}
	summary := &catalog.CatalogSummary{
		ImageCount:   len(index.Images),
		ReleaseCount: len(index.Releases),
	}
	for _, img := range index.Images {
		if img.Signed {
			summary.SignedCount++
		}
		if img.Provenance {
			summary.ProvenanceCount++
		}
		if img.Passed {
			summary.PassingCount++
		}
		if img.Evidence != nil {
			if img.Evidence.SBOM {
				summary.SBOMCount++
			}
			if img.Evidence.Vulnerabilities {
				summary.ScanCount++
			}
		}
	}
	return summary
}

func fleetTargets(cfg fleet.Config) string {
	targets := []string{}
	for _, language := range cfg.Matrix.Languages {
		for _, tier := range cfg.Matrix.Tiers {
			targets = append(targets, language+"-"+tier)
		}
	}
	return strings.Join(targets, ",")
}

func runCatalogGather() error {
	owner, repo, err := detectCatalogRepo(catalogGatherOpts.owner, catalogGatherOpts.repo)
	if err != nil {
		return err
	}
	registryBase := catalogGatherOpts.registryBase
	if registryBase == "" {
		registryBase = "ghcr.io/" + strings.ToLower(owner) + "/" + strings.ToLower(repo)
	}
	outDir := catalogbuild.FirstNonEmptyStr(catalogGatherOpts.outDir, GlobalOpts.CatalogPath, filepath.Join("site", "src", "data", "catalog"))
	imgDir := filepath.Join(outDir, "images")
	if err := os.MkdirAll(imgDir, 0o755); err != nil {
		return err
	}

	source := newReleaseSource(owner, repo, os.Getenv("GITHUB_TOKEN"))
	releases, err := source.ListReleases(catalogGatherOpts.limit)
	if err != nil {
		return err
	}
	generatedAt := catalogGatherOpts.generatedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if len(releases) == 0 {
		ok, err := catalogbuild.RebuildIndexFromExistingImages(owner, repo, registryBase, outDir, catalogGatherOpts.vulnDir, generatedAt)
		if err != nil {
			return err
		}
		if ok {
			if err := stampCatalogIndexMetadata(outDir); err != nil {
				return err
			}
			fmt.Fprintln(out, "[gather] rebuilt index.json from existing image records")
			return nil
		}
		empty := catalogbuild.BuildIndex(owner, repo, registryBase, generatedAt, nil, nil)
		if err := writeJSONFile(filepath.Join(outDir, "index.json"), empty); err != nil {
			return err
		}
		return stampCatalogIndexMetadata(outDir)
	}

	refreshSet := catalogbuild.RefreshTagSet(releases, catalogGatherOpts.forceRefreshAll, catalogGatherOpts.forceRefreshTags)
	targets := catalogbuild.Targets(catalogGatherOpts.targets)
	images := []catalogbuild.ImageRecord{}
	for _, target := range targets {
		rec, err := catalogbuild.BuildImageRecord(target, releases, refreshSet, catalogbuild.BuildOptions{
			RegistryBase:  registryBase,
			SBOMCacheDir:  catalogGatherOpts.sbomCacheDir,
			EnrichmentDir: catalogGatherOpts.enrichmentDir,
			VulnDir:       catalogGatherOpts.vulnDir,
			Source:        source,
		})
		if err != nil {
			fmt.Fprintf(errOut, "[gather] %s: %v\n", target, err)
			continue
		}
		if rec == nil {
			continue
		}
		if err := writeJSONFile(filepath.Join(imgDir, target+".json"), rec); err != nil {
			return err
		}
		images = append(images, *rec)
		fmt.Fprintf(out, "[gather] wrote %s (%d releases)\n", target, len(rec.Releases))
	}
	index := catalogbuild.BuildIndex(owner, repo, registryBase, generatedAt, releases, images)
	if err := writeJSONFile(filepath.Join(outDir, "index.json"), index); err != nil {
		return err
	}
	if err := stampCatalogIndexMetadata(outDir); err != nil {
		return err
	}
	fmt.Fprintf(out, "[gather] wrote index.json with %d images\n", len(index.Images))
	return nil
}

// newReleaseSource builds the GitHub release source. It is a package var so
// tests can inject an offline fake and exercise the full gather-to-index path
// without touching api.github.com.
var newReleaseSource = func(owner, repo, token string) catalogbuild.ReleaseSource {
	return &githubReleaseSource{
		owner:  owner,
		repo:   repo,
		token:  token,
		client: http.DefaultClient,
	}
}

type githubReleaseSource struct {
	owner  string
	repo   string
	token  string
	client *http.Client
}

func (s *githubReleaseSource) ListReleases(limit int) ([]catalogbuild.Release, error) {
	if limit <= 0 {
		limit = 10
	}
	perPage := limit * 2
	if perPage < 1 {
		perPage = 1
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases?per_page=%d", s.owner, s.repo, perPage)
	body, err := s.get(url, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	var raw []struct {
		TagName     string `json:"tag_name"`
		Name        string `json:"name"`
		PublishedAt string `json:"published_at"`
		CreatedAt   string `json:"created_at"`
		Prerelease  bool   `json:"prerelease"`
		Draft       bool   `json:"draft"`
		Assets      []struct {
			Name               string  `json:"name"`
			BrowserDownloadURL string  `json:"browser_download_url"`
			Size               int64   `json:"size"`
			Digest             *string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	releases := []catalogbuild.Release{}
	for _, rel := range raw {
		if rel.Draft {
			continue
		}
		assets := make([]catalogbuild.Asset, 0, len(rel.Assets))
		for _, asset := range rel.Assets {
			assets = append(assets, catalogbuild.Asset{
				Name:   asset.Name,
				URL:    asset.BrowserDownloadURL,
				Size:   asset.Size,
				Digest: asset.Digest,
			})
		}
		releases = append(releases, catalogbuild.Release{
			Tag:         rel.TagName,
			Name:        rel.Name,
			PublishedAt: catalogbuild.FirstNonEmptyStr(rel.PublishedAt, rel.CreatedAt),
			Prerelease:  rel.Prerelease,
			Assets:      assets,
		})
		if len(releases) >= limit {
			break
		}
	}
	return releases, nil
}

func (s *githubReleaseSource) DownloadAsset(asset catalogbuild.Asset) ([]byte, error) {
	return s.get(asset.URL, "application/octet-stream")
}

func (s *githubReleaseSource) get(url, accept string) ([]byte, error) {
	client := s.client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, readErr := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		if len(body) > 240 {
			body = body[:240]
		}
		return nil, fmt.Errorf("GitHub request %s failed: %s: %s", url, res.Status, strings.TrimSpace(string(body)))
	}
	if readErr != nil {
		return nil, readErr
	}
	return body, nil
}

func detectCatalogRepo(ownerFlag, repoFlag string) (string, string, error) {
	if ownerFlag != "" && repoFlag != "" {
		return ownerFlag, repoFlag, nil
	}
	if owner := os.Getenv("GH_OWNER"); owner != "" && os.Getenv("GH_REPO") != "" {
		return owner, os.Getenv("GH_REPO"), nil
	}
	if repo := os.Getenv("GITHUB_REPOSITORY"); repo != "" {
		parts := strings.SplitN(repo, "/", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			return parts[0], parts[1], nil
		}
	}
	cmd := exec.Command("git", "remote", "get-url", "origin")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("unable to detect GitHub repo: set --owner/--repo or GH_OWNER/GH_REPO")
	}
	owner, repo := parseGitHubRemote(strings.TrimSpace(string(raw)))
	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("unable to parse GitHub repo from origin %q: set --owner/--repo", strings.TrimSpace(string(raw)))
	}
	return owner, repo, nil
}

func parseGitHubRemote(remote string) (string, string) {
	remote = strings.TrimSuffix(remote, ".git")
	if idx := strings.Index(remote, "github.com"); idx != -1 {
		rest := strings.TrimLeft(remote[idx+len("github.com"):], ":/")
		parts := strings.Split(rest, "/")
		if len(parts) >= 2 {
			return parts[0], parts[1]
		}
	}
	parts := strings.Split(remote, "/")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", ""
}

func writeJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var (
		data []byte
		err  error
	)
	if catalogGatherOpts.pretty {
		data, err = json.MarshalIndent(value, "", "  ")
	} else {
		data, err = json.Marshal(value)
	}
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
