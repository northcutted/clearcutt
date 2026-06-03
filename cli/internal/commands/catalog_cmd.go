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
	"sort"
	"strings"
	"time"

	"github.com/northcutted/clearcutt/internal/catalog"
	"github.com/spf13/cobra"
)

type catalogGatherFlags struct {
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
}

var catalogGatherOpts catalogGatherFlags

func NewCatalogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Build and enrich the site catalog data",
	}
	cmd.AddCommand(newCatalogGatherCmd())
	cmd.AddCommand(newCatalogEnrichCmd())
	cmd.AddCommand(newCatalogBuildCmd())
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
	cmd.Flags().IntVar(&catalogGatherOpts.limit, "limit", envIntValue("RELEASE_LIMIT", 10), "Maximum non-draft releases to inspect")
	cmd.Flags().StringVar(&catalogGatherOpts.owner, "owner", os.Getenv("GH_OWNER"), "GitHub owner (defaults to GH_OWNER, GITHUB_REPOSITORY, or git remote)")
	cmd.Flags().StringVar(&catalogGatherOpts.repo, "repo", os.Getenv("GH_REPO"), "GitHub repository (defaults to GH_REPO, GITHUB_REPOSITORY, or git remote)")
	cmd.Flags().StringVar(&catalogGatherOpts.registryBase, "registry-base", "", "Registry namespace (defaults to ghcr.io/<owner>/<repo>)")
	cmd.Flags().StringVar(&catalogGatherOpts.outDir, "out-dir", "", "Catalog output directory (defaults to --catalog)")
	cmd.Flags().StringVar(&catalogGatherOpts.enrichmentDir, "enrichment-dir", envOr("ENRICHMENT_DIR", filepath.Join("site", "src", "data", "enrichment")), "Directory of registry enrichment JSON")
	cmd.Flags().StringVar(&catalogGatherOpts.sbomCacheDir, "sbom-cache-dir", envOr("SBOM_CACHE_DIR", filepath.Join("site", "src", "data", "sboms")), "Directory to cache downloaded SBOM assets")
	cmd.Flags().StringVar(&catalogGatherOpts.vulnDir, "vuln-dir", envOr("VULN_DIR", filepath.Join("site", "src", "data", "vulnerabilities")), "Directory of vulnerability scan JSON")
	cmd.Flags().StringVar(&catalogGatherOpts.targets, "targets", os.Getenv("CATALOG_TARGETS"), "Comma-separated target allowlist")
	cmd.Flags().BoolVar(&catalogGatherOpts.forceRefreshAll, "force-refresh-all", parseScanBool(os.Getenv("FORCE_REFRESH_ALL")), "Refresh every release asset instead of reusing the SBOM cache")
	cmd.Flags().StringVar(&catalogGatherOpts.forceRefreshTags, "force-refresh-tags", os.Getenv("FORCE_REFRESH_TAGS"), "Comma-separated release tags to refresh")
	cmd.Flags().StringVar(&catalogGatherOpts.generatedAt, "generated-at", "", "Override index generatedAt timestamp (tests/reproducibility)")
	return cmd
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
	outDir := firstNonEmptyStr(catalogGatherOpts.outDir, GlobalOpts.CatalogPath, filepath.Join("site", "src", "data", "catalog"))
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
		ok, err := rebuildIndexFromExistingImages(owner, repo, registryBase, outDir, catalogGatherOpts.vulnDir, generatedAt)
		if err != nil {
			return err
		}
		if ok {
			fmt.Fprintln(out, "[gather] rebuilt index.json from existing image records")
			return nil
		}
		empty := buildCatalogIndex(owner, repo, registryBase, generatedAt, nil, nil)
		return writeJSONFile(filepath.Join(outDir, "index.json"), empty)
	}

	refreshSet := refreshTagSet(releases, catalogGatherOpts.forceRefreshAll, catalogGatherOpts.forceRefreshTags)
	targets := gatherTargets(catalogGatherOpts.targets)
	images := []gatherImageRecord{}
	for _, target := range targets {
		rec, err := buildImageRecord(target, releases, refreshSet, gatherBuildOptions{
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
	index := buildCatalogIndex(owner, repo, registryBase, generatedAt, releases, images)
	if err := writeJSONFile(filepath.Join(outDir, "index.json"), index); err != nil {
		return err
	}
	fmt.Fprintf(out, "[gather] wrote index.json with %d images\n", len(index.Images))
	return nil
}

// newReleaseSource builds the GitHub release source. It is a package var so
// tests can inject an offline fake and exercise the full gather-to-index path
// without touching api.github.com.
var newReleaseSource = func(owner, repo, token string) ReleaseSource {
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

func (s *githubReleaseSource) ListReleases(limit int) ([]catalogRelease, error) {
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
	releases := []catalogRelease{}
	for _, rel := range raw {
		if rel.Draft {
			continue
		}
		assets := make([]catalogAsset, 0, len(rel.Assets))
		for _, asset := range rel.Assets {
			assets = append(assets, catalogAsset{
				Name:   asset.Name,
				URL:    asset.BrowserDownloadURL,
				Size:   asset.Size,
				Digest: asset.Digest,
			})
		}
		releases = append(releases, catalogRelease{
			Tag:         rel.TagName,
			Name:        rel.Name,
			PublishedAt: firstNonEmptyStr(rel.PublishedAt, rel.CreatedAt),
			Prerelease:  rel.Prerelease,
			Assets:      assets,
		})
		if len(releases) >= limit {
			break
		}
	}
	return releases, nil
}

func (s *githubReleaseSource) DownloadAsset(asset catalogAsset) ([]byte, error) {
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

func gatherTargets(filter string) []string {
	allowed := map[string]bool{}
	if filter != "" {
		for _, target := range strings.Split(filter, ",") {
			target = strings.TrimSpace(target)
			if target != "" {
				allowed[target] = true
			}
		}
	}
	targets := []string{}
	for _, langKey := range gatherLanguageOrder {
		for _, tier := range gatherTierOrder {
			target := langKey + "-" + tier
			if len(allowed) == 0 || allowed[target] {
				targets = append(targets, target)
			}
		}
	}
	return targets
}

func buildCatalogIndex(owner, repo, registryBase, generatedAt string, releases []catalogRelease, images []gatherImageRecord) gatherCatalogIndex {
	var latest *catalogRelease
	for i := range releases {
		if !releases[i].Prerelease {
			latest = &releases[i]
			break
		}
	}
	if latest == nil && len(releases) > 0 {
		latest = &releases[0]
	}
	releaseSummaries := make([]catalog.ReleaseSummary, 0, len(releases))
	for i := range releases {
		releaseSummaries = append(releaseSummaries, catalog.ReleaseSummary{
			Tag:         releases[i].Tag,
			PublishedAt: releases[i].PublishedAt,
			IsLatest:    latest != nil && releases[i].Tag == latest.Tag,
		})
	}
	summaries := make([]gatherCatalogImageSummary, 0, len(images))
	for _, img := range images {
		if len(img.Releases) > 0 {
			summaries = append(summaries, summarizeImageForIndex(img))
		}
	}
	latestTag := ""
	if latest != nil {
		latestTag = latest.Tag
	}
	return gatherCatalogIndex{
		GeneratedAt:  generatedAt,
		Owner:        owner,
		Repo:         repo,
		RepoURL:      fmt.Sprintf("https://github.com/%s/%s", owner, repo),
		RegistryBase: registryBase,
		LatestTag:    latestTag,
		Releases:     releaseSummaries,
		Languages:    gatherLanguageList(),
		Tiers:        gatherTierList(),
		Images:       summaries,
	}
}

func gatherLanguageList() []gatherLanguageOut {
	out := []gatherLanguageOut{}
	seen := map[string]int{}
	for _, key := range gatherLanguageOrder {
		lang := gatherLanguages[key]
		entry := gatherLanguageOut{ID: lang.ID, DisplayName: lang.Display, Version: lang.Version}
		seenKey := lang.ID + "-" + lang.Version
		if idx, ok := seen[seenKey]; ok {
			out[idx] = entry
			continue
		}
		seen[seenKey] = len(out)
		out = append(out, entry)
	}
	return out
}

func gatherTierList() []gatherTierOut {
	out := make([]gatherTierOut, 0, len(gatherTierOrder))
	for _, id := range gatherTierOrder {
		tier := gatherTiers[id]
		out = append(out, gatherTierOut{ID: id, Name: tier.Name, Blurb: tier.Blurb})
	}
	return out
}

func rebuildIndexFromExistingImages(owner, repo, registryBase, outDir, vulnDir, generatedAt string) (bool, error) {
	imgDir := filepath.Join(outDir, "images")
	entries, err := os.ReadDir(imgDir)
	if err != nil {
		return false, nil
	}
	files := []string{}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return false, nil
	}
	images := []gatherImageRecord{}
	for _, file := range files {
		imagePath := filepath.Join(imgDir, file)
		data, err := os.ReadFile(imagePath)
		if err != nil {
			return false, err
		}
		var img gatherImageRecord
		if err := json.Unmarshal(data, &img); err != nil {
			return false, err
		}
		for i := range img.Releases {
			lastRebuiltAt := firstNonEmptyStr(img.Releases[i].LastRebuiltAt, img.Releases[i].PublishedAt)
			for j := range img.Releases[i].Architectures {
				arch := &img.Releases[i].Architectures[j]
				raw, info := loadVulnerabilities(img.Releases[i].Tag, img.ID, arch.Arch, vulnDir)
				if raw != nil {
					arch.Vulnerabilities = raw
					arch.vulnInfo = info
				} else if arch.Vulnerabilities != nil {
					var parsed catalog.VulnerabilitiesInfo
					if err := json.Unmarshal(*arch.Vulnerabilities, &parsed); err == nil {
						arch.vulnInfo = &parsed
					}
				}
				if arch.vulnInfo != nil && arch.vulnInfo.ScannedAt != "" && arch.vulnInfo.ScannedAt > lastRebuiltAt {
					lastRebuiltAt = arch.vulnInfo.ScannedAt
				}
			}
			img.Releases[i].LastRebuiltAt = lastRebuiltAt
			img.Releases[i].Evidence = releaseEvidenceFromGather(&img.Releases[i])
		}
		if err := writeJSONFile(imagePath, img); err != nil {
			return false, err
		}
		if len(img.Releases) > 0 {
			images = append(images, img)
		}
	}
	if len(images) == 0 {
		return false, nil
	}

	byTag := map[string]catalogRelease{}
	for _, img := range images {
		for _, rel := range img.Releases {
			if _, ok := byTag[rel.Tag]; !ok {
				byTag[rel.Tag] = catalogRelease{Tag: rel.Tag, PublishedAt: rel.PublishedAt}
			}
		}
	}
	releases := make([]catalogRelease, 0, len(byTag))
	for _, rel := range byTag {
		releases = append(releases, rel)
	}
	sort.Slice(releases, func(i, j int) bool { return releases[i].PublishedAt > releases[j].PublishedAt })
	latestTag := ""
	if len(images[0].Releases) > 0 {
		latestTag = images[0].Releases[0].Tag
	}
	for i := range releases {
		releases[i].Prerelease = releases[i].Tag != latestTag
	}
	index := buildCatalogIndex(owner, repo, registryBase, generatedAt, releases, images)
	index.LatestTag = latestTag
	for i := range index.Releases {
		index.Releases[i].IsLatest = index.Releases[i].Tag == latestTag
	}
	if err := writeJSONFile(filepath.Join(outDir, "index.json"), index); err != nil {
		return false, err
	}
	return true, nil
}

func writeJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
