package commands

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
)

const (
	defaultUpdateRepo   = "northcutted/clearcutt"
	defaultUpdateIssuer = "https://token.actions.githubusercontent.com"
	maxUpdateAssetBytes = 256 << 20
)

type updateFlags struct {
	version          string
	repo             string
	output           string
	check            bool
	force            bool
	cosign           string
	workflowIdentity string
	oidcIssuer       string
}

type updateResult struct {
	Status         string `json:"status"`
	CurrentVersion string `json:"currentVersion"`
	TargetVersion  string `json:"targetVersion"`
	Repository     string `json:"repository"`
	Asset          string `json:"asset"`
	Output         string `json:"output,omitempty"`
	Verified       bool   `json:"verified"`
	Updated        bool   `json:"updated"`
}

type githubUpdateRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

var updateOpts updateFlags
var updateHTTPClient = &http.Client{Timeout: 90 * time.Second}
var updateAPIBaseURL = "https://api.github.com"
var updateExecutable = os.Executable
var updateVerifyBlob = func(ctx context.Context, cosign, binary, bundle, identity, issuer string) error {
	cmd := exec.CommandContext(ctx, cosign, "verify-blob", binary,
		"--bundle", bundle,
		"--certificate-identity", identity,
		"--certificate-oidc-issuer", issuer,
	)
	if raw, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cosign verify-blob failed: %w: %s", err, strings.TrimSpace(string(raw)))
	}
	return nil
}

func NewUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Install a checksum- and Sigstore-verified ClearCutt CLI release",
		Long: `Checks GitHub Releases for a ClearCutt CLI version and, unless --check is
used, downloads the matching platform binary, checksum manifest, and Sigstore
bundle. The binary is replaced only after its SHA-256 checksum and the exact
release-workflow certificate identity both verify. cosign must be available.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(cmd.Context())
		},
	}
	f := cmd.Flags()
	f.StringVar(&updateOpts.version, "version", "latest", "Release tag to install, or latest")
	f.StringVar(&updateOpts.repo, "repo", defaultUpdateRepo, "GitHub owner/repo that publishes CLI assets")
	f.StringVar(&updateOpts.output, "output", "", "Installation path (default: replace the running executable)")
	f.BoolVar(&updateOpts.check, "check", false, "Report the selected release without downloading or installing it")
	f.BoolVar(&updateOpts.force, "force", false, "Install even when the current and selected versions match")
	f.StringVar(&updateOpts.cosign, "cosign", "cosign", "Path to the cosign executable")
	f.StringVar(&updateOpts.workflowIdentity, "workflow-identity", "", "Exact release workflow certificate identity (default derived from --repo)")
	f.StringVar(&updateOpts.oidcIssuer, "oidc-issuer", defaultUpdateIssuer, "Sigstore certificate OIDC issuer")
	return cmd
}

func runUpdate(ctx context.Context) error {
	if _, _, err := splitUpdateRepo(updateOpts.repo); err != nil {
		return err
	}
	release, err := fetchUpdateRelease(ctx, updateOpts.repo, updateOpts.version)
	if err != nil {
		return err
	}
	assetName, err := updateAssetName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	result := updateResult{
		Status:         "available",
		CurrentVersion: Version,
		TargetVersion:  release.TagName,
		Repository:     updateOpts.repo,
		Asset:          assetName,
	}
	if updateOpts.check {
		return printUpdateResult(result)
	}
	if !updateOpts.force && normalizeUpdateVersion(Version) == normalizeUpdateVersion(release.TagName) {
		result.Status = "current"
		return printUpdateResult(result)
	}

	assetURL, err := updateReleaseAssetURL(release, assetName)
	if err != nil {
		return err
	}
	bundleURL, err := updateReleaseAssetURL(release, assetName+".sig")
	if err != nil {
		return err
	}
	checksumsURL, err := updateReleaseAssetURL(release, "SHA256SUMS.txt")
	if err != nil {
		return err
	}
	target, err := updateTargetPath(updateOpts.output)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if info, err := os.Stat(target); err == nil && info.IsDir() {
		return fmt.Errorf("update target %s is a directory", target)
	}
	tmpDir, err := os.MkdirTemp(filepath.Dir(target), ".clearcutt-update-")
	if err != nil {
		return fmt.Errorf("create update staging directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	binaryPath := filepath.Join(tmpDir, assetName)
	bundlePath := binaryPath + ".sig"
	checksumsPath := filepath.Join(tmpDir, "SHA256SUMS.txt")
	for _, item := range []struct{ url, path string }{{assetURL, binaryPath}, {bundleURL, bundlePath}, {checksumsURL, checksumsPath}} {
		if err := downloadUpdateAsset(ctx, item.url, item.path); err != nil {
			return err
		}
	}
	if err := verifyUpdateChecksum(binaryPath, checksumsPath, assetName); err != nil {
		return err
	}
	identity := strings.TrimSpace(updateOpts.workflowIdentity)
	if identity == "" {
		identity = "https://github.com/" + updateOpts.repo + "/.github/workflows/release.yml@refs/heads/main"
	}
	if err := updateVerifyBlob(ctx, updateOpts.cosign, binaryPath, bundlePath, identity, updateOpts.oidcIssuer); err != nil {
		return err
	}
	if err := os.Chmod(binaryPath, updateTargetMode(target)); err != nil {
		return fmt.Errorf("make downloaded CLI executable: %w", err)
	}
	if err := replaceUpdateTarget(binaryPath, target); err != nil {
		return err
	}
	result.Status = "updated"
	result.Output = target
	result.Verified = true
	result.Updated = true
	return printUpdateResult(result)
}

func splitUpdateRepo(repo string) (string, string, error) {
	parts := strings.Split(strings.TrimSpace(repo), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.ContainsAny(repo, "?#\\") {
		return "", "", fmt.Errorf("invalid --repo %q (expected owner/repo)", repo)
	}
	return parts[0], parts[1], nil
}

func fetchUpdateRelease(ctx context.Context, repo, version string) (githubUpdateRelease, error) {
	endpoint := strings.TrimRight(updateAPIBaseURL, "/") + "/repos/" + repo + "/releases/latest"
	if normalized := strings.TrimSpace(version); normalized != "" && normalized != "latest" {
		endpoint = strings.TrimRight(updateAPIBaseURL, "/") + "/repos/" + repo + "/releases/tags/" + neturl.PathEscape(normalizeUpdateVersion(normalized))
	}
	raw, err := fetchUpdateBytes(ctx, endpoint)
	if err != nil {
		return githubUpdateRelease{}, fmt.Errorf("resolve ClearCutt release: %w", err)
	}
	var release githubUpdateRelease
	if err := json.Unmarshal(raw, &release); err != nil {
		return release, fmt.Errorf("parse GitHub release response: %w", err)
	}
	if release.TagName == "" {
		return release, fmt.Errorf("GitHub release response has no tag_name")
	}
	return release, nil
}

func updateAssetName(goos, goarch string) (string, error) {
	if goos != "darwin" && goos != "linux" && goos != "windows" {
		return "", fmt.Errorf("ClearCutt release binaries do not support %s/%s", goos, goarch)
	}
	arch := goarch
	switch goarch {
	case "x86_64":
		arch = "amd64"
	case "aarch64":
		arch = "arm64"
	}
	if arch != "amd64" && arch != "arm64" {
		return "", fmt.Errorf("ClearCutt release binaries do not support %s/%s", goos, goarch)
	}
	name := "clearcutt-" + goos + "-" + arch
	if goos == "windows" {
		name += ".exe"
	}
	return name, nil
}

func updateReleaseAssetURL(release githubUpdateRelease, name string) (string, error) {
	for _, asset := range release.Assets {
		if asset.Name == name && asset.BrowserDownloadURL != "" {
			return asset.BrowserDownloadURL, nil
		}
	}
	return "", fmt.Errorf("release %s does not contain required asset %s", release.TagName, name)
}

func fetchUpdateBytes(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "clearcutt-update/"+Version)
	parsedURL, _ := neturl.Parse(url)
	host := strings.ToLower(parsedURL.Hostname())
	githubHost := host == "github.com" || host == "api.github.com" || strings.HasSuffix(host, ".github.com")
	if token := firstNonEmptyString(os.Getenv("GH_TOKEN"), os.Getenv("GITHUB_TOKEN")); token != "" && githubHost {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := updateHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s returned %s", url, resp.Status)
	}
	limited := io.LimitReader(resp.Body, maxUpdateAssetBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxUpdateAssetBytes {
		return nil, fmt.Errorf("download from %s exceeds %d bytes", url, maxUpdateAssetBytes)
	}
	return raw, nil
}

func downloadUpdateAsset(ctx context.Context, url, path string) error {
	raw, err := fetchUpdateBytes(ctx, url)
	if err != nil {
		return fmt.Errorf("download %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func verifyUpdateChecksum(binaryPath, manifestPath, assetName string) error {
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	expected := ""
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == assetName {
			expected = strings.ToLower(fields[0])
			break
		}
	}
	if len(expected) != sha256.Size*2 {
		return fmt.Errorf("SHA256SUMS.txt does not contain a valid checksum for %s", assetName)
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return fmt.Errorf("SHA256SUMS.txt contains an invalid checksum for %s", assetName)
	}
	raw, err := os.ReadFile(binaryPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("checksum mismatch for %s: got %s, expected %s", assetName, actual, expected)
	}
	return nil
}

func updateTargetPath(explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		path, err := filepath.Abs(explicit)
		if err != nil {
			return "", err
		}
		return path, nil
	}
	path, err := updateExecutable()
	if err != nil {
		return "", fmt.Errorf("resolve running executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return filepath.Abs(path)
}

func updateTargetMode(target string) os.FileMode {
	if info, err := os.Stat(target); err == nil {
		return info.Mode().Perm() | 0o111
	}
	return 0o755
}

func replaceUpdateTarget(staged, target string) error {
	backup := target + ".clearcutt-update-backup"
	hadTarget := false
	if _, err := os.Stat(target); err == nil {
		hadTarget = true
		_ = os.Remove(backup)
		if err := os.Rename(target, backup); err != nil {
			return fmt.Errorf("stage existing CLI for replacement: %w", err)
		}
	}
	if err := os.Rename(staged, target); err != nil {
		if hadTarget {
			_ = os.Rename(backup, target)
		}
		return fmt.Errorf("install verified CLI: %w", err)
	}
	if hadTarget {
		_ = os.Remove(backup)
	}
	return nil
}

func normalizeUpdateVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" || version == "latest" {
		return version
	}
	if !strings.HasPrefix(version, "v") {
		return "v" + version
	}
	return version
}

func printUpdateResult(result updateResult) error {
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, result)
	case "yaml", "yml":
		return output.PrintYAML(out, result)
	default:
		if result.Status == "updated" {
			fmt.Fprintf(out, "updated ClearCutt %s to %s (checksum and Sigstore identity verified)\n", result.TargetVersion, result.Output)
		} else if result.Status == "current" {
			fmt.Fprintf(out, "ClearCutt %s is already installed\n", result.CurrentVersion)
		} else {
			fmt.Fprintf(out, "ClearCutt %s is available (current: %s, asset: %s)\n", result.TargetVersion, result.CurrentVersion, result.Asset)
		}
		return nil
	}
}
