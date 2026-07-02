package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt/internal/platformsource"
)

const cliAssetsManifestName = "clearcutt-cli-assets.json"

type cliAssetTarget struct {
	GOOS   string
	GOARCH string
	Name   string
}

type cliAssetManifest struct {
	SchemaVersion    string                 `json:"schemaVersion"`
	VersionTag       string                 `json:"versionTag"`
	SourceDir        string                 `json:"sourceDir"`
	ChecksumManifest string                 `json:"checksumManifest"`
	Assets           []cliAssetManifestFile `json:"assets"`
}

type cliAssetManifestFile struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	GOOS      string `json:"goos,omitempty"`
	GOARCH    string `json:"goarch,omitempty"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature,omitempty"`
}

func runFleetBuildCLIAssets() error {
	versionTag, err := normalizeCLIAssetVersionTag(fleetOpts.versionTag)
	if err != nil {
		return err
	}
	sourceDir, err := resolveCLIAssetSourceDir(fleetOpts.cliSourceDir)
	if err != nil {
		return err
	}
	// Regenerate the embedded platform source archive before compiling so a
	// released binary can never ship a stale (or missing) scaffold archive.
	repoRoot, ok := platformsource.FindRepoRoot(sourceDir)
	if !ok {
		return fmt.Errorf("cannot regenerate the embedded platform source archive: no repo root (clearcutt.fleet.yaml + go.work) above %s", sourceDir)
	}
	archivePath, err := platformsource.WriteArchive(repoRoot)
	if err != nil {
		return fmt.Errorf("regenerate embedded platform source archive: %w", err)
	}
	fmt.Fprintf(out, "[fleet] regenerated embedded platform source archive (%s)\n", archivePath)
	outputDir := strings.TrimSpace(fleetOpts.buildOutputsDir)
	if outputDir == "" {
		outputDir = "build-outputs"
	}
	outputDir, err = filepath.Abs(outputDir)
	if err != nil {
		return fmt.Errorf("resolve build output directory: %w", err)
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create build output directory: %w", err)
	}

	targets := defaultCLIAssetTargets()
	manifest := cliAssetManifest{
		SchemaVersion:    "clearcutt.cli-assets.v1",
		VersionTag:       versionTag,
		SourceDir:        sourceDir,
		ChecksumManifest: "SHA256SUMS.txt",
		Assets:           []cliAssetManifestFile{},
	}
	binaryPaths := make([]string, 0, len(targets))
	for _, target := range targets {
		path := filepath.Join(outputDir, target.Name)
		if err := buildCLIAsset(sourceDir, versionTag, target, path); err != nil {
			return err
		}
		sum, err := cliAssetFileSHA256(path)
		if err != nil {
			return err
		}
		binaryPaths = append(binaryPaths, path)
		manifest.Assets = append(manifest.Assets, cliAssetManifestFile{
			Name:   target.Name,
			Kind:   "binary",
			GOOS:   target.GOOS,
			GOARCH: target.GOARCH,
			SHA256: sum,
		})
	}

	signaturePaths := []string{}
	if fleetOpts.signCLIAssets {
		cosignBin := strings.TrimSpace(fleetOpts.cosignBin)
		if cosignBin == "" {
			cosignBin = "cosign"
		}
		for i, path := range binaryPaths {
			sigPath := path + ".sig"
			if err := signCLIAsset(cosignBin, path, sigPath); err != nil {
				return err
			}
			sum, err := cliAssetFileSHA256(sigPath)
			if err != nil {
				return err
			}
			signaturePaths = append(signaturePaths, sigPath)
			manifest.Assets[i].Signature = filepath.Base(sigPath)
			manifest.Assets = append(manifest.Assets, cliAssetManifestFile{
				Name:   filepath.Base(sigPath),
				Kind:   "signature",
				SHA256: sum,
			})
		}
	}

	manifestPath := filepath.Join(outputDir, cliAssetsManifestName)
	if err := writeCLIAssetsManifest(manifestPath, manifest); err != nil {
		return err
	}

	checksumInputs := append([]string{}, binaryPaths...)
	checksumInputs = append(checksumInputs, signaturePaths...)
	checksumInputs = append(checksumInputs, manifestPath)
	checksumPath := filepath.Join(outputDir, "SHA256SUMS.txt")
	if err := writeSHA256Sums(checksumPath, checksumInputs); err != nil {
		return err
	}
	if fleetOpts.githubOutputPath != "" {
		if err := appendGitHubOutputs(fleetOpts.githubOutputPath, map[string]string{
			"cli_assets_checksum": filepath.ToSlash(checksumPath),
			"cli_assets_count":    fmt.Sprintf("%d", len(checksumInputs)),
			"cli_assets_manifest": filepath.ToSlash(manifestPath),
		}); err != nil {
			return err
		}
	}

	fmt.Fprintf(out, "[fleet] built %d CLI binaries for %s under %s\n", len(binaryPaths), versionTag, outputDir)
	if fleetOpts.signCLIAssets {
		fmt.Fprintf(out, "[fleet] signed %d CLI binaries with cosign sign-blob\n", len(binaryPaths))
	}
	fmt.Fprintf(out, "[fleet] wrote %s and %s\n", filepath.Base(manifestPath), filepath.Base(checksumPath))
	return nil
}

func normalizeCLIAssetVersionTag(raw string) (string, error) {
	tag := strings.TrimSpace(raw)
	if tag == "" {
		return "", fmt.Errorf("--version-tag is required")
	}
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	return tag, nil
}

func resolveCLIAssetSourceDir(raw string) (string, error) {
	sourceDir := strings.TrimSpace(raw)
	if sourceDir == "" {
		sourceDir = "cli"
	}
	candidates := []string{sourceDir}
	if sourceDir == "cli" {
		candidates = append(candidates, ".")
	}
	for _, candidate := range candidates {
		abs, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if nonEmptyFile(filepath.Join(abs, "go.mod")) && pathExists(filepath.Join(abs, "cmd", "clearcutt")) {
			return abs, nil
		}
	}
	return "", fmt.Errorf("--source-dir must point to the ClearCutt CLI Go module containing go.mod and cmd/clearcutt")
}

func defaultCLIAssetTargets() []cliAssetTarget {
	return []cliAssetTarget{
		{GOOS: "darwin", GOARCH: "amd64", Name: "clearcutt-darwin-amd64"},
		{GOOS: "darwin", GOARCH: "arm64", Name: "clearcutt-darwin-arm64"},
		{GOOS: "linux", GOARCH: "amd64", Name: "clearcutt-linux-amd64"},
		{GOOS: "linux", GOARCH: "arm64", Name: "clearcutt-linux-arm64"},
		{GOOS: "windows", GOARCH: "amd64", Name: "clearcutt-windows-amd64.exe"},
		{GOOS: "windows", GOARCH: "arm64", Name: "clearcutt-windows-arm64.exe"},
	}
}

func buildCLIAsset(sourceDir, versionTag string, target cliAssetTarget, outputPath string) error {
	fmt.Fprintf(out, "[fleet] compiling %s (%s/%s)\n", target.Name, target.GOOS, target.GOARCH)
	return runExternalCommand(externalCommand{
		Name: "go",
		Args: []string{
			"build",
			"-ldflags", "-s -w -X github.com/northcutted/clearcutt/internal/commands.Version=" + versionTag,
			"-o", outputPath,
			"./cmd/clearcutt",
		},
		Dir: sourceDir,
		Env: []string{
			"CGO_ENABLED=0",
			"GOOS=" + target.GOOS,
			"GOARCH=" + target.GOARCH,
		},
	})
}

func signCLIAsset(cosignBin, assetPath, bundlePath string) error {
	fmt.Fprintf(out, "[fleet] keylessly signing %s\n", filepath.Base(assetPath))
	return runExternalCommand(externalCommand{
		Name: cosignBin,
		Args: []string{
			"sign-blob",
			"--yes",
			assetPath,
			"--bundle",
			bundlePath,
		},
	})
}

func writeCLIAssetsManifest(path string, manifest cliAssetManifest) error {
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o644)
}

func writeSHA256Sums(path string, inputs []string) error {
	names := append([]string{}, inputs...)
	sort.Slice(names, func(i, j int) bool {
		return filepath.Base(names[i]) < filepath.Base(names[j])
	})
	var b strings.Builder
	for _, input := range names {
		sum, err := cliAssetFileSHA256(input)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s  %s\n", sum, filepath.Base(input))
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func cliAssetFileSHA256(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
