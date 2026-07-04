package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/northcutted/clearcutt/internal/build"
	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/oci"
	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
)

type fleetFlags struct {
	configPath          string
	coreDir             string
	buildOutputsDir     string
	system              string
	language            string
	tier                string
	versionTag          string
	githubOutputPath    string
	workflowIdentity    string
	sourceRef           string
	sourceBranch        string
	provenanceRef       string
	cliSourceDir        string
	cosignBin           string
	archiveReleaseNotes bool
	checkOnly           bool
	allowPreview        bool
	signCLIAssets       bool
	engine              string
}

type externalCommand struct {
	Name string
	Args []string
	Dir  string
	Env  []string
}

var (
	fleetOpts                     fleetFlags
	runExternalCommand            = runExternalCommandDefault
	captureExternalOutput         = captureExternalCommandDefault
	releaseAssetUploadMaxAttempts = 5
	releaseAssetUploadRetryDelay  = 30 * time.Second
	releaseAssetUploadThrottle    = time.Second
	releaseAssetUploadSleep       = time.Sleep
)

func NewFleetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fleet",
		Short: "Run the config-driven fleet release pipeline",
		Long: `Runs the whitelabel fleet release mechanics from clearcutt.fleet.yaml.
GitHub Actions provides OIDC identity and artifact transport; this command group
owns target naming, single-arch publication, optional Nix cache publication,
multi-arch assembly, cosign evidence, digest aggregation, provenance export, and
GitHub Release finalization.`,
	}

	certifyTargetCmd := &cobra.Command{
		Use:   "certify-target",
		Short: "Build and gate one single-architecture fleet target without publishing",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFleetCertifyTarget()
		},
	}
	addFleetTargetFlags(certifyTargetCmd)
	certifyTargetCmd.Flags().StringVar(&fleetOpts.engine, "engine", "go", "Build engine: 'go' (native in-process gates) or 'shell' (legacy pipeline.sh fallback)")

	publishTargetCmd := &cobra.Command{
		Use:   "publish-target",
		Short: "Build, gate, and publish one single-architecture fleet target",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFleetPublishTarget()
		},
	}
	addFleetTargetFlags(publishTargetCmd)
	publishTargetCmd.Flags().StringVar(&fleetOpts.engine, "engine", "go", "Build engine: 'go' (native in-process gates plus go-containerregistry publish) or 'shell' (legacy pipeline.sh fallback)")
	publishTargetCmd.Flags().StringVar(&fleetOpts.versionTag, "version-tag", "", "Release version tag, for example v1.2.3")

	publishCacheCmd := &cobra.Command{
		Use:   "publish-cache",
		Short: "Publish one certified Nix derivation to the configured optional binary cache",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFleetPublishCache()
		},
	}
	addFleetCommonFlags(publishCacheCmd)
	publishCacheCmd.Flags().StringVar(&fleetOpts.system, "system", "", "Nix system to cache, for example x86_64-linux (required)")
	publishCacheCmd.Flags().StringVar(&fleetOpts.language, "language", "", "Fleet language/runtime target, for example node24 (required)")
	publishCacheCmd.Flags().StringVar(&fleetOpts.tier, "tier", "", "Fleet tier: dev, slim, or distroless (required)")
	_ = publishCacheCmd.MarkFlagRequired("system")
	_ = publishCacheCmd.MarkFlagRequired("language")
	_ = publishCacheCmd.MarkFlagRequired("tier")

	seedCachePlanCmd := &cobra.Command{
		Use:   "seed-cache-plan",
		Short: "Plan which fleet cells still need Nix cache seeding",
		Long: `Dry-runs each configured release matrix cell against the Nix backend and
emits only the cells that would still build. This owns the seed-cache workflow's
analyze phase: no compilation, no cache writes, and no partial matrix output if
any cell fails to evaluate.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFleetSeedCachePlan()
		},
	}
	seedCachePlanCmd.Flags().StringVar(&fleetOpts.configPath, "fleet-config", fleet.DefaultConfigPath, "Path to clearcutt fleet config")
	seedCachePlanCmd.Flags().StringVar(&fleetOpts.coreDir, "core-dir", "core", "Path to the Nix fleet core directory")
	seedCachePlanCmd.Flags().StringVar(&fleetOpts.githubOutputPath, "github-output", "", "Optional GITHUB_OUTPUT file to append seed_matrix=<json> and has_work=<bool> to")

	assembleCmd := &cobra.Command{
		Use:   "assemble-target",
		Short: "Assemble, sign, attest, and digest one multi-architecture image target",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFleetAssembleTarget()
		},
	}
	addFleetCommonFlags(assembleCmd)
	assembleCmd.Flags().StringVar(&fleetOpts.language, "language", "", "Fleet language/runtime target, for example node24 (required)")
	assembleCmd.Flags().StringVar(&fleetOpts.tier, "tier", "", "Fleet tier: dev, slim, or distroless (required)")
	assembleCmd.Flags().StringVar(&fleetOpts.versionTag, "version-tag", "", "Release version tag, for example v1.2.3 (required)")
	assembleCmd.Flags().StringVar(&fleetOpts.githubOutputPath, "github-output", "", "Optional GITHUB_OUTPUT file to append image=<ref> and digest=<sha256> to")
	_ = assembleCmd.MarkFlagRequired("language")
	_ = assembleCmd.MarkFlagRequired("tier")
	_ = assembleCmd.MarkFlagRequired("version-tag")

	aggregateCmd := &cobra.Command{
		Use:   "aggregate-digests",
		Short: "Aggregate per-target digest manifests into a release matrix",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFleetAggregateDigests()
		},
	}
	addFleetCommonFlags(aggregateCmd)
	aggregateCmd.Flags().StringVar(&fleetOpts.githubOutputPath, "github-output", "", "Optional GITHUB_OUTPUT file to append matrix=<json> to")

	workflowMatricesCmd := &cobra.Command{
		Use:   "workflow-matrices",
		Short: "Export fleet and service matrices for GitHub Actions workflows",
		Long: `Exports every matrix shape used by the release and PR-gate workflows in one
CLI-owned step. Use --github-output in GitHub Actions to append release_matrix,
image_matrix, service_release_matrix, and service_image_matrix outputs.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFleetWorkflowMatrices()
		},
	}
	workflowMatricesCmd.Flags().StringVar(&fleetOpts.configPath, "fleet-config", fleet.DefaultConfigPath, "Path to clearcutt fleet config")
	workflowMatricesCmd.Flags().StringVar(&fleetOpts.githubOutputPath, "github-output", "", "Optional GITHUB_OUTPUT file to append workflow matrix JSON outputs")

	buildCLIAssetsCmd := &cobra.Command{
		Use:   "build-cli-assets",
		Short: "Build, optionally sign, and checksum release CLI binaries",
		Long: `Builds the ClearCutt CLI release asset matrix from the checked-out Go
module, signs each binary with cosign when --sign is set, writes a
clearcutt-cli-assets.json manifest, and emits SHA256SUMS.txt for installer
verification. GitHub Actions still provides OIDC identity; the CLI owns the
asset matrix and deterministic release packaging mechanics.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolveRepoRootDefault(cmd, "source-dir", &fleetOpts.cliSourceDir)
			return runFleetBuildCLIAssets()
		},
	}
	buildCLIAssetsCmd.Flags().StringVar(&fleetOpts.versionTag, "version-tag", "", "Release version tag, for example v1.2.3 (required)")
	buildCLIAssetsCmd.Flags().StringVar(&fleetOpts.cliSourceDir, "source-dir", "cli", "Path to the ClearCutt CLI Go module")
	buildCLIAssetsCmd.Flags().StringVar(&fleetOpts.buildOutputsDir, "build-outputs", "build-outputs", "Directory for release CLI assets")
	buildCLIAssetsCmd.Flags().BoolVar(&fleetOpts.signCLIAssets, "sign", false, "Keylessly sign each binary with cosign sign-blob")
	buildCLIAssetsCmd.Flags().StringVar(&fleetOpts.cosignBin, "cosign-bin", "cosign", "Cosign executable to use when --sign is set")
	buildCLIAssetsCmd.Flags().StringVar(&fleetOpts.githubOutputPath, "github-output", "", "Optional GITHUB_OUTPUT file to append cli_assets_manifest, cli_assets_checksum, and cli_assets_count")
	_ = buildCLIAssetsCmd.MarkFlagRequired("version-tag")

	exportCmd := &cobra.Command{
		Use:   "export-provenance",
		Short: "Export SLSA provenance from OCI attestations as a release asset",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFleetExportProvenance()
		},
	}
	addFleetCommonFlags(exportCmd)
	exportCmd.Flags().StringVar(&fleetOpts.language, "language", "", "Fleet language/runtime target, for example node24 (required)")
	exportCmd.Flags().StringVar(&fleetOpts.tier, "tier", "", "Fleet tier: dev, slim, or distroless (required)")
	exportCmd.Flags().StringVar(&fleetOpts.provenanceRef, "ref", "", "Image reference to export provenance from; prefer immutable image@sha256:... refs")
	_ = exportCmd.MarkFlagRequired("language")
	_ = exportCmd.MarkFlagRequired("tier")

	verifyCmd := &cobra.Command{
		Use:   "verify-target",
		Short: "Verify one released target using fleet-configured identity defaults",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFleetVerifyTarget()
		},
	}
	addFleetCommonFlags(verifyCmd)
	verifyCmd.Flags().StringVar(&releaseEvidenceOpts.ref, "ref", "", "Image reference to verify (required)")
	verifyCmd.Flags().StringVar(&releaseEvidenceOpts.digest, "digest", "", "Expected image digest (sha256:...), matched against the resolved digest")
	verifyCmd.Flags().StringVar(&fleetOpts.workflowIdentity, "workflow-identity", "", "Exact Sigstore certificate identity override")
	verifyCmd.Flags().StringVar(&fleetOpts.sourceRef, "source-ref", "", "Source ref for GitHub-native provenance verification")
	verifyCmd.Flags().StringVar(&fleetOpts.sourceBranch, "source-branch", "", "Source branch for slsa-verifier")
	verifyCmd.Flags().StringVar(&releaseEvidenceOpts.outPath, "out", "", "Write the machine-readable verification checklist to this JSON file")
	_ = verifyCmd.MarkFlagRequired("ref")

	finalizeCmd := &cobra.Command{
		Use:   "finalize-release",
		Short: "Create or update the GitHub Release, upload assets, and publish notes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFleetFinalizeRelease()
		},
	}
	addFleetCommonFlags(finalizeCmd)
	finalizeCmd.Flags().StringVar(&fleetOpts.versionTag, "version-tag", "", "Release version tag, for example v1.2.3 (required)")
	finalizeCmd.Flags().BoolVar(&fleetOpts.archiveReleaseNotes, "archive-release-notes", false, "Commit published release notes to docs/releases/<tag>.md on the source branch when possible")
	_ = finalizeCmd.MarkFlagRequired("version-tag")

	compileCmd := &cobra.Command{
		Use:   "compile",
		Short: "Compile clearcutt.fleet.yaml into the generated core/lib/fleet-matrix.nix build set",
		Long: `Resolves matrix.languages × matrix.tiers from clearcutt.fleet.yaml into the
concrete (language, version, tier) image cells, stamps each with its lifecycle
from the shared version policy, derives the realized-closure gate targets, and
writes the result to core/lib/fleet-matrix.nix.

The file is generated data, not logic: the hardened per-runtime recipes stay in
lib/registry.nix. Use --check in CI to fail when the committed file has drifted
from the fleet config without writing anything.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolveRepoRootDefault(cmd, "fleet-config", &fleetOpts.configPath)
			resolveRepoRootDefault(cmd, "core-dir", &fleetOpts.coreDir)
			return runFleetCompile()
		},
	}
	compileCmd.Flags().StringVar(&fleetOpts.configPath, "fleet-config", fleet.DefaultConfigPath, "Path to clearcutt fleet config")
	compileCmd.Flags().StringVar(&fleetOpts.coreDir, "core-dir", "core", "Path to the Nix fleet core directory")
	compileCmd.Flags().BoolVar(&fleetOpts.checkOnly, "check", false, "Verify core/lib/fleet-matrix.nix is up to date without writing; exit non-zero on drift")
	compileCmd.Flags().BoolVar(&fleetOpts.allowPreview, "allow-preview", false, "Union preview-channel runtimes into the matrix (language-level matrix.languages only)")

	cmd.AddCommand(certifyTargetCmd, publishTargetCmd, publishCacheCmd, seedCachePlanCmd, assembleCmd, aggregateCmd, workflowMatricesCmd, buildCLIAssetsCmd, exportCmd, verifyCmd, finalizeCmd, compileCmd)
	return cmd
}

func fleetMatrixPath(coreDir string) string {
	return filepath.Join(coreDir, "lib", "fleet-matrix.nix")
}

func runFleetCompile() error {
	cfg, err := fleet.Load(fleetOpts.configPath)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	matrix, err := cfg.CompileMatrix(fleetOpts.allowPreview)
	if err != nil {
		return fmt.Errorf("compile fleet matrix: %w", err)
	}
	rendered := fleet.RenderMatrixNix(matrix)
	path := fleetMatrixPath(fleetOpts.coreDir)

	if fleetOpts.checkOnly {
		existing, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w (run `clearcutt fleet compile` to generate it)", path, err)
		}
		if string(existing) != rendered {
			return fmt.Errorf("%s is out of date; run `clearcutt fleet compile` to regenerate it", path)
		}
		if !GlobalOpts.Quiet {
			fmt.Fprintf(out, "%s is up to date (%d cells)\n", path, len(matrix.Cells))
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create fleet matrix directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(rendered), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if !GlobalOpts.Quiet {
		fmt.Fprintf(out, "wrote %s (%d cells)\n", path, len(matrix.Cells))
	}
	return nil
}

func addFleetCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&fleetOpts.configPath, "fleet-config", fleet.DefaultConfigPath, "Path to clearcutt fleet config")
	cmd.Flags().StringVar(&fleetOpts.coreDir, "core-dir", "core", "Path to the Nix fleet core directory")
	cmd.Flags().StringVar(&fleetOpts.buildOutputsDir, "build-outputs", "build-outputs", "Path to release build outputs")
}

func addFleetTargetFlags(cmd *cobra.Command) {
	addFleetCommonFlags(cmd)
	cmd.Flags().StringVar(&fleetOpts.system, "system", "", "Nix system to build, for example x86_64-linux (required)")
	cmd.Flags().StringVar(&fleetOpts.language, "language", "", "Fleet language/runtime target, for example node24 (required)")
	cmd.Flags().StringVar(&fleetOpts.tier, "tier", "", "Fleet tier: dev, slim, or distroless (required)")
	_ = cmd.MarkFlagRequired("system")
	_ = cmd.MarkFlagRequired("language")
	_ = cmd.MarkFlagRequired("tier")
}

func runFleetCertifyTarget() error {
	return runFleetTarget(false)
}

func runFleetPublishTarget() error {
	if err := runFleetTarget(true); err != nil {
		return err
	}
	target := fleetTarget(fleetOpts.language, fleetOpts.tier)
	return stageArchReleaseAssets(resolveBuildOutputsDir(fleetOpts.coreDir, fleetOpts.buildOutputsDir), target, archSuffixForSystem(fleetOpts.system))
}

func normalizeBuildEngine(engine string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(engine))
	if normalized == "" {
		normalized = "go"
	}
	switch normalized {
	case "go", "shell":
		return normalized, nil
	default:
		return "", fmt.Errorf("--engine must be go or shell")
	}
}

func runFleetTarget(publish bool) error {
	cfg, err := fleet.Load(fleetOpts.configPath)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	target := fleetTarget(fleetOpts.language, fleetOpts.tier)
	coreDir := fleetOpts.coreDir

	engine, err := normalizeBuildEngine(fleetOpts.engine)
	if err != nil {
		return err
	}
	// Native-Go build engine: runs the build + in-process boundary gates instead
	// of shelling into pipeline.sh. The publish path pushes the staging image
	// through the in-process OCI client, so no shell script owns the target mechanics.
	if engine == "go" {
		if publish {
			return runFleetPublishTargetGo(cfg, target, coreDir)
		}
		return runFleetCertifyTargetGo(target, coreDir)
	}
	args := []string{
		"develop",
		"--extra-experimental-features", "nix-command flakes",
		"--accept-flake-config",
	}
	args = append(args, nixClientOptionArgs(cfg)...)
	args = append(args,
		"--command", "./pipeline/pipeline.sh",
		"--system", fleetOpts.system,
		"--registry", cfg.Registry.Host,
		"--repo", strings.ToLower(cfg.RepoPath()),
	)
	if publish {
		args = append(args, "--publish")
	} else {
		args = append(args, "--skip-local-signing")
	}
	if strings.TrimSpace(fleetOpts.versionTag) != "" {
		args = append(args, "--version-tag", fleetOpts.versionTag)
	}
	args = append(args, target)
	if err := runExternalCommand(externalCommand{
		Name: "nix",
		Args: args,
		Dir:  coreDir,
		Env: []string{
			"CLEARCUTT_IMAGE_PREFIX=" + cfg.Registry.ImagePrefix,
			"GITHUB_REF_NAME=" + strings.TrimSpace(fleetOpts.versionTag),
		},
	}); err != nil {
		return err
	}
	return nil
}

var fleetBuildRunner = func() build.Runner {
	return build.NixToolRunner{
		Runner: build.ExecRunner{Stdout: out, Stderr: errOut},
	}
}

var fleetOCIClient = func() *oci.Client {
	user, token := registryDestCredentialPair()
	if strings.TrimSpace(user) != "" && strings.TrimSpace(token) != "" {
		return oci.NewClientWithBasicAuth(user, token)
	}
	return oci.NewClient()
}

var fleetPushImageArchive = func(client *oci.Client, ref, archivePath string) (string, error) {
	return client.PushImageArchive(ref, archivePath)
}

var fleetPushImageIndex = func(client *oci.Client, ref string, sources []oci.IndexImage) (string, error) {
	return client.PushImageIndex(ref, sources)
}

// runFleetCertifyTargetGo runs the certify path through the native-Go build
// engine: nix build + Syft/Grype + the in-process closure-purity and runtime-cve
// gates, emitting the same test-results predicate pipeline.sh produces.
func runFleetCertifyTargetGo(target, coreDir string) error {
	outDir := resolveBuildOutputsDir(coreDir, fleetOpts.buildOutputsDir)
	opts := build.Options{
		Target:        target,
		System:        fleetOpts.system,
		Kind:          "runtime",
		CoreDir:       coreDir,
		OutputDir:     outDir,
		AllowlistPath: filepath.Join(coreDir, "tests", "closure-purity-allowlist.txt"),
		FloorPath:     filepath.Join(coreDir, "tests", "runtime-dep-floor.json"),
	}
	runner := fleetBuildRunner()
	if _, err := build.CertifyTarget(runner, opts, time.Now(), out); err != nil {
		return err
	}
	return nil
}

func runFleetPublishTargetGo(cfg fleet.Config, target, coreDir string) error {
	outDir := resolveBuildOutputsDir(coreDir, fleetOpts.buildOutputsDir)
	opts := build.Options{
		Target:        target,
		System:        fleetOpts.system,
		Kind:          "runtime",
		CoreDir:       coreDir,
		OutputDir:     outDir,
		AllowlistPath: filepath.Join(coreDir, "tests", "closure-purity-allowlist.txt"),
		FloorPath:     filepath.Join(coreDir, "tests", "runtime-dep-floor.json"),
	}
	runner := fleetBuildRunner()
	if _, err := build.CertifyTarget(runner, opts, time.Now(), out); err != nil {
		return err
	}
	tarPath := filepath.Join(outDir, target+".tar.gz")
	stageTag := fleetStageTag(cfg, fleetOpts.language, fleetOpts.tier, fleetOpts.system)
	fmt.Fprintf(out, "[fleet] publishing per-arch staging image with Go engine -> %s\n", stageTag)
	digest, err := fleetPushImageArchive(fleetOCIClient(), stageTag, tarPath)
	if err != nil {
		return fmt.Errorf("OCI per-arch staging push failed for %s: %w", target, err)
	}
	if digest != "" {
		fmt.Fprintf(out, "[fleet] pushed staging manifest digest %s\n", digest)
	}
	return nil
}

func fleetStageTag(cfg fleet.Config, language, tier, system string) string {
	arch := archSuffixForSystem(system)
	return fmt.Sprintf("%s:%s", cfg.ImageName(language), "_stage-"+tier+"-"+arch)
}

func registryDestCredentialPair() (string, string) {
	user := firstNonEmptyString(os.Getenv("REGISTRY_USER"), os.Getenv("CLEARCUTT_REGISTRY_USER"), os.Getenv("GITHUB_ACTOR"))
	token := firstNonEmptyString(os.Getenv("REGISTRY_TOKEN"), os.Getenv("CLEARCUTT_REGISTRY_TOKEN"), os.Getenv("GITHUB_TOKEN"))
	return user, token
}

func runFleetPublishCache() error {
	cfg, err := fleet.Load(fleetOpts.configPath)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	cache := cfg.Release.NixCache
	if cache.Bucket == "" || cache.PublicBaseURL == "" || cache.SigningKeyName == "" {
		fmt.Fprintln(out, "[fleet] skipping optional Nix binary-cache publish; configure release.nixCache.bucket, publicBaseUrl, and signingKeyName to enable it")
		return nil
	}
	requiredEnv := []string{"NIX_CACHE_SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "CLOUDFLARE_ACCOUNT_ID"}
	for _, name := range requiredEnv {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			fmt.Fprintf(out, "[fleet] skipping optional Nix binary-cache publish; %s is not set\n", name)
			return nil
		}
	}

	secretDir, err := os.MkdirTemp("", "clearcutt-nix-cache-key-")
	if err != nil {
		return fmt.Errorf("create Nix cache signing key temp dir: %w", err)
	}
	defer os.RemoveAll(secretDir)
	secretPath := filepath.Join(secretDir, "secret-key.pem")
	if err := os.WriteFile(secretPath, []byte(os.Getenv("NIX_CACHE_SECRET_KEY")+"\n"), 0o600); err != nil {
		return fmt.Errorf("write Nix cache signing key: %w", err)
	}

	installable := fmt.Sprintf(`.#packages.%s."%s"`, fleetOpts.system, fleetTarget(fleetOpts.language, fleetOpts.tier))
	pathInfoArgs := append([]string{
		"path-info",
		"--extra-experimental-features", "nix-command flakes",
		"--accept-flake-config",
	}, nixClientOptionArgs(cfg)...)
	pathInfoArgs = append(pathInfoArgs, installable)
	outPathRaw, err := captureExternalOutput(externalCommand{
		Name: "nix",
		Args: pathInfoArgs,
		Dir:  fleetOpts.coreDir,
	})
	if err != nil {
		return err
	}
	outPath := strings.TrimSpace(outPathRaw)
	if outPath == "" {
		return fmt.Errorf("nix path-info returned an empty output path for %s", installable)
	}
	storeHash := pathBaseHash(outPath)
	narinfoKey := storeHash + ".narinfo"
	narinfoURL := strings.TrimRight(cache.PublicBaseURL, "/") + "/" + narinfoKey
	r2Endpoint := "https://" + os.Getenv("CLOUDFLARE_ACCOUNT_ID") + ".r2.cloudflarestorage.com"
	cacheStore := fmt.Sprintf("s3://%s?region=auto&endpoint=%s&secret-key=%s", cache.Bucket, r2Endpoint, secretPath)
	env := []string{
		"AWS_DEFAULT_REGION=auto",
		"AWS_EC2_METADATA_DISABLED=true",
	}

	if err := runExternalCommand(externalCommand{Name: "nix", Args: []string{"store", "sign", "--recursive", "--key-file", secretPath, outPath}, Dir: fleetOpts.coreDir}); err != nil {
		return err
	}
	_ = runExternalCommand(externalCommand{Name: "aws", Args: []string{"--endpoint-url", r2Endpoint, "s3", "rm", "s3://" + cache.Bucket + "/" + narinfoKey}, Dir: fleetOpts.coreDir, Env: env})
	copyArgs := append([]string{
		"copy", "--extra-experimental-features", "nix-command flakes", "--accept-flake-config", "--refresh",
		"--option", "narinfo-cache-positive-ttl", "0",
		"--option", "narinfo-cache-negative-ttl", "0",
	}, nixClientOptionArgs(cfg)...)
	copyArgs = append(copyArgs,
		"--to", cacheStore, outPath,
	)
	if err := runExternalCommand(externalCommand{
		Name: "nix",
		Args: copyArgs,
		Dir:  fleetOpts.coreDir,
	}); err != nil {
		return err
	}

	if err := waitForSignedNarinfo(r2Endpoint, cache.Bucket, narinfoKey, cache.SigningKeyName, env); err != nil {
		return err
	}
	purgeCloudflareCache(cache, narinfoURL)
	if err := waitForPublicNarinfo(narinfoURL, cache.SigningKeyName); err != nil {
		fmt.Fprintf(out, "[fleet] warning: %v\n", err)
	}
	return nil
}

func runFleetAssembleTarget() error {
	cfg, err := fleet.Load(fleetOpts.configPath)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	target := fleetTarget(fleetOpts.language, fleetOpts.tier)
	image := cfg.ImageName(fleetOpts.language)
	rolling := image + ":" + fleetOpts.tier
	versioned := image + ":" + fleetOpts.versionTag + "-" + fleetOpts.tier
	manifests := []oci.IndexImage{}
	for _, system := range cfg.Matrix.Systems {
		manifests = append(manifests, oci.IndexImage{
			Ref:          image + ":_stage-" + fleetOpts.tier + "-" + archSuffixForSystem(system),
			OS:           "linux",
			Architecture: ociArchitectureForSystem(system),
		})
	}
	if len(manifests) == 0 {
		return fmt.Errorf("fleet matrix has no systems")
	}

	client := fleetOCIClient()
	digest, err := fleetPushImageIndex(client, rolling, manifests)
	if err != nil {
		return fmt.Errorf("assemble rolling image index %s: %w", rolling, err)
	}
	if _, err := fleetPushImageIndex(client, versioned, manifests); err != nil {
		return fmt.Errorf("assemble versioned image index %s: %w", versioned, err)
	}
	if err := runCoreToolCommand(fleetOpts.coreDir, "cosign", "sign", "--yes", rolling); err != nil {
		return err
	}
	if err := runCoreToolCommand(fleetOpts.coreDir, "cosign", "sign", "--yes", versioned); err != nil {
		return err
	}
	for _, system := range cfg.Matrix.Systems {
		dir := filepath.Join(fleetOpts.buildOutputsDir, artifactSystemDir(system))
		if err := runCoreToolCommand(fleetOpts.coreDir, "cosign", "attest", "--yes", "--type", "spdxjson", "--predicate", absToolPath(filepath.Join(dir, target+".sbom.json")), rolling); err != nil {
			return err
		}
	}
	for _, system := range cfg.Matrix.Systems {
		dir := filepath.Join(fleetOpts.buildOutputsDir, artifactSystemDir(system))
		if err := runCoreToolCommand(fleetOpts.coreDir, "cosign", "attest", "--yes", "--type", "custom", "--predicate", absToolPath(filepath.Join(dir, target+".test-results.json")), rolling); err != nil {
			return err
		}
	}

	if digest == "" {
		return fmt.Errorf("OCI index push returned an empty digest for %s", rolling)
	}
	manifest := fleetDigestManifest{
		Image:        image,
		Digest:       digest,
		Language:     fleetOpts.language,
		Tier:         fleetOpts.tier,
		RollingTag:   fleetOpts.tier,
		VersionedTag: fleetOpts.versionTag + "-" + fleetOpts.tier,
	}
	digestDir := filepath.Join(fleetOpts.buildOutputsDir, "digests")
	if err := os.MkdirAll(digestDir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(digestDir, target+".digest.json")
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	if fleetOpts.githubOutputPath != "" {
		if err := appendGitHubOutputs(fleetOpts.githubOutputPath, map[string]string{
			"image":  image,
			"digest": digest,
		}); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "[fleet] digest manifest written: %s\n", path)
	return nil
}

func runFleetAggregateDigests() error {
	digests, err := readFleetDigestManifests(fleetOpts.buildOutputsDir)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(digests)
	if err != nil {
		return err
	}
	if fleetOpts.githubOutputPath != "" {
		fleetRaw, serviceRaw, err := splitFleetDigestMatrixOutputs(digests)
		if err != nil {
			return err
		}
		if err := appendGitHubOutputs(fleetOpts.githubOutputPath, map[string]string{"matrix": string(raw)}); err != nil {
			return err
		}
		if err := appendGitHubOutputs(fleetOpts.githubOutputPath, map[string]string{
			"fleet_matrix":   string(fleetRaw),
			"service_matrix": string(serviceRaw),
		}); err != nil {
			return err
		}
	}
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		_, err = fmt.Fprintln(out, string(raw))
		return err
	case "yaml", "yml":
		return output.PrintYAML(out, digests)
	default:
		tp := output.NewTablePrinter("IMAGE", "DIGEST", "LANGUAGE", "TIER")
		for _, digest := range digests {
			tp.AddRow(digest.Image, digest.Digest, digest.Language, digest.Tier)
		}
		return tp.Print(out)
	}
}

func runFleetExportProvenance() error {
	cfg, err := fleet.Load(fleetOpts.configPath)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	target := fleetTarget(fleetOpts.language, fleetOpts.tier)
	rolling := cfg.ImageName(fleetOpts.language) + ":" + fleetOpts.tier
	ref := firstNonEmptyString(fleetOpts.provenanceRef, rolling)
	if err := os.MkdirAll(fleetOpts.buildOutputsDir, 0o755); err != nil {
		return err
	}
	outputPath := filepath.Join(fleetOpts.buildOutputsDir, target+".intoto.jsonl")
	if err := downloadAttestation(outputPath, "https://slsa.dev/provenance/v1", ref, fleetOpts.coreDir); err != nil {
		return err
	}
	if !nonEmptyFile(outputPath) {
		if err := downloadAttestation(outputPath, "https://slsa.dev/provenance/v0.2", ref, fleetOpts.coreDir); err != nil {
			return err
		}
	}
	if nonEmptyFile(outputPath) {
		fmt.Fprintf(out, "[fleet] provenance exported: %s\n", outputPath)
	} else {
		fmt.Fprintf(out, "[fleet] warning: SLSA provenance could not be downloaded for %s\n", ref)
	}
	return nil
}

func runFleetVerifyTarget() error {
	cfg, err := fleet.Load(fleetOpts.configPath)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	releaseEvidenceOpts.repo = cfg.RepoPath()
	releaseEvidenceOpts.workflowIdentity = firstNonEmptyString(fleetOpts.workflowIdentity, cfg.Release.WorkflowIdentity)
	releaseEvidenceOpts.oidcIssuer = firstNonEmptyString(releaseEvidenceOpts.oidcIssuer, "https://token.actions.githubusercontent.com")
	releaseEvidenceOpts.sourceRef = firstNonEmptyString(fleetOpts.sourceRef, "refs/heads/"+cfg.Release.SourceBranch)
	releaseEvidenceOpts.sourceBranch = firstNonEmptyString(fleetOpts.sourceBranch, cfg.Release.SourceBranch)
	releaseEvidenceOpts.coreDir = fleetOpts.coreDir
	return runVerifyReleaseEvidence()
}

func runFleetFinalizeRelease() error {
	cfg, err := fleet.Load(fleetOpts.configPath)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	tag := fleetOpts.versionTag
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	if err := ensureGitHubRelease(tag, cfg); err != nil {
		return err
	}
	if err := uploadReleaseAssets(tag, fleetOpts.buildOutputsDir); err != nil {
		return err
	}
	notes, err := buildFleetReleaseNotes(tag, cfg)
	if err != nil {
		return err
	}
	notesPath := filepath.Join(os.TempDir(), "clearcutt-release-notes-"+strings.TrimPrefix(tag, "v")+".md")
	if err := os.WriteFile(notesPath, []byte(notes), 0o644); err != nil {
		return err
	}
	defer os.Remove(notesPath)
	if err := runExternalCommand(externalCommand{Name: "gh", Args: []string{"release", "edit", tag, "--notes-file", notesPath}}); err != nil {
		return err
	}
	if fleetOpts.archiveReleaseNotes {
		if err := archiveReleaseNotes(tag, notes, cfg); err != nil {
			fmt.Fprintf(out, "[fleet] warning: release notes archive skipped: %v\n", err)
		}
	}
	return nil
}

type fleetDigestManifest struct {
	Image        string `json:"image"`
	Digest       string `json:"digest"`
	Language     string `json:"language"`
	Tier         string `json:"tier"`
	RollingTag   string `json:"rollingTag"`
	VersionedTag string `json:"versionedTag"`
}

func runExternalCommandDefault(c externalCommand) error {
	cmd := exec.Command(c.Name, c.Args...)
	cmd.Dir = c.Dir
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stdout = out
	cmd.Stderr = errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", c.Name, err)
	}
	return nil
}

func captureExternalCommandDefault(c externalCommand) (string, error) {
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd := exec.Command(c.Name, c.Args...)
	cmd.Dir = c.Dir
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderrBuf.String())
		if detail != "" {
			fmt.Fprintln(errOut, detail)
		}
		return "", fmt.Errorf("%s failed: %w", c.Name, err)
	}
	return stdoutBuf.String(), nil
}

func fleetTarget(language, tier string) string {
	return language + "-" + tier
}

func archSuffixForSystem(system string) string {
	if strings.Contains(system, "aarch64") || strings.Contains(system, "arm64") {
		return "arm64"
	}
	return "amd64"
}

func ociArchitectureForSystem(system string) string {
	if strings.Contains(system, "aarch64") || strings.Contains(system, "arm64") {
		return "arm64"
	}
	return "amd64"
}

func artifactSystemDir(system string) string {
	if strings.Contains(system, "aarch64") || strings.Contains(system, "arm64") {
		return "aarch64"
	}
	return "x86_64"
}

func stageArchReleaseAssets(outputDir, target, suffix string) error {
	for _, ext := range []string{".sbom.json", ".test-results.json"} {
		src := filepath.Join(outputDir, target+ext)
		dst := filepath.Join(outputDir, target+"-"+suffix+ext)
		if err := copyFile(src, dst, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(out, "[fleet] staged release asset: %s\n", dst)
	}
	return nil
}

func pathBaseHash(outPath string) string {
	base := filepath.Base(outPath)
	if idx := strings.Index(base, "-"); idx > 0 {
		return base[:idx]
	}
	return base
}

func waitForSignedNarinfo(endpoint, bucket, key, signingKeyName string, env []string) error {
	want := "^Sig: " + signingKeyName + ":"
	for i := 0; i < 12; i++ {
		raw, err := captureExternalOutput(externalCommand{
			Name: "aws",
			Args: []string{"--endpoint-url", endpoint, "s3", "cp", "s3://" + bucket + "/" + key, "-"},
			Env:  env,
		})
		if err == nil && strings.Contains(raw, want[1:]) {
			fmt.Fprintf(out, "[fleet] verified signed cache narinfo: s3://%s/%s\n", bucket, key)
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("uploaded cache narinfo is missing %s signature: s3://%s/%s", signingKeyName, bucket, key)
}

func purgeCloudflareCache(cache fleet.NixCache, narinfoURL string) {
	token := strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN"))
	if token == "" {
		fmt.Fprintln(out, "[fleet] warning: CLOUDFLARE_API_TOKEN is not set; public edge cache may be stale")
		return
	}
	zoneID := strings.TrimSpace(os.Getenv("CLOUDFLARE_ZONE_ID"))
	if zoneID == "" && cache.CloudflareZoneName != "" {
		raw, err := captureExternalOutput(externalCommand{
			Name: "curl",
			Args: []string{"-fsSL", "-H", "Authorization: Bearer " + token, "https://api.cloudflare.com/client/v4/zones?name=" + cache.CloudflareZoneName},
		})
		if err == nil {
			zoneID = extractFirstCloudflareZoneID(raw)
		}
	}
	if zoneID == "" {
		fmt.Fprintln(out, "[fleet] warning: Cloudflare zone was not found; origin cache is signed")
		return
	}
	_ = runExternalCommand(externalCommand{
		Name: "curl",
		Args: []string{
			"-fsSL", "-X", "POST",
			"-H", "Authorization: Bearer " + token,
			"-H", "Content-Type: application/json",
			"https://api.cloudflare.com/client/v4/zones/" + zoneID + "/purge_cache",
			"--data", `{"files":["` + narinfoURL + `"]}`,
		},
	})
}

func extractFirstCloudflareZoneID(raw string) string {
	var parsed struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil || len(parsed.Result) == 0 {
		return ""
	}
	return parsed.Result[0].ID
}

func waitForPublicNarinfo(url, signingKeyName string) error {
	want := "Sig: " + signingKeyName + ":"
	for i := 0; i < 12; i++ {
		raw, err := captureExternalOutput(externalCommand{Name: "curl", Args: []string{"-fsSL", "-H", "Cache-Control: no-cache", url}})
		if err == nil && strings.Contains(raw, want) {
			fmt.Fprintf(out, "[fleet] verified signed public cache narinfo: %s\n", url)
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("public cache narinfo still does not expose %s signature: %s", signingKeyName, url)
}

func readFleetDigestManifests(dir string) ([]fleetDigestManifest, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var digests []fleetDigestManifest
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".digest.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var digest fleetDigestManifest
		if err := json.Unmarshal(raw, &digest); err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		digests = append(digests, digest)
	}
	sort.Slice(digests, func(i, j int) bool {
		if digests[i].Language == digests[j].Language {
			return digests[i].Tier < digests[j].Tier
		}
		return digests[i].Language < digests[j].Language
	})
	return digests, nil
}

func splitFleetDigestMatrixOutputs(digests []fleetDigestManifest) ([]byte, []byte, error) {
	fleetDigests := make([]fleetDigestManifest, 0, len(digests))
	serviceDigests := make([]fleetDigestManifest, 0)
	for _, digest := range digests {
		if digest.Tier == "service" {
			serviceDigests = append(serviceDigests, digest)
			continue
		}
		fleetDigests = append(fleetDigests, digest)
	}
	fleetRaw, err := json.Marshal(fleetDigests)
	if err != nil {
		return nil, nil, err
	}
	serviceRaw, err := json.Marshal(serviceDigests)
	if err != nil {
		return nil, nil, err
	}
	return fleetRaw, serviceRaw, nil
}

func runCoreToolCommand(coreDir, name string, args ...string) error {
	return runExternalCommand(externalCommand{Name: "nix", Args: build.NixDevelopCommand(name, args...), Dir: coreDir})
}

// absToolPath anchors a predicate/artifact path to an absolute path before it
// is handed to a core-pinned tool. runCoreToolCommand runs the tool through
// `nix develop` with cwd = coreDir, so a path relative to the CLI's own cwd
// (where the release workflow stages build-outputs) would otherwise resolve
// against coreDir and miss. Falls back to the input if Abs fails.
func absToolPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

func captureCoreToolOutput(coreDir, name string, args ...string) (string, error) {
	return captureExternalOutput(externalCommand{Name: "nix", Args: build.NixDevelopCommand(name, args...), Dir: coreDir})
}

func downloadAttestation(path, predicateType, ref, coreDir string) error {
	raw, err := captureCoreToolOutput(coreDir, "cosign", "download", "attestation", "--predicate-type", predicateType, ref)
	if err != nil {
		raw = ""
	}
	return os.WriteFile(path, []byte(raw), 0o644)
}

func nonEmptyFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}

func appendGitHubOutputs(path string, values map[string]string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := fmt.Fprintf(f, "%s=%s\n", key, values[key]); err != nil {
			return err
		}
	}
	return nil
}

func ensureGitHubRelease(tag string, cfg fleet.Config) error {
	if err := runExternalCommand(externalCommand{Name: "gh", Args: []string{"release", "view", tag}}); err == nil {
		fmt.Fprintf(out, "[fleet] release already exists: %s\n", tag)
		return nil
	}
	return runExternalCommand(externalCommand{Name: "gh", Args: []string{"release", "create", tag, "--title", "Release " + tag, "--generate-notes", "--target", cfg.Release.SourceBranch}})
}

func uploadReleaseAssets(tag, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	files := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if !nonEmptyFile(path) {
			continue
		}
		if isReleaseAsset(entry.Name()) {
			files = append(files, path)
		}
	}
	if len(files) == 0 {
		fmt.Fprintln(out, "[fleet] no non-empty release assets found")
		return nil
	}
	for i, file := range files {
		fmt.Fprintf(out, "[fleet] uploading release asset %d/%d: %s\n", i+1, len(files), filepath.Base(file))
		if err := uploadReleaseAssetWithRetry(tag, file); err != nil {
			return err
		}
		if i < len(files)-1 && releaseAssetUploadThrottle > 0 {
			releaseAssetUploadSleep(releaseAssetUploadThrottle)
		}
	}
	return nil
}

func uploadReleaseAssetWithRetry(tag, file string) error {
	var lastErr error
	for attempt := 1; attempt <= releaseAssetUploadMaxAttempts; attempt++ {
		args := []string{"release", "upload", tag, file, "--clobber"}
		if err := runExternalCommand(externalCommand{Name: "gh", Args: args}); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if attempt == releaseAssetUploadMaxAttempts {
			break
		}
		delay := releaseAssetUploadRetryDelay * time.Duration(attempt)
		fmt.Fprintf(errOut, "[fleet] release asset upload failed for %s (attempt %d/%d): %v; retrying in %s\n", filepath.Base(file), attempt, releaseAssetUploadMaxAttempts, lastErr, delay)
		if delay > 0 {
			releaseAssetUploadSleep(delay)
		}
	}
	return fmt.Errorf("upload release asset %s: %w", filepath.Base(file), lastErr)
}

func isReleaseAsset(name string) bool {
	return strings.HasSuffix(name, ".sbom.json") ||
		strings.HasSuffix(name, ".test-results.json") ||
		strings.HasSuffix(name, ".release-verification.json") ||
		strings.HasSuffix(name, ".intoto.jsonl") ||
		strings.HasSuffix(name, ".sig") ||
		strings.HasPrefix(name, "clearcutt-") ||
		name == "SHA256SUMS.txt"
}

func buildFleetReleaseNotes(tag string, cfg fleet.Config) (string, error) {
	rawChangelog, _ := captureExternalOutput(externalCommand{Name: "gh", Args: []string{"release", "view", tag, "--json", "body", "--jq", ".body"}})
	var b strings.Builder
	fmt.Fprintf(&b, "# %s Hardened Fleet Release %s\n\n", cfg.Branding.ProductName, tag)
	fmt.Fprintf(&b, "This release publishes the configured `%s` fleet under `%s` with Sigstore keyless signatures, SPDX SBOM attestations, SLSA Build L3 provenance, test-result attestations, and catalog-ready release assets.\n\n", fleet.DefaultConfigPath, cfg.RegistryBase())
	fmt.Fprintf(&b, "The public catalog may show newly disclosed, unfixed, dev-tier, or base-layer findings after release because catalog scans run against the latest vulnerability database.\n\n")
	b.WriteString("## OCI Images\n\n")
	b.WriteString("| Language Target |")
	for _, tier := range cfg.Matrix.Tiers {
		fmt.Fprintf(&b, " %s |", titleLabel(tier))
	}
	b.WriteString("\n|---|")
	for range cfg.Matrix.Tiers {
		b.WriteString("---|")
	}
	b.WriteString("\n")
	for _, language := range cfg.Matrix.Languages {
		image := cfg.ImageName(language)
		fmt.Fprintf(&b, "| `%s` |", language)
		for _, tier := range cfg.Matrix.Tiers {
			fmt.Fprintf(&b, " `%s:%s-%s` |", image, tag, tier)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "> Versioned tags follow `%s/<%s>-<language>:%s-<tier>`. Rolling tier tags point at the latest release.\n\n", cfg.RegistryBase(), cfg.Registry.ImagePrefix, tag)
	b.WriteString("## Nix Flake Integration\n\n")
	b.WriteString("```nix\n")
	fmt.Fprintf(&b, "inputs.fleet.url = \"github:%s/%s\";\n", cfg.RepoPath(), tag)
	b.WriteString("```\n\n")
	if strings.TrimSpace(rawChangelog) != "" {
		b.WriteString("## Changelog\n\n")
		b.WriteString(filterGeneratedReleaseNotes(rawChangelog))
		if !strings.HasSuffix(b.String(), "\n") {
			b.WriteString("\n")
		}
	}
	return b.String(), nil
}

func filterGeneratedReleaseNotes(raw string) string {
	lines := strings.Split(raw, "\n")
	keep := lines[:0]
	for _, line := range lines {
		if strings.Contains(line, "This draft release represents") ||
			strings.Contains(line, "To release these assets:") ||
			strings.Contains(line, "Simply click 'Publish Release'") {
			continue
		}
		keep = append(keep, line)
	}
	return strings.TrimSpace(strings.Join(keep, "\n")) + "\n"
}

func archiveReleaseNotes(tag, notes string, cfg fleet.Config) error {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN/GH_TOKEN is not set")
	}
	worktree, err := os.MkdirTemp("", "clearcutt-release-notes-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(worktree)
	cloneURL := fmt.Sprintf("https://x-access-token:%s@github.com/%s.git", token, cfg.RepoPath())
	if err := runExternalCommand(externalCommand{Name: "git", Args: []string{"clone", "--depth", "1", "--branch", cfg.Release.SourceBranch, cloneURL, worktree}}); err != nil {
		return err
	}
	notesPath := filepath.Join(worktree, "docs", "releases", tag+".md")
	if err := os.MkdirAll(filepath.Dir(notesPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(notesPath, []byte(notes), 0o644); err != nil {
		return err
	}
	if err := runExternalCommand(externalCommand{Name: "git", Args: []string{"diff", "--quiet", "--", "docs/releases/" + tag + ".md"}, Dir: worktree}); err == nil {
		return nil
	}
	_ = runExternalCommand(externalCommand{Name: "git", Args: []string{"config", "user.name", "github-actions[bot]"}, Dir: worktree})
	_ = runExternalCommand(externalCommand{Name: "git", Args: []string{"config", "user.email", "github-actions[bot]@users.noreply.github.com"}, Dir: worktree})
	if err := runExternalCommand(externalCommand{Name: "git", Args: []string{"add", "docs/releases/" + tag + ".md"}, Dir: worktree}); err != nil {
		return err
	}
	if err := runExternalCommand(externalCommand{Name: "git", Args: []string{"commit", "-m", "chore: archive release notes for " + tag + " [skip ci]"}, Dir: worktree}); err != nil {
		return err
	}
	return runExternalCommand(externalCommand{Name: "git", Args: []string{"push", "origin", cfg.Release.SourceBranch}, Dir: worktree})
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func titleLabel(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func resolveBuildOutputsDir(baseDir, outputDir string) string {
	if filepath.IsAbs(outputDir) {
		return outputDir
	}
	return filepath.Join(baseDir, outputDir)
}
