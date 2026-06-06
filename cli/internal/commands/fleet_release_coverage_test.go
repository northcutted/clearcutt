package commands

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
)

func TestFleetExportProvenanceAndFinalizeReleaseBranches(t *testing.T) {
	root := t.TempDir()
	configPath := writeFleetConfig(t, root)
	outputDir := filepath.Join(root, "dist")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"java21.sbom.json", "java21.test-results.json", "java21.intoto.jsonl", "clearcutt-catalog.json", "SHA256SUMS.txt"} {
		if err := os.WriteFile(filepath.Join(outputDir, name), []byte("asset\n"), 0o644); err != nil {
			t.Fatalf("write release asset: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(outputDir, "empty.sbom.json"), nil, 0o644); err != nil {
		t.Fatalf("write empty asset: %v", err)
	}

	oldFleetOpts := fleetOpts
	oldRun := runExternalCommand
	oldCapture := captureExternalOutput
	oldThrottle := releaseAssetUploadThrottle
	oldRetry := releaseAssetUploadRetryDelay
	oldMax := releaseAssetUploadMaxAttempts
	defer func() {
		fleetOpts = oldFleetOpts
		runExternalCommand = oldRun
		captureExternalOutput = oldCapture
		releaseAssetUploadThrottle = oldThrottle
		releaseAssetUploadRetryDelay = oldRetry
		releaseAssetUploadMaxAttempts = oldMax
	}()

	captureCalls := 0
	captureExternalOutput = func(c externalCommand) (string, error) {
		if c.Name == "cosign" {
			captureCalls++
			if captureCalls == 1 {
				return "", errors.New("missing v1 predicate")
			}
			return `{"predicateType":"https://slsa.dev/provenance/v0.2"}` + "\n", nil
		}
		if c.Name == "gh" && strings.Contains(strings.Join(c.Args, " "), "release view") {
			return "This draft release represents generated boilerplate.\nUseful changelog line.\nSimply click 'Publish Release'\n", nil
		}
		return "", nil
	}

	fleetOpts = fleetFlags{
		configPath:      configPath,
		buildOutputsDir: outputDir,
		language:        "java21",
		tier:            "distroless",
		versionTag:      "1.2.3",
	}
	stdout, err := runCLI(t,
		"fleet", "export-provenance",
		"--fleet-config", configPath,
		"--build-outputs", outputDir,
		"--language", "java21",
		"--tier", "distroless",
	)
	if err != nil {
		t.Fatalf("fleet export provenance failed: %v\n%s", err, stdout)
	}
	if captureCalls != 2 {
		t.Fatalf("expected provenance fallback to v0.2, got %d capture calls", captureCalls)
	}
	provPath := filepath.Join(outputDir, "java21-distroless.intoto.jsonl")
	if !nonEmptyFile(provPath) {
		t.Fatalf("expected non-empty provenance at %s", provPath)
	}

	commandsRun := []string{}
	runExternalCommand = func(c externalCommand) error {
		joined := c.Name + " " + strings.Join(c.Args, " ")
		commandsRun = append(commandsRun, joined)
		if joined == "gh release view v1.2.3" {
			return errors.New("release missing")
		}
		return nil
	}
	releaseAssetUploadThrottle = 0
	releaseAssetUploadRetryDelay = 0
	releaseAssetUploadMaxAttempts = 1

	stdout, err = runCLI(t,
		"fleet", "finalize-release",
		"--fleet-config", configPath,
		"--build-outputs", outputDir,
		"--version-tag", "1.2.3",
	)
	if err != nil {
		t.Fatalf("fleet finalize release failed: %v\n%s", err, stdout)
	}
	joined := strings.Join(commandsRun, "\n")
	for _, needle := range []string{
		"gh release create v1.2.3",
		"gh release upload v1.2.3",
		"gh release edit v1.2.3 --notes-file",
	} {
		if !strings.Contains(joined, needle) {
			t.Fatalf("expected command %q in:\n%s", needle, joined)
		}
	}

	cfg, err := fleet.Load(configPath)
	if err != nil {
		t.Fatalf("load fleet config: %v", err)
	}
	notes, err := buildFleetReleaseNotes("v1.2.3", cfg)
	if err != nil {
		t.Fatalf("build release notes: %v", err)
	}
	if !strings.Contains(notes, "Useful changelog line") || strings.Contains(notes, "draft release represents") || strings.Contains(notes, "Simply click") {
		t.Fatalf("release notes did not filter generated boilerplate:\n%s", notes)
	}
}

func TestFleetVerifyTargetAppliesConfiguredEvidenceDefaults(t *testing.T) {
	root := t.TempDir()
	configPath := writeFleetConfig(t, root)
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakes := map[string]string{
		"crane":         "#!/bin/sh\nif [ \"$1\" = digest ]; then printf 'sha256:abc123\\n'; fi\nexit 0\n",
		"cosign":        "#!/bin/sh\nexit 0\n",
		"slsa-verifier": "#!/bin/sh\nexit 0\n",
		"gh":            "#!/bin/sh\nexit 0\n",
	}
	for name, body := range fakes {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	oldFleetOpts := fleetOpts
	oldReleaseEvidenceOpts := releaseEvidenceOpts
	defer func() {
		fleetOpts = oldFleetOpts
		releaseEvidenceOpts = oldReleaseEvidenceOpts
	}()

	stdout, err := runCLI(t,
		"fleet", "verify-target",
		"--fleet-config", configPath,
		"--ref", "ghcr.io/acme/platform/platform-java21:v1.2.3-distroless",
	)
	if err != nil {
		t.Fatalf("fleet verify target failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "[evidence] complete: ghcr.io/acme/platform/platform-java21@sha256:abc123") {
		t.Fatalf("unexpected verify output:\n%s", stdout)
	}
	if releaseEvidenceOpts.repo != "acme/platform" ||
		releaseEvidenceOpts.workflowIdentity != "https://github.com/acme/platform/.github/workflows/release.yml@refs/heads/main" ||
		releaseEvidenceOpts.oidcIssuer != "https://token.actions.githubusercontent.com" ||
		releaseEvidenceOpts.sourceRef != "refs/heads/main" ||
		releaseEvidenceOpts.sourceBranch != "main" {
		t.Fatalf("fleet verify defaults not applied: %#v", releaseEvidenceOpts)
	}
}

func TestFleetReleaseHelperFailureBranches(t *testing.T) {
	oldRun := runExternalCommand
	oldMax := releaseAssetUploadMaxAttempts
	oldRetry := releaseAssetUploadRetryDelay
	defer func() {
		runExternalCommand = oldRun
		releaseAssetUploadMaxAttempts = oldMax
		releaseAssetUploadRetryDelay = oldRetry
	}()

	releaseAssetUploadMaxAttempts = 2
	releaseAssetUploadRetryDelay = 0
	attempts := 0
	runExternalCommand = func(c externalCommand) error {
		attempts++
		return errors.New("upload denied")
	}
	if err := uploadReleaseAssetWithRetry("v1", filepath.Join(t.TempDir(), "asset.sbom.json")); err == nil || !strings.Contains(err.Error(), "upload release asset") {
		t.Fatalf("expected upload retry failure, got %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected two upload attempts, got %d", attempts)
	}
	if isReleaseAsset("notes.txt") {
		t.Fatal("notes.txt should not be a release asset")
	}
	if got := filterGeneratedReleaseNotes("Keep me\nTo release these assets:\n"); got != "Keep me\n" {
		t.Fatalf("unexpected filtered notes: %q", got)
	}
}

func TestFleetArchiveNotesExternalAndCloudflareBranches(t *testing.T) {
	oldRun := runExternalCommand
	oldCapture := captureExternalOutput
	defer func() {
		runExternalCommand = oldRun
		captureExternalOutput = oldCapture
	}()

	cfg := fleet.DefaultConfig("acme", "platform")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	if err := archiveReleaseNotes("v1", "notes", cfg); err == nil || !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Fatalf("expected missing token error, got %v", err)
	}

	t.Setenv("GITHUB_TOKEN", "token")
	commandsRun := []string{}
	runExternalCommand = func(c externalCommand) error {
		joined := c.Name + " " + strings.Join(c.Args, " ")
		commandsRun = append(commandsRun, joined)
		if joined == "git diff --quiet -- docs/releases/v1.md" {
			return errors.New("changed")
		}
		return nil
	}
	if err := archiveReleaseNotes("v1", "notes", cfg); err != nil {
		t.Fatalf("archive release notes with stubs failed: %v", err)
	}
	joined := strings.Join(commandsRun, "\n")
	for _, needle := range []string{"git clone", "git add docs/releases/v1.md", "git commit -m chore: archive release notes for v1 [skip ci]", "git push origin main"} {
		if !strings.Contains(joined, needle) {
			t.Fatalf("expected archive command %q in:\n%s", needle, joined)
		}
	}

	var purge externalCommand
	captureExternalOutput = func(c externalCommand) (string, error) {
		return `{"result":[{"id":"zone-123"}]}`, nil
	}
	runExternalCommand = func(c externalCommand) error {
		purge = c
		return nil
	}
	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-token")
	t.Setenv("CLOUDFLARE_ZONE_ID", "")
	purgeCloudflareCache(fleet.NixCache{CloudflareZoneName: "example.com"}, "https://cache.example.com/x.narinfo")
	if purge.Name != "curl" || !strings.Contains(strings.Join(purge.Args, " "), "/zones/zone-123/purge_cache") {
		t.Fatalf("unexpected cloudflare purge command: %#v", purge)
	}
	if got := extractFirstCloudflareZoneID(`{"result":[{"id":"zone-456"}]}`); got != "zone-456" {
		t.Fatalf("extract zone id = %q", got)
	}
	if got := extractFirstCloudflareZoneID(`{bad json}`); got != "" {
		t.Fatalf("bad zone JSON should return empty id, got %q", got)
	}

	var output bytes.Buffer
	oldOut := out
	out = &output
	defer func() { out = oldOut }()
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	purge = externalCommand{}
	purgeCloudflareCache(fleet.NixCache{}, "https://cache.example.com/x.narinfo")
	if purge.Name != "" || !strings.Contains(output.String(), "CLOUDFLARE_API_TOKEN") {
		t.Fatalf("expected no-token cache warning, command=%#v output=%q", purge, output.String())
	}
	output.Reset()
	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-token")
	t.Setenv("CLOUDFLARE_ZONE_ID", "")
	purgeCloudflareCache(fleet.NixCache{}, "https://cache.example.com/x.narinfo")
	if purge.Name != "" || !strings.Contains(output.String(), "Cloudflare zone was not found") {
		t.Fatalf("expected missing-zone cache warning, command=%#v output=%q", purge, output.String())
	}
}

func TestExternalCommandDefaultsAndCatalogSummarizeOutput(t *testing.T) {
	oldErrOut := errOut
	var stderr bytes.Buffer
	errOut = &stderr
	defer func() { errOut = oldErrOut }()

	if err := runExternalCommandDefault(externalCommand{Name: "sh", Args: []string{"-c", "true"}}); err != nil {
		t.Fatalf("runExternalCommandDefault success failed: %v", err)
	}
	if err := runExternalCommandDefault(externalCommand{Name: "sh", Args: []string{"-c", "exit 7"}}); err == nil || !strings.Contains(err.Error(), "sh failed") {
		t.Fatalf("expected shell failure, got %v", err)
	}
	stdout, err := captureExternalCommandDefault(externalCommand{Name: "sh", Args: []string{"-c", "printf hello"}})
	if err != nil || stdout != "hello" {
		t.Fatalf("unexpected captured stdout %q err=%v", stdout, err)
	}
	if _, err := captureExternalCommandDefault(externalCommand{Name: "sh", Args: []string{"-c", "printf err >&2; exit 9"}}); err == nil || !strings.Contains(err.Error(), "sh failed") {
		t.Fatalf("expected captured failure, got %v", err)
	}

	oldOutput := catalogSummarizeOpts.output
	defer func() { catalogSummarizeOpts.output = oldOutput }()
	outPath := filepath.Join(t.TempDir(), "summary.json")
	catalogSummarizeOpts.output = outPath
	if err := runCatalogSummarize(fixtureCatalog()); err != nil {
		t.Fatalf("run catalog summarize with output failed: %v", err)
	}
	if !strings.Contains(string(readFile(t, outPath)), `"imageCount"`) {
		t.Fatalf("summary output missing image count")
	}
}

func TestFleetDigestAndMinorHelperBranches(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"node.digest.json": `{"image":"img-node","digest":"sha256:2","language":"node24","tier":"slim","rollingTag":"slim","versionedTag":"v1-slim"}`,
		"core.digest.json": `{"image":"img-core","digest":"sha256:1","language":"coreLTS","tier":"dev","rollingTag":"dev","versionedTag":"v1-dev"}`,
		"skip.txt":         "ignored",
	}
	if err := os.MkdirAll(filepath.Join(dir, "nested.digest.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	digests, err := readFleetDigestManifests(dir)
	if err != nil {
		t.Fatalf("read digest manifests: %v", err)
	}
	if len(digests) != 2 || digests[0].Language != "coreLTS" || digests[1].Language != "node24" {
		t.Fatalf("unexpected sorted digests: %#v", digests)
	}
	if _, err := readFleetDigestManifests(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing digest manifest dir should fail")
	}
	badDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(badDir, "bad.digest.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readFleetDigestManifests(badDir); err == nil || !strings.Contains(err.Error(), "parse bad.digest.json") {
		t.Fatalf("expected parse error, got %v", err)
	}

	if got := pathBaseHash("abcdef"); got != "abcdef" {
		t.Fatalf("pathBaseHash without dash = %q", got)
	}
	if got := firstNonEmptyString(" ", "\t", " value "); got != " value " {
		t.Fatalf("firstNonEmptyString should return original non-empty value, got %q", got)
	}
	if got := firstNonEmptyString(" ", ""); got != "" {
		t.Fatalf("firstNonEmptyString empty fallback = %q", got)
	}
	if got := titleLabel(""); got != "" {
		t.Fatalf("empty title label = %q", got)
	}
	absolute := filepath.Join(t.TempDir(), "dist")
	if got := resolveBuildOutputsDir("/base", absolute); got != absolute {
		t.Fatalf("absolute build outputs dir changed: %s", got)
	}

	assetDir := t.TempDir()
	for _, name := range []string{"java21.sbom.json", "java21.test-results.json"} {
		if err := os.WriteFile(filepath.Join(assetDir, name), []byte("asset"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := stageArchReleaseAssets(assetDir, "java21", "amd64"); err != nil {
		t.Fatalf("stage release assets: %v", err)
	}
	if !fileExists(filepath.Join(assetDir, "java21-amd64.sbom.json")) || !fileExists(filepath.Join(assetDir, "java21-amd64.test-results.json")) {
		t.Fatal("staged release assets were not copied")
	}

	oldRun := runExternalCommand
	defer func() { runExternalCommand = oldRun }()
	created := false
	runExternalCommand = func(c externalCommand) error {
		if strings.Join(c.Args, " ") == "release view v1" {
			return nil
		}
		created = true
		return nil
	}
	if err := ensureGitHubRelease("v1", fleet.DefaultConfig("acme", "platform")); err != nil {
		t.Fatalf("existing release should not fail: %v", err)
	}
	if created {
		t.Fatal("existing release should not be created")
	}

	if got := truncateDigest("sha256:1234567890abcdef"); got != "sha256:1234567890ab..." {
		t.Fatalf("sha digest truncation = %q", got)
	}
	if got := truncateDigest("short"); got != "short" {
		t.Fatalf("short digest truncation = %q", got)
	}
	if got := imageRecordLabel("/catalog", "java21-dev"); got != filepath.Join("/catalog", "images", "java21-dev.json") {
		t.Fatalf("image record label = %q", got)
	}
}
