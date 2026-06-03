package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/catalog"
)

type gatherMetaFixture struct {
	Lifecycle       gatherLifecycle          `json:"lifecycle"`
	RuntimeContract gatherRuntimeContract    `json:"runtimeContract"`
	Exceptions      catalog.ExceptionSummary `json:"exceptions"`
}

// Proves the ported runtime-metadata transforms reproduce gather-catalog.mjs
// byte-for-byte across the full 13-language x 3-tier matrix. The golden fixture
// (testdata/catalog/meta-golden.json) was captured from the Node functions
// verbatim, so this guards both the values and the exact JSON shape (explicit
// nulls, key order) that the catalog site and verify-catalog depend on.
func TestGatherMetadataMatchesNodeGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "catalog", "meta-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string]json.RawMessage
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	if len(golden) != 39 {
		t.Fatalf("expected 39 target fixtures, got %d", len(golden))
	}

	for target, entry := range golden {
		idx := strings.LastIndex(target, "-")
		if idx == -1 {
			t.Fatalf("malformed target id %q", target)
		}
		tier := target[idx+1:]

		got, err := json.Marshal(gatherMetaFixture{
			Lifecycle:       determineLifecycle(target, tier),
			RuntimeContract: determineRuntimeContract(target, tier),
			Exceptions:      defaultGatherExceptions(),
		})
		if err != nil {
			t.Fatal(err)
		}

		var want bytes.Buffer
		if err := json.Compact(&want, entry); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want.Bytes()) {
			t.Errorf("%s drift:\n got: %s\nwant: %s", target, got, want.Bytes())
		}
	}
}

type spdxGatherOut struct {
	Packages   []spdxPackageOut `json:"packages"`
	RootDigest *string          `json:"rootDigest"`
	Provenance provenanceOut    `json:"provenance"`
}

// Proves the SPDX compaction (package fields, cpe/purl split, license
// resolution, nix store path, layer-digest mapping, sort, root digest) and the
// in-toto/SLSA provenance summarization reproduce gather-catalog.mjs. The
// provenance `raw` passthrough is excluded here (arbitrary-key re-serialization);
// it is handled when image-record assembly lands.
func TestSpdxAndProvenanceTransformsMatchNodeGolden(t *testing.T) {
	spdxRaw, err := os.ReadFile(filepath.Join("testdata", "catalog", "spdx-fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spdx spdxDoc
	if err := json.Unmarshal(spdxRaw, &spdx); err != nil {
		t.Fatal(err)
	}
	intotoRaw, err := os.ReadFile(filepath.Join("testdata", "catalog", "intoto-fixture.jsonl"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := json.Marshal(spdxGatherOut{
		Packages:   compactPackages(spdx),
		RootDigest: rootDigest(spdx),
		Provenance: summarizeProvenance(string(intotoRaw)),
	})
	if err != nil {
		t.Fatal(err)
	}

	goldenRaw, err := os.ReadFile(filepath.Join("testdata", "catalog", "spdx-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	if err := json.Compact(&want, goldenRaw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("SPDX/provenance drift:\n got: %s\nwant: %s", got, want.Bytes())
	}
}

func TestCatalogHelperBranches(t *testing.T) {
	if got := parseCatalogTargetName("python3.13-slim.sbom.json"); got == nil || got.Target != "python3.13-slim" || got.Kind != "sbom" || got.Ext != "json" {
		t.Fatalf("unexpected parsed asset name: %#v", got)
	}
	if got := parseCatalogTargetName("not-an-asset.txt"); got != nil {
		t.Fatalf("unexpected asset parse: %#v", got)
	}
	if archForSystem("aarch64-linux") != "arm64" || archForSystem("x86_64-linux") != "amd64" {
		t.Fatal("archForSystem did not normalize expected systems")
	}
	if arch := guessArchFromAsset("target.sbom.json", &spdxDoc{DocumentNamespace: "https://example.invalid/aarch64-linux"}); arch != "arm64" {
		t.Fatalf("expected namespace arch fallback, got %s", arch)
	}
	if arch := guessArchFromAsset("target-amd64.sbom.json", nil); arch != "amd64" {
		t.Fatalf("expected filename arch, got %s", arch)
	}
	if tool := spdxTool(spdxDoc{CreationInfo: spdxCreationInfo{Creators: []string{"Organization: acme"}}}); tool != "syft" {
		t.Fatalf("expected syft fallback, got %s", tool)
	}
	if tool := spdxTool(spdxDoc{CreationInfo: spdxCreationInfo{Creators: []string{"Tool: custom-syft"}}}); tool != "custom-syft" {
		t.Fatalf("expected explicit tool, got %s", tool)
	}

	temp := t.TempDir()
	cachePath := filepath.Join(temp, "sbom.json")
	if got, ok := readCachedSBOM(cachePath, false); ok || got != nil {
		t.Fatalf("missing cache should not read: ok=%v got=%q", ok, got)
	}
	writeTestFile(t, cachePath, []byte(`{"ok":true}`))
	if got, ok := readCachedSBOM(cachePath, false); !ok || string(got) != `{"ok":true}` {
		t.Fatalf("expected cached SBOM, ok=%v got=%q", ok, got)
	}
	if got, ok := readCachedSBOM(cachePath, true); ok || got != nil {
		t.Fatalf("forced refresh should skip cache: ok=%v got=%q", ok, got)
	}
	if !fileExists(cachePath) || fileExists(filepath.Join(temp, "missing")) {
		t.Fatal("fileExists did not report expected paths")
	}

	assets := []catalogAsset{
		{Name: "target.sbom.json"},
		{Name: "target-amd64.sbom.json"},
		{Name: "target-arm64.sbom.json"},
	}
	if got := catalogAssetsNamed(assets, "target.sbom.json"); len(got) != 1 {
		t.Fatalf("expected named asset, got %#v", got)
	}
	if got := catalogArchAssets(assets, "target", ".sbom.json"); len(got) != 2 {
		t.Fatalf("expected arch assets, got %#v", got)
	}
	if got := refreshTagSet([]catalogRelease{{Tag: "v1"}, {Tag: "v2"}}, false, "v2, v3"); !got["v2"] || !got["v3"] || got["v1"] {
		t.Fatalf("unexpected refresh tag set: %#v", got)
	}
	if got := refreshTagSet([]catalogRelease{{Tag: "v1"}, {Tag: "v2"}}, true, ""); !got["v1"] || !got["v2"] {
		t.Fatalf("force refresh should include every release: %#v", got)
	}
	if got := refreshTagSet([]catalogRelease{{Tag: "v1", Prerelease: true}, {Tag: "v2"}}, false, ""); !got["v2"] || got["v1"] {
		t.Fatalf("latest non-prerelease should refresh, got %#v", got)
	}
	if got := refreshTagSet([]catalogRelease{{Tag: "v1", Prerelease: true}}, false, ""); !got["v1"] {
		t.Fatalf("all-prerelease fallback should refresh first release, got %#v", got)
	}
	if got := refreshTagSet(nil, false, ""); len(got) != 0 {
		t.Fatalf("empty release set should refresh nothing, got %#v", got)
	}
	for reason, want := range map[string]string{
		"fix_available":            "eligible",
		"base_layer":               "baseLayer",
		"no_fixed_version":         "noFixedVersion",
		"below_priority_threshold": "belowPriorityThreshold",
		"unknown-reason":           "otherDeferred",
	} {
		if got := remediationBucket(reason); got != want {
			t.Fatalf("remediationBucket(%q) = %q, want %q", reason, got, want)
		}
	}
	if got := remediationReason(catalog.FindingInfo{Severity: "medium", Layer: "runtime", FixedIn: strPtr("1.0.1")}); got != "below_priority_threshold" {
		t.Fatalf("medium runtime finding reason = %q", got)
	}
	if got := remediationReason(catalog.FindingInfo{Severity: "high", Layer: "runtime"}); got != "no_fixed_version" {
		t.Fatalf("high runtime no-fix reason = %q", got)
	}
	if got := remediationReason(catalog.FindingInfo{Severity: "high", Layer: "runtime", FixedIn: strPtr("1.0.1")}); got != "fix_available" {
		t.Fatalf("high runtime fixed reason = %q", got)
	}
	if remediationBucket("unknown-reason") != "otherDeferred" {
		t.Fatal("unknown remediation reason should use otherDeferred bucket")
	}
}

func TestCatalogProvenanceAndSPDXEdgeBranches(t *testing.T) {
	if extractNixStorePath("") != nil || extractNixStorePath("not a nix path") != nil {
		t.Fatal("non-Nix source info should not produce a store path")
	}
	if got := pickLicense(spdxPkg{LicenseDeclared: "NOASSERTION", LicenseConcluded: "Apache-2.0"}); got != "Apache-2.0" {
		t.Fatalf("pickLicense concluded branch = %q", got)
	}
	if got := pickLicense(spdxPkg{}); got != "NOASSERTION" {
		t.Fatalf("pickLicense fallback = %q", got)
	}
	checksumRoot := rootDigest(spdxDoc{Packages: []spdxPkg{{PrimaryPackagePurpose: "CONTAINER", Checksums: []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: "abc"}}}}})
	if checksumRoot == nil || *checksumRoot != "sha256:abc" {
		t.Fatalf("checksum root digest = %v", checksumRoot)
	}
	versionRoot := rootDigest(spdxDoc{Packages: []spdxPkg{{PrimaryPackagePurpose: "CONTAINER", VersionInfo: "sha256:def"}}})
	if versionRoot == nil || *versionRoot != "sha256:def" {
		t.Fatalf("version root digest = %v", versionRoot)
	}
	if rootDigest(spdxDoc{Packages: []spdxPkg{{PrimaryPackagePurpose: "CONTAINER", VersionInfo: "not-a-digest"}}}) != nil {
		t.Fatal("container package without digest should return nil root digest")
	}

	stmt := intotoStatement{
		PredicateType: "https://example.invalid/custom",
		Predicate: intotoPredicate{
			RunDetails: &intotoRunDetails{Builder: &intotoBuilder{ID: "runner-builder"}},
			BuildDefinition: &intotoBuildDefinition{
				BuildType: "https://example.invalid/build",
				ExternalParameters: &intotoExternalParams{
					Workflow:  &intotoWorkflow{Repository: "https://github.com/acme/workflow"},
					SourceURI: "https://github.com/acme/source",
				},
				ResolvedDependencies: []intotoDependency{{
					URI:    "https://github.com/acme/repo",
					Digest: &intotoDigest{GitCommit: "abc123"},
				}},
			},
		},
	}
	raw, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	if got := decodeIntotoPayload([]byte(`{"payload":"` + encoded + `"}`)); got == nil || got.PredicateType != "https://example.invalid/custom" {
		t.Fatalf("payload decode branch failed: %#v", got)
	}
	if got := decodeIntotoPayload([]byte(`{"dsseEnvelope":{"payload":"` + encoded + `"}}`)); got == nil || got.PredicateType != "https://example.invalid/custom" {
		t.Fatalf("dsse decode branch failed: %#v", got)
	}
	if decodeIntotoPayload([]byte(`{"payload":"not-base64"}`)) != nil {
		t.Fatal("invalid base64 should not decode")
	}
	if decodeIntotoPayload([]byte(`{"notPredicate":"x"}`)) != nil {
		t.Fatal("non-attestation line should not decode")
	}
	summary := summarizeProvenance(string(raw) + "\n" + `{"predicateType":"https://slsa.dev/provenance/v1","predicate":{"builder":{"id":"slsa-builder"}}}`)
	if summary.PredicateType != "https://slsa.dev/provenance/v1" || summary.Builder.ID != "slsa-builder" {
		t.Fatalf("SLSA provenance should win, got %+v", summary)
	}
	fallback := summarizeProvenance("not-json\n")
	if fallback.PredicateType != "unknown" || fallback.Builder.ID != "unknown" {
		t.Fatalf("provenance fallback = %+v", fallback)
	}
	nonSLSA := summarizeProvenance(string(raw))
	if nonSLSA.Builder.ID != "runner-builder" || nonSLSA.SourceRevision == nil || *nonSLSA.SourceRevision != "abc123" {
		t.Fatalf("expected useful non-SLSA provenance summary, got %+v", nonSLSA)
	}
}

type fakeCatalogReleaseSource struct {
	releases  []catalogRelease
	assets    map[string][]byte
	downloads []string
}

func (f *fakeCatalogReleaseSource) ListReleases(limit int) ([]catalogRelease, error) {
	if limit > 0 && len(f.releases) > limit {
		return append([]catalogRelease(nil), f.releases[:limit]...), nil
	}
	return append([]catalogRelease(nil), f.releases...), nil
}

func (f *fakeCatalogReleaseSource) DownloadAsset(asset catalogAsset) ([]byte, error) {
	f.downloads = append(f.downloads, asset.Name)
	data, ok := f.assets[asset.Name]
	if !ok {
		return nil, fmt.Errorf("missing asset fixture %s", asset.Name)
	}
	return data, nil
}

type catalogAssemblyFixture struct {
	Image   *gatherImageRecord        `json:"image"`
	Summary gatherCatalogImageSummary `json:"summary"`
}

// Exercises the full gather command through Cobra with an injected release
// source, then runs the catalog verifier against the generated files. This keeps
// the GitHub release seam honest without touching api.github.com.
func TestCatalogGatherCommandWritesVerifiableCatalogOffline(t *testing.T) {
	const target = "python3.13-slim"
	const tag = "v1.0.0"
	const publishedAt = "2026-05-29T13:44:59Z"

	temp := t.TempDir()
	outDir := filepath.Join(temp, "catalog")
	sbomDir := filepath.Join(temp, "sboms")
	enrichmentDir := filepath.Join(temp, "enrichment")
	vulnDir := filepath.Join(temp, "vulnerabilities")

	writeTestFile(t, filepath.Join(enrichmentDir, tag, target+".json"), []byte(`{
  "manifestDigest": "sha256:manifest-command",
  "architectures": [
    {
      "arch": "amd64",
      "digest": "sha256:image-amd64",
      "size": 11,
      "layers": [],
      "labels": {}
    }
  ],
  "signature": {
    "cosignBundlePresent": true
  },
  "provenance": {
    "predicateType": "https://slsa.dev/provenance/v1",
    "builder": { "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml" },
    "slsaLevel": 3
  },
  "attestations": [
    {
      "kind": "slsa-provenance",
      "predicateType": "https://slsa.dev/provenance/v1",
      "sources": ["oci", "github"]
    }
  ]
}`))
	writeTestFile(t, filepath.Join(vulnDir, tag, target+"-amd64.json"), []byte(`{"scannedAt":"2026-05-29T15:00:00Z","scanner":"grype-test","dbBuiltAt":null,"countsBySeverity":{"critical":0,"high":0,"medium":0,"low":0,"negligible":0,"unknown":0},"findings":[]}`))

	spdxRaw, err := os.ReadFile(filepath.Join("testdata", "catalog", "spdx-fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeCatalogReleaseSource{
		releases: []catalogRelease{{
			Tag:         tag,
			Name:        "v1.0.0",
			PublishedAt: publishedAt,
			Assets: []catalogAsset{
				{Name: target + "-amd64.sbom.json", URL: "https://example.invalid/" + target + "-amd64.sbom.json"},
				{Name: target + "-amd64.test-results.json", URL: "https://example.invalid/" + target + "-amd64.test-results.json"},
			},
		}},
		assets: map[string][]byte{
			target + "-amd64.sbom.json":         spdxRaw,
			target + "-amd64.test-results.json": []byte(`{"status":"passed","timestamp":"2026-05-29T13:59:00Z","assertions":[{"name":"Syft SBOM Generation","status":"passed"}]}`),
		},
	}

	oldNewReleaseSource := newReleaseSource
	t.Cleanup(func() { newReleaseSource = oldNewReleaseSource })
	newReleaseSource = func(owner, repo, token string) ReleaseSource {
		if owner != "northcutted" || repo != "clearcutt" {
			t.Fatalf("unexpected release source request for %s/%s", owner, repo)
		}
		return source
	}

	stdout, err := runCLI(t,
		"catalog", "gather",
		"--owner", "northcutted",
		"--repo", "clearcutt",
		"--registry-base", "ghcr.io/northcutted/clearcutt",
		"--out-dir", outDir,
		"--enrichment-dir", enrichmentDir,
		"--sbom-cache-dir", sbomDir,
		"--vuln-dir", vulnDir,
		"--targets", target,
		"--limit", "1",
		"--force-refresh-all",
		"--generated-at", "2026-05-29T16:00:00Z",
	)
	if err != nil {
		t.Fatalf("catalog gather failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"[gather] wrote python3.13-slim (1 releases)",
		"[gather] wrote index.json with 1 images",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected gather output %q, got:\n%s", want, stdout)
		}
	}
	for _, path := range []string{
		filepath.Join(outDir, "index.json"),
		filepath.Join(outDir, "images", target+".json"),
		filepath.Join(sbomDir, tag, target+"-amd64.sbom.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected generated file %s: %v", path, err)
		}
	}
	for _, want := range []string{target + "-amd64.sbom.json", target + "-amd64.test-results.json"} {
		if !contains(source.downloads, want) {
			t.Fatalf("expected offline fake to download %s, got %v", want, source.downloads)
		}
	}

	verifyOut, err := runCLI(t, "--catalog", outDir, "verify", "catalog")
	if err != nil {
		t.Fatalf("generated catalog did not verify: %v\n%s", err, verifyOut)
	}
	if !strings.Contains(verifyOut, "ok: 1 latest images") {
		t.Fatalf("expected verifier ok summary, got:\n%s", verifyOut)
	}
}

func TestGithubReleaseSourceListsDownloadsAndReportsErrors(t *testing.T) {
	var requested []string
	source := &githubReleaseSource{
		owner: "acme",
		repo:  "clearcutt",
		token: "token-123",
		client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requested = append(requested, req.URL.String())
			if req.Header.Get("Authorization") != "Bearer token-123" {
				t.Fatalf("expected bearer token, got %q", req.Header.Get("Authorization"))
			}
			switch {
			case strings.Contains(req.URL.Path, "/releases"):
				return textResponse(200, `[
  {
    "tag_name": "v2.0.0",
    "name": "Release 2",
    "published_at": "2026-02-01T00:00:00Z",
    "draft": false,
    "prerelease": false,
    "assets": [
      {
        "name": "python3.13-slim-amd64.sbom.json",
        "browser_download_url": "https://downloads.example/sbom",
        "size": 42,
        "digest": "sha256:asset"
      }
    ]
  },
  {
    "tag_name": "v1.0.0",
    "name": "Draft",
    "created_at": "2026-01-01T00:00:00Z",
    "draft": true,
    "assets": []
  },
  {
    "tag_name": "v0.9.0",
    "name": "Old",
    "created_at": "2025-12-01T00:00:00Z",
    "draft": false,
    "prerelease": true,
    "assets": []
  }
]`), nil
			case req.URL.Host == "downloads.example":
				return textResponse(200, `asset-bytes`), nil
			default:
				return textResponse(500, strings.Repeat("x", 260)), nil
			}
		})},
	}

	releases, err := source.ListReleases(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(releases) != 1 || releases[0].Tag != "v2.0.0" || len(releases[0].Assets) != 1 {
		t.Fatalf("unexpected releases: %#v", releases)
	}
	if releases[0].Assets[0].Digest == nil || *releases[0].Assets[0].Digest != "sha256:asset" {
		t.Fatalf("expected asset digest: %#v", releases[0].Assets[0])
	}
	data, err := source.DownloadAsset(releases[0].Assets[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "asset-bytes" {
		t.Fatalf("unexpected asset download: %q", data)
	}
	if len(requested) < 2 {
		t.Fatalf("expected release and asset requests, got %v", requested)
	}

	_, err = (&githubReleaseSource{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return textResponse(500, strings.Repeat("x", 260)), nil
	})}}).get("https://api.example/error", "application/json")
	if err == nil || !strings.Contains(err.Error(), "failed: 500") {
		t.Fatalf("expected HTTP status error, got %v", err)
	}
}

func TestCatalogRepoDetectionAndExistingIndexRebuild(t *testing.T) {
	t.Setenv("GH_OWNER", "env-owner")
	t.Setenv("GH_REPO", "env-repo")
	owner, repo, err := detectCatalogRepo("", "")
	if err != nil {
		t.Fatal(err)
	}
	if owner != "env-owner" || repo != "env-repo" {
		t.Fatalf("unexpected env repo: %s/%s", owner, repo)
	}
	if owner, repo, err = detectCatalogRepo("flag-owner", "flag-repo"); err != nil || owner != "flag-owner" || repo != "flag-repo" {
		t.Fatalf("unexpected flag repo: %s/%s err=%v", owner, repo, err)
	}
	t.Setenv("GH_OWNER", "")
	t.Setenv("GH_REPO", "")
	t.Setenv("GITHUB_REPOSITORY", "repo-owner/repo-name")
	if owner, repo, err = detectCatalogRepo("", ""); err != nil || owner != "repo-owner" || repo != "repo-name" {
		t.Fatalf("unexpected GITHUB_REPOSITORY repo: %s/%s err=%v", owner, repo, err)
	}
	for _, tc := range []struct {
		remote string
		owner  string
		repo   string
	}{
		{"git@github.com:acme/clearcutt.git", "acme", "clearcutt"},
		{"https://github.com/acme/clearcutt.git", "acme", "clearcutt"},
		{"acme/clearcutt", "acme", "clearcutt"},
		{"not-a-github-remote", "", ""},
	} {
		gotOwner, gotRepo := parseGitHubRemote(tc.remote)
		if gotOwner != tc.owner || gotRepo != tc.repo {
			t.Fatalf("parseGitHubRemote(%q) = %s/%s, want %s/%s", tc.remote, gotOwner, gotRepo, tc.owner, tc.repo)
		}
	}

	outDir := writeCommandSmokeCatalog(t)
	ok, err := rebuildIndexFromExistingImages("acme", "clearcutt", "ghcr.io/acme/clearcutt", outDir, "", "2026-02-02T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected existing image records to rebuild index")
	}
	var rebuilt catalog.CatalogIndex
	raw, err := os.ReadFile(filepath.Join(outDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &rebuilt); err != nil {
		t.Fatal(err)
	}
	if rebuilt.Owner != "acme" || rebuilt.LatestTag != "v2.0.0" || len(rebuilt.Images) != 1 || !rebuilt.Releases[0].IsLatest {
		t.Fatalf("unexpected rebuilt index: %#v", rebuilt)
	}
	ok, err = rebuildIndexFromExistingImages("acme", "clearcutt", "ghcr.io/acme/clearcutt", filepath.Join(t.TempDir(), "missing"), "", "now")
	if err != nil || ok {
		t.Fatalf("missing image dir should not rebuild, ok=%v err=%v", ok, err)
	}
}

func TestCatalogRepoDetectionUsesGitRemoteAndReportsFailures(t *testing.T) {
	t.Setenv("GH_OWNER", "")
	t.Setenv("GH_REPO", "")
	t.Setenv("GITHUB_REPOSITORY", "")

	binDir := t.TempDir()
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	if err := os.Setenv("PATH", binDir); err != nil {
		t.Fatal(err)
	}

	gitPath := filepath.Join(binDir, "git")
	writeExecutable(t, gitPath, "#!/bin/sh\nprintf '%s\\n' 'git@github.com:remote-owner/remote-repo.git'\n")
	owner, repo, err := detectCatalogRepo("", "")
	if err != nil {
		t.Fatalf("expected fake git remote detection, got %v", err)
	}
	if owner != "remote-owner" || repo != "remote-repo" {
		t.Fatalf("unexpected fake git remote repo: %s/%s", owner, repo)
	}

	writeExecutable(t, gitPath, "#!/bin/sh\nexit 2\n")
	if _, _, err := detectCatalogRepo("", ""); err == nil || !strings.Contains(err.Error(), "unable to detect GitHub repo") {
		t.Fatalf("expected git detection failure, got %v", err)
	}

	writeExecutable(t, gitPath, "#!/bin/sh\nprintf '%s\\n' 'not-a-github-remote'\n")
	if _, _, err := detectCatalogRepo("", ""); err == nil || !strings.Contains(err.Error(), "unable to parse GitHub repo") {
		t.Fatalf("expected git parse failure, got %v", err)
	}
}

// Exercises the image-record assembly path that replaces the network-heavy
// gather-catalog.mjs core: per-arch SBOM assets, persisted SBOM cache, release
// test assets plus enrichment fallback, manifest/signature/attestation merge,
// vulnerability fold-in, evidence recomputation, and slim index summary output.
func TestBuildImageRecordMatchesAssemblyGolden(t *testing.T) {
	const target = "python3.13-slim"
	const tag = "v1.0.0"
	const publishedAt = "2026-05-29T13:44:59Z"

	temp := t.TempDir()
	sbomDir := filepath.Join(temp, "sboms")
	enrichmentDir := filepath.Join(temp, "enrichment")
	vulnDir := filepath.Join(temp, "vulnerabilities")
	writeTestFile(t, filepath.Join(enrichmentDir, tag, target+".json"), []byte(`{
  "manifestDigest": "sha256:manifest-enriched",
  "architectures": [
    {
      "arch": "amd64",
      "digest": "sha256:image-amd64",
      "size": 11,
      "layers": [
        { "digest": "sha256:layer-amd64", "size": 7, "diffID": null }
      ],
      "labels": { "org.opencontainers.image.source": "https://github.com/northcutted/clearcutt" }
    },
    {
      "arch": "arm64",
      "digest": "sha256:image-arm64",
      "size": 13,
      "layers": [
        { "digest": "sha256:layer-arm64", "size": 9, "diffID": "sha256:diff-arm64" }
      ],
      "labels": {}
    }
  ],
  "signature": {
    "cosignBundlePresent": true,
    "rekorLogIndex": 12345,
    "certificate": {
      "subject": "https://github.com/northcutted/clearcutt/.github/workflows/release.yml@refs/heads/main",
      "issuer": "https://token.actions.githubusercontent.com",
      "runInvocation": null
    }
  },
  "provenance": {
    "predicateType": "https://slsa.dev/provenance/v1",
    "builder": { "id": "enrichment-builder" },
    "buildType": "enrichment-build",
    "sourceUri": "https://github.com/northcutted/clearcutt",
    "sourceRevision": "enrichment-rev",
    "slsaLevel": 3
  },
  "testResults": {
    "status": "passed",
    "timestamp": "2026-05-29T14:00:00Z",
    "assertions": [
      { "name": "Grype Vulnerability Gating", "status": "passed" }
    ]
  },
  "attestations": [
    {
      "kind": "slsa-provenance",
      "predicateType": "https://slsa.dev/provenance/v1",
      "subjectName": "ghcr.io/northcutted/clearcutt/clearcutt-python3.13",
      "subjectDigest": "sha256:subject",
      "signerIdentity": "https://github.com/northcutted/clearcutt/.github/workflows/release.yml@refs/heads/main",
      "issuer": "https://token.actions.githubusercontent.com",
      "runUrl": "https://github.com/northcutted/clearcutt/actions/runs/1/attempts/1",
      "workflowUrl": "https://github.com/northcutted/clearcutt/actions/workflows/release.yml",
      "githubApiUrl": "https://api.github.com/users/northcutted/attestations/sha256:subject",
      "transparencyLogIndex": 67890,
      "transparencyUrl": "https://search.sigstore.dev/?logIndex=67890",
      "sources": ["oci", "github"]
    }
  ]
}`))
	writeTestFile(t, filepath.Join(vulnDir, tag, target+"-amd64.json"), []byte(`{"scannedAt":"2026-05-29T15:00:00Z","scanner":"grype-test","dbBuiltAt":null,"countsBySeverity":{"critical":1,"high":0,"medium":1,"low":0,"negligible":0,"unknown":0},"findings":[{"id":"CVE-2026-0001","severity":"Critical","packageName":"python3.13","packageVersion":"3.13.1","purl":"pkg:generic/python@3.13.1","layer":"runtime","fixedIn":"3.13.2","fixState":"fixed"},{"id":"CVE-2026-0003","severity":"Medium","packageName":"zlib","packageVersion":"1.3.1","purl":"pkg:nix/zlib@1.3.1","layer":"runtime","fixedIn":null,"fixState":"unknown"}]}`))
	writeTestFile(t, filepath.Join(vulnDir, tag, target+"-arm64.json"), []byte(`{"scannedAt":"2026-05-29T15:05:00Z","scanner":"grype-test","dbBuiltAt":null,"countsBySeverity":{"critical":1,"high":1,"medium":0,"low":0,"negligible":0,"unknown":0},"findings":[{"id":"CVE-2026-0001","severity":"Critical","packageName":"python3.13","packageVersion":"3.13.1","purl":"pkg:generic/python@3.13.1","layer":"runtime","fixedIn":"3.13.2","fixState":"fixed"},{"id":"CVE-2026-0002","severity":"High","packageName":"openssl","packageVersion":"3.5.0","purl":"pkg:nix/openssl@3.5.0","layer":"base","fixedIn":null,"fixState":"unknown"}]}`))

	spdxRaw, err := os.ReadFile(filepath.Join("testdata", "catalog", "spdx-fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	intotoRaw, err := os.ReadFile(filepath.Join("testdata", "catalog", "intoto-fixture.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeCatalogReleaseSource{assets: map[string][]byte{
		target + "-amd64.sbom.json":         spdxRaw,
		target + "-arm64.sbom.json":         spdxRaw,
		target + "-amd64.test-results.json": []byte(`{"status":"passed","timestamp":"2026-05-29T13:59:00Z","assertions":[{"name":"Syft SBOM Generation","status":"passed"}]}`),
		target + ".intoto.jsonl":            intotoRaw,
		target + ".digest.json":             []byte(`{"digest":"sha256:manifest-release"}`),
	}}
	releases := []catalogRelease{{
		Tag:         tag,
		Name:        "v1.0.0",
		PublishedAt: publishedAt,
		Assets: []catalogAsset{
			{Name: target + "-amd64.sbom.json", URL: "https://example.invalid/" + target + "-amd64.sbom.json"},
			{Name: target + "-arm64.sbom.json", URL: "https://example.invalid/" + target + "-arm64.sbom.json"},
			{Name: target + "-amd64.test-results.json", URL: "https://example.invalid/" + target + "-amd64.test-results.json"},
			{Name: target + ".intoto.jsonl", URL: "https://example.invalid/" + target + ".intoto.jsonl"},
			{Name: target + ".digest.json", URL: "https://example.invalid/" + target + ".digest.json"},
		},
	}}
	img, err := buildImageRecord(target, releases, map[string]bool{tag: true}, gatherBuildOptions{
		RegistryBase:  "ghcr.io/northcutted/clearcutt",
		SBOMCacheDir:  sbomDir,
		EnrichmentDir: enrichmentDir,
		VulnDir:       vulnDir,
		Source:        source,
	})
	if err != nil {
		t.Fatal(err)
	}
	if img == nil {
		t.Fatal("expected image record")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if _, err := os.Stat(filepath.Join(sbomDir, tag, target+"-"+arch+".sbom.json")); err != nil {
			t.Fatalf("expected persisted %s SBOM: %v", arch, err)
		}
	}
	provenanceRaw, err := json.Marshal(img.Releases[0].Provenance)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(provenanceRaw, []byte(`"raw"`)) {
		t.Fatalf("producer provenance should not re-emit raw passthrough: %s", provenanceRaw)
	}

	gotRaw, err := json.Marshal(catalogAssemblyFixture{
		Image:   img,
		Summary: summarizeImageForIndex(*img),
	})
	if err != nil {
		t.Fatal(err)
	}
	compareCatalogGolden(t, filepath.Join("testdata", "catalog", "assembly-golden.json"), gotRaw)
}

func TestEnrichmentAttestationShapeOmitsReleaseAssetURL(t *testing.T) {
	raw, err := json.Marshal(gatherEnrichment{
		Attestations: []gatherEnrichmentAttestation{{
			Kind:          "slsa-provenance",
			PredicateType: "https://slsa.dev/provenance/v1",
			Sources:       []string{"oci"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("releaseAssetUrl")) {
		t.Fatalf("enrichment output must not include releaseAssetUrl; gather adds it to release records: %s", raw)
	}
	releaseAttestations := attachReleaseAssetLinks([]gatherEnrichmentAttestation{{
		Kind:          "slsa-provenance",
		PredicateType: "https://slsa.dev/provenance/v1",
		Sources:       []string{"oci"},
	}}, gatherStr("https://example.invalid/provenance.jsonl"))
	if len(releaseAttestations) != 1 || releaseAttestations[0].ReleaseAssetURL == nil {
		t.Fatalf("expected release attestation link to be attached: %#v", releaseAttestations)
	}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func compareCatalogGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	var compactGot bytes.Buffer
	if err := json.Compact(&compactGot, got); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UPDATE_CATALOG_GOLDEN") == "1" {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, compactGot.Bytes(), "", "  "); err != nil {
			t.Fatal(err)
		}
		pretty.WriteByte('\n')
		if err := os.WriteFile(path, pretty.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	goldenRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var compactWant bytes.Buffer
	if err := json.Compact(&compactWant, goldenRaw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(compactGot.Bytes(), compactWant.Bytes()) {
		t.Fatalf("catalog assembly drift:\n got: %s\nwant: %s", compactGot.Bytes(), compactWant.Bytes())
	}
}
