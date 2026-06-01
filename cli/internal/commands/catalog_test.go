package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
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

type fakeCatalogReleaseSource struct {
	assets    map[string][]byte
	downloads []string
}

func (f *fakeCatalogReleaseSource) ListReleases(limit int) ([]catalogRelease, error) {
	return nil, nil
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
