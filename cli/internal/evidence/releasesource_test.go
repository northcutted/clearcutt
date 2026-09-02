package evidence

import (
	"testing"
)

// TestReleaseSourceReadsReleasesFromTheRegistry proves the catalog can be fed
// from a registry instead of GitHub releases, through the interface it already
// used. Nothing in the catalog builder changes.
func TestReleaseSourceReadsReleasesFromTheRegistry(t *testing.T) {
	host := testRegistry(t)
	client := NewInsecureClient()
	repo := host + "/acme/app"

	for _, tag := range []string{"v1.3.0", "v1.4.0"} {
		ref := repo + ":" + tag
		seedImage(t, ref)
		bundle := sampleBundle()
		bundle.Release = tag
		bundle.Created = "2026-09-0" + tag[3:4] + "T00:00:00Z"
		if _, err := client.Attach(ref, bundle); err != nil {
			t.Fatalf("attach %s: %v", tag, err)
		}
	}

	source := NewReleaseSource(client, repo)
	releases, err := source.ListReleases(10)
	if err != nil {
		t.Fatalf("list releases: %v", err)
	}
	if len(releases) != 2 {
		t.Fatalf("expected 2 releases, got %d: %+v", len(releases), releases)
	}
	// Newest first.
	if releases[0].Tag != "v1.4.0" {
		t.Errorf("releases should be newest first, got %s then %s", releases[0].Tag, releases[1].Tag)
	}
	if len(releases[0].Assets) != 3 {
		t.Fatalf("expected 3 evidence assets on v1.4.0, got %+v", releases[0].Assets)
	}
	if releases[0].PublishedAt == "" {
		t.Error("published time should come from the evidence's created annotation")
	}

	// And the content is fetchable through the same interface.
	var sbom []byte
	for _, asset := range releases[0].Assets {
		if asset.Name == "sbom.json" {
			sbom, err = source.DownloadAsset(asset)
			if err != nil {
				t.Fatalf("download sbom: %v", err)
			}
		}
	}
	if len(sbom) == 0 || string(sbom) != `{"spdxVersion":"SPDX-2.3","packages":[]}` {
		t.Errorf("sbom did not round-trip through the release source: %q", sbom)
	}
}

// TestDefaultTagFilterRejectsBookkeeping: a repository carries more than
// releases. Cosign sidecars, the referrers tag fallback, and ClearCutt's own
// history index all live alongside the images, and listing them as product
// releases would put the tool's own plumbing in a customer's catalog.
func TestDefaultTagFilterRejectsBookkeeping(t *testing.T) {
	reject := []string{
		"sha256-22776bb048484801f7a107d45f54ac54b2187aaa64008f2987cf2162b2a3de3b",
		"sha256-abc.sig",
		"history",
	}
	for _, tag := range reject {
		if DefaultTagFilter(tag) {
			t.Errorf("tag %q should not be treated as a release", tag)
		}
	}
	for _, tag := range []string{"v1.4.0", "latest", "2026-09-01", "main"} {
		if !DefaultTagFilter(tag) {
			t.Errorf("tag %q should be treated as a release", tag)
		}
	}
}

func TestAssetRefRoundTrip(t *testing.T) {
	ref := AssetRef("ghcr.io/acme/app", "sha256:abc123", "sbom.json")
	repo, digest, file, err := ParseAssetRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	if repo != "ghcr.io/acme/app" || digest != "sha256:abc123" || file != "sbom.json" {
		t.Fatalf("round trip lost data: repo=%q digest=%q file=%q", repo, digest, file)
	}
	// A reference the catalog might carry from the GitHub era must be rejected
	// rather than silently misparsed.
	if _, _, _, err := ParseAssetRef("https://github.com/acme/app/releases/download/v1/sbom.json"); err == nil {
		t.Error("an http release URL is not an OCI asset reference and should be rejected")
	}
}
