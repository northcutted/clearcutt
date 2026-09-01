package importedfleet

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func nixImage(ref string, storePaths ...string) Observation {
	obs := Observation{SourceRef: ref, ManifestDigest: "sha256:" + ref}
	for _, path := range storePaths {
		obs.History = append(obs.History, HistoryObservation{Comment: "store paths: ['" + path + "']"})
	}
	return obs
}

// TestNixStorePathParsing pins the name/version split. nixpkgs names contain
// hyphens, so splitting on the first hyphen is wrong — the version begins at the
// first hyphen followed by a DIGIT.
func TestNixStorePathParsing(t *testing.T) {
	cases := []struct{ path, name, version string }{
		{"/nix/store/xn70pn0qd5jhdvp5rikgn1yl9bbmyxiq-zlib-1.3.2-static", "zlib", "1.3.2-static"},
		{"/nix/store/g54b6ghpnn98hfdz4yqw87w10c3hx8bv-xgcc-15.2.0-libgcc", "xgcc", "15.2.0-libgcc"},
		// A hyphenated NAME must survive intact.
		{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nss-cacert-3.123", "nss-cacert", "3.123"},
		{"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-glibc-2.42-61", "glibc", "2.42-61"},
		// No version at all.
		{"/nix/store/cccccccccccccccccccccccccccccccc-hello", "hello", ""},
	}
	for _, tc := range cases {
		set := ExtractPackages(nixImage("img", tc.path))
		if len(set.Packages) != 1 {
			t.Fatalf("%s: expected 1 package, got %+v", tc.path, set.Packages)
		}
		pkg := set.Packages[0]
		if pkg.Name != tc.name || pkg.Version != tc.version {
			t.Errorf("%s -> name=%q version=%q, want name=%q version=%q", tc.path, pkg.Name, pkg.Version, tc.name, tc.version)
		}
		if pkg.ID == "" {
			t.Errorf("%s: store hash should be captured as content identity", tc.path)
		}
	}
}

// TestExtractPackagesIsFree is the property that makes first-class Nix support
// affordable: the package set comes out of the image CONFIG, which was already
// fetched to observe the image. No network, no SBOM.
func TestExtractPackagesIsFree(t *testing.T) {
	set := ExtractPackages(nixImage("img",
		"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.2",
		"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-glibc-2.42-61"))
	if set.Source != PackageSourceNixStorePaths {
		t.Fatalf("source = %q, want %q", set.Source, PackageSourceNixStorePaths)
	}
	if len(set.Packages) != 2 {
		t.Fatalf("expected 2 packages, got %+v", set.Packages)
	}
	// An image with no package trail reports UNKNOWN, not zero packages. The
	// difference matters when the answer feeds a vulnerability question.
	empty := ExtractPackages(Observation{SourceRef: "x", History: []HistoryObservation{{CreatedBy: "RUN apt-get install"}}})
	if empty.Source != "" || len(empty.Packages) != 0 {
		t.Errorf("an unreadable image should yield an empty set with no source, got %+v", empty)
	}
}

// TestPackageGraphAnswersTheCVEQuestion is the point of the package view: when a
// CVE lands against a named package at a named version, which images ship it.
func TestPackageGraphAnswersTheCVEQuestion(t *testing.T) {
	obs := Observations{Images: []Observation{
		nixImage("reg/a:v1", "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.2", "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-glibc-2.42"),
		nixImage("reg/b:v1", "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.2", "/nix/store/cccccccccccccccccccccccccccccccc-zlib-1.3"),
		nixImage("reg/c:v1", "/nix/store/dddddddddddddddddddddddddddddddd-openssl-3.6.4"),
	}}
	graph, err := BuildPackageGraph(obs, PackageGraphOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if graph.Summary.Resolved != 3 || graph.Summary.Unresolved != 0 {
		t.Fatalf("all three images should resolve, got %+v", graph.Summary)
	}
	var vulnerable []string
	for _, reach := range graph.Reach {
		if reach.Package.Name == "openssl" && reach.Package.Version == "3.6.2" {
			vulnerable = reach.Images
		}
	}
	if strings.Join(vulnerable, ",") != "reg/a:v1,reg/b:v1" {
		t.Fatalf("openssl 3.6.2 should name exactly the two images carrying it, got %v", vulnerable)
	}
	// The patched image must NOT be swept in by name alone — version matters,
	// and content identity distinguishes two builds of the same version.
	for _, reach := range graph.Reach {
		if reach.Package.Version == "3.6.4" && len(reach.Images) != 1 {
			t.Errorf("openssl 3.6.4 should name only the patched image, got %v", reach.Images)
		}
	}
}

// TestPackageLineageFindsSiblings is the relation base detection cannot give a
// composed estate: images built from overlapping inputs are siblings, and that
// is both true and answerable.
func TestPackageLineageFindsSiblings(t *testing.T) {
	shared := []string{
		"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-glibc-2.42",
		"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-zlib-1.3",
		"/nix/store/cccccccccccccccccccccccccccccccc-openssl-3.6.2",
	}
	obs := Observations{Images: []Observation{
		nixImage("reg/sibling-a:v1", append(append([]string{}, shared...), "/nix/store/dddddddddddddddddddddddddddddddd-jre-25")...),
		nixImage("reg/sibling-b:v1", append(append([]string{}, shared...), "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-jdk-25")...),
		nixImage("reg/unrelated:v1", "/nix/store/ffffffffffffffffffffffffffffffff-busybox-1.36"),
	}}
	graph, err := BuildPackageGraph(obs, PackageGraphOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Lineage) != 1 {
		t.Fatalf("expected exactly one sibling pair, got %+v", graph.Lineage)
	}
	pair := graph.Lineage[0]
	if pair.Shared != 3 {
		t.Errorf("siblings share 3 packages, got %d", pair.Shared)
	}
	if pair.A == "reg/unrelated:v1" || pair.B == "reg/unrelated:v1" {
		t.Error("an image sharing nothing must not appear in lineage")
	}
}

// TestPlanSBOMFetchDeduplicatesByContent is what keeps the expensive path
// affordable. An estate re-tags the same content every release, so the number of
// distinct images is far below the number of tags.
func TestPlanSBOMFetchDeduplicatesByContent(t *testing.T) {
	obs := Observations{}
	for i := 0; i < 10; i++ {
		obs.Images = append(obs.Images, Observation{
			SourceRef:      fmt.Sprintf("reg/app:v%d", i),
			ManifestDigest: "sha256:same-content",
		})
	}
	obs.Images = append(obs.Images, Observation{SourceRef: "reg/other:v1", ManifestDigest: "sha256:different"})
	// A Nix image needs no fetch at all.
	obs.Images = append(obs.Images, nixImage("reg/nix:v1", "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-glibc-2.42"))

	plan := PlanSBOMFetch(obs)
	if plan.Unresolved != 11 {
		t.Errorf("11 images lack a package set, got %d", plan.Unresolved)
	}
	if plan.Fetches != 2 {
		t.Errorf("only 2 distinct contents need fetching, got %d", plan.Fetches)
	}
	if plan.Saved != 9 {
		t.Errorf("deduplication should avoid 9 fetches, got %d", plan.Saved)
	}
}

type fakeSBOMFetcher struct {
	calls int
	body  []byte
	err   error
}

func (f *fakeSBOMFetcher) FetchSBOM(context.Context, string) ([]byte, error) {
	f.calls++
	return f.body, f.err
}

func TestEnrichWithSBOMsFetchesOncePerDistinctContent(t *testing.T) {
	obs := Observations{}
	for i := 0; i < 6; i++ {
		obs.Images = append(obs.Images, Observation{
			SourceRef:      fmt.Sprintf("reg/app:v%d", i),
			DigestRef:      "reg/app@sha256:same",
			ManifestDigest: "sha256:same",
		})
	}
	fetcher := &fakeSBOMFetcher{body: []byte(`{"packages":[{"name":"openssl","versionInfo":"3.6.2"},{"name":"glibc","versionInfo":"2.42"}]}`)}
	enriched, warnings, err := EnrichWithSBOMs(context.Background(), obs, fetcher, 4)
	if err != nil {
		t.Fatal(err)
	}
	if fetcher.calls != 1 {
		t.Errorf("six tags on one content should cost ONE fetch, got %d", fetcher.calls)
	}
	for _, image := range enriched.Images {
		set := ExtractPackages(image)
		if len(set.Packages) != 2 {
			t.Fatalf("every tag should carry the fetched packages, got %+v for %s", set.Packages, image.SourceRef)
		}
	}
	if len(warnings) == 0 {
		t.Error("enrichment should report what it read")
	}
}

func TestEnrichWithSBOMsReportsFailuresAsUnknown(t *testing.T) {
	obs := Observations{Images: []Observation{{SourceRef: "reg/app:v1", DigestRef: "reg/app@sha256:x", ManifestDigest: "sha256:x"}}}
	fetcher := &fakeSBOMFetcher{err: fmt.Errorf("MANIFEST_UNKNOWN")}
	enriched, warnings, err := EnrichWithSBOMs(context.Background(), obs, fetcher, 1)
	if err != nil {
		t.Fatalf("a missing SBOM is not a fatal error: %v", err)
	}
	if len(ExtractPackages(enriched.Images[0]).Packages) != 0 {
		t.Error("a failed fetch must not invent packages")
	}
	joined := strings.Join(warnings, " ")
	if !strings.Contains(joined, "UNKNOWN") {
		t.Errorf("failures must be reported as unknown rather than empty, got %v", warnings)
	}
}

func TestParseSBOMPackagesHandlesBothFormats(t *testing.T) {
	spdx := ParseSBOMPackages([]byte(`{"packages":[{"name":"openssl","versionInfo":"3.6.2"}]}`))
	if len(spdx) != 1 || spdx[0].Name != "openssl" || spdx[0].Version != "3.6.2" {
		t.Errorf("SPDX parse failed: %+v", spdx)
	}
	cyclone := ParseSBOMPackages([]byte(`{"components":[{"name":"glibc","version":"2.42"}]}`))
	if len(cyclone) != 1 || cyclone[0].Name != "glibc" {
		t.Errorf("CycloneDX parse failed: %+v", cyclone)
	}
	if got := ParseSBOMPackages([]byte(`{not json`)); got != nil {
		t.Errorf("malformed SBOM should yield nothing, got %+v", got)
	}
}
