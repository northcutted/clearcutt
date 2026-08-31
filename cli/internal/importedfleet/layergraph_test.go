package importedfleet

import (
	"fmt"
	"strings"
	"testing"
)

// sized builds an observation whose layers carry explicit byte sizes, so the byte
// accounting is asserted against numbers the test states rather than incidental ones.
func sized(ref string, layers map[string]int64, order ...string) Observation {
	o := baseObservation("", ref)
	o.ManifestDigest = "sha256:" + fakeHex(ref)
	o.DigestRef = repositoryOf(ref) + "@" + o.ManifestDigest
	for _, name := range order {
		o.Layers = append(o.Layers, LayerObservation{Digest: "sha256:" + fakeHex(name), Size: layers[name]})
	}
	normalizeObservation(&o)
	return o
}

func layerGraphOf(t *testing.T, opts LayerGraphOptions, images ...Observation) LayerGraph {
	t.Helper()
	if opts.GeneratedAt == "" {
		opts.GeneratedAt = "2026-01-01T00:00:00Z"
	}
	graph, err := BuildLayerGraph(Observations{Images: images}, opts)
	if err != nil {
		t.Fatalf("BuildLayerGraph: %v", err)
	}
	return graph
}

func profileFor(t *testing.T, graph LayerGraph, ref string) LayerImageProfile {
	t.Helper()
	for _, profile := range graph.Images {
		if profile.Ref == ref {
			return profile
		}
	}
	t.Fatalf("no profile for %q in %+v", ref, graph.Images)
	return LayerImageProfile{}
}

func TestBuildLayerGraphIdentifiesTheFleetCore(t *testing.T) {
	sizes := map[string]int64{"core": 100, "a": 10, "b": 20}
	one := sized("reg.test/x/a:v1", sizes, "core", "a")
	two := sized("reg.test/y/b:v1", sizes, "core", "b")

	graph := layerGraphOf(t, LayerGraphOptions{}, one, two)

	if graph.Summary.CoreLayers != 1 {
		t.Fatalf("CoreLayers = %d, want 1", graph.Summary.CoreLayers)
	}
	if graph.Summary.DistinctLayers != 3 {
		t.Fatalf("DistinctLayers = %d, want 3", graph.Summary.DistinctLayers)
	}
	if graph.Summary.SharedLayers != 1 || graph.Summary.UniqueLayers != 2 {
		t.Fatalf("shared/unique = %d/%d, want 1/2", graph.Summary.SharedLayers, graph.Summary.UniqueLayers)
	}
	if len(graph.Common) != 1 || graph.Common[0].Coverage != 1 {
		t.Fatalf("Common = %+v, want the single core layer at full coverage", graph.Common)
	}
}

func TestBuildLayerGraphCoverageThresholdSelectsCommonLayers(t *testing.T) {
	sizes := map[string]int64{"wide": 10, "narrow": 10, "solo": 10}
	a := sized("reg.test/a:v1", sizes, "wide", "narrow")
	b := sized("reg.test/b:v1", sizes, "wide", "narrow")
	c := sized("reg.test/c:v1", sizes, "wide", "solo")
	d := sized("reg.test/d:v1", sizes, "wide")

	// "wide" is in 4/4; "narrow" in 2/4.
	strict := layerGraphOf(t, LayerGraphOptions{CoverageThreshold: 1.0}, a, b, c, d)
	if len(strict.Common) != 1 {
		t.Fatalf("at coverage 1.0 only the universal layer qualifies, got %+v", strict.Common)
	}
	loose := layerGraphOf(t, LayerGraphOptions{CoverageThreshold: 0.5}, a, b, c, d)
	if len(loose.Common) != 2 {
		t.Fatalf("at coverage 0.5 both wide and narrow qualify, got %+v", loose.Common)
	}
	if loose.Common[0].ImageCount < loose.Common[1].ImageCount {
		t.Fatal("common layers must rank widest-coverage first")
	}
}

func TestBuildLayerGraphRejectsOutOfRangeThresholds(t *testing.T) {
	if _, err := BuildLayerGraph(Observations{}, LayerGraphOptions{CoverageThreshold: 1.5}); err == nil {
		t.Fatal("expected a coverage range error")
	}
	if _, err := BuildLayerGraph(Observations{}, LayerGraphOptions{CoverageThreshold: -0.5}); err == nil {
		t.Fatal("expected a coverage range error for a negative value")
	}
	if _, err := BuildLayerGraph(Observations{}, LayerGraphOptions{MinSimilarity: 2}); err == nil {
		t.Fatal("expected a similarity range error")
	}
}

func TestBuildLayerGraphAccountsForSharedAndUniqueBytes(t *testing.T) {
	sizes := map[string]int64{"shared": 1000, "onlyA": 300, "onlyB": 700}
	a := sized("reg.test/a:v1", sizes, "shared", "onlyA")
	b := sized("reg.test/b:v1", sizes, "shared", "onlyB")

	graph := layerGraphOf(t, LayerGraphOptions{}, a, b)

	profile := profileFor(t, graph, "reg.test/a:v1")
	if profile.TotalBytes != 1300 || profile.SharedBytes != 1000 || profile.UniqueBytes != 300 {
		t.Fatalf("profile bytes = %+v, want total 1300 / shared 1000 / unique 300", profile)
	}
	if profile.UniqueShare != 0.23 {
		t.Fatalf("UniqueShare = %.2f, want 0.23", profile.UniqueShare)
	}
	// Stored once: 1000+300+700. Naive: shared counted twice.
	if graph.Summary.StoredBytes != 2000 {
		t.Fatalf("StoredBytes = %d, want 2000", graph.Summary.StoredBytes)
	}
	if graph.Summary.NaiveBytes != 3000 {
		t.Fatalf("NaiveBytes = %d, want 3000", graph.Summary.NaiveBytes)
	}
	if graph.Summary.SharingRatio != 0.33 {
		t.Fatalf("SharingRatio = %.2f, want 0.33", graph.Summary.SharingRatio)
	}
}

func TestBuildLayerGraphGroupsContentIdenticalImages(t *testing.T) {
	sizes := map[string]int64{"one": 100, "two": 200, "other": 50}
	v1 := sized("reg.test/app:v1", sizes, "one", "two")
	v2 := sized("reg.test/app:v2", sizes, "two", "one") // same set, different order
	v3 := sized("reg.test/app:v3", sizes, "one", "other")

	graph := layerGraphOf(t, LayerGraphOptions{}, v1, v2, v3)

	if len(graph.Identical) != 1 {
		t.Fatalf("want one identical group, got %+v", graph.Identical)
	}
	group := graph.Identical[0]
	if len(group.Images) != 2 || group.Images[0] != "reg.test/app:v1" || group.Images[1] != "reg.test/app:v2" {
		t.Fatalf("Images = %v, want v1 and v2 (layer order must not matter)", group.Images)
	}
	if group.LayerCount != 2 || group.Bytes != 300 {
		t.Fatalf("group = %+v, want 2 layers / 300 bytes", group)
	}
	if graph.Summary.IdenticalGroups != 1 {
		t.Fatalf("Summary.IdenticalGroups = %d, want 1", graph.Summary.IdenticalGroups)
	}
}

func TestBuildLayerGraphComputesJaccardAndContainment(t *testing.T) {
	sizes := map[string]int64{"a": 10, "b": 10, "c": 10, "d": 10}
	small := sized("reg.test/small:v1", sizes, "a", "b")
	large := sized("reg.test/large:v1", sizes, "a", "b", "c", "d")

	graph := layerGraphOf(t, LayerGraphOptions{MinSimilarity: -1}, small, large)

	if len(graph.Similar) != 1 {
		t.Fatalf("want one pair, got %+v", graph.Similar)
	}
	pair := graph.Similar[0]
	if pair.SharedLayers != 2 || pair.SharedBytes != 20 {
		t.Fatalf("pair overlap = %d layers / %d bytes, want 2/20", pair.SharedLayers, pair.SharedBytes)
	}
	// Union is 4, so jaccard 0.5; the smaller set is wholly contained, so 1.00.
	if pair.Jaccard != 0.5 {
		t.Fatalf("Jaccard = %.2f, want 0.50", pair.Jaccard)
	}
	if pair.Containment != 1 {
		t.Fatalf("Containment = %.2f, want 1.00", pair.Containment)
	}
}

func TestBuildLayerGraphMinSimilarityFiltersWeakPairs(t *testing.T) {
	sizes := map[string]int64{"a": 10, "b": 10, "c": 10, "d": 10, "e": 10}
	a := sized("reg.test/a:v1", sizes, "a", "b", "c")
	b := sized("reg.test/b:v1", sizes, "a", "d", "e")

	// Shared 1 of union 5 = 0.2.
	loose := layerGraphOf(t, LayerGraphOptions{MinSimilarity: 0.1}, a, b)
	if len(loose.Similar) != 1 {
		t.Fatalf("pair should survive a 0.1 floor, got %+v", loose.Similar)
	}
	strict := layerGraphOf(t, LayerGraphOptions{MinSimilarity: 0.5}, a, b)
	if len(strict.Similar) != 0 {
		t.Fatalf("pair should be filtered by a 0.5 floor, got %+v", strict.Similar)
	}
	if len(strict.Clusters) != 0 {
		t.Fatalf("no pair means no cluster, got %+v", strict.Clusters)
	}
	// Pairs are still counted as compared even when filtered from the report.
	if strict.Summary.PairsCompared != 1 {
		t.Fatalf("PairsCompared = %d, want 1", strict.Summary.PairsCompared)
	}
}

func TestBuildLayerGraphClustersAreTransitive(t *testing.T) {
	sizes := map[string]int64{"ab": 10, "bc": 10, "a": 10, "c": 10, "far": 10}
	// a—b share "ab", b—c share "bc", a and c share nothing directly.
	a := sized("reg.test/a:v1", sizes, "ab", "a")
	b := sized("reg.test/b:v1", sizes, "ab", "bc")
	c := sized("reg.test/c:v1", sizes, "bc", "c")
	lonely := sized("reg.test/lonely:v1", sizes, "far")

	graph := layerGraphOf(t, LayerGraphOptions{MinSimilarity: 0.3}, a, b, c, lonely)

	if len(graph.Clusters) != 1 {
		t.Fatalf("want a single transitive cluster, got %+v", graph.Clusters)
	}
	cluster := graph.Clusters[0]
	if len(cluster.Images) != 3 {
		t.Fatalf("cluster should reach c through b, got %v", cluster.Images)
	}
	// No layer is held by all three, so nothing is common to the whole cluster.
	if cluster.SharedLayers != 0 {
		t.Fatalf("SharedLayers = %d, want 0", cluster.SharedLayers)
	}
	for _, ref := range cluster.Images {
		if ref == "reg.test/lonely:v1" {
			t.Fatal("an image sharing nothing must not join a cluster")
		}
	}
}

func TestBuildLayerGraphClusterReportsLayersCommonToEveryMember(t *testing.T) {
	sizes := map[string]int64{"core": 500, "a": 10, "b": 10}
	a := sized("reg.test/a:v1", sizes, "core", "a")
	b := sized("reg.test/b:v1", sizes, "core", "b")

	graph := layerGraphOf(t, LayerGraphOptions{MinSimilarity: 0.3}, a, b)

	if len(graph.Clusters) != 1 {
		t.Fatalf("want one cluster, got %+v", graph.Clusters)
	}
	if graph.Clusters[0].SharedLayers != 1 || graph.Clusters[0].SharedBytes != 500 {
		t.Fatalf("cluster common content = %d layers / %d bytes, want 1/500", graph.Clusters[0].SharedLayers, graph.Clusters[0].SharedBytes)
	}
	if graph.Clusters[0].ID != 1 {
		t.Fatalf("cluster IDs should start at 1, got %d", graph.Clusters[0].ID)
	}
}

func TestBuildLayerGraphMaxPairsCapsReportingNotClustering(t *testing.T) {
	sizes := map[string]int64{"core": 10}
	images := []Observation{}
	for i := 0; i < 5; i++ {
		images = append(images, sized(fmt.Sprintf("reg.test/a%d:v1", i), sizes, "core"))
	}
	graph := layerGraphOf(t, LayerGraphOptions{MaxPairs: 3}, images...)

	if len(graph.Similar) != 3 {
		t.Fatalf("want the pair report capped at 3, got %d", len(graph.Similar))
	}
	if graph.Summary.PairsReported != 3 {
		t.Fatalf("PairsReported = %d, want 3", graph.Summary.PairsReported)
	}
	// All five images share the core layer, so clustering must still see them all.
	if len(graph.Clusters) != 1 || len(graph.Clusters[0].Images) != 5 {
		t.Fatalf("the cap must not shrink clusters, got %+v", graph.Clusters)
	}
	if len(graph.Warnings) == 0 {
		t.Fatal("expected a warning naming the cap")
	}
}

func TestBuildLayerGraphNegativeMaxPairsKeepsEveryPair(t *testing.T) {
	sizes := map[string]int64{"core": 10}
	images := []Observation{}
	for i := 0; i < 4; i++ {
		images = append(images, sized(fmt.Sprintf("reg.test/a%d:v1", i), sizes, "core"))
	}
	graph := layerGraphOf(t, LayerGraphOptions{MaxPairs: -1}, images...)
	if len(graph.Similar) != 6 {
		t.Fatalf("want all 6 pairs, got %d", len(graph.Similar))
	}
}

func TestBuildLayerGraphCountsARepeatedLayerOnceWithinAnImage(t *testing.T) {
	sizes := map[string]int64{"dup": 100, "other": 50}
	repeated := sized("reg.test/a:v1", sizes, "dup", "dup", "other")
	single := sized("reg.test/b:v1", sizes, "dup")

	graph := layerGraphOf(t, LayerGraphOptions{}, repeated, single)

	profile := profileFor(t, graph, "reg.test/a:v1")
	if profile.Layers != 2 {
		t.Fatalf("Layers = %d, want 2 distinct layers", profile.Layers)
	}
	if profile.TotalBytes != 150 {
		t.Fatalf("TotalBytes = %d, want 150 (a repeated layer is one piece of content)", profile.TotalBytes)
	}
}

func TestBuildLayerGraphEmptyObservationsWarnRatherThanError(t *testing.T) {
	graph, err := BuildLayerGraph(Observations{}, LayerGraphOptions{GeneratedAt: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("BuildLayerGraph: %v", err)
	}
	if len(graph.Warnings) == 0 {
		t.Fatal("expected a warning for an empty observation set")
	}
	if graph.Summary.Images != 0 {
		t.Fatalf("Images = %d, want 0", graph.Summary.Images)
	}
}

func TestBuildLayerGraphSkipsDuplicateReferences(t *testing.T) {
	sizes := map[string]int64{"a": 10}
	first := sized("reg.test/a:v1", sizes, "a")
	dupe := sized("reg.test/a:v1", sizes, "a")

	graph := layerGraphOf(t, LayerGraphOptions{}, first, dupe)

	if graph.Summary.Images != 1 {
		t.Fatalf("Images = %d, want the duplicate reference collapsed", graph.Summary.Images)
	}
}

func TestBuildLayerGraphIsDeterministic(t *testing.T) {
	sizes := map[string]int64{"core": 10, "a": 10, "b": 10}
	a := sized("reg.test/a:v1", sizes, "core", "a")
	b := sized("reg.test/b:v1", sizes, "core", "b")
	c := sized("reg.test/c:v1", sizes, "core")

	first := layerGraphOf(t, LayerGraphOptions{}, a, b, c)
	second := layerGraphOf(t, LayerGraphOptions{}, c, a, b)

	if fmt.Sprint(first.Similar) != fmt.Sprint(second.Similar) {
		t.Fatalf("pair ordering is input-dependent:\n%v\n%v", first.Similar, second.Similar)
	}
	if fmt.Sprint(first.Clusters) != fmt.Sprint(second.Clusters) {
		t.Fatalf("cluster ordering is input-dependent:\n%v\n%v", first.Clusters, second.Clusters)
	}
	if fmt.Sprint(first.Common) != fmt.Sprint(second.Common) {
		t.Fatalf("common-layer ordering is input-dependent:\n%v\n%v", first.Common, second.Common)
	}
}

func TestLayerGraphMarkdownLeadsWithIdenticalContent(t *testing.T) {
	sizes := map[string]int64{"one": 100, "two": 200}
	v1 := sized("reg.test/app:v1", sizes, "one", "two")
	v2 := sized("reg.test/app:v2", sizes, "one", "two")

	md := LayerGraphMarkdown(layerGraphOf(t, LayerGraphOptions{}, v1, v2))

	for _, want := range []string{
		"# Fleet Layer Commonality",
		"## Content-identical images",
		"a release republished something that did not change",
		"Shared layers are shared content, never a base-image relationship",
		"not installed footprint on disk",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("report missing %q:\n%s", want, md)
		}
	}
}

func TestLayerGraphMarkdownStatesWhenThereIsNoUniversalCore(t *testing.T) {
	sizes := map[string]int64{"a": 10, "b": 10}
	one := sized("reg.test/a:v1", sizes, "a")
	two := sized("reg.test/b:v1", sizes, "b")

	md := LayerGraphMarkdown(layerGraphOf(t, LayerGraphOptions{}, one, two))

	if !strings.Contains(md, "No layer reaches the 75% coverage threshold") {
		t.Fatalf("expected the empty-core statement:\n%s", md)
	}
	if !strings.Contains(md, "No two observed images carry exactly the same layer set.") {
		t.Fatalf("expected the empty-identical statement:\n%s", md)
	}
}

func TestLayerGraphMermaidDrawsClustersAndEdges(t *testing.T) {
	sizes := map[string]int64{"core": 10, "a": 10, "b": 10}
	a := sized("reg.test/team/alpha:v1", sizes, "core", "a")
	b := sized("reg.test/team/beta:v1", sizes, "core", "b")

	graph := layerGraphOf(t, LayerGraphOptions{MinSimilarity: 0.3}, a, b)
	diagram := LayerGraphMermaid(graph)

	for _, want := range []string{"```mermaid", "graph LR", "subgraph cluster1", "alpha:v1", "beta:v1", "---|\"1\"|"} {
		if !strings.Contains(diagram, want) {
			t.Fatalf("diagram missing %q:\n%s", want, diagram)
		}
	}
}

func TestLayerGraphMermaidIsEmptyWithoutClusters(t *testing.T) {
	sizes := map[string]int64{"a": 10, "b": 10}
	one := sized("reg.test/a:v1", sizes, "a")
	two := sized("reg.test/b:v1", sizes, "b")

	if diagram := LayerGraphMermaid(layerGraphOf(t, LayerGraphOptions{}, one, two)); diagram != "" {
		t.Fatalf("want no diagram when nothing is connected, got:\n%s", diagram)
	}
}

func TestMermaidLabelNeutralisesBreakingCharacters(t *testing.T) {
	got := mermaidLabel(`we"ird[label]{x}`)
	for _, banned := range []string{`"`, "[", "]", "{", "}"} {
		if strings.Contains(got, banned) {
			t.Fatalf("label %q still contains %q", got, banned)
		}
	}
}

func TestHumanBytesScalesUnits(t *testing.T) {
	cases := map[int64]string{0: "—", 512: "512 B", 2048: "2 KB", 5 * 1024 * 1024: "5.0 MB", 3 * 1024 * 1024 * 1024: "3.00 GB"}
	for size, want := range cases {
		if got := humanBytes(size); got != want {
			t.Fatalf("humanBytes(%d) = %q, want %q", size, got, want)
		}
	}
}

func TestCapRowsReportsElision(t *testing.T) {
	if shown, elided := capRows(5, 10); shown != 5 || elided != 0 {
		t.Fatalf("capRows(5,10) = %d,%d", shown, elided)
	}
	if shown, elided := capRows(30, 10); shown != 10 || elided != 20 {
		t.Fatalf("capRows(30,10) = %d,%d", shown, elided)
	}
}

func TestBuildLayerGraphSkipsPairwiseAboveTheImageLimit(t *testing.T) {
	// The pair count is quadratic in fleet size, so past a limit the pairwise legs
	// are skipped. Content-level commonality is linear and must survive.
	sizes := map[string]int64{"core": 10}
	images := make([]Observation, 0, pairwiseImageLimit+1)
	for i := 0; i <= pairwiseImageLimit; i++ {
		images = append(images, sized(fmt.Sprintf("reg.test/a%04d:v1", i), sizes, "core"))
	}
	graph := layerGraphOf(t, LayerGraphOptions{}, images...)

	if len(graph.Similar) != 0 || len(graph.Clusters) != 0 {
		t.Fatalf("pairwise work must be skipped above the limit, got %d pairs / %d clusters", len(graph.Similar), len(graph.Clusters))
	}
	if graph.Summary.CoreLayers != 1 {
		t.Fatalf("CoreLayers = %d, want the core still computed", graph.Summary.CoreLayers)
	}
	if graph.Summary.SharingRatio == 0 {
		t.Fatal("deduplication accounting must still be computed above the limit")
	}
	if len(graph.Warnings) == 0 || !strings.Contains(strings.Join(graph.Warnings, " "), "quadratically") {
		t.Fatalf("expected a warning explaining the skip, got %v", graph.Warnings)
	}
}
