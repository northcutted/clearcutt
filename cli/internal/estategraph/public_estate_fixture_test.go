package estategraph

import (
	"os"
	"path/filepath"
	"testing"
)

// publicEstatePath resolves examples/public-estate from this package directory:
// cli/internal/importedfleet -> cli/internal -> cli -> repo root.
func publicEstatePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "examples", "public-estate", name)
}

// TestPublicEstateFixtureDetectorCoverage pins what the committed snapshot of 19
// real public images actually proves.
//
// Every other test in this package builds its own synthetic observations, which
// makes them precise but circular: they assert the detectors behave as designed
// against data shaped to the design. This one runs the same detectors over
// unmodified registry output from images nobody here built, so a detector that
// only works on hand-made fixtures fails here.
//
// It is also the demo's contract. The README describes what a reader will see;
// if a change alters the findings, this fails and the README has to be updated
// with it rather than quietly going stale.
func TestPublicEstateFixtureDetectorCoverage(t *testing.T) {
	path := publicEstatePath(t, "observations.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("public estate fixture not present: %v", err)
	}
	observations, err := ReadObservations(path)
	if err != nil {
		t.Fatalf("read fixture observations: %v", err)
	}
	if got := len(observations.Images); got != 19 {
		t.Fatalf("fixture should hold 19 observed images, got %d", got)
	}

	graph, err := BuildGraph(observations, GraphOptions{})
	if err != nil {
		t.Fatalf("BuildGraph over the public fixture: %v", err)
	}

	if got := graph.Summary.ResolvedConsumers; got != 3 {
		t.Errorf("expected 3 resolved consumers in the public fixture, got %d", got)
	}
	if got := graph.Summary.UnresolvedConsumers; got != 14 {
		t.Errorf("expected 14 unresolved consumers — absence is a reported state, not a dropped one — got %d", got)
	}

	// Both kinds of evidence must be present, or the fixture stops demonstrating
	// the distinction the ranking exists for.
	wantMethods := map[string]int{MethodLayerPrefix: 2, MethodOCIBaseName: 1}
	for method, want := range wantMethods {
		if got := graph.Summary.EdgesByMethod[method]; got != want {
			t.Errorf("expected %d %s edge(s), got %d (edgesByMethod=%v)", want, method, got, graph.Summary.EdgesByMethod)
		}
	}

	byConsumer := map[string]GraphEdge{}
	for _, edge := range graph.Edges {
		byConsumer[edge.ConsumerRef] = edge
	}

	// Proof: a layer-prefix edge is a fact about bytes and must be verified.
	proven, ok := byConsumer["docker.io/library/node:22-slim"]
	if !ok {
		t.Fatalf("node:22-slim should resolve to debian:bookworm-slim by layer prefix; edges=%v", byConsumer)
	}
	if proven.Method != MethodLayerPrefix || proven.Confidence != "verified" {
		t.Errorf("layer-prefix edge should be verified, got %s/%s", proven.Method, proven.Confidence)
	}

	// Claim: a label-derived edge must NOT be presented as proof.
	claimed, ok := byConsumer["docker.io/bitnami/nginx:latest"]
	if !ok {
		t.Fatalf("bitnami/nginx declares a base name and should resolve; edges=%v", byConsumer)
	}
	if claimed.Method != MethodOCIBaseName {
		t.Errorf("bitnami/nginx should resolve via %s, got %s", MethodOCIBaseName, claimed.Method)
	}
	if claimed.Confidence == "verified" {
		t.Errorf("an edge resting on a label the image author supplied must not claim verified confidence")
	}

	// The finding the README leads with: two tags widely assumed to be aliases
	// sit on different bases, so only one of them is provably current.
	if _, ok := byConsumer["docker.io/library/python:3.12-slim-bookworm"]; !ok {
		t.Errorf("python:3.12-slim-bookworm should prove onto the current debian base")
	}
	if edge, ok := byConsumer["docker.io/library/python:3.12-slim"]; ok {
		t.Errorf("python:3.12-slim was built on an older debian than the tag now points at, so it should NOT resolve; got %s -> %s", edge.Method, edge.BaseRef)
	}
}

// TestPublicEstateFixtureLayerCommonality pins the layer-level view over the
// same real data, including the dedup accounting the estate page reports.
func TestPublicEstateFixtureLayerCommonality(t *testing.T) {
	path := publicEstatePath(t, "observations.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("public estate fixture not present: %v", err)
	}
	observations, err := ReadObservations(path)
	if err != nil {
		t.Fatalf("read fixture observations: %v", err)
	}
	graph, err := BuildLayerGraph(observations, LayerGraphOptions{})
	if err != nil {
		t.Fatalf("BuildLayerGraph over the public fixture: %v", err)
	}
	if graph.Summary.DistinctLayers <= 0 || graph.Summary.SharedLayers <= 0 {
		t.Fatalf("expected shared layers across a real public estate, got %+v", graph.Summary)
	}
	if graph.Summary.SharedLayers >= graph.Summary.DistinctLayers {
		t.Errorf("shared layers (%d) cannot meet or exceed distinct layers (%d)",
			graph.Summary.SharedLayers, graph.Summary.DistinctLayers)
	}
	// A public estate of unrelated vendors has no universal layer. Asserting
	// this keeps "fleet core" honest: it must report zero when nothing is
	// common, rather than a core that does not exist.
	if graph.Summary.CoreLayers != 0 {
		t.Errorf("unrelated public images share no universal layer, got coreLayers=%d", graph.Summary.CoreLayers)
	}
	// Storing shared layers once must be cheaper than storing every copy.
	if graph.Summary.StoredBytes >= graph.Summary.NaiveBytes {
		t.Errorf("dedup accounting is backwards: stored=%d naive=%d", graph.Summary.StoredBytes, graph.Summary.NaiveBytes)
	}
}
