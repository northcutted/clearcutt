package importedfleet

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// syntheticEstate builds an estate where every image shares one universal base
// layer — the shape a well-governed fleet actually has, and the shape that used
// to be pathological: that single layer alone implies C(n, 2) pairs.
func syntheticEstate(images, uniquePerImage int) Observations {
	const familyLayers = 5
	obs := Observations{}
	for i := 0; i < images; i++ {
		layers := []LayerObservation{
			{Digest: "sha256:universal-base-layer", Size: 50 << 20, MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
		}
		// A runtime family shared by half the fleet, so members are genuinely
		// alike and clustering has something to find besides the layer everyone
		// carries. This is the realistic shape: images on a shared base differ
		// by a little, not by most of their content.
		for f := 0; f < familyLayers; f++ {
			layers = append(layers, LayerObservation{
				Digest:    fmt.Sprintf("sha256:family-%d-%d", i%2, f),
				Size:      10 << 20,
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
			})
		}
		for u := 0; u < uniquePerImage; u++ {
			layers = append(layers, LayerObservation{
				Digest:    fmt.Sprintf("sha256:unique-%d-%d", i, u),
				Size:      1 << 20,
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
			})
		}
		obs.Images = append(obs.Images, Observation{
			ID:        fmt.Sprintf("img-%d", i),
			SourceRef: fmt.Sprintf("reg.test/team/app-%d:v1", i),
			Layers:    layers,
		})
	}
	return obs
}

// TestLayerGraphScalesPastTheOldFleetCutoff is the behaviour change. Pairwise
// analysis used to switch off entirely above 500 images, so the similarity and
// cluster views — the reason to run it on a large estate — were exactly what a
// large estate could not have. A budget bounds memory without losing the
// feature.
func TestLayerGraphScalesPastTheOldFleetCutoff(t *testing.T) {
	const images = 2000
	graph, err := BuildLayerGraph(syntheticEstate(images, 1), LayerGraphOptions{})
	if err != nil {
		t.Fatalf("BuildLayerGraph on %d images: %v", images, err)
	}
	if graph.Summary.Images != images {
		t.Fatalf("expected %d images, got %d", images, graph.Summary.Images)
	}
	for _, warning := range graph.Warnings {
		if strings.Contains(warning, "pairwise") && strings.Contains(warning, "skipped") {
			t.Fatalf("pairwise analysis should not switch off at this size: %q", warning)
		}
	}
	// The universal layer is still reported where a wide layer is the answer.
	if graph.Summary.CoreLayers < 1 {
		t.Errorf("the layer every image carries must still be reported as fleet core, got coreLayers=%d", graph.Summary.CoreLayers)
	}
	if len(graph.Similar) == 0 {
		t.Errorf("similarity should still be reported for a 2000-image estate")
	}
}

// TestLayerGraphPairBudgetIsHonoured proves the bound is real rather than
// advisory, and that hitting it is reported rather than silent.
func TestLayerGraphPairBudgetIsHonoured(t *testing.T) {
	graph, err := BuildLayerGraph(syntheticEstate(1000, 2), LayerGraphOptions{MaxPairBudget: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if graph.Summary.PairsCompared > 1000 {
		t.Errorf("pairs compared (%d) exceeded the budget of 1000", graph.Summary.PairsCompared)
	}
	var warned bool
	for _, warning := range graph.Warnings {
		if strings.Contains(warning, "pair budget") {
			warned = true
			if !strings.Contains(warning, "fleet core") {
				t.Errorf("the warning should say the dropped layers are still reported elsewhere, got %q", warning)
			}
		}
	}
	if !warned {
		t.Errorf("reaching the pair budget must be reported, got warnings %v", graph.Warnings)
	}
}

// TestLayerGraphMemoryStaysBounded is the property the budget exists for: a
// universal layer across a large estate must not blow the heap up.
func TestLayerGraphMemoryStaysBounded(t *testing.T) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	if _, err := BuildLayerGraph(syntheticEstate(3000, 2), LayerGraphOptions{}); err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	// Generous: the point is bounded, not tuned. Unbounded C(3000,2) accumulators
	// would be roughly 4.5M entries and blow well past this.
	const limitBytes = 900 << 20
	if grew := after.TotalAlloc - before.TotalAlloc; grew > limitBytes {
		t.Errorf("layer graph over 3000 images allocated %dMB, over the %dMB bound",
			grew>>20, limitBytes>>20)
	}
}
