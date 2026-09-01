package estate

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Metrics is the handful of numbers that answer "is our governance getting
// better?" — carried in the history index's per-entry annotations so a trend
// can be read with ONE manifest fetch and no blob pulls.
//
// Choosing what belongs here is a product decision, not a serialization one.
// These are the measures that move when someone does the work:
//
//   - Resolved rises as provenance stops being unknown.
//   - Proven rises as that provenance stops resting on self-reported labels.
//     It is the honest metric: a fleet can raise Resolved by adding labels to
//     its own images, but only real layer evidence raises this.
//   - Stale falls as consumers get rebased onto current bases.
//
// Anything not in this list has to be read from the snapshot itself.
type Metrics struct {
	Images     int   `json:"images"`
	Resolved   int   `json:"resolved"`
	Unresolved int   `json:"unresolved"`
	Proven     int   `json:"proven"`
	Stale      int   `json:"stale"`
	Roots      int   `json:"roots"`
	Layers     int   `json:"layers"`
	Shared     int   `json:"shared"`
	StoredMB   int64 `json:"storedMB"`
}

// Annotation keys. They are namespaced so a generic tool listing the index does
// not mistake them for OCI-defined annotations.
const (
	annImages     = "dev.clearcutt.estate.images"
	annResolved   = "dev.clearcutt.estate.resolved"
	annUnresolved = "dev.clearcutt.estate.unresolved"
	annProven     = "dev.clearcutt.estate.proven"
	annStale      = "dev.clearcutt.estate.stale"
	annRoots      = "dev.clearcutt.estate.roots"
	annLayers     = "dev.clearcutt.estate.layers"
	annShared     = "dev.clearcutt.estate.shared_layers"
	annStoredMB   = "dev.clearcutt.estate.stored_mb"
)

// graphSummary mirrors only the fields Metrics needs. It is deliberately a
// separate, tolerant shape rather than a shared type: a snapshot pushed by an
// older CLI must still yield a readable trend, so unknown fields are ignored
// and missing ones stay zero.
type graphSummary struct {
	Summary struct {
		ObservedImages      int            `json:"observedImages"`
		ResolvedConsumers   int            `json:"resolvedConsumers"`
		UnresolvedConsumers int            `json:"unresolvedConsumers"`
		StaleConsumers      int            `json:"staleConsumers"`
		RootImages          int            `json:"rootImages"`
		EdgesByMethod       map[string]int `json:"edgesByMethod"`
	} `json:"summary"`
}

type layerSummary struct {
	Summary struct {
		DistinctLayers int   `json:"distinctLayers"`
		SharedLayers   int   `json:"sharedLayers"`
		StoredBytes    int64 `json:"storedBytes"`
	} `json:"summary"`
}

// MethodLayerPrefix is the one detector whose edges are proof rather than a
// claim the image's author made about itself.
const MethodLayerPrefix = "layer-prefix"

// ExtractMetrics reads the summary numbers out of a snapshot's graph artifacts.
// A snapshot missing either file still yields the metrics it can supply.
func ExtractMetrics(snapshot Snapshot) Metrics {
	var m Metrics
	if raw, ok := snapshot.Files["graph.json"]; ok {
		var g graphSummary
		if err := json.Unmarshal(raw, &g); err == nil {
			m.Images = g.Summary.ObservedImages
			m.Resolved = g.Summary.ResolvedConsumers
			m.Unresolved = g.Summary.UnresolvedConsumers
			m.Stale = g.Summary.StaleConsumers
			m.Roots = g.Summary.RootImages
			m.Proven = g.Summary.EdgesByMethod[MethodLayerPrefix]
		}
	}
	if raw, ok := snapshot.Files["layers.json"]; ok {
		var l layerSummary
		if err := json.Unmarshal(raw, &l); err == nil {
			m.Layers = l.Summary.DistinctLayers
			m.Shared = l.Summary.SharedLayers
			m.StoredMB = l.Summary.StoredBytes >> 20
		}
	}
	return m
}

// Annotations renders the metrics for an index entry.
func (m Metrics) Annotations() map[string]string {
	return map[string]string{
		annImages:     strconv.Itoa(m.Images),
		annResolved:   strconv.Itoa(m.Resolved),
		annUnresolved: strconv.Itoa(m.Unresolved),
		annProven:     strconv.Itoa(m.Proven),
		annStale:      strconv.Itoa(m.Stale),
		annRoots:      strconv.Itoa(m.Roots),
		annLayers:     strconv.Itoa(m.Layers),
		annShared:     strconv.Itoa(m.Shared),
		annStoredMB:   strconv.FormatInt(m.StoredMB, 10),
	}
}

// MetricsFromAnnotations is the inverse, for reading a history index.
func MetricsFromAnnotations(annotations map[string]string) Metrics {
	atoi := func(key string) int {
		n, _ := strconv.Atoi(annotations[key])
		return n
	}
	return Metrics{
		Images:     atoi(annImages),
		Resolved:   atoi(annResolved),
		Unresolved: atoi(annUnresolved),
		Proven:     atoi(annProven),
		Stale:      atoi(annStale),
		Roots:      atoi(annRoots),
		Layers:     atoi(annLayers),
		Shared:     atoi(annShared),
		StoredMB:   int64(atoi(annStoredMB)),
	}
}

// ProvenShare is the share of resolved relationships backed by layer evidence
// rather than a self-reported label. It is the number worth trending: adding
// labels to your own images raises Resolved, but only real evidence raises this.
func (m Metrics) ProvenShare() float64 {
	if m.Resolved == 0 {
		return 0
	}
	return float64(m.Proven) / float64(m.Resolved)
}

// Coverage is the share of observed images whose base is known at all.
func (m Metrics) Coverage() float64 {
	total := m.Resolved + m.Unresolved
	if total == 0 {
		return 0
	}
	return float64(m.Resolved) / float64(total)
}

func (m Metrics) String() string {
	return fmt.Sprintf("images=%d resolved=%d proven=%d stale=%d", m.Images, m.Resolved, m.Proven, m.Stale)
}
