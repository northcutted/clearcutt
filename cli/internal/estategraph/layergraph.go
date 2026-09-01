package estategraph

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// The layer graph answers a different question from the base graph.
//
// BuildGraph asks "what is this image built on?" — a parentage question, answered by
// layer *order*. BuildLayerGraph asks "what does the fleet have in common?" — a
// content question, answered by layer *membership*. The two are independent: images
// can share almost all their content with no parentage between them (any fleet built
// by Nix dockerTools.buildLayeredImage looks like this), and a parent/child pair can
// share very little if the child rewrites most of the filesystem.
//
// Nothing here implies a base relationship. Shared content means shared exposure —
// which is the question that matters when a package turns out to be vulnerable.
const (
	// defaultCoverageThreshold is the share of the estate a layer must appear in to
	// count as "common" rather than merely shared.
	defaultCoverageThreshold = 0.75
	// defaultMinSimilarity is the Jaccard floor for reporting an image pair and for
	// drawing a cluster edge.
	defaultMinSimilarity = 0.5
	// defaultMaxPairs caps emitted pairs; the pair count is quadratic in fleet size.
	defaultMaxPairs = 250
	// pairwiseImageLimit is a last-resort ceiling on fleet size for pairwise
	// analysis. Content-level commonality (core, coverage, deduplication) stays
	// available above it because it is linear in total layers.
	//
	// It is deliberately far above the point the pair budget starts trimming:
	// the budget bounds memory precisely, so this only catches inputs so large
	// that even building the layer index is unreasonable.
	pairwiseImageLimit = 20000

	// defaultMaxPairBudget bounds the number of pair accumulators held at once.
	//
	// Pair cost is not quadratic in fleet size, it is the sum over layers of
	// C(carriers, 2) — an inverted index, so images that share nothing are never
	// compared. But one layer carried by every image contributes C(N, 2) on its
	// own, and a well-governed estate is exactly the case where that happens:
	// the better the estate, the more images sit on one base, the wider that
	// base's layers reach.
	//
	// A budget is the right control rather than a fleet-size cutoff, because it
	// bounds what actually consumes memory. At roughly 150 bytes per
	// accumulator this is about 225MB worst case.
	defaultMaxPairBudget = 1500000
)

// LayerGraphOptions configures layer-level analysis.
type LayerGraphOptions struct {
	// GeneratedAt pins the timestamp for reproducible output.
	GeneratedAt string
	// CoverageThreshold is the fleet share a layer must reach to be reported as
	// common (0-1). Zero applies the default.
	CoverageThreshold float64
	// MinSimilarity is the Jaccard floor for pair reporting and clustering (0-1).
	// Zero applies the default; a negative value reports every overlapping pair.
	MinSimilarity float64
	// MaxPairs caps emitted image pairs, most similar first. Zero applies the
	// default; a negative value keeps all of them.
	MaxPairs int
	// MaxPairBudget bounds how many pair accumulators are held while scoring
	// similarity. Zero applies the default; a negative value removes the bound.
	// When the budget is reached the widest layers are dropped first, because a
	// layer nearly everything carries cannot tell any two images apart.
	MaxPairBudget int
}

// LayerGraph is the content-commonality view of an observed fleet.
type LayerGraph struct {
	APIVersion  string              `json:"apiVersion"`
	Kind        string              `json:"kind"`
	GeneratedAt string              `json:"generatedAt"`
	Summary     LayerGraphSummary   `json:"summary"`
	Images      []LayerImageProfile `json:"images"`
	Common      []CommonLayer       `json:"common"`
	Identical   []IdenticalGroup    `json:"identical"`
	Clusters    []LayerCluster      `json:"clusters"`
	Similar     []ImagePair         `json:"similar"`
	Warnings    []string            `json:"warnings"`
}

// LayerGraphSummary is the headline count set for the fleet's shared content.
type LayerGraphSummary struct {
	Images            int     `json:"images"`
	DistinctLayers    int     `json:"distinctLayers"`
	SharedLayers      int     `json:"sharedLayers"`
	UniqueLayers      int     `json:"uniqueLayers"`
	CoreLayers        int     `json:"coreLayers"`
	CommonLayers      int     `json:"commonLayers"`
	CoverageThreshold float64 `json:"coverageThreshold"`
	// StoredBytes counts every distinct layer once: what the registry actually holds.
	StoredBytes int64 `json:"storedBytes"`
	// NaiveBytes counts every layer once per carrying image: what the fleet would
	// cost with no sharing at all.
	NaiveBytes int64 `json:"naiveBytes"`
	// SharingRatio is the share of NaiveBytes avoided by layer reuse.
	SharingRatio    float64 `json:"sharingRatio"`
	IdenticalGroups int     `json:"identicalGroups"`
	Clusters        int     `json:"clusters"`
	PairsCompared   int     `json:"pairsCompared"`
	PairsReported   int     `json:"pairsReported"`
}

// LayerImageProfile is how much of one image is its own and how much it borrows.
type LayerImageProfile struct {
	Ref          string  `json:"ref"`
	Layers       int     `json:"layers"`
	SharedLayers int     `json:"sharedLayers"`
	UniqueLayers int     `json:"uniqueLayers"`
	TotalBytes   int64   `json:"totalBytes"`
	SharedBytes  int64   `json:"sharedBytes"`
	UniqueBytes  int64   `json:"uniqueBytes"`
	UniqueShare  float64 `json:"uniqueShare"`
}

// CommonLayer is one layer carried by at least the coverage threshold of the estate.
type CommonLayer struct {
	Digest     string   `json:"digest"`
	Size       int64    `json:"size,omitempty"`
	ImageCount int      `json:"imageCount"`
	Coverage   float64  `json:"coverage"`
	Images     []string `json:"images"`
}

// IdenticalGroup is a set of images with byte-identical layer sets.
//
// This is worth its own section rather than being left as a similarity of 1.0: images
// published under different tags with identical content usually mean a release
// republished something that did not change, and an inventory should say so plainly.
type IdenticalGroup struct {
	LayerCount int      `json:"layerCount"`
	Bytes      int64    `json:"bytes"`
	Images     []string `json:"images"`
}

// LayerCluster is a group of images connected by similarity above the threshold.
type LayerCluster struct {
	ID           int      `json:"id"`
	Images       []string `json:"images"`
	SharedLayers int      `json:"sharedLayers"`
	SharedBytes  int64    `json:"sharedBytes"`
}

// ImagePair is the measured overlap between two images.
type ImagePair struct {
	A            string  `json:"a"`
	B            string  `json:"b"`
	SharedLayers int     `json:"sharedLayers"`
	SharedBytes  int64   `json:"sharedBytes"`
	Jaccard      float64 `json:"jaccard"`
	Containment  float64 `json:"containment"`
}

// BuildLayerGraph derives the fleet's content commonality from observed images.
func BuildLayerGraph(observations Observations, opts LayerGraphOptions) (LayerGraph, error) {
	generatedAt := opts.GeneratedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	coverage := opts.CoverageThreshold
	if coverage == 0 {
		coverage = defaultCoverageThreshold
	}
	if coverage < 0 || coverage > 1 {
		return LayerGraph{}, fmt.Errorf("coverage threshold %.2f is out of range; want 0-1", coverage)
	}
	minSimilarity := opts.MinSimilarity
	if minSimilarity == 0 {
		minSimilarity = defaultMinSimilarity
	}
	if minSimilarity > 1 {
		return LayerGraph{}, fmt.Errorf("minimum similarity %.2f is out of range; want 0-1", minSimilarity)
	}
	maxPairs := opts.MaxPairs
	if maxPairs == 0 {
		maxPairs = defaultMaxPairs
	}

	graph := LayerGraph{
		APIVersion:  APIVersion,
		Kind:        "LayerCommonalityGraph",
		GeneratedAt: generatedAt,
		Summary:     LayerGraphSummary{CoverageThreshold: round2(coverage)},
		Images:      []LayerImageProfile{},
		Common:      []CommonLayer{},
		Identical:   []IdenticalGroup{},
		Clusters:    []LayerCluster{},
		Similar:     []ImagePair{},
		Warnings:    []string{},
	}

	refs, layerSets, sizes := indexObservations(observations)
	graph.Summary.Images = len(refs)
	if len(refs) == 0 {
		graph.Warnings = append(graph.Warnings, "no observations supplied; nothing to analyse")
		return graph, nil
	}

	carriers := map[string][]string{}
	for _, ref := range refs {
		for digest := range layerSets[ref] {
			carriers[digest] = append(carriers[digest], ref)
		}
	}
	for digest := range carriers {
		sort.Strings(carriers[digest])
	}
	graph.Summary.DistinctLayers = len(carriers)

	graph.Common, graph.Summary.CoreLayers, graph.Summary.SharedLayers, graph.Summary.UniqueLayers =
		summariseLayers(carriers, sizes, len(refs), coverage)
	graph.Summary.CommonLayers = len(graph.Common)
	graph.Images = profileImages(refs, layerSets, carriers, sizes)
	graph.Summary.StoredBytes, graph.Summary.NaiveBytes = accountBytes(carriers, sizes)
	if graph.Summary.NaiveBytes > 0 {
		graph.Summary.SharingRatio = round2(1 - float64(graph.Summary.StoredBytes)/float64(graph.Summary.NaiveBytes))
	}
	graph.Identical = groupIdenticalImages(refs, layerSets, sizes)
	graph.Summary.IdenticalGroups = len(graph.Identical)

	if len(refs) > pairwiseImageLimit {
		graph.Warnings = append(graph.Warnings, fmt.Sprintf(
			"pairwise similarity and clustering skipped: %d images exceed the %d-image limit, and the pair count grows quadratically; per-layer coverage and deduplication above are unaffected",
			len(refs), pairwiseImageLimit))
		return graph, nil
	}

	budget := opts.MaxPairBudget
	if budget == 0 {
		budget = defaultMaxPairBudget
	}
	pairs, compared, skippedLayers := comparePairs(carriers, layerSets, sizes, minSimilarity, budget)
	graph.Summary.PairsCompared = compared
	if skippedLayers > 0 {
		graph.Warnings = append(graph.Warnings, fmt.Sprintf(
			"pair budget of %d reached; %d of the widest layer(s) were excluded from similarity scoring. Those layers are carried by so many images that they cannot distinguish any two of them; they are still reported in full as fleet core and blast radius.",
			budget, skippedLayers))
	}
	graph.Clusters = clusterImages(refs, pairs, layerSets, carriers, sizes)
	graph.Summary.Clusters = len(graph.Clusters)
	if maxPairs > 0 && len(pairs) > maxPairs {
		graph.Warnings = append(graph.Warnings, fmt.Sprintf("%d image pairs met the similarity floor; reporting the %d most similar", len(pairs), maxPairs))
		pairs = pairs[:maxPairs]
	}
	graph.Similar = pairs
	graph.Summary.PairsReported = len(pairs)
	return graph, nil
}

// indexObservations reduces observations to sorted refs, layer sets, and layer sizes.
//
// A layer set is deliberately a set: a layer repeated within one image is one piece
// of content, and counting it twice would inflate both overlap and byte accounting.
func indexObservations(observations Observations) ([]string, map[string]map[string]struct{}, map[string]int64) {
	refs := []string{}
	layerSets := map[string]map[string]struct{}{}
	sizes := map[string]int64{}
	for _, obs := range observations.Images {
		normalizeObservation(&obs)
		ref := firstNonEmpty(obs.SourceRef, obs.DigestRef, obs.ID)
		if ref == "" {
			continue
		}
		if _, dup := layerSets[ref]; dup {
			continue
		}
		set := map[string]struct{}{}
		for _, layer := range obs.Layers {
			if layer.Digest == "" {
				continue
			}
			set[layer.Digest] = struct{}{}
			if layer.Size > sizes[layer.Digest] {
				sizes[layer.Digest] = layer.Size
			}
		}
		layerSets[ref] = set
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs, layerSets, sizes
}

// summariseLayers splits layers into common, core, shared, and unique.
func summariseLayers(carriers map[string][]string, sizes map[string]int64, images int, coverage float64) (common []CommonLayer, core, shared, unique int) {
	common = []CommonLayer{}
	for digest, holders := range carriers {
		switch {
		case len(holders) == 1:
			unique++
		default:
			shared++
		}
		if len(holders) == images {
			core++
		}
		if float64(len(holders))/float64(images) >= coverage {
			common = append(common, CommonLayer{
				Digest:     digest,
				Size:       sizes[digest],
				ImageCount: len(holders),
				Coverage:   round2(float64(len(holders)) / float64(images)),
				Images:     holders,
			})
		}
	}
	sort.SliceStable(common, func(i, j int) bool {
		if common[i].ImageCount != common[j].ImageCount {
			return common[i].ImageCount > common[j].ImageCount
		}
		if common[i].Size != common[j].Size {
			return common[i].Size > common[j].Size
		}
		return common[i].Digest < common[j].Digest
	})
	return common, core, shared, unique
}

// profileImages measures how much of each image is content nothing else carries.
func profileImages(refs []string, layerSets map[string]map[string]struct{}, carriers map[string][]string, sizes map[string]int64) []LayerImageProfile {
	out := make([]LayerImageProfile, 0, len(refs))
	for _, ref := range refs {
		profile := LayerImageProfile{Ref: ref, Layers: len(layerSets[ref])}
		for digest := range layerSets[ref] {
			size := sizes[digest]
			profile.TotalBytes += size
			if len(carriers[digest]) > 1 {
				profile.SharedLayers++
				profile.SharedBytes += size
				continue
			}
			profile.UniqueLayers++
			profile.UniqueBytes += size
		}
		if profile.TotalBytes > 0 {
			profile.UniqueShare = round2(float64(profile.UniqueBytes) / float64(profile.TotalBytes))
		}
		out = append(out, profile)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// accountBytes returns what the registry stores versus what the fleet would cost with
// no layer reuse at all.
func accountBytes(carriers map[string][]string, sizes map[string]int64) (stored, naive int64) {
	for digest, holders := range carriers {
		stored += sizes[digest]
		naive += sizes[digest] * int64(len(holders))
	}
	return stored, naive
}

// groupIdenticalImages finds images whose layer sets are exactly equal.
func groupIdenticalImages(refs []string, layerSets map[string]map[string]struct{}, sizes map[string]int64) []IdenticalGroup {
	byFingerprint := map[string][]string{}
	for _, ref := range refs {
		digests := make([]string, 0, len(layerSets[ref]))
		for digest := range layerSets[ref] {
			digests = append(digests, digest)
		}
		sort.Strings(digests)
		fingerprint := ""
		for _, digest := range digests {
			fingerprint += digest + "\n"
		}
		byFingerprint[fingerprint] = append(byFingerprint[fingerprint], ref)
	}
	out := []IdenticalGroup{}
	for fingerprint, group := range byFingerprint {
		if len(group) < 2 || fingerprint == "" {
			continue
		}
		sort.Strings(group)
		entry := IdenticalGroup{LayerCount: len(layerSets[group[0]]), Images: group}
		for digest := range layerSets[group[0]] {
			entry.Bytes += sizes[digest]
		}
		out = append(out, entry)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i].Images) != len(out[j].Images) {
			return len(out[i].Images) > len(out[j].Images)
		}
		return out[i].Images[0] < out[j].Images[0]
	})
	return out
}

// comparePairs measures overlap for every pair that shares at least one layer.
//
// Pairs are generated from the layer index rather than from the image list, so images
// with nothing in common are never compared. On a sparse estate that turns a
// quadratic scan into work proportional to the sharing that actually exists.
func comparePairs(carriers map[string][]string, layerSets map[string]map[string]struct{}, sizes map[string]int64, minSimilarity float64, budget int) ([]ImagePair, int, int) {
	type accumulator struct {
		layers int
		bytes  int64
	}
	overlap := map[[2]string]*accumulator{}
	digests := make([]string, 0, len(carriers))
	for digest := range carriers {
		digests = append(digests, digest)
	}
	// Narrowest layers first, so if the budget runs out the layers dropped are
	// the widest ones — the layers nearly everything carries, which say the
	// least about whether any two images are alike. A layer in every image adds
	// the same constant to every pair's intersection; it cannot separate them.
	// Those layers are still fully reported as fleet core and blast radius,
	// which is where a wide layer is actually the interesting answer.
	sort.SliceStable(digests, func(i, j int) bool {
		li, lj := len(carriers[digests[i]]), len(carriers[digests[j]])
		if li != lj {
			return li < lj
		}
		return digests[i] < digests[j]
	})
	skippedLayers := 0
	excluded := map[string]struct{}{}
	for _, digest := range digests {
		holders := carriers[digest]
		if n := len(holders); budget > 0 && n > 1 {
			// Pairs this layer would add, before inserting any of them.
			if adding := n * (n - 1) / 2; len(overlap)+adding > budget {
				skippedLayers++
				excluded[digest] = struct{}{}
				continue
			}
		}
		for i := 0; i < len(holders); i++ {
			for j := i + 1; j < len(holders); j++ {
				key := [2]string{holders[i], holders[j]}
				item, ok := overlap[key]
				if !ok {
					item = &accumulator{}
					overlap[key] = item
				}
				item.layers++
				item.bytes += sizes[digest]
			}
		}
	}
	// A layer excluded from the intersection must be excluded from the union
	// too, or similarity is measured against layers that were never compared and
	// every score is depressed by the same arbitrary amount. Scoring over the
	// layers that actually discriminate keeps Jaccard meaning what it says.
	effectiveSize := func(ref string) int {
		size := len(layerSets[ref])
		if len(excluded) == 0 {
			return size
		}
		for digest := range excluded {
			if _, ok := layerSets[ref][digest]; ok {
				size--
			}
		}
		return size
	}

	pairs := make([]ImagePair, 0, len(overlap))
	for key, item := range overlap {
		left, right := effectiveSize(key[0]), effectiveSize(key[1])
		union := left + right - item.layers
		pair := ImagePair{A: key[0], B: key[1], SharedLayers: item.layers, SharedBytes: item.bytes}
		if union > 0 {
			pair.Jaccard = round2(float64(item.layers) / float64(union))
		}
		if smaller := min(left, right); smaller > 0 {
			pair.Containment = round2(float64(item.layers) / float64(smaller))
		}
		if pair.Jaccard < minSimilarity {
			continue
		}
		pairs = append(pairs, pair)
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].Jaccard != pairs[j].Jaccard {
			return pairs[i].Jaccard > pairs[j].Jaccard
		}
		if pairs[i].SharedLayers != pairs[j].SharedLayers {
			return pairs[i].SharedLayers > pairs[j].SharedLayers
		}
		if pairs[i].A != pairs[j].A {
			return pairs[i].A < pairs[j].A
		}
		return pairs[i].B < pairs[j].B
	})
	return pairs, len(overlap), skippedLayers
}

// clusterImages groups images into connected components of the similarity graph, then
// reports the content every member of a component holds.
//
// Connectivity, not mutual similarity, is the right grouping here: a cluster answers
// "which images move together when this content changes", and that relation is
// transitive through a shared middle image even when the two ends look unalike.
func clusterImages(refs []string, pairs []ImagePair, layerSets map[string]map[string]struct{}, carriers map[string][]string, sizes map[string]int64) []LayerCluster {
	parent := map[string]string{}
	for _, ref := range refs {
		parent[ref] = ref
	}
	var find func(string) string
	find = func(ref string) string {
		if parent[ref] != ref {
			parent[ref] = find(parent[ref])
		}
		return parent[ref]
	}
	for _, pair := range pairs {
		a, b := find(pair.A), find(pair.B)
		if a != b {
			parent[a] = b
		}
	}
	members := map[string][]string{}
	for _, ref := range refs {
		root := find(ref)
		members[root] = append(members[root], ref)
	}
	out := []LayerCluster{}
	for _, group := range members {
		if len(group) < 2 {
			continue
		}
		sort.Strings(group)
		cluster := LayerCluster{Images: group}
		for digest := range layerSets[group[0]] {
			held := 0
			for _, holder := range carriers[digest] {
				if containsSorted(group, holder) {
					held++
				}
			}
			if held == len(group) {
				cluster.SharedLayers++
				cluster.SharedBytes += sizes[digest]
			}
		}
		out = append(out, cluster)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i].Images) != len(out[j].Images) {
			return len(out[i].Images) > len(out[j].Images)
		}
		return out[i].Images[0] < out[j].Images[0]
	})
	for i := range out {
		out[i].ID = i + 1
	}
	return out
}

func containsSorted(sorted []string, target string) bool {
	i := sort.SearchStrings(sorted, target)
	return i < len(sorted) && sorted[i] == target
}

// round2 keeps reported ratios stable across runs and readable in a report.
func round2(value float64) float64 {
	return math.Round(value*100) / 100
}

// WriteLayerGraph persists a layer graph as JSON.
func WriteLayerGraph(path string, graph LayerGraph) error {
	return writeJSON(path, graph)
}
