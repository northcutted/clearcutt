package importedfleet

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Package is one installed component of an image.
type Package struct {
	// Name is the package name, e.g. "glibc".
	Name string `json:"name"`
	// Version is the version string where one could be determined.
	Version string `json:"version,omitempty"`
	// ID is a content identity when the source provides one — a Nix store hash
	// pins EXACT bytes, which is stronger than a version string: two images
	// carrying glibc-2.42 may still carry different builds of it.
	ID string `json:"id,omitempty"`
}

// Key is the identity used when comparing images. Content identity wins when
// available, because it is the only one that cannot collide across rebuilds.
func (p Package) Key() string {
	if p.ID != "" {
		return p.ID
	}
	if p.Version != "" {
		return p.Name + "@" + p.Version
	}
	return p.Name
}

// PackageSet is what an image contains, and how we know.
type PackageSet struct {
	// Source records the evidence: "nix-store-paths" is read from the image
	// config at no network cost; "sbom" required fetching an attached document.
	// "" means nothing could be determined.
	Source   string    `json:"source,omitempty"`
	Packages []Package `json:"packages"`
}

// Evidence sources, strongest and cheapest first.
const (
	// PackageSourceNixStorePaths is free. Nix dockerTools writes one history
	// entry per layer naming the store paths that layer carries, so the image
	// CONFIG — already fetched to observe the image at all — contains the exact
	// package set with content hashes. No SBOM, no extra request.
	PackageSourceNixStorePaths = "nix-store-paths"
	// PackageSourceSBOM required fetching an attached SBOM document.
	PackageSourceSBOM = "sbom"
)

// nixStorePath matches /nix/store/<32-char-hash>-<name>. The hash is base32
// over a fixed alphabet and always 32 characters.
var nixStorePath = regexp.MustCompile(`/nix/store/([0-9a-df-np-sv-z]{32})-([^'"\s,\]\[]+)`)

// versionStart finds where a nixpkgs name ends and its version begins: the
// first hyphen followed by a digit. Package names contain hyphens
// ("nss-cacert"), so splitting on the first hyphen would be wrong.
var versionStart = regexp.MustCompile(`-[0-9]`)

// ExtractPackages reads an image's package set from metadata already in the
// observation, at no network cost.
//
// It returns an empty set rather than an error when nothing is readable. That
// is the common case for a builder that leaves no package trail in its config,
// and callers report it as unknown rather than as zero packages — the
// difference matters when the answer feeds a vulnerability question.
func ExtractPackages(obs Observation) PackageSet {
	seen := map[string]Package{}
	source := ""
	for _, entry := range obs.History {
		for _, match := range nixStorePath.FindAllStringSubmatch(entry.Comment, -1) {
			pkg := parseNixStorePath(match[1], match[2])
			seen[pkg.Key()] = pkg
			source = PackageSourceNixStorePaths
		}
		// Packages folded in from a fetched SBOM. Reading these back is what
		// makes the expensive path worth taking; without it the fetch would be
		// performed and then discarded.
		if rest, ok := strings.CutPrefix(entry.Comment, sbomHistoryMarker); ok {
			for _, field := range strings.Fields(rest) {
				name, version, _ := strings.Cut(field, "@")
				if name == "" {
					continue
				}
				pkg := Package{Name: name, Version: version}
				seen[pkg.Key()] = pkg
			}
			if source == "" {
				source = PackageSourceSBOM
			}
		}
	}
	if len(seen) == 0 {
		return PackageSet{}
	}
	packages := make([]Package, 0, len(seen))
	for _, pkg := range seen {
		packages = append(packages, pkg)
	}
	sortPackages(packages)
	return PackageSet{Source: source, Packages: packages}
}

func parseNixStorePath(hash, name string) Package {
	pkg := Package{ID: hash, Name: name}
	if loc := versionStart.FindStringIndex(name); loc != nil {
		pkg.Name = name[:loc[0]]
		pkg.Version = name[loc[0]+1:]
	}
	return pkg
}

func sortPackages(packages []Package) {
	sort.SliceStable(packages, func(i, j int) bool {
		if packages[i].Name != packages[j].Name {
			return packages[i].Name < packages[j].Name
		}
		if packages[i].Version != packages[j].Version {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].ID < packages[j].ID
	})
}

// PackageReach is one package and every image carrying it.
type PackageReach struct {
	Package Package  `json:"package"`
	Images  []string `json:"images"`
	Count   int      `json:"count"`
}

// PackageLineage is a pair of images measured by shared package content.
//
// For composed builders this is the relation that base detection cannot give.
// Two Nix or Wolfi images built from the same inputs are siblings, not
// ancestor and descendant — there is no base to find, but "these were built
// from the same package set" is both true and answerable.
type PackageLineage struct {
	A           string  `json:"a"`
	B           string  `json:"b"`
	Shared      int     `json:"shared"`
	Jaccard     float64 `json:"jaccard"`
	Containment float64 `json:"containment"`
}

// PackageGraph is the package-level view of an estate.
type PackageGraph struct {
	APIVersion  string              `json:"apiVersion"`
	Kind        string              `json:"kind"`
	GeneratedAt string              `json:"generatedAt"`
	Summary     PackageGraphSummary `json:"summary"`
	Reach       []PackageReach      `json:"reach"`
	Lineage     []PackageLineage    `json:"lineage"`
	Warnings    []string            `json:"warnings"`
}

type PackageGraphSummary struct {
	Images int `json:"images"`
	// Resolved counts images whose package set could be read. The gap between
	// this and Images is the honest coverage number.
	Resolved         int            `json:"resolved"`
	Unresolved       int            `json:"unresolved"`
	BySource         map[string]int `json:"bySource"`
	DistinctPackages int            `json:"distinctPackages"`
	SharedPackages   int            `json:"sharedPackages"`
	WidestReach      int            `json:"widestReach"`
	LineagePairs     int            `json:"lineagePairs"`
}

// PackageGraphOptions configures the package view.
type PackageGraphOptions struct {
	GeneratedAt string
	// MinSimilarity is the Jaccard floor for reporting a lineage pair.
	MinSimilarity float64
	// MaxReach caps reported packages, widest first. Zero applies a default.
	MaxReach int
	// MaxPairs caps reported lineage pairs. Zero applies a default.
	MaxPairs int
	// MaxPairBudget bounds pair accumulators, as in the layer graph.
	MaxPairBudget int
}

const (
	defaultPackageMinSimilarity = 0.5
	defaultMaxReach             = 100
	defaultPackageMaxPairs      = 250
)

// BuildPackageGraph computes package reach and lineage from observations.
//
// Every input is metadata already fetched, so this costs no network at all for
// builders that record their package set in the image config — which is the
// case this exists to serve.
func BuildPackageGraph(observations Observations, opts PackageGraphOptions) (PackageGraph, error) {
	graph := PackageGraph{
		APIVersion:  APIVersion,
		Kind:        "PackageGraph",
		GeneratedAt: firstNonEmpty(opts.GeneratedAt, observations.GeneratedAt),
		Summary:     PackageGraphSummary{BySource: map[string]int{}},
		Reach:       []PackageReach{},
		Lineage:     []PackageLineage{},
		Warnings:    []string{},
	}
	minSimilarity := opts.MinSimilarity
	if minSimilarity == 0 {
		minSimilarity = defaultPackageMinSimilarity
	}
	maxReach := opts.MaxReach
	if maxReach == 0 {
		maxReach = defaultMaxReach
	}
	maxPairs := opts.MaxPairs
	if maxPairs == 0 {
		maxPairs = defaultPackageMaxPairs
	}
	budget := opts.MaxPairBudget
	if budget == 0 {
		budget = defaultMaxPairBudget
	}

	sets := map[string]map[string]struct{}{}
	byKey := map[string]Package{}
	carriers := map[string][]string{}
	refs := []string{}

	for _, obs := range observations.Images {
		ref := firstNonEmpty(obs.SourceRef, obs.DigestRef, obs.ID)
		if ref == "" {
			continue
		}
		graph.Summary.Images++
		set := ExtractPackages(obs)
		if len(set.Packages) == 0 {
			graph.Summary.Unresolved++
			continue
		}
		graph.Summary.Resolved++
		graph.Summary.BySource[set.Source]++
		refs = append(refs, ref)
		keys := map[string]struct{}{}
		for _, pkg := range set.Packages {
			key := pkg.Key()
			keys[key] = struct{}{}
			byKey[key] = pkg
			carriers[key] = append(carriers[key], ref)
		}
		sets[ref] = keys
	}
	sort.Strings(refs)

	graph.Summary.DistinctPackages = len(carriers)
	for key, images := range carriers {
		if len(images) > 1 {
			graph.Summary.SharedPackages++
		}
		sort.Strings(images)
		graph.Reach = append(graph.Reach, PackageReach{Package: byKey[key], Images: images, Count: len(images)})
	}
	sort.SliceStable(graph.Reach, func(i, j int) bool {
		if graph.Reach[i].Count != graph.Reach[j].Count {
			return graph.Reach[i].Count > graph.Reach[j].Count
		}
		return graph.Reach[i].Package.Key() < graph.Reach[j].Package.Key()
	})
	if len(graph.Reach) > 0 {
		graph.Summary.WidestReach = graph.Reach[0].Count
	}
	if maxReach > 0 && len(graph.Reach) > maxReach {
		graph.Warnings = append(graph.Warnings, fmt.Sprintf("%d packages present; reporting the %d most widespread", len(graph.Reach), maxReach))
		graph.Reach = graph.Reach[:maxReach]
	}

	pairs, skipped := comparePackagePairs(carriers, sets, minSimilarity, budget)
	graph.Summary.LineagePairs = len(pairs)
	if skipped > 0 {
		graph.Warnings = append(graph.Warnings, fmt.Sprintf(
			"pair budget of %d reached; %d of the most widespread package(s) were excluded from lineage scoring. A package nearly every image carries cannot distinguish any two of them; it is still reported in full under reach.",
			budget, skipped))
	}
	if maxPairs > 0 && len(pairs) > maxPairs {
		graph.Warnings = append(graph.Warnings, fmt.Sprintf("%d lineage pair(s) met the similarity floor; reporting the %d closest", len(pairs), maxPairs))
		pairs = pairs[:maxPairs]
	}
	graph.Lineage = pairs

	if graph.Summary.Unresolved > 0 {
		graph.Warnings = append(graph.Warnings, fmt.Sprintf(
			"%d of %d image(s) record no package set in their config. Their packages are UNKNOWN, not absent — attach or fetch an SBOM to include them.",
			graph.Summary.Unresolved, graph.Summary.Images))
	}
	return graph, nil
}

// comparePackagePairs mirrors the layer graph's budgeted approach: walk the
// package index rather than the image list, narrowest first, so images sharing
// nothing are never compared and a budget drops the packages that could not
// have distinguished anything.
func comparePackagePairs(carriers map[string][]string, sets map[string]map[string]struct{}, minSimilarity float64, budget int) ([]PackageLineage, int) {
	overlap := map[[2]string]int{}
	keys := make([]string, 0, len(carriers))
	for key := range carriers {
		keys = append(keys, key)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		li, lj := len(carriers[keys[i]]), len(carriers[keys[j]])
		if li != lj {
			return li < lj
		}
		return keys[i] < keys[j]
	})
	excluded := map[string]struct{}{}
	skipped := 0
	for _, key := range keys {
		holders := carriers[key]
		if n := len(holders); budget > 0 && n > 1 {
			if adding := n * (n - 1) / 2; len(overlap)+adding > budget {
				skipped++
				excluded[key] = struct{}{}
				continue
			}
		}
		for i := 0; i < len(holders); i++ {
			for j := i + 1; j < len(holders); j++ {
				overlap[[2]string{holders[i], holders[j]}]++
			}
		}
	}

	effective := func(ref string) int {
		size := len(sets[ref])
		if len(excluded) == 0 {
			return size
		}
		for key := range excluded {
			if _, ok := sets[ref][key]; ok {
				size--
			}
		}
		return size
	}

	pairs := make([]PackageLineage, 0, len(overlap))
	for key, shared := range overlap {
		left, right := effective(key[0]), effective(key[1])
		union := left + right - shared
		pair := PackageLineage{A: key[0], B: key[1], Shared: shared}
		if union > 0 {
			pair.Jaccard = round2(float64(shared) / float64(union))
		}
		if smaller := min(left, right); smaller > 0 {
			pair.Containment = round2(float64(shared) / float64(smaller))
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
		if pairs[i].A != pairs[j].A {
			return pairs[i].A < pairs[j].A
		}
		return pairs[i].B < pairs[j].B
	})
	return pairs, skipped
}

// WritePackageGraph writes a package graph to disk.
func WritePackageGraph(path string, graph PackageGraph) error {
	return writeJSON(path, graph)
}
