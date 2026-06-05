// Package rules defines which paths from the live site/ directory belong in the
// portable, embedded Astro catalog template.
//
// It is deliberately free of any //go:embed directive (and of any dependency on
// the parent sitetemplate package) so the template generator can import it
// before the embedded template/ directory exists. The same predicate is shared
// by the generator, the on-disk scaffold copy, and the drift test, so the three
// can never disagree about what the template contains.
package rules

import "strings"

// excludedComponents are path segments that never belong in the template no
// matter where they appear: build artifacts, installed dependencies, and
// VCS/OS noise.
var excludedComponents = map[string]struct{}{
	"node_modules": {},
	"dist":         {},
	".astro":       {},
	".git":         {},
	".DS_Store":    {},
}

// excludedPrefixes are slash-separated path prefixes (relative to site/) that are
// pruned from the template. These hold CLI data-pipeline inputs and
// clearcutt-specific runtime data that a scaffolded site receives separately:
// generated catalog data is copied into public/catalog at scaffold time, while
// SBOM/scan/enrichment inputs under src/data are only consumed by the generator,
// never by the Astro build. Embedding them would bloat the binary to no purpose
// (src/data/sboms alone is ~1GB in this repo).
var excludedPrefixes = []string{
	"src/data",
	"public/catalog",
	"public/vex",
}

// IsExcluded reports whether a path relative to site/ (slash- or OS-separated)
// must be kept out of the embedded template.
func IsExcluded(rel string) bool {
	rel = strings.ReplaceAll(rel, "\\", "/")
	rel = strings.TrimPrefix(rel, "./")
	rel = strings.Trim(rel, "/")
	if rel == "" || rel == "." {
		return false
	}
	for _, part := range strings.Split(rel, "/") {
		if _, bad := excludedComponents[part]; bad {
			return true
		}
	}
	for _, prefix := range excludedPrefixes {
		if rel == prefix || strings.HasPrefix(rel, prefix+"/") {
			return true
		}
	}
	return false
}
