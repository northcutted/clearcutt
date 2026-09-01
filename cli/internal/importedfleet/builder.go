package importedfleet

import (
	"sort"
	"strings"
)

// Builder identifies how an image was assembled, and — the part that matters
// for provenance — whether that assembler STACKS layers on a base or COMPOSES
// them from a declaration.
//
// The distinction is not cosmetic. Base-image detection rests on layer
// prefixes: a derived image begins with exactly its base's layers, in order.
// That holds for Docker, buildkit and buildpacks, where a build literally
// starts from another image. It does not hold for Nix dockerTools or apko,
// which take a package set and lay it out across layers by size and sharing.
// Two Nix images built from the same nixpkgs share most of their layers and
// neither is a prefix of the other, because neither was built ON the other.
//
// For a composed estate, "no base relationships found" is the correct answer
// rather than a coverage gap, and reporting it as a gap would push an operator
// to hunt for provenance that does not exist. What such an estate has instead
// is shared content — which is what the layer graph measures.
type Builder struct {
	// Name is the assembler: "nix", "apko", "buildkit", "docker",
	// "buildpacks", "debuerreotype", or "" when nothing identifies it.
	Name string `json:"name,omitempty"`
	// Stacks reports whether this builder produces images that begin with a
	// base image's layers. False means base detection cannot apply, and is not
	// a statement about image quality.
	Stacks bool `json:"stacks"`
}

// reproducibleBuildEpochCreated is the timestamp a reproducible builder stamps
// when it refuses to record a real build time. Nix dockerTools uses exactly
// this value.
const reproducibleBuildEpochCreated = "1970-01-01T00:00:01Z"

// DetectBuilder classifies an image from metadata already in an observation —
// labels, history and the created timestamp. It pulls no blobs.
//
// Order matters: the most specific signal wins, because a Nix image can carry
// generic OCI labels and an apko image can carry a plausible-looking history.
func DetectBuilder(obs Observation) Builder {
	// Nix dockerTools writes one history entry per layer, each naming the store
	// paths that layer carries. Nothing else produces that shape.
	for _, entry := range obs.History {
		if strings.Contains(entry.Comment, "/nix/store/") || strings.HasPrefix(entry.Comment, "store paths:") {
			return Builder{Name: "nix", Stacks: false}
		}
	}
	// apko names itself in createdBy, and Chainguard's images carry its labels.
	for _, entry := range obs.History {
		if strings.TrimSpace(entry.CreatedBy) == "apko" {
			return Builder{Name: "apko", Stacks: false}
		}
	}
	for key := range obs.Labels {
		if strings.HasPrefix(key, "dev.chainguard.") {
			return Builder{Name: "apko", Stacks: false}
		}
	}
	// Buildpacks stack on a run image and say so.
	for key := range obs.Labels {
		if strings.HasPrefix(key, "io.buildpacks.") {
			return Builder{Name: "buildpacks", Stacks: true}
		}
	}
	// Docker-lineage builders leave shell commands and buildkit markers.
	for _, entry := range obs.History {
		switch {
		case strings.Contains(entry.Comment, "buildkit.dockerfile"):
			return Builder{Name: "buildkit", Stacks: true}
		case strings.Contains(entry.Comment, "debuerreotype"):
			return Builder{Name: "debuerreotype", Stacks: true}
		case strings.Contains(entry.CreatedBy, "#(nop)"), strings.HasPrefix(entry.CreatedBy, "/bin/sh -c"), strings.HasPrefix(entry.CreatedBy, "RUN "):
			return Builder{Name: "docker", Stacks: true}
		}
	}
	// A reproducible epoch with no other signal still tells us the builder
	// refused to record a build time, which stacking builders do not do.
	if strings.TrimSpace(obs.Created) == reproducibleBuildEpochCreated {
		return Builder{Name: "", Stacks: false}
	}
	// Unknown. Assume stacking, because that is the assumption base detection
	// already makes and this must not silently exempt an image from it.
	return Builder{Name: "", Stacks: true}
}

// BuilderProfile summarises how an estate was built.
type BuilderProfile struct {
	// ByBuilder counts images per named builder; "" means unidentified.
	ByBuilder map[string]int `json:"byBuilder"`
	// Stacking and Composed count images by layering model.
	Stacking int `json:"stacking"`
	Composed int `json:"composed"`
}

// ComposedShare is the fraction of the estate built by non-stacking builders.
func (p BuilderProfile) ComposedShare() float64 {
	total := p.Stacking + p.Composed
	if total == 0 {
		return 0
	}
	return float64(p.Composed) / float64(total)
}

// ProfileBuilders classifies every observation.
func ProfileBuilders(observations Observations) BuilderProfile {
	profile := BuilderProfile{ByBuilder: map[string]int{}}
	for _, obs := range observations.Images {
		builder := DetectBuilder(obs)
		name := builder.Name
		if name == "" {
			name = "unidentified"
		}
		profile.ByBuilder[name]++
		if builder.Stacks {
			profile.Stacking++
		} else {
			profile.Composed++
		}
	}
	return profile
}

// composedEstateThreshold is the share of composed images above which an empty
// base graph should be explained rather than reported as a gap. Set high on
// purpose: a mixed estate still wants its stacking images resolved, and only a
// predominantly composed estate should change how the result reads.
const composedEstateThreshold = 0.75

// ComposedEstateNote returns the explanation to attach to a graph whose base
// detection found little or nothing because the estate is composed rather than
// stacked. It returns "" when the estate is mostly stacking, or when base
// detection worked anyway.
func ComposedEstateNote(profile BuilderProfile, resolved int) string {
	if profile.ComposedShare() < composedEstateThreshold {
		return ""
	}
	if resolved > 0 {
		return ""
	}
	names := []string{}
	for name := range profile.ByBuilder {
		if name != "unidentified" && !builderStacks(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	detail := "a non-stacking builder"
	if len(names) > 0 {
		detail = strings.Join(names, " and ")
	}
	return "No base relationships were found, and for this estate that is the correct answer rather than a gap: " +
		"it is built by " + detail + ", which composes layers from a package set instead of stacking them on a base image. " +
		"There is no base to detect, so provenance here is shared CONTENT rather than ancestry — see the layer view for what these images have in common and which of them one vulnerable layer would reach."
}

// builderStacks reports the layering model for a builder name.
func builderStacks(name string) bool {
	switch name {
	case "nix", "apko":
		return false
	default:
		return true
	}
}
