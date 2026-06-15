// Package versionpolicy is the single source of truth for ClearCutt runtime
// line channels (lts/current/preview/experimental) and the lifecycle labels
// derived from them.
//
// The canonical data lives in core/lib/version-policy.json (read by the Nix
// flake starting in the fleet-compilation work). The copy in this package is a
// byte-identical mirror embedded into the CLI binary so the Go catalog builder
// and the Nix build agree on one classification rather than maintaining two
// hand-written switches. The mirror is enforced against the canonical by
// TestVersionPolicyMirrorMatchesCanonical.
package versionpolicy

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed version-policy.json
var policyJSON []byte

// Channel is a runtime line's support channel.
type Channel string

const (
	ChannelLTS          Channel = "lts"
	ChannelCurrent      Channel = "current"
	ChannelPreview      Channel = "preview"
	ChannelExperimental Channel = "experimental"
)

// Policy is the parsed version policy.
type Policy struct {
	SchemaVersion int                       `json:"schemaVersion"`
	Languages     map[string]LanguagePolicy `json:"languages"`
}

// LanguagePolicy holds one language's per-version channels.
type LanguagePolicy struct {
	// OmitInProduction marks toolchain languages (go/rust/cc) whose runtime is
	// not shipped in production tiers, mirroring registry.nix. Such lines are
	// never productionAllowed even when their channel is otherwise production-
	// eligible, because the production image ships no runtime.
	OmitInProduction bool `json:"omitInProduction,omitempty"`
	// Versions maps a runtime version (e.g. "3.14", "21", "LTS") to its channel.
	Versions map[string]Channel `json:"versions"`
}

// Lifecycle is the classification the catalog builder records per image.
type Lifecycle struct {
	Status            string
	Support           string
	ProductionAllowed bool
}

type lineInfo struct {
	channel          Channel
	omitInProduction bool
}

var (
	loaded      Policy
	loadedIndex map[string]lineInfo
)

func init() {
	if err := json.Unmarshal(policyJSON, &loaded); err != nil {
		// The embedded mirror is validated by tests; a parse failure here means
		// the binary was built with a corrupt policy and cannot classify images.
		panic(fmt.Sprintf("versionpolicy: invalid embedded version-policy.json: %v", err))
	}
	loadedIndex = loaded.lineIndex()
}

// Loaded returns the embedded policy.
func Loaded() Policy { return loaded }

// lineIndex maps a runtime line id (e.g. "python3.14", "coreLTS") to its info.
// The line id is the language name concatenated with the version, matching the
// flake's mkPackageName (`${lang}${ver}`) and the catalog builder's
// gatherLangKey (which strips the trailing -tier segment).
func (p Policy) lineIndex() map[string]lineInfo {
	idx := make(map[string]lineInfo)
	for lang, lp := range p.Languages {
		for ver, ch := range lp.Versions {
			idx[lang+ver] = lineInfo{channel: ch, omitInProduction: lp.OmitInProduction}
		}
	}
	return idx
}

// ChannelFor returns the channel for a runtime line id, and false if the line is
// not described by the policy.
func ChannelFor(line string) (Channel, bool) {
	info, ok := loadedIndex[line]
	if !ok {
		return "", false
	}
	return info.channel, true
}

// Resolve returns the runtime versions a (language, channel) selector maps to,
// optionally unioning the language's preview versions on top. This is the
// resolver behind language-level matrix.languages entries: `{language: java,
// channel: lts}` resolves to java's lts versions, and --allow-preview / the
// fleet's preview toggle additionally unions java's preview versions. Versions
// come back in deterministic sorted order so the generated matrix is stable.
func Resolve(language, channel string, includePreview bool) ([]string, error) {
	lp, ok := loaded.Languages[language]
	if !ok {
		return nil, fmt.Errorf("unknown language %q in version policy (known: %s)", language, strings.Join(knownLanguages(), ", "))
	}
	ch := Channel(channel)
	switch ch {
	case ChannelLTS, ChannelCurrent, ChannelPreview, ChannelExperimental:
	default:
		return nil, fmt.Errorf("invalid channel %q for language %q (use lts, current, preview, or experimental)", channel, language)
	}
	// Languages without an LTS line (e.g. python tracks current; go/rust/cc are
	// experimental toolchains) reject channel: lts with an actionable message
	// rather than silently resolving to nothing.
	if ch == ChannelLTS && len(versionsInChannel(lp, ChannelLTS)) == 0 {
		return nil, fmt.Errorf("language %q has no LTS line; use channel: current", language)
	}

	out := []string{}
	seen := map[string]bool{}
	addChannel := func(want Channel) {
		for _, v := range versionsInChannel(lp, want) {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	addChannel(ch)
	if includePreview && ch != ChannelPreview {
		addChannel(ChannelPreview)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("channel %q selects no versions for language %q", channel, language)
	}
	return out, nil
}

func versionsInChannel(lp LanguagePolicy, want Channel) []string {
	var out []string
	for v, ch := range lp.Versions {
		if ch == want {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func knownLanguages() []string {
	out := make([]string, 0, len(loaded.Languages))
	for l := range loaded.Languages {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// ShipsProductionRuntime reports whether a runtime line ships a runtime in
// production tiers, i.e. it is not a toolchain line marked omitInProduction in
// registry.nix (go/rust/cc compile static binaries; their toolchain is not part
// of the production image). Unknown lines default to true so an unrecognized
// production tier is conservatively gated by the realized-closure checks rather
// than silently dropped from coverage.
func ShipsProductionRuntime(line string) bool {
	info, ok := loadedIndex[line]
	if !ok {
		return true
	}
	return !info.omitInProduction
}

func channelLabels(ch Channel) (status, support string) {
	switch ch {
	case ChannelLTS:
		return "active", "lts"
	case ChannelCurrent:
		return "active", "current"
	case ChannelExperimental:
		return "experimental", "unsupported"
	default: // ChannelPreview and any unknown channel
		return "preview", "preview"
	}
}

func isProductionChannel(ch Channel) bool {
	return ch == ChannelLTS || ch == ChannelCurrent
}

// LifecycleFor classifies a runtime line id at a tier. Unknown lines fall back
// to the conservative preview/preview/not-production default, matching the
// prior hard-coded switch in catalogbuild. Production eligibility requires a
// production channel (lts/current), a non-dev tier, and a runtime that actually
// ships in production (not omitInProduction).
func LifecycleFor(line, tier string) Lifecycle {
	info, ok := loadedIndex[line]
	if !ok {
		return Lifecycle{Status: "preview", Support: "preview", ProductionAllowed: false}
	}
	status, support := channelLabels(info.channel)
	productionAllowed := isProductionChannel(info.channel) && tier != "dev" && !info.omitInProduction
	return Lifecycle{Status: status, Support: support, ProductionAllowed: productionAllowed}
}
