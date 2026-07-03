// Package fixprobe answers, for one CVE-affected package, who in nixpkgs
// carries the scanner's fixed version, whether that source is Hydra-cached,
// and how risky an in-place override would be. It is the live counterpart to
// the static route classifier in internal/commands (remediation_route.go):
// the classifier reads committed policy data, the probe reads nixpkgs itself.
//
// Degradation is first-class — per-ref fetch failures are recorded on the
// result, never returned — because the triage layer's contract is to fall
// back to the static classification; the probe can never block planning.
package fixprobe

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SchemaVersion identifies the Availability JSON contract embedded in triage
// reports and decision-record probe snapshots.
const SchemaVersion = "clearcutt.fixprobe/v1"

// Ref kinds. Only channels are Hydra-cached: a fix pulled from a channel is
// substitutable; a fix pulled from a bare branch is a from-source build.
const (
	RefKindChannel = "channel"
	RefKindBranch  = "branch"
	RefKindPin     = "pin"
)

// Override-risk levels. The diff behind them is a heuristic (line-level, not
// semantic), and every reason string says so.
const (
	RiskLow     = "low"
	RiskHigh    = "high"
	RiskUnknown = "unknown"
)

// Fetcher abstracts the nixpkgs file fetch so tests inject fixtures and the
// probe degrades gracefully offline. The default implementation uses the
// GitHub contents API (GITHUB_TOKEN/GH_TOKEN honored, unauthenticated
// fallback).
type Fetcher interface {
	// FileAt returns the raw file content at a nixpkgs ref (branch name or rev).
	FileAt(ctx context.Context, path, ref string) ([]byte, error)
}

// Input describes one probe. SourcePath is resolved by the caller (the triage
// command evaluates meta.position against the local pin); the probe itself
// never shells out, keeping it unit-testable.
type Input struct {
	Package          string // display name, e.g. "openssl"
	SourcePath       string // repo-relative nixpkgs path, e.g. "pkgs/development/libraries/openssl/default.nix"
	PinRev           string // locked rev of the pin that currently sources the package
	PinName          string // flake input name, e.g. "nixpkgs" / "nixpkgs-node"
	InstalledVersion string
	FixedVersion     string // scanner-reported fixed version
	Refs             []Ref  // refs to sweep; DefaultRefs when empty
	// Now stamps ProbedAt so callers keep the probe deterministic; the wall
	// clock is consulted only when zero.
	Now time.Time
}

// Ref is one nixpkgs ref to sweep.
type Ref struct {
	Name string // "nixos-unstable", "master", "staging-next", "nixos-25.11"
	Kind string // "channel" (Hydra-cached) | "branch" (not cached) | "pin"
}

// RefStatus is the probe outcome for one ref.
type RefStatus struct {
	Ref         string `json:"ref"`
	Kind        string `json:"kind"`
	Version     string `json:"version,omitempty"` // extracted; "" = indeterminate
	HasFix      bool   `json:"hasFix"`
	HydraCached bool   `json:"hydraCached"`
	Error       string `json:"error,omitempty"` // per-ref fetch failure, non-fatal
}

// OverrideRisk grades an in-place version override of the pinned derivation
// against the nearest fix-carrying ref.
type OverrideRisk struct {
	Level        string `json:"level"`        // "low" | "high" | "unknown"
	ChangedLines int    `json:"changedLines"` // non-version/hash lines changed pin→fix
	Reason       string `json:"reason"`
}

// Availability is the probe report: who carries the fix, whether that source
// is substitutable, and how risky an override is. PinHasFix is the retirement
// predicate for rebuild overlays and unstable opt-ins.
type Availability struct {
	SchemaVersion string `json:"schemaVersion"` // "clearcutt.fixprobe/v1"
	Package       string `json:"package"`
	SourcePath    string `json:"sourcePath"`
	FixedVersion  string `json:"fixedVersion"`
	// PinName echoes which flake input the pin sweep probed (e.g. "nixpkgs",
	// "nixpkgs-node") so a report reader can tell WHICH pin PinHasFix speaks for
	// — dedicated-pin runtimes retire against their own pin, not the main one.
	PinName      string        `json:"pinName,omitempty"`
	PinHasFix    bool          `json:"pinHasFix"`
	Refs         []RefStatus   `json:"refs"`
	OverrideRisk *OverrideRisk `json:"overrideRisk,omitempty"` // vs the nearest fix-carrying ref
	ProbedAt     string        `json:"probedAt"`
	Degraded     bool          `json:"degraded"` // probe partially/fully unavailable
}

// DefaultRefs is the sweep used when Input.Refs is empty, mirroring the fleet
// default (remediation.probe.refs): the Hydra-cached unstable channel first,
// then the branches a fix reaches before any channel does. Callers append
// their configured stable channel when one is set.
func DefaultRefs() []Ref {
	return []Ref{
		{Name: "nixos-unstable", Kind: RefKindChannel},
		{Name: "master", Kind: RefKindBranch},
		{Name: "staging-next", Kind: RefKindBranch},
	}
}

// Probe sweeps the pin rev plus the configured refs and reports fix
// availability. It is pure given its Fetcher: no exec, and no wall-clock read
// beyond the Now default. Per-ref fetch failures land on RefStatus.Error and
// flip Degraded — they never fail the call.
func Probe(ctx context.Context, f Fetcher, in Input) (*Availability, error) {
	if f == nil {
		return nil, fmt.Errorf("fixprobe: Fetcher is required")
	}
	if strings.TrimSpace(in.SourcePath) == "" {
		return nil, fmt.Errorf("fixprobe: SourcePath is required")
	}
	if strings.TrimSpace(in.PinRev) == "" {
		return nil, fmt.Errorf("fixprobe: PinRev is required")
	}
	if strings.TrimSpace(in.FixedVersion) == "" {
		return nil, fmt.Errorf("fixprobe: FixedVersion is required")
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	refs := in.Refs
	if len(refs) == 0 {
		refs = DefaultRefs()
	}
	// The pin rev is always probed first: PinHasFix is what retires rebuild
	// overlays and opt-ins, so it must be answered even on a custom sweep.
	sweep := make([]Ref, 0, len(refs)+1)
	sweep = append(sweep, Ref{Name: in.PinRev, Kind: RefKindPin})
	for _, ref := range refs {
		if strings.TrimSpace(ref.Name) == "" {
			continue
		}
		if ref.Kind == "" {
			ref.Kind = RefKindBranch
		}
		sweep = append(sweep, ref)
	}

	avail := &Availability{
		SchemaVersion: SchemaVersion,
		Package:       in.Package,
		SourcePath:    in.SourcePath,
		FixedVersion:  in.FixedVersion,
		PinName:       in.PinName,
		ProbedAt:      now.UTC().Format(time.RFC3339),
	}
	bodies := make([][]byte, len(sweep))
	for i, ref := range sweep {
		status := RefStatus{Ref: ref.Name, Kind: ref.Kind, HydraCached: ref.Kind == RefKindChannel}
		body, err := f.FileAt(ctx, in.SourcePath, ref.Name)
		if err != nil {
			status.Error = err.Error()
			avail.Degraded = true
		} else {
			bodies[i] = body
			status.Version = extractVersion(body, in.InstalledVersion)
			status.HasFix = status.Version != "" && CompareVersions(status.Version, in.FixedVersion) >= 0
		}
		avail.Refs = append(avail.Refs, status)
	}
	avail.PinHasFix = avail.Refs[0].HasFix

	// Override risk only matters when the pin lacks the fix and another ref
	// carries it. An errored pin fetch leaves nothing to diff against, so the
	// risk is honestly unknown rather than assumed low.
	if !avail.PinHasFix {
		if idx := nearestFixIdx(avail.Refs); idx > 0 {
			if bodies[0] == nil {
				avail.OverrideRisk = &OverrideRisk{Level: RiskUnknown, Reason: "pin-rev source file could not be fetched; override risk not assessable"}
			} else {
				avail.OverrideRisk = diffOverrideRisk(bodies[0], bodies[idx], in.PinRev, sweep[idx].Name)
			}
		}
	}
	return avail, nil
}

// nearestFixIdx picks the fix-carrying ref an override would be diffed
// against: the first Hydra-cached one in sweep order, else the first of any
// kind — cached refs win because they are also the refs a pin-hop would use.
// 0 (the pin slot) doubles as "none".
func nearestFixIdx(refs []RefStatus) int {
	for i := 1; i < len(refs); i++ {
		if refs[i].HasFix && refs[i].HydraCached {
			return i
		}
	}
	for i := 1; i < len(refs); i++ {
		if refs[i].HasFix {
			return i
		}
	}
	return 0
}

var (
	versionAssignRe  = regexp.MustCompile(`(?m)^\s*version\s*=\s*"([^"]*)"\s*;`)
	versionLiteralRe = regexp.MustCompile(`^[0-9][0-9A-Za-z.+~_-]*$`)
	// exemptAssignRe matches the assignments that legitimately change on every
	// version bump; anything else that differs is patch-set/build-logic churn.
	exemptAssignRe = regexp.MustCompile(`^\s*(version|hash|sha256|sha512|outputHash)\s*=`)
)

// extractVersion pulls the version a nixpkgs file would build. Single-version
// files are taken at face value. Multi-version files (openssl carries
// 3.0/3.5/3.6 side by side) are anchored to the installed version's
// major.minor; anything short of exactly one confident match returns "" —
// honest, not guessed — which downstream means HasFix false.
func extractVersion(content []byte, installedVersion string) string {
	var candidates []string
	seen := map[string]bool{}
	for _, m := range versionAssignRe.FindAllSubmatch(content, -1) {
		v := string(m[1])
		// Interpolations ("${...}") and other non-literal assignments are not
		// versions this probe can reason about.
		if !versionLiteralRe.MatchString(v) || seen[v] {
			continue
		}
		seen[v] = true
		candidates = append(candidates, v)
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	anchor := majorMinor(installedVersion)
	if anchor == "" {
		return ""
	}
	matched := ""
	for _, v := range candidates {
		if majorMinor(v) != anchor {
			continue
		}
		if matched != "" {
			return "" // two stanzas on the installed line: ambiguous
		}
		matched = v
	}
	return matched
}

// majorMinor reduces a version to its numeric major.minor line ("3.6.2" ->
// "3.6", "24" -> "24"); "" when the version does not start numerically.
func majorMinor(version string) string {
	parts := strings.SplitN(strings.TrimPrefix(strings.TrimSpace(version), "v"), ".", 3)
	major := leadingDigits(parts[0])
	if major == "" {
		return ""
	}
	if len(parts) == 1 {
		return major
	}
	minor := leadingDigits(parts[1])
	if minor == "" {
		return major
	}
	return major + "." + minor
}

// CompareVersions is the lenient, semver-ish ordering HasFix relies on:
// dot-separated segments compare numerically on their leading digits, then by
// suffix rank, so "1.1.1w" > "1.1.1v" and "3.0.13+quic" > "3.0.13" while
// "3.7.0-rc1" < "3.7.0" — a ref carrying only a pre-release must not count as
// carrying the fix. Missing segments count as zero ("3.6" == "3.6.0"). It
// exists because nixpkgs version strings are not strict semver; a strict
// parser would reject exactly the suffixed packages this probe is for.
func CompareVersions(a, b string) int {
	as := strings.Split(strings.TrimPrefix(strings.TrimSpace(a), "v"), ".")
	bs := strings.Split(strings.TrimPrefix(strings.TrimSpace(b), "v"), ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var sa, sb versionSegment
		if i < len(as) {
			sa = parseVersionSegment(as[i])
		}
		if i < len(bs) {
			sb = parseVersionSegment(bs[i])
		}
		if sa.num != sb.num {
			if sa.num < sb.num {
				return -1
			}
			return 1
		}
		ra, rb := suffixRank(sa.suffix), suffixRank(sb.suffix)
		if ra != rb {
			if ra < rb {
				return -1
			}
			return 1
		}
		if c := strings.Compare(sa.suffix, sb.suffix); c != 0 {
			return c
		}
	}
	return 0
}

// suffixRank orders segment residues around the release point: pre-release
// residues (-rc1, ~beta2, 18beta1) sort BELOW the bare release, everything
// else (openssl letters, +quic) keeps sorting above it.
func suffixRank(suffix string) int {
	if suffix == "" {
		return 1
	}
	if isPreReleaseSuffix(suffix) {
		return 0
	}
	return 2
}

// preReleaseWords are the residue spellings nixpkgs uses for not-yet-released
// builds; a leading '-' or '~' separator marks the same intent on its own.
var preReleaseWords = []string{"alpha", "beta", "rc", "pre", "dev"}

func isPreReleaseSuffix(suffix string) bool {
	trimmed := strings.TrimLeft(suffix, "-~.")
	marked := len(trimmed) != len(suffix)
	lower := strings.ToLower(trimmed)
	for _, word := range preReleaseWords {
		if strings.HasPrefix(lower, word) {
			return true
		}
	}
	// A bare separator with an arbitrary residue ("-20250101") still marks a
	// pre-release ordering in the schemes that use it.
	return marked
}

type versionSegment struct {
	num    int
	suffix string
}

func parseVersionSegment(s string) versionSegment {
	digits := leadingDigits(s)
	num, _ := strconv.Atoi(digits)
	return versionSegment{num: num, suffix: s[len(digits):]}
}

func leadingDigits(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

// diffOverrideRisk is the patch-churn heuristic: a line-level multiset diff
// of the source file between the pin rev and the fix-carrying ref, ignoring
// blank lines and version/hash assignments. Any other changed line means the
// derivation's patch set or build logic moved underneath the version — the
// node-24 case — so an in-place override is flagged high.
func diffOverrideRisk(pinContent, fixContent []byte, pinRev, fixRef string) *OverrideRisk {
	counts := map[string]int{}
	for _, line := range strings.Split(string(pinContent), "\n") {
		if l := strings.TrimSpace(line); l != "" && !exemptAssignRe.MatchString(l) {
			counts[l]++
		}
	}
	for _, line := range strings.Split(string(fixContent), "\n") {
		if l := strings.TrimSpace(line); l != "" && !exemptAssignRe.MatchString(l) {
			counts[l]--
		}
	}
	changed := 0
	for _, c := range counts {
		if c < 0 {
			c = -c
		}
		changed += c
	}
	if changed > 0 {
		return &OverrideRisk{
			Level:        RiskHigh,
			ChangedLines: changed,
			Reason:       fmt.Sprintf("%d line(s) beyond version/hash assignments differ between pin %s and %s: patch set or build logic churned, an in-place override may not apply cleanly (line-diff heuristic)", changed, shortRev(pinRev), fixRef),
		}
	}
	return &OverrideRisk{
		Level:  RiskLow,
		Reason: fmt.Sprintf("only version/hash assignments differ between pin %s and %s: a pure version bump (line-diff heuristic)", shortRev(pinRev), fixRef),
	}
}

// shortRev abbreviates a 40-char rev for reason strings meant for tables.
func shortRev(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}
