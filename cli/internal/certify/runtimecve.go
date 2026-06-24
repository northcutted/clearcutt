package certify

// runtimecve.go is the native-Go port of core/tests/closure-cve-check.py, the
// runtime-patch completeness gate: it proves no STOCK (below-floor) build of a
// CVE-remediated dependency (openssl/sqlite) ships inside a production image. It
// walks the SHIPPED closure — never a .drv build closure — and default-denies
// any tracked store path whose version is below the committed floor.

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

// RuntimeFloor is the parsed runtime-dep-floor.json: per-dep minimum versions
// plus the anchored matcher built from those dep names so the two cannot drift.
type RuntimeFloor struct {
	entries map[string]runtimeFloorEntry
	names   []string // sorted dep names
	depRe   *regexp.Regexp
}

type runtimeFloorEntry struct {
	tuple   []int
	version string
}

// RuntimeCveViolation is one shipped store path below its floor.
type RuntimeCveViolation struct {
	Path    string
	Message string
}

// RuntimeCveResult is the outcome of a runtime-patch completeness scan.
type RuntimeCveResult struct {
	Violations []RuntimeCveViolation // sorted by message
	Tracked    []string              // "openssl>=3.6.3", ... for the clean summary
}

// Clean reports whether every tracked, shipped dep meets its floor.
func (r RuntimeCveResult) Clean() bool { return len(r.Violations) == 0 }

// LoadRuntimeDepFloor parses runtime-dep-floor.json. A missing, empty, or
// malformed floor is a hard error: a silently-empty floor makes the default-deny
// gate vacuous.
func LoadRuntimeDepFloor(pathName string) (*RuntimeFloor, error) {
	if pathName == "" {
		return nil, fmt.Errorf("runtime-dep-floor is required: pass --floor FILE")
	}
	data, err := os.ReadFile(pathName)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("runtime-dep-floor file not found: %s", pathName)
		}
		return nil, err
	}
	var doc struct {
		Deps []struct {
			Name       string `json:"name"`
			MinVersion string `json:"minVersion"`
		} `json:"deps"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("runtime-dep-floor %s: invalid JSON: %w", pathName, err)
	}
	if len(doc.Deps) == 0 {
		return nil, fmt.Errorf("runtime-dep-floor %s: expected a non-empty 'deps' list of {name, minVersion}", pathName)
	}
	entries := make(map[string]runtimeFloorEntry, len(doc.Deps))
	for _, d := range doc.Deps {
		if d.Name == "" || d.MinVersion == "" {
			return nil, fmt.Errorf("runtime-dep-floor %s: every dep needs 'name' and 'minVersion'", pathName)
		}
		tuple, ok := parseDottedVersion(d.MinVersion)
		if !ok {
			return nil, fmt.Errorf("runtime-dep-floor %s: unparseable minVersion %q for %q", pathName, d.MinVersion, d.Name)
		}
		entries[d.Name] = runtimeFloorEntry{tuple: tuple, version: d.MinVersion}
	}

	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)

	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = regexp.QuoteMeta(n)
	}
	// Anchor <dep>-<dotted-numeric>[-<output>]: the dotted-numeric version group
	// plus the optional bare-lowercase nix output suffix is what skips .drv /
	// .tar.gz / .zip / .patch artifacts.
	depRe, err := regexp.Compile("^(" + strings.Join(quoted, "|") + ")-([0-9][0-9.]*)(?:-[a-z]+)?$")
	if err != nil {
		return nil, fmt.Errorf("runtime-dep-floor %s: building matcher: %w", pathName, err)
	}

	return &RuntimeFloor{entries: entries, names: names, depRe: depRe}, nil
}

// Tracked returns "dep>=floor" strings (sorted) for the clean summary.
func (f *RuntimeFloor) Tracked() []string {
	out := make([]string, len(f.names))
	for i, n := range f.names {
		out[i] = fmt.Sprintf("%s>=%s", n, f.entries[n].version)
	}
	return out
}

// parseDottedVersion parses a purely dotted-numeric version into a comparable
// int slice. A non-numeric segment (e.g. "3.6.3a", "3.6.3-rc1") returns ok=false
// so callers default-deny on input they cannot prove clears the floor.
func parseDottedVersion(version string) ([]int, bool) {
	if version == "" {
		return nil, false
	}
	parts := strings.Split(version, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil, false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil, false
			}
			n = n*10 + int(c-'0')
		}
		out = append(out, n)
	}
	return out, true
}

// versionGE reports candidate >= floor as version tuples (NOT string compare),
// zero-padding the shorter so 3.6 == 3.6.0 and 3.6.10 > 3.6.3.
func versionGE(candidate, floor []int) bool {
	width := len(candidate)
	if len(floor) > width {
		width = len(floor)
	}
	for i := 0; i < width; i++ {
		c, f := 0, 0
		if i < len(candidate) {
			c = candidate[i]
		}
		if i < len(floor) {
			f = floor[i]
		}
		if c != f {
			return c > f
		}
	}
	return true
}

// evaluateComponent returns a violation message for a hash-stripped store name,
// or "" when it is not a tracked dep (no match / artifact skip) or is at/above
// its floor.
func (f *RuntimeFloor) evaluateComponent(componentName string) string {
	m := f.depRe.FindStringSubmatch(componentName)
	if m == nil {
		return ""
	}
	dep, rawVersion := m[1], m[2]
	entry := f.entries[dep]
	parsed, ok := parseDottedVersion(rawVersion)
	if !ok {
		return fmt.Sprintf("image ships %s-%s with an unparseable version (floor %s) — cannot prove it is patched", dep, rawVersion, entry.version)
	}
	if !versionGE(parsed, entry.tuple) {
		return fmt.Sprintf("image ships %s-%s (floor %s)", dep, rawVersion, entry.version)
	}
	return ""
}

// runtimeCveFindings tracks violations keyed by store path so layer whiteouts
// can drop findings shadowed by later layers, and dedups store components.
type runtimeCveFindings struct {
	violations map[string]string
	seen       map[string]bool
}

func newRuntimeCveFindings() *runtimeCveFindings {
	return &runtimeCveFindings{violations: map[string]string{}, seen: map[string]bool{}}
}

func (rf *runtimeCveFindings) inspectMember(hdr *tar.Header, floor *RuntimeFloor) {
	name := normalizeMemberName(hdr.Name)
	if name == "" {
		return
	}
	base := path.Base(name)
	if strings.HasPrefix(base, ".wh.") {
		// Violations are keyed by "/nix/store/<comp>" (leading slash), so the
		// whiteout-discard key needs the same leading slash to match — correcting
		// the original python's inconsistency where store-level whiteouts never
		// discarded. A whiteout-ed store path is not in the shipped rootfs.
		delete(rf.violations, "/"+path.Join(path.Dir(name), base[len(".wh."):]))
		return
	}
	m := closureStoreCompRe.FindStringSubmatch(name)
	if m == nil {
		return
	}
	component := m[1]
	storePath := "/nix/store/" + component
	if rf.seen[storePath] {
		return
	}
	rf.seen[storePath] = true
	if msg := floor.evaluateComponent(stripStoreHash(component)); msg != "" {
		rf.violations[storePath] = fmt.Sprintf("%s at %s", msg, storePath)
	}
}

func (rf *runtimeCveFindings) result(floor *RuntimeFloor) RuntimeCveResult {
	violations := make([]RuntimeCveViolation, 0, len(rf.violations))
	for p, msg := range rf.violations {
		violations = append(violations, RuntimeCveViolation{Path: p, Message: msg})
	}
	sort.Slice(violations, func(i, j int) bool { return violations[i].Message < violations[j].Message })
	return RuntimeCveResult{Violations: violations, Tracked: floor.Tracked()}
}

// ScanImageArchiveForRuntimeCve walks every layer of a docker-save or
// OCI-layout image archive and returns the runtime-patch completeness result.
func ScanImageArchiveForRuntimeCve(archivePath string, floor *RuntimeFloor) (RuntimeCveResult, error) {
	rf := newRuntimeCveFindings()
	if err := walkImageLayers(archivePath, func(hdr *tar.Header) error {
		rf.inspectMember(hdr, floor)
		return nil
	}); err != nil {
		return RuntimeCveResult{}, err
	}
	return rf.result(floor), nil
}

// ScanStorePathsForRuntimeCve evaluates each store path in a closureInfo
// store-paths file instead of an image archive.
func ScanStorePathsForRuntimeCve(storePathsFile string, floor *RuntimeFloor) (RuntimeCveResult, error) {
	data, err := os.ReadFile(storePathsFile)
	if err != nil {
		return RuntimeCveResult{}, err
	}
	var storePaths []string
	for _, line := range strings.Split(string(data), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			storePaths = append(storePaths, s)
		}
	}
	if len(storePaths) == 0 {
		return RuntimeCveResult{}, fmt.Errorf("store paths file is empty: %s", storePathsFile)
	}

	rf := newRuntimeCveFindings()
	for _, storePath := range storePaths {
		component := path.Base(strings.TrimRight(storePath, "/"))
		if msg := floor.evaluateComponent(stripStoreHash(component)); msg != "" {
			rf.violations[storePath] = fmt.Sprintf("%s at %s", msg, storePath)
		}
	}
	return rf.result(floor), nil
}
