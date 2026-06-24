package certify

// closure.go is the native-Go port of core/tests/closure-purity-check.py. It
// walks a docker-save or OCI-layout image archive (layer tar headers, so
// permission bits survive non-root extraction) or an on-disk /nix/store closure
// and flags any store path that ships an interactive shell or package manager,
// or any setuid/setgid regular file. Unlike ScanLayerForRuntimeTools (the
// consumer-facing FHS check), this walks the FULL /nix/store closure.

import (
	"archive/tar"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Store paths that provide any of these bin entries are violations.
var (
	closureShellBinaries = map[string]bool{
		"sh": true, "bash": true, "ash": true, "dash": true,
	}
	closurePkgManagerBinaries = map[string]bool{
		"npm": true, "npx": true, "corepack": true,
		"pip": true, "pip3": true, "apk": true, "dpkg": true, "rpm": true,
	}
	// Versioned pip entry points (pip3.13, pip3.14, ...) are the same violation.
	closureVersionedPipRe = regexp.MustCompile(`^pip[0-9]+(\.[0-9]+)*$`)
	closureStoreBinRe     = regexp.MustCompile(`^nix/store/([^/]+)/bin/([^/]+)$`)
	closureStoreCompRe    = regexp.MustCompile(`^nix/store/([^/]+)`)
)

// setuid/setgid bits as encoded in a tar header mode field.
const (
	closureSetuid = 0o4000
	closureSetgid = 0o2000
	closureSticky = 0o1000
)

// ClosureAllowlistEntry is one explained exception: a store-name fnmatch glob
// plus a mandatory one-line reason.
type ClosureAllowlistEntry struct {
	Pattern string
	Reason  string
	re      *regexp.Regexp
}

// ClosureViolation is a single offending in-image path and its message.
type ClosureViolation struct {
	Path    string
	Message string
}

// ClosurePurityResult is the outcome of a closure-purity scan.
type ClosurePurityResult struct {
	Violations   []ClosureViolation // sorted by message
	Accepted     []string           // allowlisted findings, in encounter order
	ScannedRoots []string           // every store root seen (for referrer diagnosis)
}

// Clean reports whether the scan found no (non-allowlisted) violations.
func (r ClosurePurityResult) Clean() bool { return len(r.Violations) == 0 }

func closureFlaggedCategory(name string) string {
	if closureShellBinaries[name] {
		return "interactive shell"
	}
	if closurePkgManagerBinaries[name] || closureVersionedPipRe.MatchString(name) {
		return "package manager"
	}
	return ""
}

// stripStoreHash returns the store component name without its 32-char hash
// prefix (everything after the first '-').
func stripStoreHash(component string) string {
	if i := strings.IndexByte(component, '-'); i >= 0 {
		return component[i+1:]
	}
	return component
}

// storeRoot maps /nix/store/<hash-name>/sub/path to /nix/store/<hash-name>, or
// "" when the path is not under a store.
func storeRoot(p string) string {
	parts := strings.Split(p, "/")
	idx := -1
	for i, part := range parts {
		if part == "store" {
			idx = i
			break
		}
	}
	if idx < 0 || idx+1 >= len(parts) || parts[idx+1] == "" {
		return ""
	}
	return strings.Join(parts[:idx+2], "/")
}

func normalizeMemberName(name string) string {
	name = strings.TrimLeft(name, "/")
	for strings.HasPrefix(name, "./") {
		name = name[2:]
	}
	return strings.TrimRight(name, "/")
}

// LoadClosureAllowlist parses an explained-exception allowlist. Every
// non-comment line must be "<store-name-pattern> <one-line reason>"; an
// unexplained entry is rejected so exceptions stay justified. A missing file is
// treated as an empty allowlist.
func LoadClosureAllowlist(pathName string) ([]ClosureAllowlistEntry, error) {
	if pathName == "" {
		return nil, nil
	}
	data, err := os.ReadFile(pathName)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var entries []ClosureAllowlistEntry
	for lineno, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexFunc(line, unicode.IsSpace)
		if idx < 0 {
			return nil, fmt.Errorf("allowlist %s:%d: every entry needs '<store-name-pattern> <one-line reason>', got: %q", pathName, lineno+1, line)
		}
		pattern := line[:idx]
		reason := strings.TrimSpace(line[idx:])
		if reason == "" {
			return nil, fmt.Errorf("allowlist %s:%d: every entry needs '<store-name-pattern> <one-line reason>', got: %q", pathName, lineno+1, line)
		}
		re, err := fnmatchToRegexp(pattern)
		if err != nil {
			return nil, fmt.Errorf("allowlist %s:%d: invalid pattern %q: %w", pathName, lineno+1, pattern, err)
		}
		entries = append(entries, ClosureAllowlistEntry{Pattern: pattern, Reason: reason, re: re})
	}
	return entries, nil
}

// fnmatchToRegexp translates an fnmatch glob to an anchored regexp, mirroring
// Python's fnmatch semantics ('*' and '?' do not treat '/' specially).
func fnmatchToRegexp(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '[':
			j := i + 1
			if j < len(pattern) && (pattern[j] == '!' || pattern[j] == '^') {
				j++
			}
			if j < len(pattern) && pattern[j] == ']' {
				j++
			}
			for j < len(pattern) && pattern[j] != ']' {
				j++
			}
			if j >= len(pattern) {
				b.WriteString(`\[`)
			} else {
				stuff := pattern[i+1 : j]
				neg := ""
				switch {
				case strings.HasPrefix(stuff, "!"):
					neg, stuff = "^", stuff[1:]
				case strings.HasPrefix(stuff, "^"):
					neg, stuff = `\^`, stuff[1:]
				}
				stuff = strings.ReplaceAll(stuff, `\`, `\\`)
				b.WriteString("[" + neg + stuff + "]")
				i = j
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

func closureAllowReason(entries []ClosureAllowlistEntry, candidate string) string {
	for _, e := range entries {
		if e.re.MatchString(candidate) {
			return fmt.Sprintf("%s (%s)", e.Pattern, e.Reason)
		}
	}
	return ""
}

// closureFindings collects violations keyed by in-image path so layer whiteouts
// can drop findings shadowed by later layers.
type closureFindings struct {
	allowlist    []ClosureAllowlistEntry
	violations   map[string]string
	accepted     []string
	scannedRoots map[string]bool
}

func newClosureFindings(allowlist []ClosureAllowlistEntry) *closureFindings {
	return &closureFindings{
		allowlist:    allowlist,
		violations:   map[string]string{},
		scannedRoots: map[string]bool{},
	}
}

func (f *closureFindings) record(p, allowKey, message string) {
	if reason := closureAllowReason(f.allowlist, allowKey); reason != "" {
		f.accepted = append(f.accepted, fmt.Sprintf("%s [allowlisted: %s]", message, reason))
		return
	}
	f.violations[p] = message
}

func (f *closureFindings) discard(p string) { delete(f.violations, p) }

func (f *closureFindings) result() ClosurePurityResult {
	violations := make([]ClosureViolation, 0, len(f.violations))
	for p, m := range f.violations {
		violations = append(violations, ClosureViolation{Path: p, Message: m})
	}
	sort.Slice(violations, func(i, j int) bool { return violations[i].Message < violations[j].Message })
	roots := make([]string, 0, len(f.scannedRoots))
	for r := range f.scannedRoots {
		roots = append(roots, r)
	}
	sort.Strings(roots)
	return ClosurePurityResult{Violations: violations, Accepted: f.accepted, ScannedRoots: roots}
}

func (f *closureFindings) inspectMember(hdr *tar.Header) {
	name := normalizeMemberName(hdr.Name)
	if name == "" {
		return
	}
	if r := storeRoot("/" + name); r != "" {
		f.scannedRoots[r] = true
	}

	base := path.Base(name)
	if strings.HasPrefix(base, ".wh.") {
		f.discard(path.Join(path.Dir(name), base[len(".wh."):]))
		return
	}

	isFile := hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA
	isLink := hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink
	if m := closureStoreBinRe.FindStringSubmatch(name); m != nil && (isFile || isLink) {
		component, binary := m[1], m[2]
		if category := closureFlaggedCategory(binary); category != "" {
			f.record(name, stripStoreHash(component),
				fmt.Sprintf("store path /nix/store/%s provides %s bin/%s", component, category, binary))
		}
	}

	if isFile && hdr.Mode&(closureSetuid|closureSetgid) != 0 {
		bit := "setgid"
		if hdr.Mode&closureSetuid != 0 {
			bit = "setuid"
		}
		allowKey := "/" + name
		if cm := closureStoreCompRe.FindStringSubmatch(name); cm != nil {
			allowKey = stripStoreHash(cm[1])
		}
		f.record(name, allowKey, fmt.Sprintf("%s regular file /%s (mode %o)", bit, name, hdr.Mode))
	}
}

// ScanImageArchiveForClosurePurity walks every layer of a docker-save or
// OCI-layout image archive and returns the closure-purity result.
func ScanImageArchiveForClosurePurity(archivePath string, allowlist []ClosureAllowlistEntry) (ClosurePurityResult, error) {
	f := newClosureFindings(allowlist)
	if err := walkImageLayers(archivePath, func(hdr *tar.Header) error {
		f.inspectMember(hdr)
		return nil
	}); err != nil {
		return ClosurePurityResult{}, err
	}
	return f.result(), nil
}

// ScanStorePathsForClosurePurity walks an on-disk /nix/store closure (a
// closureInfo store-paths file) instead of an image archive.
func ScanStorePathsForClosurePurity(storePathsFile string, allowlist []ClosureAllowlistEntry) (ClosurePurityResult, error) {
	data, err := os.ReadFile(storePathsFile)
	if err != nil {
		return ClosurePurityResult{}, err
	}
	var storePaths []string
	for _, line := range strings.Split(string(data), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			storePaths = append(storePaths, s)
		}
	}
	if len(storePaths) == 0 {
		return ClosurePurityResult{}, fmt.Errorf("store paths file is empty: %s", storePathsFile)
	}

	f := newClosureFindings(allowlist)
	for _, storePath := range storePaths {
		f.scannedRoots[storePath] = true
		allowKey := stripStoreHash(path.Base(storePath))

		if dirEntries, err := os.ReadDir(filepath.Join(storePath, "bin")); err == nil {
			for _, entry := range dirEntries {
				if category := closureFlaggedCategory(entry.Name()); category != "" {
					f.record(filepath.Join(storePath, "bin", entry.Name()), allowKey,
						fmt.Sprintf("store path %s provides %s bin/%s", storePath, category, entry.Name()))
				}
			}
		}

		_ = filepath.WalkDir(storePath, func(p string, d os.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() {
				return nil //nolint:nilerr // best-effort walk, mirror python os.walk tolerance
			}
			info, err := d.Info()
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
			if info.Mode()&(os.ModeSetuid|os.ModeSetgid) == 0 {
				return nil
			}
			bit := "setgid"
			mode := closureSetgid
			if info.Mode()&os.ModeSetuid != 0 {
				bit, mode = "setuid", closureSetuid
			}
			perm := int(info.Mode().Perm()) | mode
			if info.Mode()&os.ModeSticky != 0 {
				perm |= closureSticky
			}
			f.record(p, allowKey, fmt.Sprintf("%s regular file %s (mode %o)", bit, p, perm))
			return nil
		})
	}
	return f.result(), nil
}
