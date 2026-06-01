package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/northcutted/clearcutt/internal/catalog"
	"github.com/spf13/cobra"
)

// scan.go is the catalog vulnerability scanner: it scans every
// cached SBOM with grype and emits one normalized vulnerability JSON per
// (tag, target, arch). The output shape — including its `inclusion` and
// `remediation` classification and explicit null fields — is reproduced exactly
// so the catalog site, the remediation planner, and the release gate that consume
// it see no change.

type scanFlags struct {
	mode        string
	sbomDir     string
	outDir      string
	depth       string
	tags        string
	all         bool
	concurrency int
}

var scanOpts scanFlags

var scanStrictModes = map[string]bool{"remediation": true, "release": true}

var scanTargetFileRe = regexp.MustCompile(`^(.+)-(amd64|arm64)\.sbom\.json$`)

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func nowRFC3339Milli() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

func NewScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan cached SBOMs with grype and emit normalized vulnerability JSON",
		Long: `Scans each cached SBOM under --sbom-dir with grype and writes a normalized
findings JSON per (tag, target, arch) under --out-dir, classifying each finding's
layer (runtime vs base), inclusion category, and remediation status. In
remediation/release mode the scan fails closed on missing tooling or scan errors;
in catalog mode it is best-effort.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan()
		},
	}
	cmd.Flags().StringVar(&scanOpts.mode, "mode", envOr("SCAN_MODE", "catalog"), "Scan mode: catalog (best-effort), remediation, or release (fail closed)")
	cmd.Flags().StringVar(&scanOpts.sbomDir, "sbom-dir", envOr("SBOM_CACHE_DIR", filepath.Join("site", "src", "data", "sboms")), "Directory of cached SBOMs (<tag>/<target>-<arch>.sbom.json)")
	cmd.Flags().StringVar(&scanOpts.outDir, "out-dir", envOr("VULN_DIR", filepath.Join("site", "src", "data", "vulnerabilities")), "Directory to write normalized vulnerability JSON into")
	cmd.Flags().StringVar(&scanOpts.depth, "depth", os.Getenv("SCAN_TAG_DEPTH"), "Scan only the newest N tags by version (empty = all)")
	cmd.Flags().StringVar(&scanOpts.tags, "tags", os.Getenv("SCAN_TAGS"), "Comma-separated explicit tag allowlist (overrides --depth/--all)")
	cmd.Flags().BoolVar(&scanOpts.all, "all", parseScanBool(os.Getenv("SCAN_ALL_TAGS")), "Scan every cached tag (overrides --depth)")
	cmd.Flags().IntVar(&scanOpts.concurrency, "concurrency", 0, "Parallel grype workers (0 = CPU count or $SCAN_CONCURRENCY)")
	return cmd
}

// -- grype input model -------------------------------------------------------

type grypeResult struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability grypeVuln     `json:"vulnerability"`
	Artifact      grypeArtifact `json:"artifact"`
}

type grypeVuln struct {
	ID          string      `json:"id"`
	Severity    string      `json:"severity"`
	DataSource  string      `json:"dataSource"`
	Namespace   string      `json:"namespace"`
	Description string      `json:"description"`
	Fix         grypeFix    `json:"fix"`
	Cvss        []grypeCvss `json:"cvss"`
	Epss        []grypeEpss `json:"epss"`
	Risk        *float64    `json:"risk"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type grypeCvss struct {
	Type    string           `json:"type"`
	Version string           `json:"version"`
	Vector  string           `json:"vector"`
	Metrics grypeCvssMetrics `json:"metrics"`
}

type grypeCvssMetrics struct {
	BaseScore *float64 `json:"baseScore"`
}

type grypeEpss struct {
	Date       string   `json:"date"`
	Epss       *float64 `json:"epss"`
	Percentile *float64 `json:"percentile"`
}

type grypeArtifact struct {
	Name       string          `json:"name"`
	Version    string          `json:"version"`
	Purl       json.RawMessage `json:"purl"`
	SourceInfo string          `json:"sourceInfo"`
}

// -- normalized output model -------------------------------------------------
//
// Distinct from catalog.FindingInfo (which is the omitempty-tolerant *consumer*
// shape). The producer emits explicit nulls and a fixed key order to match the
// retired .mjs byte-for-byte.

type scanReport struct {
	ScannedAt        string                 `json:"scannedAt"`
	Scanner          string                 `json:"scanner"`
	DBBuiltAt        *string                `json:"dbBuiltAt"`
	CountsBySeverity catalog.SeverityCounts `json:"countsBySeverity"`
	Findings         []scanFinding          `json:"findings"`
}

type scanFinding struct {
	ID             string                  `json:"id"`
	Severity       string                  `json:"severity"`
	PackageName    string                  `json:"packageName"`
	PackageVersion string                  `json:"packageVersion"`
	Purl           *string                 `json:"purl"`
	Layer          string                  `json:"layer"`
	FixedIn        *string                 `json:"fixedIn"`
	FixState       string                  `json:"fixState"`
	Remediation    catalog.RemediationInfo `json:"remediation"`
	Inclusion      catalog.InclusionInfo   `json:"inclusion"`
	DataSource     *string                 `json:"dataSource"`
	Namespace      *string                 `json:"namespace"`
	Description    *string                 `json:"description"`
	CvssScore      *float64                `json:"cvssScore"`
	CvssVersion    *string                 `json:"cvssVersion"`
	CvssVector     *string                 `json:"cvssVector"`
	EpssScore      *float64                `json:"epssScore"`
	EpssPercentile *float64                `json:"epssPercentile"`
	RiskScore      *float64                `json:"riskScore"`
}

type targetMeta struct {
	target   string
	runtime  string
	language string
	version  string
	tier     string
}

// -- pure classification (mirrors the .mjs predicates) -----------------------

func parseScanBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func strOrNil(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

var targetRuntimeRe = regexp.MustCompile(`^([a-z]+)(.+)$`)

func targetMetadata(target string) targetMeta {
	idx := strings.LastIndex(target, "-")
	rt := target
	tier := "unknown"
	if idx != -1 {
		rt = target[:idx]
		tier = target[idx+1:]
	}
	if rt == "coreLTS" {
		return targetMeta{target: target, runtime: rt, language: "core", version: "LTS", tier: tier}
	}
	m := targetRuntimeRe.FindStringSubmatch(rt)
	if m == nil {
		return targetMeta{target: target, runtime: rt, language: rt, version: "", tier: tier}
	}
	return targetMeta{target: target, runtime: rt, language: m[1], version: m[2], tier: tier}
}

func displayLanguage(language string) string {
	switch language {
	case "core":
		return "Core"
	case "java":
		return "Java"
	case "node":
		return "Node.js"
	case "python":
		return "Python"
	case "go":
		return "Go"
	case "dotnet":
		return ".NET"
	case "rust":
		return "Rust"
	case "cc":
		return "C/C++"
	default:
		return language
	}
}

var primaryGoUnderscoreRe = regexp.MustCompile(`^go_[0-9_]+$`)
var primaryPythonRe = regexp.MustCompile(`^python[0-9.]*$`)

func isPrimaryRuntimePackage(meta targetMeta, packageName string) bool {
	pkg := strings.ToLower(packageName)
	switch meta.language {
	case "python":
		return pkg == "python" || primaryPythonRe.MatchString(pkg)
	case "java":
		return strings.Contains(pkg, "jdk") || strings.Contains(pkg, "jre") || strings.Contains(pkg, "openjdk") || strings.Contains(pkg, "zulu")
	case "node":
		return pkg == "node" || pkg == "nodejs" || strings.HasPrefix(pkg, "nodejs")
	case "go":
		return pkg == "go" || strings.HasPrefix(pkg, "go-") || primaryGoUnderscoreRe.MatchString(pkg)
	case "dotnet":
		return strings.Contains(pkg, "dotnet") || strings.Contains(pkg, "aspnetcore")
	case "rust":
		return pkg == "rustc" || pkg == "cargo"
	case "cc":
		return pkg == "gcc" || pkg == "clang"
	default:
		return false
	}
}

func classifyLayer(meta targetMeta, name, sourceInfo string, purl *string) string {
	if purl != nil && (strings.HasPrefix(*purl, "pkg:nix") || strings.Contains(*purl, "outputhash=")) {
		return "runtime"
	}
	if strings.Contains(sourceInfo, "/nix/store/") {
		return "runtime"
	}
	if strings.HasPrefix(name, "nix") || strings.Contains(name, "clearcutt") {
		return "runtime"
	}
	if isPrimaryRuntimePackage(meta, name) {
		return "runtime"
	}
	return "base"
}

func remediationMetadata(layer, severityKey string, fixedIn *string) catalog.RemediationInfo {
	highPriority := severityKey == "critical" || severityKey == "high"
	if layer != "runtime" {
		return catalog.RemediationInfo{
			Status:  "deferred",
			Reason:  "base_layer",
			Summary: "This comes from the underlying base image, so ClearCutt lists it but cannot update it from the runtime layer.",
		}
	}
	if !highPriority {
		return catalog.RemediationInfo{
			Status:  "deferred",
			Reason:  "below_priority_threshold",
			Summary: "This is below the release-blocking severity threshold, so it is listed for awareness.",
		}
	}
	if fixedIn == nil {
		return catalog.RemediationInfo{
			Status:  "deferred",
			Reason:  "no_fixed_version",
			Summary: "No safe fixed version is currently listed for this package. We keep it visible until an upstream fix is available.",
		}
	}
	return catalog.RemediationInfo{
		Status:  "eligible",
		Reason:  "fix_available",
		Summary: "A safe fixed version is available for a package ClearCutt adds to this image.",
	}
}

func inclusionMetadata(meta targetMeta, name, layer string) catalog.InclusionInfo {
	pkg := strings.ToLower(name)
	lang := displayLanguage(meta.language)
	version := ""
	if meta.version != "" {
		version = " " + meta.version
	}
	variant := fmt.Sprintf("%s%s %s", lang, version, meta.tier)

	if layer == "base" {
		return catalog.InclusionInfo{
			Category: "base_image",
			Summary:  "Inherited from the enterprise base image underneath the ClearCutt runtime layer.",
		}
	}
	if isPrimaryRuntimePackage(meta, pkg) {
		return catalog.InclusionInfo{
			Category: "primary_runtime",
			Summary:  fmt.Sprintf("Primary %s%s runtime required by this image variant.", lang, version),
		}
	}
	if pkg == "cacert" || pkg == "nss-cacert" {
		return catalog.InclusionInfo{
			Category: "trust_store",
			Summary:  "TLS CA trust store required by networked runtimes.",
		}
	}
	if meta.tier == "slim" && (pkg == "bash" || pkg == "bash-interactive" || pkg == "busybox") {
		return catalog.InclusionInfo{
			Category: "tier_tooling",
			Summary:  "Intentional slim-tier diagnostic utility. Distroless variants remove shells and core utilities.",
		}
	}
	if meta.language == "java" && pkg == "cups" {
		return catalog.InclusionInfo{
			Category: "java_compatibility",
			Summary:  "Pulled by the selected Java runtime closure for printing/AWT compatibility. Candidate for a headless-minimal profile.",
		}
	}
	if meta.language == "java" && pkg == "libtiff" {
		return catalog.InclusionInfo{
			Category: "java_compatibility",
			Summary:  "Pulled by the selected Java runtime closure for image/font stack compatibility. Candidate for a headless-minimal profile.",
		}
	}
	switch pkg {
	case "glibc", "gcc-unwrapped", "libgcc", "zlib", "bzip2", "xz", "openssl":
		return catalog.InclusionInfo{
			Category: "runtime_dependency",
			Summary:  fmt.Sprintf("Runtime library required by the selected %s closure.", variant),
		}
	}
	return catalog.InclusionInfo{
		Category: "transitive_runtime",
		Summary:  fmt.Sprintf("Transitive dependency of the selected %s Nix runtime closure.", variant),
	}
}

func pickCvss(arr []grypeCvss) (score *float64, version *string, vector *string) {
	if len(arr) == 0 {
		return nil, nil, nil
	}
	candidates := arr
	for _, c := range arr {
		if strings.ToLower(c.Type) == "primary" {
			candidates = []grypeCvss{c}
			break
		}
	}
	var best *grypeCvss
	for i := range candidates {
		c := candidates[i]
		if c.Metrics.BaseScore == nil {
			continue
		}
		if best == nil || *c.Metrics.BaseScore > *best.Metrics.BaseScore {
			cp := c
			best = &cp
		}
	}
	if best == nil {
		return nil, nil, nil
	}
	return best.Metrics.BaseScore, strOrNil(best.Version), strOrNil(best.Vector)
}

func pickEpss(arr []grypeEpss) (score *float64, percentile *float64) {
	if len(arr) == 0 {
		return nil, nil
	}
	sorted := make([]grypeEpss, len(arr))
	copy(sorted, arr)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Date > sorted[j].Date
	})
	e := sorted[0]
	if e.Epss == nil {
		return nil, nil
	}
	return e.Epss, e.Percentile
}

func parsePurl(raw json.RawMessage) *string {
	if len(raw) == 0 {
		return nil
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return &asString
	}
	var asArray []string
	if err := json.Unmarshal(raw, &asArray); err == nil {
		if len(asArray) == 0 {
			return nil
		}
		return &asArray[0]
	}
	return nil
}

var scanSevKeys = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "negligible": true}
var scanSevOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4, "unknown": 5}

func normalizeGrype(result grypeResult, scannedAt, scanner string, dbBuiltAt *string, meta targetMeta) scanReport {
	counts := catalog.SeverityCounts{}
	findings := make([]scanFinding, 0, len(result.Matches))
	for _, m := range result.Matches {
		v := m.Vulnerability
		a := m.Artifact
		sev := strings.ToLower(v.Severity)
		if sev == "" {
			sev = "unknown"
		}
		sevKey := "unknown"
		if scanSevKeys[sev] {
			sevKey = sev
		}
		switch sevKey {
		case "critical":
			counts.Critical++
		case "high":
			counts.High++
		case "medium":
			counts.Medium++
		case "low":
			counts.Low++
		case "negligible":
			counts.Negligible++
		default:
			counts.Unknown++
		}

		purl := parsePurl(a.Purl)
		var fixedIn *string
		if len(v.Fix.Versions) > 0 {
			joined := strings.Join(v.Fix.Versions, ", ")
			fixedIn = &joined
		}
		fixState := v.Fix.State
		if fixState == "" {
			fixState = "unknown"
		}
		layer := classifyLayer(meta, a.Name, a.SourceInfo, purl)
		cvssScore, cvssVersion, cvssVector := pickCvss(v.Cvss)
		epssScore, epssPercentile := pickEpss(v.Epss)

		id := v.ID
		if id == "" {
			id = "UNKNOWN"
		}
		severity := v.Severity
		if severity == "" {
			severity = "Unknown"
		}

		findings = append(findings, scanFinding{
			ID:             id,
			Severity:       severity,
			PackageName:    a.Name,
			PackageVersion: a.Version,
			Purl:           purl,
			Layer:          layer,
			FixedIn:        fixedIn,
			FixState:       fixState,
			Remediation:    remediationMetadata(layer, sevKey, fixedIn),
			Inclusion:      inclusionMetadata(meta, a.Name, layer),
			DataSource:     strOrNil(v.DataSource),
			Namespace:      strOrNil(v.Namespace),
			Description:    strOrNil(v.Description),
			CvssScore:      cvssScore,
			CvssVersion:    cvssVersion,
			CvssVector:     cvssVector,
			EpssScore:      epssScore,
			EpssPercentile: epssPercentile,
			RiskScore:      v.Risk,
		})
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		sa, ok := scanSevOrder[strings.ToLower(a.Severity)]
		if !ok {
			sa = 99
		}
		sb, ok := scanSevOrder[strings.ToLower(b.Severity)]
		if !ok {
			sb = 99
		}
		if sa != sb {
			return sa < sb
		}
		csa := -1.0
		if a.CvssScore != nil {
			csa = *a.CvssScore
		}
		csb := -1.0
		if b.CvssScore != nil {
			csb = *b.CvssScore
		}
		if csa != csb {
			return csa > csb
		}
		if a.PackageName != b.PackageName {
			return a.PackageName < b.PackageName
		}
		return a.ID < b.ID
	})

	return scanReport{
		ScannedAt:        scannedAt,
		Scanner:          scanner,
		DBBuiltAt:        dbBuiltAt,
		CountsBySeverity: counts,
		Findings:         findings,
	}
}

// -- tag window selection (mirrors selectTags in the .mjs) -------------------

func scanVersionTuple(value string) []int {
	raw := strings.Split(strings.TrimLeft(value, "v"), ".")
	parts := make([]int, 0, len(raw))
	for _, p := range raw {
		t := strings.TrimSpace(p)
		n, err := strconv.Atoi(t)
		if err != nil {
			return []int{0, 0, 0}
		}
		parts = append(parts, n)
	}
	return parts
}

func compareScanTuples(a, b []int) int {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for i := 0; i < limit; i++ {
		if a[i] != b[i] {
			return a[i] - b[i]
		}
	}
	return len(a) - len(b)
}

func selectScanTags(allTags []string, strict bool) ([]string, error) {
	explicit := []string{}
	for _, t := range strings.Split(scanOpts.tags, ",") {
		if s := strings.TrimSpace(t); s != "" {
			explicit = append(explicit, s)
		}
	}
	if len(explicit) > 0 {
		allow := map[string]bool{}
		for _, t := range explicit {
			allow[t] = true
		}
		selected := []string{}
		for _, t := range allTags {
			if allow[t] {
				selected = append(selected, t)
			}
		}
		scanLogf("tag window: explicit tags=%s -> scanning %s (skipped %d)", strings.Join(explicit, ", "), joinOrNone(selected), len(allTags)-len(selected))
		return selected, nil
	}
	if scanOpts.all {
		scanLogf("tag window: all tags requested -> scanning %d tag(s)", len(allTags))
		return allTags, nil
	}
	rawDepth := strings.TrimSpace(scanOpts.depth)
	if rawDepth != "" {
		depth, err := strconv.Atoi(rawDepth)
		if err != nil || depth <= 0 {
			if msg := fmt.Sprintf("[scan] invalid tag window depth %q; scanning all tags.", rawDepth); strict {
				return nil, fmt.Errorf("%s", msg)
			} else {
				scanWarnf("invalid tag window depth %q; scanning all tags.", rawDepth)
			}
			return allTags, nil
		}
		if depth >= len(allTags) {
			scanLogf("tag window: depth=%d covers all %d tag(s)", depth, len(allTags))
			return allTags, nil
		}
		sorted := make([]string, len(allTags))
		copy(sorted, allTags)
		sort.SliceStable(sorted, func(i, j int) bool {
			return compareScanTuples(scanVersionTuple(sorted[i]), scanVersionTuple(sorted[j])) > 0
		})
		selected := sorted[:depth]
		scanLogf("tag window: depth=%d -> scanning %s (skipped %d older)", depth, strings.Join(selected, ", "), len(allTags)-len(selected))
		return selected, nil
	}
	scanLogf("tag window: default all -> scanning %d tag(s)", len(allTags))
	return allTags, nil
}

func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}

// -- execution ---------------------------------------------------------------

func scanLogf(format string, args ...any) {
	fmt.Fprintf(errOut, "[scan] "+format+"\n", args...)
}

func scanWarnf(format string, args ...any) {
	fmt.Fprintf(errOut, "[scan] "+format+"\n", args...)
}

func grypeVersionProbe(grypeBin string) (string, *string) {
	out, err := exec.Command(grypeBin, "version", "-o", "json").Output()
	if err != nil {
		return "grype", nil
	}
	var parsed struct {
		Version     string `json:"version"`
		Application string `json:"application"`
		DB          struct {
			Built string `json:"built"`
		} `json:"db"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return "grype", nil
	}
	version := parsed.Version
	if version == "" {
		version = parsed.Application
	}
	if version == "" {
		version = "grype"
	}
	return version, strOrNil(parsed.DB.Built)
}

type scanWorkItem struct {
	tag, target, arch, sbomPath, outPath string
}

func runScan() error {
	strict := scanStrictModes[scanOpts.mode]
	grypeBin := envOr("GRYPE_BIN", "grype")
	grypeOpts := strings.Fields(os.Getenv("GRYPE_OPTS"))

	if _, err := exec.LookPath(grypeBin); err != nil {
		msg := fmt.Sprintf("[scan] %s not on PATH - install Grype to enable CVE reporting.", grypeBin)
		if strict {
			return fmt.Errorf("%s", msg)
		}
		scanWarnf("%s not on PATH - install Grype to enable CVE reporting.", grypeBin)
		return nil
	}

	info, err := os.Stat(scanOpts.sbomDir)
	if err != nil || !info.IsDir() {
		msg := fmt.Sprintf("[scan] no SBOM cache at %s - run gather first.", scanOpts.sbomDir)
		if strict {
			return fmt.Errorf("%s", msg)
		}
		scanWarnf("no SBOM cache at %s - run gather first.", scanOpts.sbomDir)
		return nil
	}

	scannerVersion, dbBuiltAt := grypeVersionProbe(grypeBin)
	dbBuiltLabel := "unknown"
	if dbBuiltAt != nil {
		dbBuiltLabel = *dbBuiltAt
	}
	scanLogf("grype %s, db built %s", scannerVersion, dbBuiltLabel)

	entries, err := os.ReadDir(scanOpts.sbomDir)
	if err != nil {
		return fmt.Errorf("[scan] failed to read SBOM cache %s: %w", scanOpts.sbomDir, err)
	}
	allTags := []string{}
	for _, e := range entries {
		if e.IsDir() {
			allTags = append(allTags, e.Name())
		}
	}
	tags, err := selectScanTags(allTags, strict)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(scanOpts.outDir, 0o755); err != nil {
		return fmt.Errorf("[scan] failed to create output dir %s: %w", scanOpts.outDir, err)
	}

	work := []scanWorkItem{}
	for _, tag := range tags {
		tagOut := filepath.Join(scanOpts.outDir, tag)
		if err := os.MkdirAll(tagOut, 0o755); err != nil {
			return fmt.Errorf("[scan] failed to create output dir %s: %w", tagOut, err)
		}
		tagDir := filepath.Join(scanOpts.sbomDir, tag)
		files, err := os.ReadDir(tagDir)
		if err != nil {
			return fmt.Errorf("[scan] failed to read %s: %w", tagDir, err)
		}
		for _, f := range files {
			m := scanTargetFileRe.FindStringSubmatch(f.Name())
			if m == nil {
				continue
			}
			work = append(work, scanWorkItem{
				tag:      tag,
				target:   m[1],
				arch:     m[2],
				sbomPath: filepath.Join(tagDir, f.Name()),
				outPath:  filepath.Join(tagOut, fmt.Sprintf("%s-%s.json", m[1], m[2])),
			})
		}
	}

	concurrency := scanOpts.concurrency
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
		if env := os.Getenv("SCAN_CONCURRENCY"); env != "" {
			if n, err := strconv.Atoi(env); err == nil && n > 0 {
				concurrency = n
			}
		}
	}
	if concurrency < 1 {
		concurrency = 1
	}
	scanLogf("scanning %d SBOM(s) with concurrency %d", len(work), concurrency)

	var mu sync.Mutex
	total, failed := 0, 0
	scanOne := func(item scanWorkItem) {
		report, err := scanSBOM(grypeBin, grypeOpts, item, scannerVersion, dbBuiltAt)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			failed++
			scanWarnf("%s/%s/%s: %v", item.tag, item.target, item.arch, err)
			return
		}
		c := report.CountsBySeverity
		scanLogf("%s/%s/%s: %d findings (crit=%d high=%d med=%d low=%d)", item.tag, item.target, item.arch, len(report.Findings), c.Critical, c.High, c.Medium, c.Low)
		total++
	}

	var wg sync.WaitGroup
	ch := make(chan scanWorkItem)
	workers := concurrency
	if workers > len(work) {
		workers = len(work)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range ch {
				scanOne(item)
			}
		}()
	}
	for _, item := range work {
		ch <- item
	}
	close(ch)
	wg.Wait()

	scanLogf("done. %d scans succeeded, %d failed.", total, failed)
	if strict && total == 0 {
		return fmt.Errorf("[scan] strict %s mode found zero SBOMs to scan.", scanOpts.mode)
	}
	if strict && failed > 0 {
		return fmt.Errorf("[scan] strict %s mode had %d failed scan(s).", scanOpts.mode, failed)
	}
	return nil
}

func scanSBOM(grypeBin string, grypeOpts []string, item scanWorkItem, scannerVersion string, dbBuiltAt *string) (scanReport, error) {
	args := append([]string{"sbom:" + item.sbomPath, "-o", "json", "--quiet"}, grypeOpts...)
	raw, err := exec.Command(grypeBin, args...).Output()
	if err != nil && len(raw) == 0 {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
			if len(stderr) > 200 {
				stderr = stderr[:200]
			}
		}
		return scanReport{}, fmt.Errorf("grype failed: %v: %s", err, stderr)
	}
	var result grypeResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return scanReport{}, fmt.Errorf("grype produced unparseable JSON: %w", err)
	}
	report := normalizeGrype(result, nowRFC3339Milli(), "grype-"+scannerVersion, dbBuiltAt, targetMetadata(item.target))
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return scanReport{}, err
	}
	if err := os.WriteFile(item.outPath, out, 0o644); err != nil {
		return scanReport{}, err
	}
	return report, nil
}
