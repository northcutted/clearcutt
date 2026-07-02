// Package build is the native-Go fleet build engine: the port of
// core/pipeline/pipeline.sh's certify_target gating path. It orchestrates the
// Nix build, SBOM, and Grype scan as explicit-argv subprocesses (zero shell)
// behind a Runner seam, and runs the closure-purity and runtime-cve boundary
// gates IN-PROCESS via the certify package (no python subprocess). The actual
// `nix build` of a Linux image runs on a Linux host / CI; everything else here
// is unit-testable with a fake Runner over a crafted image archive.
package build

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/northcutted/clearcutt/internal/certify"
)

// Runner executes external tools (nix, syft, grype). Explicit argv, never a
// shell. Capture writes the tool's stdout to outPath (for SBOM/scan artifacts)
// and reports whether the tool exited non-zero via the returned error.
type Runner interface {
	Run(dir, name string, args ...string) error
	Capture(dir, outPath, name string, args ...string) error
}

// Options configures a single certify run.
type Options struct {
	Target                   string // e.g. coreLTS-slim, java21-distroless, postgres16
	System                   string // e.g. x86_64-linux
	Kind                     string // "runtime" or "service"
	CoreDir                  string // working dir for the build (holds flake.nix)
	OutputDir                string // build-outputs directory (absolute or core-relative)
	AllowlistPath            string // closure-purity explained-exception allowlist
	FloorPath                string // runtime-dep-floor.json
	ServiceProductionAllowed bool
	ServiceLifecycleStatus   string
}

// Assertion is one named gate result in the test-results predicate.
type Assertion struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// Policy mirrors the pipeline.sh test-results predicate policy block.
type Policy struct {
	Blocking          bool   `json:"blocking"`
	FailOn            string `json:"failOn"`
	OnlyFixed         bool   `json:"onlyFixed"`
	ProductionAllowed bool   `json:"productionAllowed"`
	LifecycleStatus   string `json:"lifecycleStatus"`
}

// Evidence points at the SBOM and scan artifacts.
type Evidence struct {
	SBOMPath string `json:"sbomPath"`
	ScanPath string `json:"scanPath"`
}

// Result is the test-results predicate, byte-compatible with the one
// pipeline.sh emits, so downstream catalog/attestation consumers are unchanged.
type Result struct {
	System               string      `json:"system"`
	Target               string      `json:"target"`
	Kind                 string      `json:"kind"`
	Language             string      `json:"language"`
	Tier                 string      `json:"tier"`
	Status               string      `json:"status"`
	ClosurePurity        *bool       `json:"closurePurity"`
	RuntimePatchComplete *bool       `json:"runtimePatchComplete"`
	Timestamp            string      `json:"timestamp"`
	Policy               Policy      `json:"policy"`
	Evidence             Evidence    `json:"evidence"`
	Assertions           []Assertion `json:"assertions"`
}

// parseTarget derives the language and tier from a target name, mirroring
// pipeline.sh: "java21-distroless" -> ("java21","distroless"); a service target
// is its own language with tier "service".
func parseTarget(target, kind string) (lang, tier string) {
	if kind == "service" {
		return target, "service"
	}
	parts := strings.SplitN(target, "-", 2)
	lang = strings.ToLower(parts[0])
	if len(parts) > 1 {
		tier = parts[1]
	}
	return lang, tier
}

// grypeStatus maps a Grype gate outcome to passed/warning/failed, mirroring the
// pipeline.sh tier/kind policy: dev runtime and non-production services downgrade
// a hit to a warning; everything else is a hard failure.
func grypeStatus(failed bool, kind, tier string, productionAllowed bool, lifecycle string) string {
	if !failed {
		return "passed"
	}
	if kind == "runtime" && tier == "dev" {
		return "warning"
	}
	if kind == "service" && (!productionAllowed || lifecycle != "active") {
		return "warning"
	}
	return "failed"
}

// policyBlocking mirrors pipeline.sh: dev runtime and non-production services are
// non-blocking; everything else blocks a release on a gate failure.
func policyBlocking(kind, tier string, productionAllowed bool, lifecycle string) bool {
	if kind == "runtime" && tier == "dev" {
		return false
	}
	if kind == "service" && (!productionAllowed || lifecycle != "active") {
		return false
	}
	return true
}

// aggregateStatus folds gate statuses into an overall verdict: any failed ->
// failed; else any warning -> warning; else any skipped (with the rest passed)
// -> skipped; else passed.
func aggregateStatus(statuses ...string) string {
	out := "passed"
	for _, s := range statuses {
		switch s {
		case "failed":
			return "failed"
		case "warning":
			if out != "failed" {
				out = "warning"
			}
		case "skipped":
			if out == "passed" {
				out = "skipped"
			}
		case "passed":
		default:
			return "failed"
		}
	}
	return out
}

func boolPtr(b bool) *bool { return &b }

// CertifyTarget builds, scans, and gates one target, writing the test-results
// predicate to OutputDir/<target>.test-results.json. It returns the predicate
// and a non-nil error when a blocking gate (Grype/closure-purity/runtime-cve)
// fails. now and w are injected for deterministic, capturable runs.
func CertifyTarget(r Runner, opts Options, now time.Time, w io.Writer) (Result, error) {
	if strings.HasSuffix(opts.System, "-darwin") {
		return Result{}, fmt.Errorf("OCI image target %q is only buildable on a Linux host; use a Linux runner", opts.Target)
	}
	lang, tier := parseTarget(opts.Target, opts.Kind)
	logf(w, "Certifying %s target %s [%s]", opts.Kind, opts.Target, opts.System)

	// Subprocesses run with cwd=CoreDir (nix --out-link, syft's archive arg),
	// while this process reads the same paths from its own cwd. Anchor the
	// output dir to an absolute path so both sides resolve identically.
	outDir, err := filepath.Abs(opts.OutputDir)
	if err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return Result{}, err
	}
	tarPath := filepath.Join(outDir, opts.Target+".tar.gz")
	sbomPath := filepath.Join(outDir, opts.Target+".sbom.json")
	scanPath := filepath.Join(outDir, opts.Target+".grype.json")
	linkPath := filepath.Join(outDir, opts.Target+"-link")

	// A. Nix compilation. The build is the one step that requires a Linux host;
	// the rest of the pipeline runs anywhere over the produced archive.
	buildAttr := fmt.Sprintf(".#packages.%s.\"%s\"", opts.System, opts.Target)
	logf(w, "Compiling OCI image via Nix: %s", buildAttr)
	if err := r.Run(opts.CoreDir, "nix", "build", buildAttr, "--out-link", linkPath,
		"--extra-experimental-features", "nix-command flakes", "--accept-flake-config"); err != nil {
		return Result{}, fmt.Errorf("nix build failed for %s: %w", opts.Target, err)
	}
	data, err := os.ReadFile(linkPath) // follows the out-link symlink to the store path
	if err != nil {
		return Result{}, fmt.Errorf("reading nix build output for %s: %w", opts.Target, err)
	}
	if err := os.WriteFile(tarPath, data, 0o644); err != nil {
		return Result{}, err
	}
	_ = os.Remove(linkPath)

	// B. SBOM via Syft (against the compressed OCI archive).
	logf(w, "Generating SPDX SBOM via Syft -> %s", sbomPath)
	if err := r.Capture(opts.CoreDir, sbomPath, "syft", "docker-archive:"+tarPath, "-o", "spdx-json"); err != nil {
		return Result{}, fmt.Errorf("syft SBOM generation failed for %s: %w", opts.Target, err)
	}

	// C. Vulnerability gate via Grype (fail-on high, only-fixed). A non-zero exit
	// means fixable Critical/High CVEs; the tier/kind policy decides severity.
	logf(w, "Scanning SBOM via Grype (fail-on high, only-fixed)...")
	grypeErr := r.Capture(opts.CoreDir, scanPath, "grype", "sbom:"+sbomPath, "--fail-on", "high", "--only-fixed", "-o", "json")
	grype := grypeStatus(grypeErr != nil, opts.Kind, tier, opts.ServiceProductionAllowed, opts.ServiceLifecycleStatus)

	// C1. Closure purity (distroless runtime) — IN-PROCESS, no python.
	closureStatus := "skipped"
	var closurePtr *bool
	if opts.Kind == "runtime" && tier == "distroless" {
		logf(w, "Closure-purity gate (in-process) on distroless target...")
		allowlist, err := certify.LoadClosureAllowlist(opts.AllowlistPath)
		if err != nil {
			return Result{}, fmt.Errorf("loading closure-purity allowlist: %w", err)
		}
		res, err := certify.ScanImageArchiveForClosurePurity(tarPath, allowlist)
		if err != nil {
			return Result{}, fmt.Errorf("closure-purity scan failed for %s: %w", opts.Target, err)
		}
		if res.Clean() {
			closureStatus, closurePtr = "passed", boolPtr(true)
		} else {
			closureStatus, closurePtr = "failed", boolPtr(false)
			for _, v := range res.Violations {
				logf(w, "[closure-purity] VIOLATION: %s", v.Message)
			}
		}
	}

	// C2. Runtime-patch completeness (slim + distroless runtime) — IN-PROCESS.
	runtimeStatus := "skipped"
	var runtimePtr *bool
	if opts.Kind == "runtime" && (tier == "slim" || tier == "distroless") {
		logf(w, "Runtime-cve gate (in-process) on %s target...", tier)
		floor, err := certify.LoadRuntimeDepFloor(opts.FloorPath)
		if err != nil {
			return Result{}, fmt.Errorf("loading runtime-dep floor: %w", err)
		}
		res, err := certify.ScanImageArchiveForRuntimeCve(tarPath, floor)
		if err != nil {
			return Result{}, fmt.Errorf("runtime-cve scan failed for %s: %w", opts.Target, err)
		}
		if res.Clean() {
			runtimeStatus, runtimePtr = "passed", boolPtr(true)
		} else {
			runtimeStatus, runtimePtr = "failed", boolPtr(false)
			for _, v := range res.Violations {
				logf(w, "[runtime-cve] VIOLATION: %s", v.Message)
			}
		}
	}

	// D. Assemble the test-results predicate.
	statuses := []string{"passed", "passed", grype}
	if closureStatus != "skipped" {
		statuses = append(statuses, closureStatus)
	}
	if runtimeStatus != "skipped" {
		statuses = append(statuses, runtimeStatus)
	}
	lifecycle := opts.ServiceLifecycleStatus
	if opts.Kind == "service" && lifecycle == "" {
		lifecycle = "preview"
	}

	result := Result{
		System:               opts.System,
		Target:               opts.Target,
		Kind:                 opts.Kind,
		Language:             lang,
		Tier:                 tier,
		Status:               aggregateStatus(statuses...),
		ClosurePurity:        closurePtr,
		RuntimePatchComplete: runtimePtr,
		Timestamp:            now.UTC().Format("2006-01-02T15:04:05Z"),
		Policy: Policy{
			Blocking:          policyBlocking(opts.Kind, tier, opts.ServiceProductionAllowed, lifecycle),
			FailOn:            "high",
			OnlyFixed:         true,
			ProductionAllowed: opts.ServiceProductionAllowed,
			LifecycleStatus:   lifecycle,
		},
		Evidence: Evidence{SBOMPath: sbomPath, ScanPath: scanPath},
		Assertions: []Assertion{
			{Name: "Nix Compilation", Status: "passed"},
			{Name: "Syft SBOM Generation", Status: "passed"},
			{Name: "Grype Vulnerability Gating", Status: grype},
			{Name: "Closure Purity (distroless boundary)", Status: closureStatus},
			{Name: "Runtime-Patch Completeness (crypto identity allowlist)", Status: runtimeStatus},
		},
	}

	predicatePath := filepath.Join(outDir, opts.Target+".test-results.json")
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return result, err
	}
	if err := os.WriteFile(predicatePath, append(encoded, '\n'), 0o644); err != nil {
		return result, err
	}
	logf(w, "Test-results predicate written -> %s", predicatePath)

	// E. Fail closed on any blocking gate.
	if grype == "failed" {
		return result, fmt.Errorf("vulnerability gate failed for %s: fixable Critical/High CVEs", opts.Target)
	}
	if closureStatus == "failed" {
		return result, fmt.Errorf("closure-purity gate failed for %s", opts.Target)
	}
	if runtimeStatus == "failed" {
		return result, fmt.Errorf("runtime-cve gate failed for %s", opts.Target)
	}
	logf(w, "Target certified: %s", opts.Target)
	return result, nil
}

func logf(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, "[build] "+format+"\n", args...)
}
