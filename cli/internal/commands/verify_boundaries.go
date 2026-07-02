package commands

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/northcutted/clearcutt/internal/certify"
	"github.com/spf13/cobra"
)

type boundariesFlags struct {
	allowlist      string
	floor          string
	storePaths     string
	coreDir        string
	buildOutputs   string
	closureTargets []string
	runtimeTargets []string
}

var boundariesOpts boundariesFlags

// newVerifyBoundariesCmd runs every image-security boundary gate over one
// shipped closure. It is the CLI-owned umbrella for the gates that previously
// lived only in core/tests/verify.sh, so a forker gets the same verification by
// running the binary. New gates are added here as they are ported.
func newVerifyBoundariesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "boundaries [image-archive]",
		Short: "Run all image-security boundary gates (closure purity + runtime-patch completeness)",
		Long: `Runs every native-Go image-security boundary gate over one shipped closure
(a docker-save / OCI-layout archive, or a closureInfo store-paths file):

  closure-purity   no shells, package managers, or setuid/setgid files
  runtime-cve      every CVE-remediated crypto path is a known-good identity

Fails if any gate fails. This is the CLI-owned umbrella that replaces the
per-gate python invocations in core/tests/verify.sh.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			archive := ""
			if len(args) == 1 {
				archive = args[0]
			}
			return runVerifyBoundaries(archive)
		},
	}
	cmd.Flags().StringVar(&boundariesOpts.allowlist, "allowlist", "", "closure-purity explained-exception allowlist file")
	cmd.Flags().StringVar(&boundariesOpts.floor, "floor", "", "runtime-dep-floor.json for the runtime-cve gate (required)")
	cmd.Flags().StringVar(&boundariesOpts.storePaths, "store-paths", "", "closureInfo store-paths file to scan instead of an image archive")
	_ = cmd.MarkFlagRequired("floor")
	return cmd
}

// newVerifyBoundarySuiteCmd owns the PR-gate representative image-security
// boundary loop that used to live in core/tests/verify.sh: closure-purity over
// the representative distroless image and runtime-CVE completeness over slim +
// distroless. Missing archives are built through Nix, preserving Nix as the
// hermetic image backend while keeping orchestration in the CLI.
func newVerifyBoundarySuiteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "boundary-suite",
		Short: "Run the representative image-security boundary suite for PR gates",
		Long: `Runs the representative native-Go image-security boundary suite over a
ClearCutt core build-output directory. Missing archives are realized with
nix build from the core flake; closure-purity then runs over the configured
distroless target(s), and runtime-cve runs over slim + distroless target(s).

This is the CLI-owned replacement for the closure-purity/runtime-CVE portion of
core/tests/verify.sh in PR gates.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerifyBoundarySuite()
		},
	}
	cmd.Flags().StringVar(&boundariesOpts.coreDir, "core-dir", "", "ClearCutt core flake directory (auto-detected when omitted)")
	cmd.Flags().StringVar(&boundariesOpts.buildOutputs, "build-outputs", "build-outputs", "Build output directory containing image tarballs, relative to --core-dir unless absolute")
	cmd.Flags().StringVar(&boundariesOpts.allowlist, "allowlist", "", "closure-purity explained-exception allowlist file (defaults to core/tests/closure-purity-allowlist.txt)")
	cmd.Flags().StringVar(&boundariesOpts.floor, "floor", "", "runtime-dep-floor.json for the runtime-cve gate (defaults to core/tests/runtime-dep-floor.json)")
	cmd.Flags().StringSliceVar(&boundariesOpts.closureTargets, "closure-target", []string{"coreLTS-distroless"}, "Image target(s) to run closure-purity against")
	cmd.Flags().StringSliceVar(&boundariesOpts.runtimeTargets, "runtime-target", []string{"coreLTS-slim", "coreLTS-distroless"}, "Image target(s) to run runtime-cve against")
	return cmd
}

func runVerifyBoundaries(archive string) error {
	if (archive != "") == (boundariesOpts.storePaths != "") {
		return fmt.Errorf("provide exactly one of <image-archive> or --store-paths FILE")
	}

	failed := false

	// Gate 1: closure purity.
	allowlist, err := certify.LoadClosureAllowlist(boundariesOpts.allowlist)
	if err != nil {
		return err
	}
	var purity certify.ClosurePurityResult
	if archive != "" {
		purity, err = certify.ScanImageArchiveForClosurePurity(archive, allowlist)
	} else {
		purity, err = certify.ScanStorePathsForClosurePurity(boundariesOpts.storePaths, allowlist)
	}
	if err != nil {
		return err
	}
	for _, note := range purity.Accepted {
		fmt.Fprintf(out, "[closure-purity] ACCEPTED: %s\n", note)
	}
	if purity.Clean() {
		fmt.Fprintln(out, "[closure-purity] clean: no shells, package managers, or setuid/setgid files found.")
	} else {
		for _, v := range purity.Violations {
			fmt.Fprintf(errOut, "[closure-purity] VIOLATION: %s\n", v.Message)
		}
		failed = true
	}

	// Gate 2: runtime-patch completeness.
	floor, err := certify.LoadRuntimeDepFloor(boundariesOpts.floor)
	if err != nil {
		return err
	}
	var runtimeCve certify.RuntimeCveResult
	if archive != "" {
		runtimeCve, err = certify.ScanImageArchiveForRuntimeCve(archive, floor)
	} else {
		runtimeCve, err = certify.ScanStorePathsForRuntimeCve(boundariesOpts.storePaths, floor)
	}
	if err != nil {
		return err
	}
	if runtimeCve.Clean() {
		fmt.Fprintf(out, "[runtime-cve] clean: every shipped crypto path matches a known-good identity (%s).\n", strings.Join(runtimeCve.Tracked, ", "))
	} else {
		for _, v := range runtimeCve.Violations {
			fmt.Fprintf(errOut, "[runtime-cve] VIOLATION: %s\n", v.Message)
		}
		failed = true
	}

	if failed {
		return ErrCheckFailed
	}
	fmt.Fprintln(out, "[boundaries] all image-security boundary gates passed.")
	return nil
}

func runVerifyBoundarySuite() error {
	coreDir, err := resolveCoreDir(boundariesOpts.coreDir)
	if err != nil {
		return err
	}
	buildOutputs := boundariesOpts.buildOutputs
	if buildOutputs == "" {
		buildOutputs = "build-outputs"
	}
	if !filepath.IsAbs(buildOutputs) {
		buildOutputs = filepath.Join(coreDir, buildOutputs)
	}
	allowlistPath := boundariesOpts.allowlist
	if allowlistPath == "" {
		allowlistPath = filepath.Join(coreDir, "tests", "closure-purity-allowlist.txt")
	}
	floorPath := boundariesOpts.floor
	if floorPath == "" {
		floorPath = filepath.Join(coreDir, "tests", "runtime-dep-floor.json")
	}

	allowlist, err := certify.LoadClosureAllowlist(allowlistPath)
	if err != nil {
		return err
	}
	floor, err := certify.LoadRuntimeDepFloor(floorPath)
	if err != nil {
		return err
	}

	failed := false
	for _, target := range nonEmptyStrings(boundariesOpts.closureTargets) {
		archive, err := ensureBoundarySuiteArchive(coreDir, buildOutputs, target)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "[boundary-suite] closure-purity %s -> %s\n", target, archive)
		result, err := certify.ScanImageArchiveForClosurePurity(archive, allowlist)
		if err != nil {
			return fmt.Errorf("closure-purity scan failed for %s: %w", target, err)
		}
		for _, note := range result.Accepted {
			fmt.Fprintf(out, "[closure-purity:%s] ACCEPTED: %s\n", target, note)
		}
		if result.Clean() {
			fmt.Fprintf(out, "[closure-purity:%s] clean\n", target)
		} else {
			for _, v := range result.Violations {
				fmt.Fprintf(errOut, "[closure-purity:%s] VIOLATION: %s\n", target, v.Message)
			}
			failed = true
		}
	}

	for _, target := range nonEmptyStrings(boundariesOpts.runtimeTargets) {
		archive, err := ensureBoundarySuiteArchive(coreDir, buildOutputs, target)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "[boundary-suite] runtime-cve %s -> %s\n", target, archive)
		result, err := certify.ScanImageArchiveForRuntimeCve(archive, floor)
		if err != nil {
			return fmt.Errorf("runtime-cve scan failed for %s: %w", target, err)
		}
		if result.Clean() {
			fmt.Fprintf(out, "[runtime-cve:%s] clean: every shipped crypto path matches a known-good identity (%s).\n", target, strings.Join(result.Tracked, ", "))
		} else {
			for _, v := range result.Violations {
				fmt.Fprintf(errOut, "[runtime-cve:%s] VIOLATION: %s\n", target, v.Message)
			}
			failed = true
		}
	}

	if failed {
		return ErrCheckFailed
	}
	fmt.Fprintln(out, "[boundary-suite] representative image-security boundary suite passed.")
	return nil
}

func ensureBoundarySuiteArchive(coreDir, buildOutputs, target string) (string, error) {
	// nix build runs with cwd=coreDir and resolves a relative --out-link there,
	// while this process reads the link from its own cwd. Anchor to absolute.
	buildOutputs, err := filepath.Abs(buildOutputs)
	if err != nil {
		return "", err
	}
	archive := filepath.Join(buildOutputs, target+".tar.gz")
	if _, err := os.Stat(archive); err == nil {
		return archive, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.MkdirAll(buildOutputs, 0o755); err != nil {
		return "", err
	}
	linkPath := filepath.Join(buildOutputs, target+"-link")
	_ = os.Remove(linkPath)
	fmt.Fprintf(out, "[boundary-suite] %s archive missing; realizing with nix build...\n", target)
	if err := runExternalCommand(externalCommand{
		Name: "nix",
		Dir:  coreDir,
		Args: []string{
			"build",
			".#" + target,
			"--out-link",
			linkPath,
			"--extra-experimental-features",
			"nix-command flakes",
			"--accept-flake-config",
		},
	}); err != nil {
		return "", err
	}
	if err := copyDereferenceFile(linkPath, archive); err != nil {
		return "", fmt.Errorf("copy nix build output for %s: %w", target, err)
	}
	_ = os.Remove(linkPath)
	return archive, nil
}

func copyDereferenceFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	outFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(outFile, in); err != nil {
		_ = outFile.Close()
		return err
	}
	return outFile.Close()
}

func nonEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
