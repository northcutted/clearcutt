package build

import (
	"io"
	"os"
	"os/exec"
)

// ExecRunner is the production Runner: explicit-argv subprocesses, never a
// shell, so the build engine inherits the zero-shell guarantee.
type ExecRunner struct {
	Stdout io.Writer
	Stderr io.Writer
}

// NixToolRunner routes non-Nix tools through the core flake dev shell while
// leaving direct `nix` invocations untouched. This keeps the Go build engine in
// charge of orchestration without requiring syft/grype/etc. to be installed on
// the ambient PATH.
type NixToolRunner struct {
	Runner Runner
}

// Run executes name with args in dir, streaming stdout/stderr.
func (e ExecRunner) Run(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = e.Stdout
	cmd.Stderr = e.Stderr
	return cmd.Run()
}

// Run executes name directly when it is nix, otherwise via
// `nix develop --command <name> ...` in dir.
func (n NixToolRunner) Run(dir, name string, args ...string) error {
	r := n.runner()
	if name == "nix" {
		return r.Run(dir, name, args...)
	}
	return r.Run(dir, "nix", NixDevelopCommand(name, args...)...)
}

// Capture mirrors Run while writing the wrapped command's stdout to outPath.
func (n NixToolRunner) Capture(dir, outPath, name string, args ...string) error {
	r := n.runner()
	if name == "nix" {
		return r.Capture(dir, outPath, name, args...)
	}
	return r.Capture(dir, outPath, "nix", NixDevelopCommand(name, args...)...)
}

func (n NixToolRunner) runner() Runner {
	if n.Runner != nil {
		return n.Runner
	}
	return ExecRunner{}
}

// NixDevelopCommand returns argv for running a tool from the current flake
// dev shell.
func NixDevelopCommand(name string, args ...string) []string {
	out := []string{
		"develop",
		"--extra-experimental-features", "nix-command flakes",
		"--accept-flake-config",
		"--command", name,
	}
	out = append(out, args...)
	return out
}

// Capture executes name with args in dir, writing stdout to outPath. The output
// file is written even when the tool exits non-zero (e.g. Grype on a finding),
// and the non-zero exit is returned so the caller can gate on it.
func (e ExecRunner) Capture(dir, outPath, name string, args ...string) error {
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = out
	cmd.Stderr = e.Stderr
	return cmd.Run()
}
