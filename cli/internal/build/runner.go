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

// Run executes name with args in dir, streaming stdout/stderr.
func (e ExecRunner) Run(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = e.Stdout
	cmd.Stderr = e.Stderr
	return cmd.Run()
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
