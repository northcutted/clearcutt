package commands

import (
	"errors"
	"io"
	"os"
)

// ErrCheckFailed is a sentinel returned by gating commands (verify, certify,
// conformance, exceptions) when one or more policy checks fail. main treats it
// as a process exit code 1 without printing a redundant "Error:" line, since the
// command has already rendered a detailed report.
var ErrCheckFailed = errors.New("one or more checks failed")

// out and errOut are the writers used for all command output. They default to
// the process stdio but are swapped in tests to capture output, which keeps the
// commands testable without threading a writer through every function.
var (
	out    io.Writer = os.Stdout
	errOut io.Writer = os.Stderr
)
