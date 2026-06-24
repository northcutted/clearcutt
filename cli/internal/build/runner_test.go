package build

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecRunnerRun(t *testing.T) {
	r := ExecRunner{}
	if err := r.Run(t.TempDir(), "true"); err != nil {
		t.Fatalf("Run true: %v", err)
	}
	if err := r.Run(t.TempDir(), "false"); err == nil {
		t.Fatal("Run false should return a non-zero exit error")
	}
	if err := r.Run(t.TempDir(), "clearcutt-no-such-binary-xyz"); err == nil {
		t.Fatal("Run of a missing binary should error")
	}
}

func TestExecRunnerCapture(t *testing.T) {
	r := ExecRunner{}
	out := filepath.Join(t.TempDir(), "out.txt")
	if err := r.Capture("", out, "echo", "hello-capture"); err != nil {
		t.Fatalf("Capture echo: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read captured output: %v", err)
	}
	if !strings.Contains(string(data), "hello-capture") {
		t.Errorf("captured %q, want it to contain hello-capture", data)
	}

	// A non-zero exit still writes the (empty) file and returns the error, so a
	// caller like the Grype gate can both keep the scan artifact and gate on it.
	if err := r.Capture("", filepath.Join(t.TempDir(), "f.txt"), "false"); err == nil {
		t.Fatal("Capture of a failing command should return its exit error")
	}

	// An unwritable output path errors before exec.
	if err := r.Capture("", filepath.Join(t.TempDir(), "nope", "deep", "x.txt"), "echo", "hi"); err == nil {
		t.Fatal("Capture should error when the output path cannot be created")
	}
}
