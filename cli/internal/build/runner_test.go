package build

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recordingBuildRunner struct {
	runs     []recordedBuildCall
	captures []recordedBuildCall
}

type recordedBuildCall struct {
	dir     string
	outPath string
	name    string
	args    []string
}

func (r *recordingBuildRunner) Run(dir, name string, args ...string) error {
	r.runs = append(r.runs, recordedBuildCall{dir: dir, name: name, args: append([]string(nil), args...)})
	return nil
}

func (r *recordingBuildRunner) Capture(dir, outPath, name string, args ...string) error {
	r.captures = append(r.captures, recordedBuildCall{dir: dir, outPath: outPath, name: name, args: append([]string(nil), args...)})
	return nil
}

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

func TestNixToolRunnerWrapsNonNixTools(t *testing.T) {
	rec := &recordingBuildRunner{}
	r := NixToolRunner{Runner: rec}
	if err := r.Run("/repo/core", "syft", "docker-archive:image.tar.gz", "-o", "spdx-json"); err != nil {
		t.Fatalf("Run syft: %v", err)
	}
	if len(rec.runs) != 1 {
		t.Fatalf("expected one run, got %#v", rec.runs)
	}
	call := rec.runs[0]
	if call.dir != "/repo/core" || call.name != "nix" {
		t.Fatalf("unexpected wrapped run call: %#v", call)
	}
	joined := strings.Join(call.args, " ")
	for _, want := range []string{
		"develop --extra-experimental-features nix-command flakes --accept-flake-config",
		"--command syft docker-archive:image.tar.gz -o spdx-json",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("wrapped run args missing %q in %q", want, joined)
		}
	}

	if err := r.Capture("/repo/core", "/tmp/grype.json", "grype", "sbom:sbom.json", "-o", "json"); err != nil {
		t.Fatalf("Capture grype: %v", err)
	}
	if len(rec.captures) != 1 {
		t.Fatalf("expected one capture, got %#v", rec.captures)
	}
	capture := rec.captures[0]
	if capture.name != "nix" || capture.outPath != "/tmp/grype.json" {
		t.Fatalf("unexpected wrapped capture call: %#v", capture)
	}
	if joined := strings.Join(capture.args, " "); !strings.Contains(joined, "--command grype sbom:sbom.json -o json") {
		t.Fatalf("wrapped capture args missing grype command: %q", joined)
	}
}

func TestNixToolRunnerLeavesNixDirect(t *testing.T) {
	rec := &recordingBuildRunner{}
	r := NixToolRunner{Runner: rec}
	if err := r.Run("/repo/core", "nix", "build", ".#pkg"); err != nil {
		t.Fatalf("Run nix: %v", err)
	}
	if len(rec.runs) != 1 || rec.runs[0].name != "nix" || strings.Join(rec.runs[0].args, " ") != "build .#pkg" {
		t.Fatalf("nix run should stay direct, got %#v", rec.runs)
	}
	if err := r.Capture("/repo/core", "/tmp/out", "nix", "path-info", ".#pkg"); err != nil {
		t.Fatalf("Capture nix: %v", err)
	}
	if len(rec.captures) != 1 || rec.captures[0].name != "nix" || strings.Join(rec.captures[0].args, " ") != "path-info .#pkg" {
		t.Fatalf("nix capture should stay direct, got %#v", rec.captures)
	}
}
