package commands

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Conformance probes the live host, so the overall result is environment
// dependent (a missing interpreter is a legitimate fail). We assert the report is
// well-formed and that the error, if any, is the gate sentinel rather than a crash.
func TestConformanceRun_ReportIsWellFormed(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "report.json")

	_, err := runCLI(t, "conformance", "run", "--image", "host", "--output", reportPath)
	if err != nil && !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("unexpected error type: %v", err)
	}

	data, rerr := os.ReadFile(reportPath)
	if rerr != nil {
		t.Fatalf("failed to read conformance report: %v", rerr)
	}

	var report ConformanceReport
	if uerr := json.Unmarshal(data, &report); uerr != nil {
		t.Fatalf("report is not valid JSON: %v", uerr)
	}
	if report.Status != "passed" && report.Status != "failed" {
		t.Errorf("unexpected status %q", report.Status)
	}
	if len(report.Assertions) == 0 {
		t.Fatal("expected at least the baseline host assertions")
	}

	// The baseline (host-independent) checks must always be present.
	want := map[string]bool{"runtime.user.nonroot": false, "runtime.paths.tmp_writable": false}
	for _, a := range report.Assertions {
		if _, ok := want[a.Name]; ok {
			want[a.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("expected assertion %q in report", name)
		}
	}

	// A failed report must correspond to the gate sentinel, and vice versa.
	if report.Status == "failed" && !errors.Is(err, ErrCheckFailed) {
		t.Errorf("failed report should return ErrCheckFailed")
	}
	if report.Status == "passed" && err != nil {
		t.Errorf("passed report should return nil error, got %v", err)
	}
}
