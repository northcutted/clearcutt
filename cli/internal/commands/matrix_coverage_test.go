package commands

import (
	"strings"
	"testing"
)

func TestMatrixExplainFallbackAndFailureBranches(t *testing.T) {
	stdout, err := runCLI(t, "--format", "yaml", "matrix", "explain", "java25", "--config", "missing-clearcutt.yaml")
	if err != nil {
		t.Fatalf("matrix explain should fall back to built-ins when config is missing: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "fleetConfigFound: false") || !strings.Contains(stdout, "java25") {
		t.Fatalf("unexpected missing-config explanation:\n%s", stdout)
	}

	stdout, err = runCLI(t, "matrix", "explain", "ruby3.4", "--config", "missing-clearcutt.yaml")
	if err == nil || !strings.Contains(err.Error(), "unsupported runtime line") {
		t.Fatalf("expected unsupported fallback error, got err=%v stdout=\n%s", err, stdout)
	}
}

func TestMatrixAddRemoveFailureBranches(t *testing.T) {
	path := writeFleetConfig(t, t.TempDir())
	stdout, err := runCLI(t, "matrix", "add", "ruby3.4", "--fleet-config", path)
	if err == nil || !strings.Contains(err.Error(), "unsupported runtime line") {
		t.Fatalf("expected unsupported add error, got err=%v stdout=\n%s", err, stdout)
	}
	stdout, err = runCLI(t, "matrix", "remove", "ruby3.4", "--fleet-config", path)
	if err == nil || !strings.Contains(err.Error(), "not selected") {
		t.Fatalf("expected missing remove error, got err=%v stdout=\n%s", err, stdout)
	}
}

func TestMatrixHelperNoopBranches(t *testing.T) {
	if got := appendUnique([]string{"java21"}, "java21"); len(got) != 1 {
		t.Fatalf("appendUnique duplicate should not append: %#v", got)
	}
	if got := appendUnique([]string{"java21"}, " "); len(got) != 1 {
		t.Fatalf("appendUnique blank should not append: %#v", got)
	}
	if got, removed := removeString([]string{"java21"}, "ruby3.4"); removed || len(got) != 1 {
		t.Fatalf("removeString absent = %#v %t", got, removed)
	}
}
