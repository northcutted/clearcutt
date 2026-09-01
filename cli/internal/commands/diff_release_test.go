package commands

import (
	"encoding/json"
	"strings"
	"testing"
)

const diffCatalog = "../testdata/diff-catalog"

// TestDiffReportsWhatChangedBetweenReleases covers the `diff` command, which had
// no test at all and was the single largest uncovered block in the package.
//
// It is the command an operator runs to answer "what actually changed in this
// release?", so the properties worth pinning are that it names the direction of
// the comparison, reports a digest change as changed, and reports a size delta
// with a sign.
func TestDiffReportsWhatChangedBetweenReleases(t *testing.T) {
	stdout, err := runCLI(t, "--catalog", diffCatalog, "diff", "java21-distroless",
		"--from", "v1.0.0", "--to", "v1.1.0")
	if err != nil {
		t.Fatalf("diff: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"java21-distroless",
		"Comparing: v1.0.0 -> v1.1.0",
		"Manifest Digest Change: changed",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("diff output missing %q:\n%s", want, stdout)
		}
	}
	// The fixture grows by ~10MB, so the delta must be signed and positive —
	// an unsigned delta would leave the reader unable to tell growth from
	// shrinkage.
	if !strings.Contains(stdout, "Total Size Delta:       +") {
		t.Errorf("size delta should be signed and positive:\n%s", stdout)
	}
}

// TestDiffReversedShowsTheOppositeDelta: the direction of comparison has to be
// honoured, or a rollback would read as a growth.
func TestDiffReversedShowsTheOppositeDelta(t *testing.T) {
	stdout, err := runCLI(t, "--catalog", diffCatalog, "diff", "java21-distroless",
		"--from", "v1.1.0", "--to", "v1.0.0")
	if err != nil {
		t.Fatalf("reversed diff: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "Comparing: v1.1.0 -> v1.0.0") {
		t.Errorf("reversed diff should say so:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Total Size Delta:       -") {
		t.Errorf("reversing the comparison must flip the sign of the delta:\n%s", stdout)
	}
}

// TestDiffLatestAliasesResolve: `latest` and `latest-N` are the aliases an
// operator actually types; they must resolve without knowing tag names.
func TestDiffLatestAliasesResolve(t *testing.T) {
	stdout, err := runCLI(t, "--catalog", diffCatalog, "diff", "java21-distroless",
		"--from", "latest-1", "--to", "latest")
	if err != nil {
		t.Fatalf("alias diff: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "Comparing: v1.0.0 -> v1.1.0") {
		t.Errorf("latest-1 -> latest should resolve to the two fixture releases:\n%s", stdout)
	}
}

func TestDiffJSONOutputIsMachineReadable(t *testing.T) {
	stdout, err := runCLI(t, "--format", "json", "--catalog", diffCatalog,
		"diff", "java21-distroless", "--from", "v1.0.0", "--to", "v1.1.0")
	if err != nil {
		t.Fatalf("json diff: %v\n%s", err, stdout)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("--format json must emit parseable JSON: %v\n%s", err, stdout)
	}
	if len(payload) == 0 {
		t.Error("the JSON diff should carry the comparison, not an empty object")
	}
}

// TestDiffUnknownReferencesFail: a typo in a tag must be an error, not a
// silently empty comparison that reads as "nothing changed".
func TestDiffUnknownReferencesFail(t *testing.T) {
	if _, err := runCLI(t, "--catalog", diffCatalog, "diff", "java21-distroless",
		"--from", "v9.9.9", "--to", "v1.1.0"); err == nil {
		t.Error("an unknown --from tag should fail rather than compare against nothing")
	}
	if _, err := runCLI(t, "--catalog", diffCatalog, "diff", "no-such-image",
		"--from", "v1.0.0", "--to", "v1.1.0"); err == nil {
		t.Error("an unknown image id should fail")
	}
}
