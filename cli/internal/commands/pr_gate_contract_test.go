package commands

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	// A job definition in the workflow: exactly two spaces of indent inside `jobs:`.
	prGateJobRe = regexp.MustCompile(`(?m)^  ([a-z0-9][a-z0-9-]*):$`)
	// An entry in the summary job's `needs:` list.
	prGateNeedRe = regexp.MustCompile(`(?m)^      - ([a-z0-9][a-z0-9-]*)$`)
	// A key in the embedded `selected = {...}` contract dict.
	prGateContractRe = regexp.MustCompile(`(?m)^\s+"([a-z0-9][a-z0-9-]*)": `)
)

// TestPRGateSummaryContractMatchesItsJobs guards the drift that failed run
// 33447064730: `pr-gate-summary` keeps a hand-written dict naming every job it
// requires, and deleting a job elsewhere in the file leaves that dict stale. The
// contract then demands a job nothing will ever run, and the whole gate reports
// failure with `validate-service-images=None (selected)` after all 29 real jobs
// have passed — a red run with nothing actually broken.
//
// The reverse drift is worse because it is silent: adding a job to `needs:` and
// forgetting the dict means its result is never checked, so the gate goes green
// on a failed job.
//
// Nothing else catches either direction locally. actionlint validates workflow
// syntax but knows nothing about a contract embedded in a `run:` heredoc, and
// the contract itself only evaluates on GitHub's runners.
func TestPRGateSummaryContractMatchesItsJobs(t *testing.T) {
	root, ok := findRepoRoot()
	if !ok {
		t.Skip("repo root not found")
	}
	path := filepath.Join(root, ".github", "workflows", "pr-gate.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("pr-gate.yml not present: %v", err)
	}
	body := string(raw)

	jobsAt := strings.Index(body, "\njobs:\n")
	if jobsAt < 0 {
		t.Fatalf("%s: no top-level jobs: block", path)
	}
	jobs := map[string]bool{}
	for _, m := range prGateJobRe.FindAllStringSubmatch(body[jobsAt:], -1) {
		jobs[m[1]] = true
	}
	if len(jobs) == 0 {
		t.Fatalf("%s: parsed no job names", path)
	}

	summaryAt := strings.Index(body, "\n  pr-gate-summary:\n")
	if summaryAt < 0 {
		t.Fatalf("%s: no pr-gate-summary job", path)
	}
	summary := body[summaryAt:]

	needs := map[string]bool{}
	needsAt := strings.Index(summary, "\n    needs:\n")
	if needsAt < 0 {
		t.Fatalf("%s: pr-gate-summary has no needs: list", path)
	}
	// The needs list ends at the next key at the job's own indent level.
	needsBlock := summary[needsAt+len("\n    needs:\n"):]
	if end := regexp.MustCompile(`(?m)^    [a-z]`).FindStringIndex(needsBlock); end != nil {
		needsBlock = needsBlock[:end[0]]
	}
	for _, m := range prGateNeedRe.FindAllStringSubmatch(needsBlock, -1) {
		needs[m[1]] = true
	}

	contract := map[string]bool{}
	selAt := strings.Index(summary, "selected = {")
	if selAt < 0 {
		t.Fatalf("%s: pr-gate-summary has no selected = { contract", path)
	}
	selBlock := summary[selAt:]
	close := strings.Index(selBlock, "\n          }")
	if close < 0 {
		t.Fatalf("%s: unterminated selected = { block", path)
	}
	for _, m := range prGateContractRe.FindAllStringSubmatch(selBlock[:close], -1) {
		contract[m[1]] = true
	}
	if len(contract) == 0 {
		t.Fatalf("%s: parsed no contract entries", path)
	}

	for _, name := range sorted(contract) {
		if !jobs[name] {
			t.Errorf("pr-gate-summary contract requires %q, but no such job is defined in %s "+
				"(deleted or renamed job left behind in the contract)", name, filepath.Base(path))
		}
		if !needs[name] {
			t.Errorf("pr-gate-summary contract requires %q, but it is not in the job's needs: list, "+
				"so its result is never available to the contract", name)
		}
	}
	for _, name := range sorted(needs) {
		if name == "changes" {
			continue // consumed directly for path-filter outputs, not as a checked result
		}
		if !contract[name] {
			t.Errorf("pr-gate-summary needs %q but the contract does not check it, "+
				"so the gate reports success even when that job fails", name)
		}
	}
}

func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
