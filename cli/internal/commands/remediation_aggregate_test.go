package commands

import (
	"strings"
	"testing"
)

// fakeRunner records Run calls and returns canned Output by command prefix.
type fakeRunner struct {
	runs    []string
	outputs map[string]string
}

func (f *fakeRunner) Run(dir, name string, args ...string) error {
	f.runs = append(f.runs, name+" "+strings.Join(args, " "))
	return nil
}

func (f *fakeRunner) Output(dir, name string, args ...string) (string, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	for prefix, val := range f.outputs {
		if strings.HasPrefix(key, prefix) {
			return val, nil
		}
	}
	return "", nil
}

func (f *fakeRunner) ranContaining(substr string) bool {
	for _, r := range f.runs {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
}

func sampleCampaigns() []RemediationCampaign {
	return []RemediationCampaign{
		{Package: "openssl", CVE: "CVE-2026-34182", InstalledVersion: "3.6.2", FixedVersion: "3.6.3"},
		{Package: "sqlite", CVE: "CVE-2026-11822", InstalledVersion: "3.51.2", FixedVersion: "3.53.2"},
	}
}

func TestResetRollingBranchCheckoutsBaseThenForceCreates(t *testing.T) {
	r := &fakeRunner{}
	if err := resetRollingBranch(r, "core", "cve-remediation/auto", "main"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if len(r.runs) != 2 {
		t.Fatalf("expected 2 git calls, got %v", r.runs)
	}
	if r.runs[0] != "git checkout main" {
		t.Errorf("first call: %q", r.runs[0])
	}
	if r.runs[1] != "git checkout -B cve-remediation/auto" {
		t.Errorf("second call: %q", r.runs[1])
	}
}

func TestFoldIntoRollingFastForwardsAndCleansUp(t *testing.T) {
	r := &fakeRunner{}
	if err := foldIntoRolling(r, "core", "cve-remediation/auto", "cve-remediation/cve-2026-34182-openssl"); err != nil {
		t.Fatalf("fold: %v", err)
	}
	want := []string{
		"git branch -f cve-remediation/auto cve-remediation/cve-2026-34182-openssl",
		"git checkout cve-remediation/auto",
		"git branch -D cve-remediation/cve-2026-34182-openssl",
	}
	if len(r.runs) != len(want) {
		t.Fatalf("expected %d calls, got %v", len(want), r.runs)
	}
	for i, w := range want {
		if r.runs[i] != w {
			t.Errorf("call %d = %q, want %q", i, r.runs[i], w)
		}
	}
}

func TestAggregatedPROpensWhenNoExistingPR(t *testing.T) {
	r := &fakeRunner{outputs: map[string]string{
		"gh pr list":    "0", // dedup guard: no open PR
		"git rev-parse": "",  // no remote ref yet -> plain push
	}}
	if err := openOrUpdateAggregatedPR(r, "core", "cve-remediation/auto", "main", sampleCampaigns()); err != nil {
		t.Fatalf("open: %v", err)
	}
	if !r.ranContaining("gh pr create") {
		t.Errorf("expected gh pr create, runs: %v", r.runs)
	}
	if r.ranContaining("gh pr edit") {
		t.Errorf("must NOT edit when no PR exists, runs: %v", r.runs)
	}
	// No remote tip -> plain push, not a force-with-lease.
	if r.ranContaining("--force-with-lease") {
		t.Errorf("expected plain push with no remote tip, runs: %v", r.runs)
	}
}

func TestAggregatedPRUpdatesWhenPRExists(t *testing.T) {
	r := &fakeRunner{outputs: map[string]string{
		"gh pr list":    "1",       // an open PR already exists for the head
		"git rev-parse": "abc1234", // remote tip present -> force-with-lease
	}}
	if err := openOrUpdateAggregatedPR(r, "core", "cve-remediation/auto", "main", sampleCampaigns()); err != nil {
		t.Fatalf("update: %v", err)
	}
	if !r.ranContaining("gh pr edit cve-remediation/auto") {
		t.Errorf("expected gh pr edit, runs: %v", r.runs)
	}
	if r.ranContaining("gh pr create") {
		t.Errorf("must NOT create a second PR, runs: %v", r.runs)
	}
	if !r.ranContaining("--force-with-lease=cve-remediation/auto:abc1234") {
		t.Errorf("expected force-with-lease against remote tip, runs: %v", r.runs)
	}
}

func TestAggregatedPRTitleAndBody(t *testing.T) {
	one := []RemediationCampaign{{Package: "openssl", CVE: "CVE-2026-34182", InstalledVersion: "3.6.2", FixedVersion: "3.6.3"}}
	if got := aggregatedPRTitle(one); !strings.Contains(got, "openssl") || !strings.Contains(got, "CVE-2026-34182") {
		t.Errorf("single title: %q", got)
	}
	if got := aggregatedPRTitle(sampleCampaigns()); !strings.Contains(got, "2 CVEs") {
		t.Errorf("multi title: %q", got)
	}

	body := aggregatedPRBody(sampleCampaigns())
	for _, want := range []string{"CVE-2026-34182", "CVE-2026-11822", "openssl", "sqlite", "do not merge", "single rolling branch"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
}
