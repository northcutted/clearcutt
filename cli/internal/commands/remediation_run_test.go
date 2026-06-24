package commands

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func dispatchGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}

func dispatchGitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

// Exercises the full dispatch path that the deferral/dry-run tests skip: a real
// git repo with a bare origin, a fake drafting agent that produces a
// cve-remediation/* branch, and a stub `gh`. Asserts that the agent's per-CVE
// branch is folded onto the single rolling branch, that rolling branch is pushed
// to origin, and ONE aggregated draft PR is opened for it.
func TestRemediationRunDispatchesAgentAndOpensAggregatedPR(t *testing.T) {
	for _, bin := range []string{"git", "bash"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}

	workRepo := t.TempDir()
	originRepo := t.TempDir()
	binDir := t.TempDir()
	ghLog := filepath.Join(binDir, "gh-calls.txt")

	// Bare origin, then a work repo on main wired to it.
	dispatchGit(t, "", "init", "--bare", originRepo)
	dispatchGit(t, workRepo, "init")
	dispatchGit(t, workRepo, "config", "user.email", "test@example.com")
	dispatchGit(t, workRepo, "config", "user.name", "Test Runner")
	if err := os.WriteFile(filepath.Join(workRepo, "README.md"), []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dispatchGit(t, workRepo, "add", ".")
	dispatchGit(t, workRepo, "commit", "--quiet", "-m", "seed")
	dispatchGit(t, workRepo, "branch", "-M", "main")
	dispatchGit(t, workRepo, "remote", "add", "origin", originRepo)
	dispatchGit(t, workRepo, "push", "--quiet", "origin", "main")

	// Fake drafting agent: stands in for cve-draft-agent.py by creating the
	// remediation branch, committing an overlay, and writing the summary JSON.
	agentPath := filepath.Join(binDir, "fake-agent.sh")
	writeExecutable(t, agentPath, `#!/usr/bin/env bash
set -e
git checkout -b cve-remediation/test-branch >/dev/null 2>&1
mkdir -p overlays/cve
printf 'overlay\n' > overlays/cve/patch.nix
git add -A
git commit --quiet -m "automated patch"
mkdir -p "$(dirname "$REMEDIATION_SUMMARY_PATH")"
printf '%s\n' '{"recipe":{"route":"version_bump"},"validation":[],"affected_targets":[]}' > "$REMEDIATION_SUMMARY_PATH"
`)

	// Stub gh: record the invocation and succeed, so no real PR is attempted.
	writeExecutable(t, filepath.Join(binDir, "gh"), "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> '"+ghLog+"'\nexit 0\n")

	root := t.TempDir()
	finding := map[string]any{
		"id":             "CVE-2026-44444",
		"severity":       "Critical",
		"packageName":    "python",
		"packageVersion": "3.13.1",
		"layer":          "runtime",
		"fixedIn":        "3.13.2",
		"fixState":       "fixed",
	}
	writeRemediationScan(t, root, "v1.0.0", "python3.13-slim-amd64.json", []map[string]any{finding})

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() {
		_ = os.Chdir(oldWd)
		_ = os.Setenv("PATH", oldPath)
	})
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workRepo); err != nil {
		t.Fatal(err)
	}

	planPath := filepath.Join(t.TempDir(), "plan.json")
	stdout, err := runCLI(t,
		"remediation", "run",
		"--vuln-root", root,
		"--core-dir", ".",
		"--agent-script", agentPath,
		"--plan-out", planPath,
		"--limit", "1",
	)
	if err != nil {
		t.Fatalf("remediation run failed: %v\n%s", err, stdout)
	}

	// Branch detection + dispatch happened, and one aggregated PR was opened.
	for _, want := range []string{"Dispatching AI Patching Agent", "Opening aggregated draft PR for cve-remediation/auto"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %q in output, got:\n%s", want, stdout)
		}
	}

	// The single rolling branch reached origin (not the per-CVE branch).
	if remote := dispatchGitOut(t, workRepo, "ls-remote", "origin", "cve-remediation/auto"); !strings.Contains(remote, "cve-remediation/auto") {
		t.Fatalf("expected cve-remediation/auto on origin, got: %q", remote)
	}
	// The per-CVE branch was folded in and deleted, never pushed on its own.
	if remote := dispatchGitOut(t, workRepo, "ls-remote", "origin", "cve-remediation/test-branch"); strings.Contains(remote, "cve-remediation/test-branch") {
		t.Fatalf("per-CVE branch should not be pushed, but found on origin: %q", remote)
	}

	// HEAD ends on the rolling branch (overlays accumulate there across campaigns).
	if branch := dispatchGitOut(t, workRepo, "branch", "--show-current"); branch != "cve-remediation/auto" {
		t.Fatalf("expected HEAD on cve-remediation/auto, got %q", branch)
	}

	// gh was invoked to open ONE aggregated draft PR for the rolling branch.
	logBytes, err := os.ReadFile(ghLog)
	if err != nil {
		t.Fatalf("gh was never invoked: %v", err)
	}
	ghCall := string(logBytes)
	for _, want := range []string{"pr create", "--draft", "cve-remediation/auto", "--base main"} {
		if !strings.Contains(ghCall, want) {
			t.Fatalf("expected gh call to contain %q, got: %q", want, ghCall)
		}
	}
}

// Guards the push hardening: re-pushing a remediation branch that already exists
// on origin, from a fresh single-branch clone that never tracked it, is exactly
// where bare --force-with-lease fails ("stale info"). The CLI fetches the branch
// into the tracking ref first, so the re-push succeeds.
func TestRemediationOpenPRRepushesExistingBranchFromFreshClone(t *testing.T) {
	for _, bin := range []string{"git", "bash"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}

	originRepo := t.TempDir()
	producer := t.TempDir()
	binDir := t.TempDir()
	ghLog := filepath.Join(binDir, "gh-calls.txt")
	branch := "cve-remediation/cve-2026-1-openssl"

	// A prior run: origin already carries the remediation branch at v1.
	dispatchGit(t, "", "init", "--bare", originRepo)
	dispatchGit(t, producer, "init")
	dispatchGit(t, producer, "config", "user.email", "p@example.com")
	dispatchGit(t, producer, "config", "user.name", "Producer")
	if err := os.WriteFile(filepath.Join(producer, "README.md"), []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dispatchGit(t, producer, "add", ".")
	dispatchGit(t, producer, "commit", "--quiet", "-m", "seed")
	dispatchGit(t, producer, "branch", "-M", "main")
	dispatchGit(t, producer, "remote", "add", "origin", originRepo)
	dispatchGit(t, producer, "push", "--quiet", "origin", "main")
	dispatchGit(t, producer, "checkout", "-b", branch)
	if err := os.WriteFile(filepath.Join(producer, "patch.txt"), []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dispatchGit(t, producer, "add", ".")
	dispatchGit(t, producer, "commit", "--quiet", "-m", "patch v1")
	dispatchGit(t, producer, "push", "--quiet", "origin", branch)

	// A new CI runner: fresh single-branch clone with no tracking ref for the
	// remediation branch, then a locally-recreated branch with an updated patch.
	fresh := t.TempDir()
	dispatchGit(t, "", "clone", "--quiet", "--single-branch", "--branch", "main", originRepo, fresh)
	dispatchGit(t, fresh, "config", "user.email", "ci@example.com")
	dispatchGit(t, fresh, "config", "user.name", "CI")
	dispatchGit(t, fresh, "checkout", "-b", branch)
	if err := os.WriteFile(filepath.Join(fresh, "patch.txt"), []byte("v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dispatchGit(t, fresh, "add", ".")
	dispatchGit(t, fresh, "commit", "--quiet", "-m", "patch v2")

	writeExecutable(t, filepath.Join(binDir, "gh"), "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> '"+ghLog+"'\nexit 0\n")
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() {
		_ = os.Chdir(oldWd)
		_ = os.Setenv("PATH", oldPath)
	})
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(fresh); err != nil {
		t.Fatal(err)
	}

	stdout, err := runCLI(t, "remediation", "open-pr", "--branch", branch, "--package", "openssl", "--cve", "CVE-2026-1")
	if err != nil {
		t.Fatalf("open-pr re-push failed (the bug this hardening fixes): %v\n%s", err, stdout)
	}

	// origin now carries the updated patch.
	if got := dispatchGitOut(t, originRepo, "show", branch+":patch.txt"); got != "v2" {
		t.Fatalf("expected origin %s to advance to v2, got %q", branch, got)
	}
}
