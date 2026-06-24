package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestAddGrypeIgnoreRulesPreservesHeaderAndDedups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".grype.yaml")
	seed := "# header comment line one\n# line two\nignore:\n  - vulnerability: CVE-2026-7210\n    package:\n      name: python\n      version: 3.14.4\n      type: UnknownPackage\n"
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	rules := []grypeIgnoreRule{
		{Vulnerability: "CVE-2026-9669", Package: &grypeIgnorePkg{Name: "python", Version: "3.14.4", Type: "UnknownPackage"}},
		{Vulnerability: "CVE-2026-9669", Package: &grypeIgnorePkg{Name: "python", Version: "3.13.13", Type: "UnknownPackage"}},
		// already present -> must not duplicate
		{Vulnerability: "CVE-2026-7210", Package: &grypeIgnorePkg{Name: "python", Version: "3.14.4", Type: "UnknownPackage"}},
	}
	added, err := addGrypeIgnoreRules(path, rules)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if added != 2 {
		t.Errorf("added = %d, want 2 (the existing 7210 rule is a no-op)", added)
	}

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, "# header comment line one") {
		t.Errorf("header comment was lost:\n%s", got)
	}

	// Re-parse and assert the full, deduped rule set.
	var cfg grypeConfig
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	count := map[string]int{}
	for _, r := range cfg.Ignore {
		count[r.Vulnerability+"/"+r.Package.Version]++
	}
	if count["CVE-2026-7210/3.14.4"] != 1 {
		t.Errorf("existing rule duplicated or dropped: %v", count)
	}
	if count["CVE-2026-9669/3.14.4"] != 1 || count["CVE-2026-9669/3.13.13"] != 1 {
		t.Errorf("new rules missing: %v", count)
	}

	// Idempotent: re-adding the same rules adds nothing.
	again, err := addGrypeIgnoreRules(path, rules)
	if err != nil {
		t.Fatal(err)
	}
	if again != 0 {
		t.Errorf("second add = %d, want 0 (idempotent)", again)
	}
}

func TestRemediationIgnoreCommandValidation(t *testing.T) {
	dir := t.TempDir()
	grypePath := filepath.Join(dir, ".grype.yaml")
	evidenceDir := filepath.Join(dir, "evidence")

	base := []string{"remediation", "ignore", "--grype-config", grypePath, "--evidence-dir", evidenceDir, "--core-dir", dir}

	// Missing/invalid required flags are rejected.
	for _, args := range [][]string{
		append(append([]string{}, base...), "--package", "python", "--version", "3.14.4", "--reason", "r", "--expires", "2026-09-22"),                     // bad cve (none)
		append(append([]string{}, base...), "--cve", "CVE-2026-9669", "--version", "3.14.4", "--reason", "r", "--expires", "2026-09-22"),                  // missing package
		append(append([]string{}, base...), "--cve", "CVE-2026-9669", "--package", "python", "--reason", "r", "--expires", "2026-09-22"),                  // missing version
		append(append([]string{}, base...), "--cve", "CVE-2026-9669", "--package", "python", "--version", "3.14.4", "--expires", "2026-09-22"),            // missing reason
		append(append([]string{}, base...), "--cve", "CVE-2026-9669", "--package", "python", "--version", "3.14.4", "--reason", "r", "--expires", "nope"), // bad expiry
	} {
		if _, err := runCLI(t, args...); err == nil {
			t.Errorf("expected validation error for args: %v", args)
		}
	}

	// A valid invocation writes both the rule and the evidence.
	if _, err := runCLI(t, append(append([]string{}, base...),
		"--cve", "CVE-2026-9669", "--package", "python", "--version", "3.14.4", "--version", "3.13.13",
		"--reason", "fix 3.14.6 not yet in nixpkgs", "--expires", "2026-09-22")...); err != nil {
		t.Fatalf("valid ignore: %v", err)
	}
	if _, err := os.Stat(grypePath); err != nil {
		t.Errorf(".grype.yaml not written: %v", err)
	}
	evidence := filepath.Join(evidenceDir, "cve-2026-9669-python.ignore.evidence.json")
	data, err := os.ReadFile(evidence)
	if err != nil {
		t.Fatalf("evidence not written: %v", err)
	}
	for _, want := range []string{"CVE-2026-9669", "scanner_suppressed", "2026-09-22", "not yet in nixpkgs"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("evidence missing %q:\n%s", want, data)
		}
	}
}
