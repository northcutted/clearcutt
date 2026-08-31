package commands

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
)

func TestRuntimeScaffoldForceNoMatrixAndValidateFailureBranches(t *testing.T) {
	root := t.TempDir()
	configPath := writeFleetConfig(t, root)
	coreDir := filepath.Join(root, "core")

	stdout, err := runCLI(t,
		"runtime", "scaffold", "crystal-head",
		"--fleet-config", configPath,
		"--core-dir", coreDir,
		"--language", "crystal-lang",
		"--version", "head",
		"--package", "crystal",
		"--dev-package", "shards",
		"--smoke", "crystal --version",
		"--omit-in-production",
		"--no-add-to-matrix",
	)
	if err != nil {
		t.Fatalf("runtime scaffold explicit custom failed: %v\n%s", err, stdout)
	}
	loaded, err := fleet.Load(configPath)
	if err != nil {
		t.Fatalf("load scaffolded config: %v", err)
	}
	if containsString(loaded.Matrix.Languages, "crystal-head") {
		t.Fatalf("--no-add-to-matrix should leave runtime unselected: %#v", loaded.Matrix.Languages)
	}
	extension, err := os.ReadFile(filepath.Join(coreDir, "lib", "runtime-extensions.nix"))
	if err != nil {
		t.Fatalf("read runtime extension: %v", err)
	}
	for _, needle := range []string{`crystal-lang = {`, `devExtra = [ pkgs.shards ];`, `omitInProduction = true;`} {
		if !strings.Contains(string(extension), needle) {
			t.Fatalf("runtime extension missing %q:\n%s", needle, extension)
		}
	}

	stdout, err = runCLI(t, "--format", "yaml", "runtime", "validate", "crystal-head", "--fleet-config", configPath, "--core-dir", coreDir)
	if !errors.Is(err, ErrCheckFailed) || !strings.Contains(stdout, "runtime.selected") {
		t.Fatalf("expected YAML validation failure for unselected runtime, got err=%v stdout=\n%s", err, stdout)
	}

	stdout, err = runCLI(t, "runtime", "scaffold", "crystal-head", "--fleet-config", configPath, "--core-dir", coreDir, "--language", "crystal-lang", "--version", "head", "--package", "crystal")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected duplicate scaffold error, got err=%v stdout=\n%s", err, stdout)
	}

	stdout, err = runCLI(t,
		"runtime", "scaffold", "crystal-head",
		"--fleet-config", configPath,
		"--core-dir", coreDir,
		"--language", "crystal-lang",
		"--version", "head",
		"--package", "crystal_1_13",
		"--force",
	)
	if err != nil || !strings.Contains(stdout, "updated crystal-head") {
		t.Fatalf("expected forced scaffold update, got err=%v stdout=\n%s", err, stdout)
	}

	stdout, err = runCLI(t, "runtime", "scaffold", "java21", "--fleet-config", configPath, "--core-dir", coreDir)
	if err == nil || !strings.Contains(err.Error(), "is built in") {
		t.Fatalf("expected built-in scaffold error, got err=%v stdout=\n%s", err, stdout)
	}
	stdout, err = runCLI(t, "runtime", "scaffold", "head", "--fleet-config", configPath, "--core-dir", coreDir)
	if err == nil || !strings.Contains(err.Error(), "cannot derive language/version") {
		t.Fatalf("expected derive error, got err=%v stdout=\n%s", err, stdout)
	}
	stdout, err = runCLI(t, "runtime", "validate", "ruby3.4", "--fleet-config", configPath, "--core-dir", coreDir)
	if !errors.Is(err, ErrCheckFailed) || !strings.Contains(stdout, "runtime.supported") {
		t.Fatalf("expected unsupported validate failure, got err=%v stdout=\n%s", err, stdout)
	}
}

func TestRuntimeHelpersAndNixEvalBranches(t *testing.T) {
	oldRuntimeOpts := runtimeOpts
	oldRun := runExternalCommand
	defer func() {
		runtimeOpts = oldRuntimeOpts
		runExternalCommand = oldRun
	}()

	runtimeOpts = runtimeFlags{}
	if _, err := runtimeScaffoldLine(" "); err == nil {
		t.Fatal("blank runtime line should fail")
	}
	runtimeOpts.packageCandidates = []string{"  custom.pkg  ", " "}
	runtimeOpts.devPackages = []string{" bundler "}
	runtimeOpts.smoke = []string{" custom --version "}
	spec, err := runtimeScaffoldLine("custom1")
	if err != nil {
		t.Fatalf("runtime scaffold line with explicit candidates failed: %v", err)
	}
	if spec.Language != "custom" || spec.Version != "1" || len(spec.PackageCandidates) != 1 || len(spec.DevPackages) != 1 || len(spec.Smoke) != 1 {
		t.Fatalf("runtime scaffold line did not clean fields: %#v", spec)
	}
	if got := defaultRuntimeDescription("", ""); got != "Custom runtime line" {
		t.Fatalf("defaultRuntimeDescription empty = %q", got)
	}
	if lang, version, ok := parseRuntimeLineVersion("java21"); !ok || lang != "java" || version != "21" {
		t.Fatalf("java21 parse = %q %q %t", lang, version, ok)
	}
	if _, _, ok := parseRuntimeLineVersion("head"); ok {
		t.Fatal("head should not parse without language/version flags")
	}
	if containsExactString([]string{"java"}, "ruby") {
		t.Fatal("containsExactString should reject absent value")
	}

	cfg := fleet.DefaultConfig("acme", "platform")
	cfg.RuntimeLines = []fleet.RuntimeLine{
		{ID: "zig0.15", Language: "zig", Version: "0.15", PackageCandidates: []string{"zig_0_15"}, DevPackages: []string{"pkg-config"}, OmitInProduction: true},
		{ID: "zig0.16", Language: "zig", Version: "0.16", PackageCandidates: []string{"zig_0_16"}},
		{ID: "crystal-head", Language: "crystal-lang", Version: "head", PackageCandidates: []string{"crystal"}},
	}
	rendered := renderRuntimeExtensionsNix(cfg)
	for _, needle := range []string{`crystal-lang = {`, `zig = {`, `"0.15" = {`, `"0.16" = {`, `devExtra = [ pkgs.pkg-config ];`, `omitInProduction = true;`} {
		if !strings.Contains(rendered, needle) {
			t.Fatalf("rendered runtime extension missing %q:\n%s", needle, rendered)
		}
	}
	if got := nixAttr("bad attr"); got != `"bad attr"` {
		t.Fatalf("nixAttr should quote invalid attrs, got %q", got)
	}

	runtimeOpts.system = ""
	if err := runRuntimeNixEval(fleet.RuntimeLine{ID: "ruby3.4"}); err == nil {
		t.Fatal("runRuntimeNixEval should reject empty system")
	}
	runtimeOpts.system = "aarch64-linux"
	runtimeOpts.coreDir = "/tmp/core"
	var captured externalCommand
	runExternalCommand = func(c externalCommand) error {
		captured = c
		return nil
	}
	if err := runRuntimeNixEval(fleet.RuntimeLine{ID: "ruby3.4"}); err != nil {
		t.Fatalf("runRuntimeNixEval failed with stub: %v", err)
	}
	if captured.Name != "nix" || captured.Dir != "/tmp/core" || !strings.Contains(strings.Join(captured.Args, " "), `.#devShells.aarch64-linux."ruby3.4-dev".name`) {
		t.Fatalf("unexpected nix eval command: %#v", captured)
	}
}

func TestOutputRuntimeValidationTableAndFailure(t *testing.T) {
	oldFormat := GlobalOpts.Format
	oldOut := out
	defer func() {
		GlobalOpts.Format = oldFormat
		out = oldOut
	}()

	var buf bytes.Buffer
	out = &buf
	GlobalOpts.Format = "table"
	err := outputRuntimeValidation(RuntimeValidation{
		ID:     "ruby3.4",
		Status: "fail",
		Checks: []PlatformStatusCheck{{ID: "runtime.selected", Status: "fail", Message: "missing"}},
	}, true)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected ErrCheckFailed, got %v", err)
	}
	if !strings.Contains(buf.String(), "runtime.selected") {
		t.Fatalf("table validation output missing check:\n%s", buf.String())
	}
}
