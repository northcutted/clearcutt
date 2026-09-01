package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
)

type runtimeFlags struct {
	fleetConfig        string
	coreDir            string
	language           string
	version            string
	description        string
	packageCandidates  []string
	devPackages        []string
	smoke              []string
	appTemplateRuntime string
	omitInProduction   bool
	noAddToMatrix      bool
	force              bool
	nix                bool
	system             string
}

type RuntimeValidation struct {
	ID     string                `json:"id"`
	Status string                `json:"status"`
	Checks []PlatformStatusCheck `json:"checks"`
}

var runtimeOpts runtimeFlags

func NewRuntimeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "runtime",
		Short: "Scaffold and validate custom runtime lines",
		Long: `Scaffold and validate custom runtime lines without hand-editing Nix.
Built-in runtime lines can be selected with matrix add. Use runtime scaffold
when the fleet needs a new language family or version that is not built in.`,
	}

	scaffoldCmd := &cobra.Command{
		Use:   "scaffold <runtime-line>",
		Short: "Generate a custom runtime line and backend extension",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Default paths write into the repo root's fleet config and core/
			// tree even when scaffolding from a subdirectory.
			resolveRepoRootDefault(cmd, "fleet-config", &runtimeOpts.fleetConfig)
			resolveRepoRootDefault(cmd, "core-dir", &runtimeOpts.coreDir)
			return runRuntimeScaffold(args[0])
		},
	}
	addRuntimeCommonFlags(scaffoldCmd)
	scaffoldCmd.Flags().StringVar(&runtimeOpts.language, "language", "", "Runtime language family (default derived from runtime line)")
	scaffoldCmd.Flags().StringVar(&runtimeOpts.version, "version", "", "Runtime version (default derived from runtime line)")
	scaffoldCmd.Flags().StringVar(&runtimeOpts.description, "description", "", "Human-readable runtime description")
	scaffoldCmd.Flags().StringArrayVar(&runtimeOpts.packageCandidates, "package", nil, "Nix package candidate attr path; repeat for fallbacks")
	scaffoldCmd.Flags().StringArrayVar(&runtimeOpts.devPackages, "dev-package", nil, "Additional dev-tier Nix package attr path; repeat as needed")
	scaffoldCmd.Flags().StringArrayVar(&runtimeOpts.smoke, "smoke", nil, "Smoke command for humans and follow-up tests; repeat as needed")
	scaffoldCmd.Flags().StringVar(&runtimeOpts.appTemplateRuntime, "app-template-runtime", "", "Optional supported app template runtime to enable, for example ruby")
	scaffoldCmd.Flags().BoolVar(&runtimeOpts.omitInProduction, "omit-in-production", false, "Ship toolchain only in dev tier; production tiers contain only hardened base tools")
	scaffoldCmd.Flags().BoolVar(&runtimeOpts.noAddToMatrix, "no-add-to-matrix", false, "Create the runtime line without selecting it in matrix.languages")
	scaffoldCmd.Flags().BoolVar(&runtimeOpts.force, "force", false, "Replace an existing custom runtime line")

	validateCmd := &cobra.Command{
		Use:   "validate <runtime-line>",
		Short: "Validate a runtime line and generated backend extension",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate the same root-level files runtime scaffold writes.
			resolveRepoRootDefault(cmd, "fleet-config", &runtimeOpts.fleetConfig)
			resolveRepoRootDefault(cmd, "core-dir", &runtimeOpts.coreDir)
			return runRuntimeValidate(args[0])
		},
	}
	addRuntimeCommonFlags(validateCmd)
	validateCmd.Flags().BoolVar(&runtimeOpts.nix, "nix", false, "Also run a Nix flake eval for the runtime dev shell")
	validateCmd.Flags().StringVar(&runtimeOpts.system, "system", "x86_64-linux", "Nix system for --nix validation")

	cmd.AddCommand(scaffoldCmd, validateCmd)
	return cmd
}

func addRuntimeCommonFlags(cmd *cobra.Command) {
	addConfigFlag(cmd, &runtimeOpts.fleetConfig, "Path to the ClearCutt config")
	cmd.Flags().StringVar(&runtimeOpts.coreDir, "core-dir", "core", "Path to the Nix fleet core directory")
}

func runRuntimeScaffold(runtimeLine string) error {
	cfg, err := fleet.Load(runtimeOpts.fleetConfig)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	spec, err := runtimeScaffoldLine(runtimeLine)
	if err != nil {
		return err
	}
	if _, builtin := fleet.RuntimeLineInfo(spec.ID); builtin {
		return fmt.Errorf("%q is built in; use matrix add %s instead", spec.ID, spec.ID)
	}
	replaced := false
	for i, existing := range cfg.RuntimeLines {
		if existing.ID == spec.ID {
			if !runtimeOpts.force {
				return fmt.Errorf("runtime line %q already exists; pass --force to replace it", spec.ID)
			}
			cfg.RuntimeLines[i] = spec
			replaced = true
			break
		}
	}
	if !replaced {
		cfg.RuntimeLines = append(cfg.RuntimeLines, spec)
	}
	if !runtimeOpts.noAddToMatrix {
		cfg.Matrix.Languages = appendUnique(cfg.Matrix.Languages, spec.ID)
	}
	if spec.AppTemplateRuntime != "" {
		cfg.Templates.Runtimes = appendUnique(cfg.Templates.Runtimes, spec.AppTemplateRuntime)
	}
	if err := writeFleetConfigFile(runtimeOpts.fleetConfig, cfg); err != nil {
		return err
	}
	if err := writeRuntimeExtensionsFile(cfg, runtimeOpts.coreDir); err != nil {
		return err
	}
	if !GlobalOpts.Quiet {
		action := "scaffolded"
		if replaced {
			action = "updated"
		}
		fmt.Fprintf(out, "%s %s in %s and %s\n", action, spec.ID, runtimeOpts.fleetConfig, runtimeExtensionsPath(runtimeOpts.coreDir))
	}
	return nil
}

func runtimeScaffoldLine(runtimeLine string) (fleet.RuntimeLine, error) {
	runtimeLine = strings.TrimSpace(runtimeLine)
	if runtimeLine == "" {
		return fleet.RuntimeLine{}, fmt.Errorf("runtime line must not be empty")
	}
	language := strings.TrimSpace(runtimeOpts.language)
	version := strings.TrimSpace(runtimeOpts.version)
	if language == "" || version == "" {
		parsedLanguage, parsedVersion, ok := parseRuntimeLineVersion(runtimeLine)
		if !ok {
			return fleet.RuntimeLine{}, fmt.Errorf("cannot derive language/version from %q; pass --language and --version", runtimeLine)
		}
		if language == "" {
			language = parsedLanguage
		}
		if version == "" {
			version = parsedVersion
		}
	}
	spec := fleet.RuntimeLine{
		ID:                 runtimeLine,
		Language:           language,
		Version:            version,
		Description:        firstNonEmptyString(runtimeOpts.description, defaultRuntimeDescription(language, version)),
		PackageCandidates:  cleanStringSlice(runtimeOpts.packageCandidates),
		DevPackages:        cleanStringSlice(runtimeOpts.devPackages),
		Smoke:              cleanStringSlice(runtimeOpts.smoke),
		AppTemplateRuntime: strings.TrimSpace(runtimeOpts.appTemplateRuntime),
		OmitInProduction:   runtimeOpts.omitInProduction,
	}
	applyRuntimeDefaults(&spec)
	if spec.AppTemplateRuntime != "" && !appTemplateRuntimeSupported(spec.AppTemplateRuntime) {
		return fleet.RuntimeLine{}, fmt.Errorf("unsupported app template runtime %q (supported: %s)", spec.AppTemplateRuntime, supportedAppTemplateRuntimeList())
	}
	if len(spec.PackageCandidates) == 0 {
		return fleet.RuntimeLine{}, fmt.Errorf("runtime line %q requires at least one --package value", runtimeLine)
	}
	return spec, nil
}

func applyRuntimeDefaults(spec *fleet.RuntimeLine) {
	if len(spec.PackageCandidates) == 0 {
		spec.PackageCandidates = defaultPackageCandidates(spec.Language, spec.Version)
	}
	if len(spec.Smoke) == 0 && spec.Language != "" {
		spec.Smoke = []string{spec.Language + " --version"}
	}
	switch spec.Language {
	case "ruby":
		if spec.AppTemplateRuntime == "" {
			spec.AppTemplateRuntime = "ruby"
		}
	}
}

func defaultPackageCandidates(language, version string) []string {
	normalizedVersion := strings.NewReplacer(".", "_", "-", "_").Replace(version)
	candidates := []string{}
	if language != "" && normalizedVersion != "" {
		candidates = append(candidates, language+"_"+normalizedVersion)
	}
	if language != "" {
		candidates = append(candidates, language)
	}
	return candidates
}

func defaultRuntimeDescription(language, version string) string {
	if language == "" || version == "" {
		return "Custom runtime line"
	}
	return titleLabel(language) + " " + version + " runtime line"
}

func parseRuntimeLineVersion(runtimeLine string) (language, version string, ok bool) {
	if strings.EqualFold(runtimeLine, "coreLTS") {
		return "core", "LTS", true
	}
	runtime, major, minor, parsed := parseRuntimeLine(runtimeLine)
	if !parsed || runtime == "" {
		return "", "", false
	}
	if minor > 0 {
		return runtime, fmt.Sprintf("%d.%d", major, minor), true
	}
	return runtime, fmt.Sprintf("%d", major), true
}

func runRuntimeValidate(runtimeLine string) error {
	cfg, err := fleet.Load(runtimeOpts.fleetConfig)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	runtimeLine = strings.TrimSpace(runtimeLine)
	checks := []PlatformStatusCheck{}
	hasFail := false
	add := func(id, status, msg string) {
		checks = append(checks, PlatformStatusCheck{ID: id, Status: status, Message: msg})
		if status == "fail" {
			hasFail = true
		}
	}

	line, ok := cfg.RuntimeLineInfo(runtimeLine)
	if !ok {
		add("runtime.supported", "fail", fmt.Sprintf("%s is not a built-in or custom runtime line", runtimeLine))
		return outputRuntimeValidation(RuntimeValidation{ID: runtimeLine, Status: "fail", Checks: checks}, true)
	}
	add("runtime.supported", "pass", fmt.Sprintf("%s resolves to %s %s", line.ID, line.Language, line.Version))

	selected := false
	for _, selectedLine := range cfg.Matrix.Languages {
		if selectedLine == runtimeLine {
			selected = true
			break
		}
	}
	if selected {
		add("runtime.selected", "pass", "runtime line is selected in matrix.languages")
	} else {
		add("runtime.selected", "fail", "runtime line is not selected in matrix.languages; run clearcutt matrix add "+runtimeLine)
	}

	if line.AppTemplateRuntime != "" {
		if containsExactString(cfg.Templates.Runtimes, line.AppTemplateRuntime) {
			add("runtime.template", "pass", "app template runtime "+line.AppTemplateRuntime+" is enabled")
		} else {
			add("runtime.template", "fail", "app template runtime "+line.AppTemplateRuntime+" is not enabled in templates.runtimes")
		}
	}

	if cfg.IsCustomRuntimeLine(runtimeLine) {
		if len(line.PackageCandidates) > 0 {
			add("runtime.packages", "pass", "custom runtime declares Nix package candidates")
		} else {
			add("runtime.packages", "fail", "custom runtime has no packageCandidates")
		}
		if err := validateRuntimeExtensionsFile(cfg, runtimeOpts.coreDir); err != nil {
			add("runtime.extension", "fail", err.Error())
		} else {
			add("runtime.extension", "pass", "runtime-extensions.nix matches custom runtime lines in fleet config")
		}
	} else {
		add("runtime.extension", "pass", "built-in runtime is provided by core/lib/registry.nix")
	}

	if runtimeOpts.nix {
		if err := runRuntimeNixEval(line); err != nil {
			add("runtime.nix", "fail", err.Error())
		} else {
			add("runtime.nix", "pass", "Nix dev shell attr evaluated")
		}
	}

	status := "pass"
	if hasFail {
		status = "fail"
	}
	return outputRuntimeValidation(RuntimeValidation{ID: runtimeLine, Status: status, Checks: checks}, hasFail)
}

func runRuntimeNixEval(line fleet.RuntimeLine) error {
	if strings.TrimSpace(runtimeOpts.system) == "" {
		return fmt.Errorf("--system must not be empty")
	}
	attr := fmt.Sprintf(".#devShells.%s.\"%s-dev\".name", runtimeOpts.system, line.ID)
	return runExternalCommand(externalCommand{
		Name: "nix",
		Args: []string{
			"eval",
			"--extra-experimental-features", "nix-command flakes",
			"--accept-flake-config",
			attr,
		},
		Dir: runtimeOpts.coreDir,
	})
}

func outputRuntimeValidation(result RuntimeValidation, failed bool) error {
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		if err := output.PrintJSON(out, result); err != nil {
			return err
		}
	case "yaml", "yml":
		if err := output.PrintYAML(out, result); err != nil {
			return err
		}
	default:
		tp := output.NewTablePrinter("CHECK", "STATUS", "MESSAGE")
		for _, check := range result.Checks {
			tp.AddRow(check.ID, check.Status, check.Message)
		}
		if err := tp.Print(out); err != nil {
			return err
		}
	}
	if failed {
		return ErrCheckFailed
	}
	return nil
}

func writeRuntimeExtensionsFile(cfg fleet.Config, coreDir string) error {
	path := runtimeExtensionsPath(coreDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create runtime extension directory: %w", err)
	}
	raw := []byte(renderRuntimeExtensionsNix(cfg))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func validateRuntimeExtensionsFile(cfg fleet.Config, coreDir string) error {
	path := runtimeExtensionsPath(coreDir)
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	expected := renderRuntimeExtensionsNix(cfg)
	if string(raw) != expected {
		return fmt.Errorf("%s is out of sync; run clearcutt runtime scaffold --force for the custom runtime line", path)
	}
	return nil
}

func runtimeExtensionsPath(coreDir string) string {
	return filepath.Join(coreDir, "lib", "runtime-extensions.nix")
}

func renderRuntimeExtensionsNix(cfg fleet.Config) string {
	lines := append([]fleet.RuntimeLine(nil), cfg.RuntimeLines...)
	sort.Slice(lines, func(i, j int) bool {
		if lines[i].Language == lines[j].Language {
			return lines[i].Version < lines[j].Version
		}
		return lines[i].Language < lines[j].Language
	})

	var b strings.Builder
	b.WriteString("# Generated by `clearcutt runtime scaffold` from clearcutt.fleet.yaml.\n")
	b.WriteString("# Built-in runtime lines live in registry.nix; custom runtime lines are merged\n")
	b.WriteString("# here so fleet owners can extend the product surface through the CLI.\n\n")
	b.WriteString("{ pkgs, getPkg, removeNpm ? null }:\n\n")
	b.WriteString("{\n")
	if len(lines) == 0 {
		b.WriteString("  languages = {};\n")
		b.WriteString("}\n")
		return b.String()
	}

	b.WriteString("  languages = {\n")
	currentLanguage := ""
	for i, line := range lines {
		if line.Language != currentLanguage {
			if currentLanguage != "" {
				b.WriteString("      };\n")
				b.WriteString("    };\n")
				b.WriteString("\n")
			}
			currentLanguage = line.Language
			fmt.Fprintf(&b, "    %s = {\n", nixAttr(line.Language))
			b.WriteString("      versions = {\n")
		}
		fmt.Fprintf(&b, "        %q = {\n", line.Version)
		fmt.Fprintf(&b, "          overlayName = %q;\n", runtimeOverlayName(line))
		fmt.Fprintf(&b, "          raw = [ (getPkg %s %q) ];\n", nixPackageCandidateList(line.PackageCandidates), packageErrorMessage(line))
		if len(line.DevPackages) > 0 {
			fmt.Fprintf(&b, "          devExtra = [ %s ];\n", strings.Join(nixPackageRefs(line.DevPackages), " "))
		}
		if line.OmitInProduction {
			b.WriteString("          omitInProduction = true;\n")
		}
		b.WriteString("        };\n")
		if i == len(lines)-1 {
			b.WriteString("      };\n")
			b.WriteString("    };\n")
		}
	}
	b.WriteString("  };\n")
	b.WriteString("}\n")
	return b.String()
}

func runtimeOverlayName(line fleet.RuntimeLine) string {
	id := regexp.MustCompile(`[^A-Za-z0-9]+`).ReplaceAllString(line.ID, " ")
	parts := strings.Fields(id)
	for i, part := range parts {
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return "clearcutt" + strings.Join(parts, "")
}

func packageErrorMessage(line fleet.RuntimeLine) string {
	label := line.Language
	if line.Version != "" {
		label += " " + line.Version
	}
	return titleLabel(label) + " is not available in this nixpkgs version"
}

func nixPackageCandidateList(candidates []string) string {
	parts := []string{}
	for _, candidate := range candidates {
		segments := splitNixAttrPath(candidate)
		quoted := []string{}
		for _, segment := range segments {
			quoted = append(quoted, fmt.Sprintf("%q", segment))
		}
		parts = append(parts, "[ "+strings.Join(quoted, " ")+" ]")
	}
	return "[ " + strings.Join(parts, " ") + " ]"
}

func nixPackageRefs(packages []string) []string {
	refs := []string{}
	for _, pkg := range packages {
		refs = append(refs, "pkgs."+strings.Join(splitNixAttrPath(pkg), "."))
	}
	return refs
}

func splitNixAttrPath(path string) []string {
	parts := strings.Split(strings.TrimSpace(path), ".")
	clean := []string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			clean = append(clean, part)
		}
	}
	return clean
}

func nixAttr(attr string) string {
	if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_'-]*$`).MatchString(attr) {
		return attr
	}
	return fmt.Sprintf("%q", attr)
}

func cleanStringSlice(values []string) []string {
	clean := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			clean = append(clean, value)
		}
	}
	return clean
}

func containsExactString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
