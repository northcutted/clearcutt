package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/northcutted/clearcutt/internal/build"
	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/oci"
	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
)

type serviceFlags struct {
	fleetConfig       string
	coreDir           string
	buildOutputsDir   string
	template          string
	version           string
	description       string
	packageCandidates []string
	ports             []string
	dataDirs          []string
	env               []string
	entrypoint        []string
	cmd               []string
	smoke             []string
	stateful          bool
	productionAllowed bool
	force             bool
	all               bool
	nix               bool
	system            string
	versionTag        string
	githubOutputPath  string
	buildEngine       string
	containerEngine   string
	image             string
	commandOnly       bool
	githubActions     bool
	matrixKind        string
	provenanceRef     string
}

type serviceFunctionalSmokeProfile struct {
	Name     string
	Probe    []string
	Attempts int
	Delay    time.Duration
}

var serviceSmokeSleep = time.Sleep

type ServiceValidation struct {
	ID     string                `json:"id"`
	Status string                `json:"status"`
	Checks []PlatformStatusCheck `json:"checks"`
}

var serviceOpts serviceFlags

func NewServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Scaffold, build, smoke, and publish first-class service images",
		Long: `Scaffold and operate platform-owned service images without editing Nix.
Services use built-in templates and package candidates in clearcutt.fleet.yaml;
the generated Nix extension stays an implementation detail.`,
	}

	scaffoldCmd := &cobra.Command{
		Use:   "scaffold <service-id>",
		Short: "Add a service image to clearcutt.fleet.yaml",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Default paths write into the repo root's fleet config and core/
			// tree even when scaffolding from a subdirectory.
			resolveRepoRootDefault(cmd, "fleet-config", &serviceOpts.fleetConfig)
			resolveRepoRootDefault(cmd, "core-dir", &serviceOpts.coreDir)
			return runServiceScaffold(args[0])
		},
	}
	addServiceCommonFlags(scaffoldCmd)
	scaffoldCmd.Flags().StringVar(&serviceOpts.template, "template", "", "Service template: "+strings.Join(fleet.SupportedServiceTemplateNames(), ", "))
	scaffoldCmd.Flags().StringVar(&serviceOpts.version, "version", "", "Service major or package version, for example 16")
	scaffoldCmd.Flags().StringVar(&serviceOpts.description, "description", "", "Human-readable service description")
	scaffoldCmd.Flags().StringArrayVar(&serviceOpts.packageCandidates, "package", nil, "Nix package candidate attr path; repeat for fallbacks")
	scaffoldCmd.Flags().StringArrayVar(&serviceOpts.ports, "port", nil, "Port in name:port/protocol, port/protocol, or port form; repeat as needed")
	scaffoldCmd.Flags().StringArrayVar(&serviceOpts.dataDirs, "data-dir", nil, "Writable data directory; repeat as needed")
	scaffoldCmd.Flags().StringArrayVar(&serviceOpts.env, "env", nil, "Container environment entry KEY=value; repeat as needed")
	scaffoldCmd.Flags().StringArrayVar(&serviceOpts.entrypoint, "entrypoint", nil, "Entrypoint argv item; repeat in order")
	scaffoldCmd.Flags().StringArrayVar(&serviceOpts.cmd, "cmd", nil, "Default command argv item; repeat in order")
	scaffoldCmd.Flags().StringArrayVar(&serviceOpts.smoke, "smoke", nil, "Smoke command; repeat as needed")
	scaffoldCmd.Flags().BoolVar(&serviceOpts.stateful, "stateful", false, "Mark the service as stateful")
	scaffoldCmd.Flags().BoolVar(&serviceOpts.productionAllowed, "production-allowed", false, "Allow the service image for production catalog/policy use")
	scaffoldCmd.Flags().BoolVar(&serviceOpts.force, "force", false, "Replace an existing service image")
	_ = scaffoldCmd.MarkFlagRequired("template")
	_ = scaffoldCmd.MarkFlagRequired("version")

	explainCmd := &cobra.Command{
		Use:   "explain <service-id>",
		Short: "Explain a service image template expansion",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServiceExplain(args[0])
		},
	}
	addServiceCommonFlags(explainCmd)

	validateCmd := &cobra.Command{
		Use:   "validate [service-id]",
		Short: "Validate service image config and generated backend extension",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate the same root-level files service scaffold writes.
			resolveRepoRootDefault(cmd, "fleet-config", &serviceOpts.fleetConfig)
			resolveRepoRootDefault(cmd, "core-dir", &serviceOpts.coreDir)
			id := ""
			if len(args) == 1 {
				id = args[0]
			}
			return runServiceValidate(id)
		},
	}
	addServiceCommonFlags(validateCmd)
	validateCmd.Flags().BoolVar(&serviceOpts.all, "all", false, "Validate all configured service images")
	validateCmd.Flags().BoolVar(&serviceOpts.nix, "nix", false, "Also run a Nix flake eval for service package attrs")
	validateCmd.Flags().StringVar(&serviceOpts.system, "system", "x86_64-linux", "Nix system for --nix validation")

	buildCmd := &cobra.Command{
		Use:   "build <service-id>",
		Short: "Build and certify one single-architecture service image locally",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServiceTarget(args[0], false)
		},
	}
	addServiceTargetFlags(buildCmd)

	publishCmd := &cobra.Command{
		Use:   "publish <service-id>",
		Short: "Build, certify, and publish one single-architecture service image",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServiceTarget(args[0], true)
		},
	}
	addServiceTargetFlags(publishCmd)
	publishCmd.Flags().StringVar(&serviceOpts.versionTag, "version-tag", "", "Release version tag, for example v1.2.3")

	assembleCmd := &cobra.Command{
		Use:   "assemble <service-id>",
		Short: "Assemble, sign, attest, and digest one multi-architecture service image",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServiceAssemble(args[0])
		},
	}
	addServiceCommonFlags(assembleCmd)
	assembleCmd.Flags().StringVar(&serviceOpts.buildOutputsDir, "build-outputs", "build-outputs", "Path to release build outputs")
	assembleCmd.Flags().StringVar(&serviceOpts.versionTag, "version-tag", "", "Release version tag, for example v1.2.3 (required)")
	assembleCmd.Flags().StringVar(&serviceOpts.githubOutputPath, "github-output", "", "Optional GITHUB_OUTPUT file to append image=<ref> and digest=<sha256> to")
	_ = assembleCmd.MarkFlagRequired("version-tag")

	exportCmd := &cobra.Command{
		Use:   "export-provenance <service-id>",
		Short: "Export service SLSA provenance from OCI attestations as a release asset",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServiceExportProvenance(args[0])
		},
	}
	addServiceCommonFlags(exportCmd)
	exportCmd.Flags().StringVar(&serviceOpts.buildOutputsDir, "build-outputs", "build-outputs", "Path to release build outputs")
	exportCmd.Flags().StringVar(&serviceOpts.provenanceRef, "ref", "", "Image reference to export provenance from; prefer immutable image@sha256:... refs")

	smokeCmd := &cobra.Command{
		Use:   "smoke <service-id>",
		Short: "Run configured service smoke commands against a local image",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServiceSmoke(args[0])
		},
	}
	addServiceCommonFlags(smokeCmd)
	smokeCmd.Flags().StringVar(&serviceOpts.containerEngine, "engine", "docker", "Container engine: docker or podman")
	smokeCmd.Flags().StringVar(&serviceOpts.image, "image", "", "Image reference to smoke; defaults to fleet service image with :current")
	smokeCmd.Flags().BoolVar(&serviceOpts.commandOnly, "command-only", false, "Only run configured smoke commands; skip built-in functional service probes")

	matrixCmd := &cobra.Command{
		Use:   "matrix",
		Short: "Export service image matrices",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServiceMatrix()
		},
	}
	addServiceCommonFlags(matrixCmd)
	matrixCmd.Flags().BoolVar(&serviceOpts.githubActions, "github-actions", false, "Emit a GitHub Actions include matrix")
	matrixCmd.Flags().StringVar(&serviceOpts.matrixKind, "matrix", "release", "GitHub Actions matrix kind: release or image")

	cmd.AddCommand(scaffoldCmd, explainCmd, validateCmd, buildCmd, publishCmd, assembleCmd, exportCmd, smokeCmd, matrixCmd)
	return cmd
}

func addServiceCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&serviceOpts.fleetConfig, "fleet-config", fleet.DefaultConfigPath, "Path to clearcutt fleet config")
	cmd.Flags().StringVar(&serviceOpts.coreDir, "core-dir", "core", "Path to the Nix fleet core directory")
}

func addServiceTargetFlags(cmd *cobra.Command) {
	addServiceCommonFlags(cmd)
	cmd.Flags().StringVar(&serviceOpts.buildOutputsDir, "build-outputs-dir", "build-outputs", "Optional path to core build outputs directory")
	cmd.Flags().StringVar(&serviceOpts.buildEngine, "engine", "go", "Build engine: 'go' (native in-process gates; publish uses go-containerregistry) or 'shell' (legacy pipeline.sh fallback)")
	cmd.Flags().StringVar(&serviceOpts.system, "system", "", "Nix system to build, for example x86_64-linux (required)")
	_ = cmd.MarkFlagRequired("system")
}

func runServiceScaffold(id string) error {
	cfg, err := fleet.Load(serviceOpts.fleetConfig)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	spec, err := serviceScaffoldSpec(id)
	if err != nil {
		return err
	}
	replaced := false
	for i, existing := range cfg.Services {
		if existing.ID == spec.ID {
			if !serviceOpts.force {
				return fmt.Errorf("service %q already exists; pass --force to replace it", spec.ID)
			}
			cfg.Services[i] = spec
			replaced = true
			break
		}
	}
	if !replaced {
		cfg.Services = append(cfg.Services, spec)
	}
	sort.Slice(cfg.Services, func(i, j int) bool {
		return cfg.Services[i].ID < cfg.Services[j].ID
	})
	if err := writeFleetConfigFile(serviceOpts.fleetConfig, cfg); err != nil {
		return err
	}
	if err := writeServiceExtensionsFile(cfg, serviceOpts.coreDir); err != nil {
		return err
	}
	if !GlobalOpts.Quiet {
		action := "scaffolded"
		if replaced {
			action = "updated"
		}
		fmt.Fprintf(out, "%s %s in %s and %s\n", action, spec.ID, serviceOpts.fleetConfig, serviceExtensionsPath(serviceOpts.coreDir))
	}
	return nil
}

func serviceScaffoldSpec(id string) (fleet.ServiceImage, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return fleet.ServiceImage{}, fmt.Errorf("service id must not be empty")
	}
	template := strings.TrimSpace(serviceOpts.template)
	version := strings.TrimSpace(serviceOpts.version)
	defaults, ok := fleet.ServiceTemplateDefaults(template, version)
	if !ok {
		return fleet.ServiceImage{}, fmt.Errorf("unsupported service template %q (supported: %s)", template, strings.Join(fleet.SupportedServiceTemplateNames(), ", "))
	}
	defaults.ID = id
	defaults.Version = version
	defaults.Description = firstNonEmptyString(strings.TrimSpace(serviceOpts.description), defaults.Description)
	if len(serviceOpts.packageCandidates) > 0 {
		defaults.PackageCandidates = cleanStringSlice(serviceOpts.packageCandidates)
	}
	if len(serviceOpts.ports) > 0 {
		ports, err := parseServicePorts(serviceOpts.ports)
		if err != nil {
			return fleet.ServiceImage{}, err
		}
		defaults.Ports = ports
	}
	if serviceOpts.stateful {
		defaults.Stateful = true
	}
	if len(serviceOpts.dataDirs) > 0 {
		defaults.DataDirs = cleanStringSlice(serviceOpts.dataDirs)
	}
	if len(serviceOpts.env) > 0 {
		defaults.Env = cleanStringSlice(serviceOpts.env)
	}
	if len(serviceOpts.entrypoint) > 0 {
		defaults.Entrypoint = cleanStringSlice(serviceOpts.entrypoint)
	}
	if len(serviceOpts.cmd) > 0 {
		defaults.Cmd = cleanStringSlice(serviceOpts.cmd)
	}
	if len(serviceOpts.smoke) > 0 {
		defaults.Smoke = cleanStringSlice(serviceOpts.smoke)
	}
	defaults.ProductionAllowed = serviceOpts.productionAllowed
	return defaults, nil
}

func runServiceExplain(id string) error {
	cfg, err := fleet.Load(serviceOpts.fleetConfig)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	service, ok := cfg.ServiceInfo(id)
	if !ok {
		return fmt.Errorf("service %q is not configured", strings.TrimSpace(id))
	}
	explanation := struct {
		ID                string                 `json:"id"`
		Template          string                 `json:"template"`
		Version           string                 `json:"version"`
		Description       string                 `json:"description"`
		Image             string                 `json:"image"`
		PackageCandidates []string               `json:"packageCandidates"`
		Ports             []fleet.ServicePort    `json:"ports"`
		Stateful          bool                   `json:"stateful"`
		DataDirs          []string               `json:"dataDirs,omitempty"`
		Env               []string               `json:"env,omitempty"`
		Entrypoint        []string               `json:"entrypoint,omitempty"`
		Cmd               []string               `json:"cmd,omitempty"`
		Smoke             []string               `json:"smoke,omitempty"`
		Lifecycle         fleet.ServiceLifecycle `json:"lifecycle,omitempty"`
		ProductionAllowed bool                   `json:"productionAllowed"`
		FleetConfig       string                 `json:"fleetConfig"`
	}{
		ID:                service.ID,
		Template:          service.Template,
		Version:           service.Version,
		Description:       service.Description,
		Image:             cfg.ServiceImageName(service.ID),
		PackageCandidates: service.PackageCandidates,
		Ports:             service.Ports,
		Stateful:          service.Stateful,
		DataDirs:          service.DataDirs,
		Env:               service.Env,
		Entrypoint:        service.Entrypoint,
		Cmd:               service.Cmd,
		Smoke:             service.Smoke,
		Lifecycle:         service.Lifecycle,
		ProductionAllowed: service.ProductionAllowed,
		FleetConfig:       serviceOpts.fleetConfig,
	}
	switch strings.ToLower(GlobalOpts.Format) {
	case "yaml", "yml":
		return output.PrintYAML(out, explanation)
	case "json":
		return output.PrintJSON(out, explanation)
	default:
		tp := output.NewTablePrinter("FIELD", "VALUE")
		tp.AddRow("id", explanation.ID)
		tp.AddRow("template", explanation.Template)
		tp.AddRow("version", explanation.Version)
		tp.AddRow("image", explanation.Image)
		tp.AddRow("packages", strings.Join(explanation.PackageCandidates, ","))
		tp.AddRow("ports", servicePortSummary(explanation.Ports))
		tp.AddRow("stateful", strconv.FormatBool(explanation.Stateful))
		tp.AddRow("dataDirs", strings.Join(explanation.DataDirs, ","))
		tp.AddRow("productionAllowed", strconv.FormatBool(explanation.ProductionAllowed))
		return tp.Print(out)
	}
}

func runServiceValidate(id string) error {
	cfg, err := fleet.Load(serviceOpts.fleetConfig)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	services := []fleet.ServiceImage{}
	id = strings.TrimSpace(id)
	if id == "" && !serviceOpts.all {
		return fmt.Errorf("pass a service id or --all")
	}
	if id != "" && serviceOpts.all {
		return fmt.Errorf("--all cannot be used with a service id")
	}
	if id != "" {
		service, ok := cfg.ServiceInfo(id)
		if !ok {
			return outputServiceValidation([]ServiceValidation{{
				ID:     id,
				Status: "fail",
				Checks: []PlatformStatusCheck{{
					ID:      "service.configured",
					Status:  "fail",
					Message: "service is not configured in clearcutt.fleet.yaml",
				}},
			}}, true)
		}
		services = append(services, service)
	} else {
		if len(cfg.Services) == 0 {
			return fmt.Errorf("no services configured in %s", serviceOpts.fleetConfig)
		}
		for _, service := range cfg.Services {
			service, _ = cfg.ServiceInfo(service.ID)
			services = append(services, service)
		}
	}
	results := []ServiceValidation{}
	hasFail := false
	for _, service := range services {
		result, failed := validateService(cfg, service)
		if failed {
			hasFail = true
		}
		results = append(results, result)
	}
	return outputServiceValidation(results, hasFail)
}

func validateService(cfg fleet.Config, service fleet.ServiceImage) (ServiceValidation, bool) {
	checks := []PlatformStatusCheck{}
	hasFail := false
	add := func(id, status, msg string) {
		checks = append(checks, PlatformStatusCheck{ID: id, Status: status, Message: msg})
		if status == "fail" {
			hasFail = true
		}
	}
	if _, ok := fleet.ServiceTemplateInfo(service.Template); ok {
		add("service.template", "pass", fmt.Sprintf("%s template is built in", service.Template))
	} else {
		add("service.template", "fail", fmt.Sprintf("%s template is not supported", service.Template))
	}
	if len(service.PackageCandidates) > 0 {
		add("service.packages", "pass", strings.Join(service.PackageCandidates, ","))
	} else {
		add("service.packages", "fail", "service has no packageCandidates")
	}
	if len(service.Ports) > 0 {
		add("service.ports", "pass", servicePortSummary(service.Ports))
	} else {
		add("service.ports", "warn", "service declares no exposed ports")
	}
	if service.Stateful {
		if len(service.DataDirs) == 0 {
			add("service.storage", "fail", "stateful service has no dataDirs")
		} else {
			add("service.storage", "pass", strings.Join(service.DataDirs, ","))
		}
	} else {
		add("service.storage", "pass", "stateless")
	}
	if service.ProductionAllowed {
		add("service.production", "pass", "productionAllowed is true")
	} else {
		add("service.production", "warn", "preview service is not productionAllowed")
	}
	if err := validateServiceExtensionsFile(cfg, serviceOpts.coreDir); err != nil {
		add("service.extension", "fail", err.Error())
	} else {
		add("service.extension", "pass", "service-extensions.nix matches fleet services")
	}
	if serviceOpts.nix {
		if err := runServiceNixEval(service); err != nil {
			add("service.nix", "fail", err.Error())
		} else {
			add("service.nix", "pass", "Nix service package attr evaluated")
		}
	}
	status := "pass"
	if hasFail {
		status = "fail"
	}
	return ServiceValidation{ID: service.ID, Status: status, Checks: checks}, hasFail
}

func runServiceNixEval(service fleet.ServiceImage) error {
	if strings.TrimSpace(serviceOpts.system) == "" {
		return fmt.Errorf("--system must not be empty")
	}
	attr := fmt.Sprintf(".#packages.%s.%q.name", serviceOpts.system, service.ID)
	return runExternalCommand(externalCommand{
		Name: "nix",
		Args: []string{
			"eval",
			"--extra-experimental-features", "nix-command flakes",
			"--accept-flake-config",
			attr,
		},
		Dir: serviceOpts.coreDir,
	})
}

func outputServiceValidation(results []ServiceValidation, failed bool) error {
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		if len(results) == 1 {
			if err := output.PrintJSON(out, results[0]); err != nil {
				return err
			}
		} else if err := output.PrintJSON(out, results); err != nil {
			return err
		}
	case "yaml", "yml":
		if len(results) == 1 {
			if err := output.PrintYAML(out, results[0]); err != nil {
				return err
			}
		} else if err := output.PrintYAML(out, results); err != nil {
			return err
		}
	default:
		tp := output.NewTablePrinter("SERVICE", "CHECK", "STATUS", "MESSAGE")
		for _, result := range results {
			for _, check := range result.Checks {
				tp.AddRow(result.ID, check.ID, check.Status, check.Message)
			}
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

func runServiceTarget(id string, publish bool) error {
	cfg, err := fleet.Load(serviceOpts.fleetConfig)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	service, ok := cfg.ServiceInfo(id)
	if !ok {
		return fmt.Errorf("service %q is not configured", strings.TrimSpace(id))
	}
	engine, err := normalizeBuildEngine(serviceOpts.buildEngine)
	if err != nil {
		return err
	}
	if engine == "go" {
		if publish {
			return runServicePublishTargetGo(cfg, service)
		}
		return runServiceCertifyTargetGo(service)
	}
	args := []string{
		"develop",
		"--extra-experimental-features", "nix-command flakes",
		"--accept-flake-config",
	}
	args = append(args, nixClientOptionArgs(cfg)...)
	args = append(args,
		"--command", "./pipeline/pipeline.sh",
		"--kind", "service",
		"--system", serviceOpts.system,
		"--registry", cfg.Registry.Host,
		"--repo", strings.ToLower(cfg.RepoPath()),
	)
	if publish {
		args = append(args, "--publish")
	} else {
		args = append(args, "--skip-local-signing")
	}
	if strings.TrimSpace(serviceOpts.versionTag) != "" {
		args = append(args, "--version-tag", serviceOpts.versionTag)
	}
	args = append(args, service.ID)
	if err := runExternalCommand(externalCommand{
		Name: "nix",
		Args: args,
		Dir:  serviceOpts.coreDir,
		Env: []string{
			"CLEARCUTT_IMAGE_PREFIX=" + cfg.Registry.ImagePrefix,
			"CLEARCUTT_SERVICE_LIFECYCLE_STATUS=" + firstNonEmptyString(service.Lifecycle.Status, "preview"),
			"CLEARCUTT_SERVICE_PRODUCTION_ALLOWED=" + strconv.FormatBool(service.ProductionAllowed),
			"GITHUB_REF_NAME=" + strings.TrimSpace(serviceOpts.versionTag),
		},
	}); err != nil {
		return err
	}
	if publish {
		return stageArchReleaseAssets(resolveBuildOutputsDir(serviceOpts.coreDir, serviceOpts.buildOutputsDir), service.ID, archSuffixForSystem(serviceOpts.system))
	}
	return nil
}

func runServiceCertifyTargetGo(service fleet.ServiceImage) error {
	_, err := certifyServiceTargetGo(service)
	return err
}

func runServicePublishTargetGo(cfg fleet.Config, service fleet.ServiceImage) error {
	outDir, err := certifyServiceTargetGo(service)
	if err != nil {
		return err
	}
	tarPath := filepath.Join(outDir, service.ID+".tar.gz")
	stageTag := serviceStageTag(cfg, service.ID, serviceOpts.system)
	fmt.Fprintf(out, "[service] publishing per-arch staging image with Go engine -> %s\n", stageTag)
	digest, err := fleetPushImageArchive(fleetOCIClient(), stageTag, tarPath)
	if err != nil {
		return fmt.Errorf("OCI per-arch service staging push failed for %s: %w", service.ID, err)
	}
	if digest != "" {
		fmt.Fprintf(out, "[service] pushed staging manifest digest %s\n", digest)
	}
	return stageArchReleaseAssets(outDir, service.ID, archSuffixForSystem(serviceOpts.system))
}

func certifyServiceTargetGo(service fleet.ServiceImage) (string, error) {
	outDir := resolveBuildOutputsDir(serviceOpts.coreDir, serviceOpts.buildOutputsDir)
	opts := build.Options{
		Target:                   service.ID,
		System:                   serviceOpts.system,
		Kind:                     "service",
		CoreDir:                  serviceOpts.coreDir,
		OutputDir:                outDir,
		AllowlistPath:            filepath.Join(serviceOpts.coreDir, "tests", "closure-purity-allowlist.txt"),
		FloorPath:                filepath.Join(serviceOpts.coreDir, "tests", "runtime-dep-floor.json"),
		ServiceProductionAllowed: service.ProductionAllowed,
		ServiceLifecycleStatus:   firstNonEmptyString(service.Lifecycle.Status, "preview"),
	}
	runner := fleetBuildRunner()
	if _, err := build.CertifyTarget(runner, opts, time.Now(), out); err != nil {
		return "", err
	}
	return outDir, nil
}

func serviceStageTag(cfg fleet.Config, serviceID, system string) string {
	return fmt.Sprintf("%s:%s", cfg.ServiceImageName(serviceID), "_stage-service-"+archSuffixForSystem(system))
}

func runServiceSmoke(id string) error {
	cfg, err := fleet.Load(serviceOpts.fleetConfig)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	service, ok := cfg.ServiceInfo(id)
	if !ok {
		return fmt.Errorf("service %q is not configured", strings.TrimSpace(id))
	}
	engine := strings.TrimSpace(serviceOpts.containerEngine)
	switch engine {
	case "docker", "podman":
	default:
		return fmt.Errorf("--engine must be docker or podman")
	}
	image := strings.TrimSpace(serviceOpts.image)
	if image == "" {
		image = cfg.ServiceImageName(service.ID) + ":current"
	}
	if len(service.Smoke) == 0 {
		return fmt.Errorf("service %q has no smoke commands", service.ID)
	}
	for _, smoke := range service.Smoke {
		entrypoint, args := splitSmokeCommand(smoke)
		if entrypoint == "" {
			continue
		}
		commandArgs := []string{"run", "--rm", "--entrypoint", entrypoint, image}
		commandArgs = append(commandArgs, args...)
		if err := runExternalCommand(externalCommand{Name: engine, Args: commandArgs}); err != nil {
			return err
		}
	}
	if serviceOpts.commandOnly {
		return nil
	}
	return runServiceFunctionalSmoke(engine, service, image)
}

func runServiceFunctionalSmoke(engine string, service fleet.ServiceImage, image string) error {
	profile, ok := serviceFunctionalSmokeProfileFor(service.Template)
	if !ok {
		return nil
	}
	container := serviceSmokeContainerName(service.ID)
	runArgs := []string{"run", "-d", "--name", container}
	runArgs = append(runArgs, image)
	if err := runExternalCommand(externalCommand{Name: engine, Args: runArgs}); err != nil {
		return fmt.Errorf("%s functional smoke start failed: %w", profile.Name, err)
	}
	cleanup := func() {
		if err := runExternalCommand(externalCommand{Name: engine, Args: []string{"rm", "-f", container}}); err != nil {
			fmt.Fprintf(errOut, "[service-smoke] cleanup failed for %s: %v\n", container, err)
		}
	}
	defer cleanup()

	if err := waitForServiceSmokeProbe(engine, container, profile); err != nil {
		dumpServiceSmokeDiagnostics(engine, container)
		return err
	}
	return nil
}

func serviceFunctionalSmokeProfileFor(template string) (serviceFunctionalSmokeProfile, bool) {
	switch strings.TrimSpace(template) {
	case "valkey":
		return serviceFunctionalSmokeProfile{
			Name:     "valkey",
			Probe:    []string{"valkey-cli", "-h", "127.0.0.1", "-p", "6379", "PING"},
			Attempts: 20,
			Delay:    time.Second,
		}, true
	case "postgres":
		// Attempts match the entrypoint's own 30-second readiness window.
		return serviceFunctionalSmokeProfile{
			Name:     "postgres",
			Probe:    []string{"pg_isready", "-h", "127.0.0.1", "-p", "5432"},
			Attempts: 30,
			Delay:    time.Second,
		}, true
	default:
		return serviceFunctionalSmokeProfile{}, false
	}
}

func waitForServiceSmokeProbe(engine, container string, profile serviceFunctionalSmokeProfile) error {
	var lastErr error
	for attempt := 1; attempt <= profile.Attempts; attempt++ {
		args := append([]string{"exec", container}, profile.Probe...)
		if err := runExternalCommand(externalCommand{Name: engine, Args: args}); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if attempt < profile.Attempts {
			serviceSmokeSleep(profile.Delay)
		}
	}
	return fmt.Errorf("%s functional smoke probe failed after %d attempt(s): %w", profile.Name, profile.Attempts, lastErr)
}

func dumpServiceSmokeDiagnostics(engine, container string) {
	logs, err := captureExternalOutput(externalCommand{Name: engine, Args: []string{"logs", container}})
	if err != nil {
		fmt.Fprintf(errOut, "[service-smoke] failed to collect logs for %s: %v\n", container, err)
	} else if logs = strings.TrimSpace(logs); logs == "" {
		fmt.Fprintf(errOut, "[service-smoke] %s produced no logs\n", container)
	} else {
		fmt.Fprintf(errOut, "[service-smoke] logs for %s:\n%s\n", container, logs)
	}

	state, err := captureExternalOutput(externalCommand{
		Name: engine,
		Args: []string{"inspect", "--format", "{{json .State}}", container},
	})
	if err != nil {
		fmt.Fprintf(errOut, "[service-smoke] failed to inspect %s: %v\n", container, err)
		return
	}
	state = strings.TrimSpace(state)
	if state == "" {
		fmt.Fprintf(errOut, "[service-smoke] %s produced no inspect state\n", container)
		return
	}
	fmt.Fprintf(errOut, "[service-smoke] state for %s:\n%s\n", container, state)
}

func serviceSmokeContainerName(id string) string {
	name := strings.ToLower(strings.TrimSpace(id))
	replacer := strings.NewReplacer(".", "-", "_", "-", "/", "-", ":", "-")
	name = replacer.Replace(name)
	name = strings.Trim(name, "-")
	if name == "" {
		name = "service"
	}
	return fmt.Sprintf("clearcutt-smoke-%s-%d", name, time.Now().UnixNano())
}

func runServiceAssemble(id string) error {
	cfg, err := fleet.Load(serviceOpts.fleetConfig)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	service, ok := cfg.ServiceInfo(id)
	if !ok {
		return fmt.Errorf("service %q is not configured", strings.TrimSpace(id))
	}
	image := cfg.ServiceImageName(service.ID)
	rolling := image + ":service"
	versioned := image + ":" + serviceOpts.versionTag + "-service"
	manifests := []oci.IndexImage{}
	for _, system := range cfg.Matrix.Systems {
		manifests = append(manifests, oci.IndexImage{
			Ref:          image + ":_stage-service-" + archSuffixForSystem(system),
			OS:           "linux",
			Architecture: ociArchitectureForSystem(system),
		})
	}
	if len(manifests) == 0 {
		return fmt.Errorf("fleet matrix has no systems")
	}
	client := fleetOCIClient()
	digest, err := fleetPushImageIndex(client, rolling, manifests)
	if err != nil {
		return fmt.Errorf("assemble rolling service image index %s: %w", rolling, err)
	}
	if _, err := fleetPushImageIndex(client, versioned, manifests); err != nil {
		return fmt.Errorf("assemble versioned service image index %s: %w", versioned, err)
	}
	if err := runCoreToolCommand(serviceOpts.coreDir, "cosign", "sign", "--yes", rolling); err != nil {
		return err
	}
	if err := runCoreToolCommand(serviceOpts.coreDir, "cosign", "sign", "--yes", versioned); err != nil {
		return err
	}
	for _, system := range cfg.Matrix.Systems {
		dir := filepath.Join(serviceOpts.buildOutputsDir, artifactSystemDir(system))
		if err := runCoreToolCommand(serviceOpts.coreDir, "cosign", "attest", "--yes", "--type", "spdxjson", "--predicate", absToolPath(filepath.Join(dir, service.ID+".sbom.json")), rolling); err != nil {
			return err
		}
	}
	for _, system := range cfg.Matrix.Systems {
		dir := filepath.Join(serviceOpts.buildOutputsDir, artifactSystemDir(system))
		if err := runCoreToolCommand(serviceOpts.coreDir, "cosign", "attest", "--yes", "--type", "custom", "--predicate", absToolPath(filepath.Join(dir, service.ID+".test-results.json")), rolling); err != nil {
			return err
		}
	}
	if digest == "" {
		return fmt.Errorf("OCI index push returned an empty digest for %s", rolling)
	}
	manifest := fleetDigestManifest{
		Image:        image,
		Digest:       digest,
		Language:     service.ID,
		Tier:         "service",
		RollingTag:   "service",
		VersionedTag: serviceOpts.versionTag + "-service",
	}
	digestDir := filepath.Join(serviceOpts.buildOutputsDir, "digests")
	if err := os.MkdirAll(digestDir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(digestDir, service.ID+".digest.json")
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	if serviceOpts.githubOutputPath != "" {
		if err := appendGitHubOutputs(serviceOpts.githubOutputPath, map[string]string{
			"image":  image,
			"digest": digest,
		}); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "[service] digest manifest written: %s\n", path)
	return nil
}

func runServiceExportProvenance(id string) error {
	cfg, err := fleet.Load(serviceOpts.fleetConfig)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	service, ok := cfg.ServiceInfo(id)
	if !ok {
		return fmt.Errorf("service %q is not configured", strings.TrimSpace(id))
	}
	rolling := cfg.ServiceImageName(service.ID) + ":service"
	ref := firstNonEmptyString(serviceOpts.provenanceRef, rolling)
	if err := os.MkdirAll(serviceOpts.buildOutputsDir, 0o755); err != nil {
		return err
	}
	outputPath := filepath.Join(serviceOpts.buildOutputsDir, service.ID+".intoto.jsonl")
	if err := downloadAttestation(outputPath, "https://slsa.dev/provenance/v1", ref, serviceOpts.coreDir); err != nil {
		return err
	}
	if !nonEmptyFile(outputPath) {
		if err := downloadAttestation(outputPath, "https://slsa.dev/provenance/v0.2", ref, serviceOpts.coreDir); err != nil {
			return err
		}
	}
	if nonEmptyFile(outputPath) {
		fmt.Fprintf(out, "[service] provenance exported: %s\n", outputPath)
	} else {
		fmt.Fprintf(out, "[service] warning: SLSA provenance could not be downloaded for %s\n", ref)
	}
	return nil
}

func runServiceMatrix() error {
	cfg, err := fleet.Load(serviceOpts.fleetConfig)
	if err != nil {
		return fmt.Errorf("failed to load fleet config: %w", err)
	}
	if serviceOpts.githubActions {
		switch strings.ToLower(serviceOpts.matrixKind) {
		case "release":
			return output.PrintJSON(out, cfg.GitHubServiceReleaseMatrix())
		case "image":
			return output.PrintJSON(out, cfg.GitHubServiceImageMatrix())
		default:
			return fmt.Errorf("--matrix must be release or image")
		}
	}
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, cfg.Services)
	case "yaml", "yml":
		return output.PrintYAML(out, cfg.Services)
	default:
		tp := output.NewTablePrinter("SERVICE", "TEMPLATE", "VERSION", "PORTS", "STATEFUL", "PROD")
		for _, service := range cfg.Services {
			service, _ = cfg.ServiceInfo(service.ID)
			tp.AddRow(service.ID, service.Template, service.Version, servicePortSummary(service.Ports), strconv.FormatBool(service.Stateful), strconv.FormatBool(service.ProductionAllowed))
		}
		return tp.Print(out)
	}
}

func writeServiceExtensionsFile(cfg fleet.Config, coreDir string) error {
	path := serviceExtensionsPath(coreDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create service extension directory: %w", err)
	}
	raw := []byte(renderServiceExtensionsNix(cfg))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func validateServiceExtensionsFile(cfg fleet.Config, coreDir string) error {
	path := serviceExtensionsPath(coreDir)
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	expected := renderServiceExtensionsNix(cfg)
	if string(raw) != expected {
		return fmt.Errorf("%s is out of sync; run clearcutt service scaffold --force for the service image", path)
	}
	return nil
}

func serviceExtensionsPath(coreDir string) string {
	return filepath.Join(coreDir, "lib", "service-extensions.nix")
}

func renderServiceExtensionsNix(cfg fleet.Config) string {
	services := append([]fleet.ServiceImage(nil), cfg.Services...)
	for i := range services {
		if service, ok := cfg.ServiceInfo(services[i].ID); ok {
			services[i] = service
		}
	}
	sort.Slice(services, func(i, j int) bool {
		return services[i].ID < services[j].ID
	})

	var b strings.Builder
	b.WriteString("# Generated by `clearcutt service scaffold` from clearcutt.fleet.yaml.\n")
	b.WriteString("# Built-in service templates are expanded here so fleet owners can add\n")
	b.WriteString("# platform service images through the CLI without learning Nix internals.\n\n")
	b.WriteString("{ }:\n\n")
	b.WriteString("[\n")
	for _, service := range services {
		fmt.Fprintf(&b, "  {\n")
		fmt.Fprintf(&b, "    id = %q;\n", service.ID)
		fmt.Fprintf(&b, "    template = %q;\n", service.Template)
		fmt.Fprintf(&b, "    version = %q;\n", service.Version)
		if service.Description != "" {
			fmt.Fprintf(&b, "    description = %q;\n", service.Description)
		}
		fmt.Fprintf(&b, "    packageCandidates = %s;\n", nixQuotedStringList(service.PackageCandidates))
		if len(service.Ports) > 0 {
			b.WriteString("    ports = [\n")
			for _, port := range service.Ports {
				fmt.Fprintf(&b, "      { name = %q; port = %d; protocol = %q; }\n", port.Name, port.Port, firstNonEmptyString(port.Protocol, "tcp"))
			}
			b.WriteString("    ];\n")
		}
		fmt.Fprintf(&b, "    stateful = %s;\n", nixBool(service.Stateful))
		if len(service.DataDirs) > 0 {
			fmt.Fprintf(&b, "    dataDirs = %s;\n", nixQuotedStringList(service.DataDirs))
		}
		if len(service.Env) > 0 {
			fmt.Fprintf(&b, "    env = %s;\n", nixQuotedStringList(service.Env))
		}
		if len(service.Entrypoint) > 0 {
			fmt.Fprintf(&b, "    entrypoint = %s;\n", nixQuotedStringList(service.Entrypoint))
		}
		if len(service.Cmd) > 0 {
			fmt.Fprintf(&b, "    cmd = %s;\n", nixQuotedStringList(service.Cmd))
		}
		if len(service.Smoke) > 0 {
			fmt.Fprintf(&b, "    smoke = %s;\n", nixQuotedStringList(service.Smoke))
		}
		b.WriteString("    lifecycle = {\n")
		if service.Lifecycle.Status != "" {
			fmt.Fprintf(&b, "      status = %q;\n", service.Lifecycle.Status)
		}
		if service.Lifecycle.Support != "" {
			fmt.Fprintf(&b, "      support = %q;\n", service.Lifecycle.Support)
		}
		if service.Lifecycle.Notes != "" {
			fmt.Fprintf(&b, "      notes = %q;\n", service.Lifecycle.Notes)
		}
		b.WriteString("    };\n")
		fmt.Fprintf(&b, "    productionAllowed = %s;\n", nixBool(service.ProductionAllowed))
		b.WriteString("  }\n")
	}
	b.WriteString("]\n")
	return b.String()
}

func parseServicePorts(values []string) ([]fleet.ServicePort, error) {
	ports := []fleet.ServicePort{}
	for _, value := range values {
		for _, part := range splitCSVList(value) {
			port, err := parseServicePort(part)
			if err != nil {
				return nil, err
			}
			ports = append(ports, port)
		}
	}
	return ports, nil
}

func parseServicePort(value string) (fleet.ServicePort, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fleet.ServicePort{}, fmt.Errorf("port must not be empty")
	}
	name := ""
	if before, after, ok := strings.Cut(value, ":"); ok {
		name = strings.TrimSpace(before)
		value = strings.TrimSpace(after)
	}
	protocol := "tcp"
	if before, after, ok := strings.Cut(value, "/"); ok {
		value = strings.TrimSpace(before)
		protocol = strings.ToLower(strings.TrimSpace(after))
	}
	number, err := strconv.Atoi(value)
	if err != nil || number < 1 || number > 65535 {
		return fleet.ServicePort{}, fmt.Errorf("invalid service port %q", value)
	}
	switch protocol {
	case "tcp", "udp":
	default:
		return fleet.ServicePort{}, fmt.Errorf("unsupported service port protocol %q", protocol)
	}
	return fleet.ServicePort{Name: name, Port: number, Protocol: protocol}, nil
}

func servicePortSummary(ports []fleet.ServicePort) string {
	parts := []string{}
	for _, port := range ports {
		label := strconv.Itoa(port.Port) + "/" + firstNonEmptyString(port.Protocol, "tcp")
		if port.Name != "" {
			label = port.Name + ":" + label
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, ",")
}

func splitSmokeCommand(smoke string) (string, []string) {
	parts := strings.Fields(strings.TrimSpace(smoke))
	if len(parts) == 0 {
		return "", nil
	}
	return parts[0], parts[1:]
}

func nixQuotedStringList(values []string) string {
	parts := []string{}
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%q", value))
	}
	return "[ " + strings.Join(parts, " ") + " ]"
}

func nixBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
