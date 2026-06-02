package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/northcutted/clearcutt/internal/catalog"
	"github.com/spf13/cobra"
)

type devFlags struct {
	tag          string
	useNix       bool
	useContainer bool
	devcontainer bool
	engine       string
	mount        string
	noRM         bool
	output       string
	print        bool
	command      string
}

var devOpts devFlags

type devTarget struct {
	InputID      string
	ImageID      string
	ImageRef     string
	Tag          string
	FullName     string
	Owner        string
	Repo         string
	WorkingDir   string
	RemoteUser   string
	NativeAttr   string
	ShellPresent bool
}

type devContainerConfig struct {
	Name            string            `json:"name"`
	Image           string            `json:"image"`
	WorkspaceFolder string            `json:"workspaceFolder"`
	RemoteUser      string            `json:"remoteUser,omitempty"`
	OverrideCommand bool              `json:"overrideCommand"`
	ContainerEnv    map[string]string `json:"containerEnv,omitempty"`
}

// NewDevCmd builds the local development entry point. It consumes published dev
// tier images or the current Nix flake outputs; it does not build or mutate the
// catalog.
func NewDevCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dev <image-id>",
		Short: "Drop into a pinned ClearCutt dev environment",
		Long: `Launch a local development environment for a ClearCutt runtime line.

The command always targets the dev tier. Passing java21-distroless, for example,
resolves to java21-dev, pins the selected release tag, and then either writes a
Dev Container definition, runs a local container engine, or opens the current Nix
native runtime closure.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDev(args[0])
		},
	}

	f := cmd.Flags()
	f.StringVar(&devOpts.tag, "tag", "", "Release tag to pin (defaults to the dev image's latest release)")
	f.BoolVar(&devOpts.useNix, "nix", false, "Launch through Nix using the current #<runtime>-native output")
	f.BoolVar(&devOpts.useContainer, "container", false, "Launch through a local container engine")
	f.BoolVar(&devOpts.devcontainer, "devcontainer", false, "Write a .devcontainer/devcontainer.json for the pinned dev image")
	f.StringVar(&devOpts.engine, "engine", "", "Container engine to use: docker, podman, or nerdctl (default auto-detect)")
	f.StringVar(&devOpts.mount, "mount", "", "Host directory to bind into the dev environment (default current directory)")
	f.BoolVar(&devOpts.noRM, "no-rm", false, "Do not pass --rm to the container engine")
	f.StringVar(&devOpts.output, "output", "", "Devcontainer JSON output path (default .devcontainer/devcontainer.json)")
	f.BoolVar(&devOpts.print, "print", false, "Print devcontainer JSON instead of writing it")
	f.StringVar(&devOpts.command, "command", "", "Non-interactive shell command to execute inside --container or --nix")

	return cmd
}

func runDev(imageID string) error {
	target, err := resolveDevTarget(imageID)
	if err != nil {
		return err
	}

	mode, err := resolveDevMode(target)
	if err != nil {
		return err
	}

	switch mode {
	case "devcontainer":
		return writeDevContainer(target)
	case "container":
		return runDevContainer(target)
	case "nix":
		return runDevNix(target)
	default:
		return fmt.Errorf("unknown dev mode %q", mode)
	}
}

func resolveDevMode(target devTarget) (string, error) {
	selected := 0
	for _, enabled := range []bool{devOpts.useNix, devOpts.useContainer, devOpts.devcontainer} {
		if enabled {
			selected++
		}
	}
	if selected > 1 {
		return "", fmt.Errorf("choose only one of --nix, --container, or --devcontainer")
	}
	if devOpts.command != "" && devOpts.devcontainer {
		return "", fmt.Errorf("--command is only valid with --container or --nix")
	}
	if devOpts.devcontainer {
		return "devcontainer", nil
	}
	if devOpts.useContainer {
		return "container", nil
	}
	if devOpts.useNix {
		if target.NativeAttr == "" {
			return "", fmt.Errorf("no Nix native package is currently exposed for %s; use --container or --devcontainer", target.ImageID)
		}
		return "nix", nil
	}

	if target.NativeAttr != "" {
		if _, err := exec.LookPath("nix"); err == nil {
			return "nix", nil
		}
	}
	return "container", nil
}

func resolveDevTarget(imageID string) (devTarget, error) {
	idx, err := catalog.LoadCatalogIndex(GlobalOpts.CatalogPath)
	if err != nil {
		if _, statErr := os.Stat(filepath.Join(GlobalOpts.CatalogPath, "index.json")); os.IsNotExist(statErr) {
			return fallbackDevTarget(imageID, err)
		}
		return devTarget{}, err
	}
	if err := catalog.ValidateCatalogIndex(idx); err != nil {
		return devTarget{}, fmt.Errorf("catalog index validation failed: %w", err)
	}

	input, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, imageID)
	if err != nil {
		return devTarget{}, err
	}
	if err := catalog.ValidateImageRecord(input); err != nil {
		return devTarget{}, fmt.Errorf("image record validation failed: %w", err)
	}

	devID := input.ID
	if input.Tier.ID != "dev" {
		devID = findDevSiblingID(idx, input)
		if devID == "" {
			return devTarget{}, fmt.Errorf("no dev-tier sibling found for %q in catalog %q", imageID, GlobalOpts.CatalogPath)
		}
	}

	devRecord := input
	if devID != input.ID {
		devRecord, err = catalog.LoadImageRecord(GlobalOpts.CatalogPath, devID)
		if err != nil {
			return devTarget{}, fmt.Errorf("failed to load dev-tier sibling %q: %w", devID, err)
		}
		if err := catalog.ValidateImageRecord(devRecord); err != nil {
			return devTarget{}, fmt.Errorf("dev image record validation failed: %w", err)
		}
	}

	release, err := latestOrTaggedRelease(devRecord.Releases, devOpts.tag)
	if err != nil {
		return devTarget{}, fmt.Errorf("%w for image %q", err, devRecord.ID)
	}

	contract := mergeRuntimeContract(devRecord.RuntimeContract, release.RuntimeContract)
	shellPresent := contract.ShellPresent != nil && *contract.ShellPresent
	if !shellPresent {
		return devTarget{}, fmt.Errorf("image %q does not declare shellPresent=true; refusing to launch an interactive dev shell", devRecord.ID)
	}

	fullName := imageFullName(devRecord)
	tag := release.Tag
	target := devTarget{
		InputID:      imageID,
		ImageID:      devRecord.ID,
		ImageRef:     pinnedTierRef(fullName, tag, devRecord.Tier.ID, release.ManifestDigest),
		Tag:          tag,
		FullName:     fullName,
		Owner:        idx.Owner,
		Repo:         idx.Repo,
		WorkingDir:   stringOrDefault(contract.WorkingDir, "/app"),
		RemoteUser:   stringOrDefault(contract.User, "10001"),
		NativeAttr:   nativeAttrName(devRecord),
		ShellPresent: shellPresent,
	}
	return target, nil
}

func fallbackDevTarget(imageID string, catalogErr error) (devTarget, error) {
	if devOpts.tag == "" {
		return devTarget{}, fmt.Errorf("failed to load catalog for %q: %w\n\nUse --tag to derive an official ClearCutt dev image without a local catalog.", imageID, catalogErr)
	}
	devID := devSiblingID(imageID)
	runtimeLine := strings.TrimSuffix(devID, "-dev")
	if runtimeLine == "" {
		return devTarget{}, fmt.Errorf("cannot derive dev image id from %q without a catalog", imageID)
	}
	fullName := fmt.Sprintf("ghcr.io/northcutted/clearcutt/clearcutt-%s", strings.ToLower(runtimeLine))
	language, version, ok := catalogRuntimeLine(devID)
	if !ok {
		return devTarget{}, fmt.Errorf("cannot derive runtime line from %q without a catalog", imageID)
	}
	return devTarget{
		InputID:      imageID,
		ImageID:      devID,
		ImageRef:     pinnedTierRef(fullName, devOpts.tag, "dev", nil),
		Tag:          devOpts.tag,
		FullName:     fullName,
		Owner:        "northcutted",
		Repo:         "clearcutt",
		WorkingDir:   "/app",
		RemoteUser:   "10001",
		NativeAttr:   nativeAttrFromRuntime(language, version),
		ShellPresent: true,
	}, nil
}

func findDevSiblingID(idx *catalog.CatalogIndex, rec *catalog.ImageRecord) string {
	for _, img := range idx.Images {
		if img.Tier == "dev" && img.Language == rec.Language.ID && img.LanguageVersion == rec.Language.Version {
			return img.ID
		}
	}
	return devSiblingID(rec.ID)
}

func devSiblingID(imageID string) string {
	if strings.HasSuffix(imageID, "-dev") {
		return imageID
	}
	if cut := strings.LastIndex(imageID, "-"); cut > 0 {
		return imageID[:cut] + "-dev"
	}
	return imageID + "-dev"
}

func mergeRuntimeContract(base, override catalog.RuntimeContract) catalog.RuntimeContract {
	merged := base
	if override.User != nil {
		merged.User = override.User
	}
	if override.WorkingDir != nil {
		merged.WorkingDir = override.WorkingDir
	}
	if override.ShellPresent != nil {
		merged.ShellPresent = override.ShellPresent
	}
	if override.PackageManagerPresent != nil {
		merged.PackageManagerPresent = override.PackageManagerPresent
	}
	if override.CACertificatesPresent != nil {
		merged.CACertificatesPresent = override.CACertificatesPresent
	}
	if override.TimezoneDataPresent != nil {
		merged.TimezoneDataPresent = override.TimezoneDataPresent
	}
	if override.DefaultEntrypoint != nil {
		merged.DefaultEntrypoint = override.DefaultEntrypoint
	}
	merged.ProductionTier = override.ProductionTier
	return merged
}

func imageFullName(rec *catalog.ImageRecord) string {
	if rec.FullName != "" {
		return rec.FullName
	}
	if rec.Registry != "" && rec.ImageName != "" {
		return strings.TrimRight(rec.Registry, "/") + "/" + rec.ImageName
	}
	return rec.ImageName
}

func pinnedTierRef(fullName, tag, tier string, digest *string) string {
	ref := fmt.Sprintf("%s:%s-%s", fullName, tag, tier)
	if digest != nil && *digest != "" {
		ref += "@" + *digest
	}
	return ref
}

func nativeAttrName(rec *catalog.ImageRecord) string {
	return nativeAttrFromRuntime(rec.Language.ID, rec.Language.Version)
}

func nativeAttrFromRuntime(language, version string) string {
	if language == "core" {
		return ""
	}
	return language + version + "-native"
}

func catalogRuntimeLine(imageID string) (language, version string, ok bool) {
	line := strings.TrimSuffix(devSiblingID(imageID), "-dev")
	if strings.EqualFold(line, "coreLTS") {
		return "core", "LTS", true
	}
	runtimeName, major, minor, parsed := parseRuntimeLine(line)
	if !parsed {
		return "", "", false
	}
	if minor > 0 {
		return runtimeName, fmt.Sprintf("%d.%d", major, minor), true
	}
	return runtimeName, fmt.Sprintf("%d", major), true
}

func stringOrDefault(value *string, fallback string) string {
	if value == nil || *value == "" {
		return fallback
	}
	return *value
}

func writeDevContainer(target devTarget) error {
	cfg := devContainerConfig{
		Name:            "ClearCutt " + target.ImageID,
		Image:           target.ImageRef,
		WorkspaceFolder: target.WorkingDir,
		RemoteUser:      target.RemoteUser,
		OverrideCommand: true,
		ContainerEnv: map[string]string{
			"CLEARCUTT_IMAGE_ID":  target.ImageID,
			"CLEARCUTT_IMAGE_TAG": target.Tag,
		},
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to render devcontainer JSON: %w", err)
	}
	raw = append(raw, '\n')

	if devOpts.print {
		_, err := out.Write(raw)
		return err
	}

	outputPath := devOpts.output
	if outputPath == "" {
		outputPath = filepath.Join(".devcontainer", "devcontainer.json")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("failed to create devcontainer output directory: %w", err)
	}
	if err := os.WriteFile(outputPath, raw, 0o644); err != nil {
		return fmt.Errorf("failed to write devcontainer file: %w", err)
	}
	if !GlobalOpts.Quiet {
		fmt.Fprintf(out, "Wrote %s for %s\n", outputPath, target.ImageRef)
	}
	return nil
}

func runDevContainer(target devTarget) error {
	engine, err := resolveContainerEngine()
	if err != nil {
		return err
	}
	mount, err := resolveDevMount()
	if err != nil {
		return err
	}
	args := devContainerArgs(target, mount)
	if !GlobalOpts.Quiet {
		fmt.Fprintf(out, "Launching %s %s at %s\n", engine, target.ImageRef, target.WorkingDir)
	}
	return runExternal(engine, args...)
}

func resolveContainerEngine() (string, error) {
	if devOpts.engine != "" {
		switch devOpts.engine {
		case "docker", "podman", "nerdctl":
			if _, err := exec.LookPath(devOpts.engine); err != nil {
				return "", fmt.Errorf("container engine %q was not found on PATH", devOpts.engine)
			}
			return devOpts.engine, nil
		default:
			return "", fmt.Errorf("--engine must be docker, podman, or nerdctl")
		}
	}
	for _, engine := range []string{"docker", "podman", "nerdctl"} {
		if _, err := exec.LookPath(engine); err == nil {
			return engine, nil
		}
	}
	return "", fmt.Errorf("no container engine found on PATH (tried docker, podman, nerdctl)")
}

func resolveDevMount() (string, error) {
	mount := devOpts.mount
	if mount == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to resolve current directory: %w", err)
		}
		mount = cwd
	}
	abs, err := filepath.Abs(mount)
	if err != nil {
		return "", fmt.Errorf("failed to resolve mount path %q: %w", mount, err)
	}
	return abs, nil
}

func devContainerArgs(target devTarget, mount string) []string {
	args := []string{"run"}
	if devOpts.command == "" {
		args = append(args, "-it")
	}
	if !devOpts.noRM {
		args = append(args, "--rm")
	}
	args = append(args,
		"-v", mount+":"+target.WorkingDir,
		"-w", target.WorkingDir,
	)
	if user := hostUserMapping(); user != "" {
		args = append(args, "--user", user)
	}
	args = append(args, "--entrypoint", "/bin/sh", target.ImageRef)
	if devOpts.command != "" {
		args = append(args, "-lc", devOpts.command)
	}
	return args
}

func hostUserMapping() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	uid := os.Getuid()
	gid := os.Getgid()
	if uid < 0 || gid < 0 {
		return ""
	}
	return fmt.Sprintf("%d:%d", uid, gid)
}

func runDevNix(target devTarget) error {
	if target.NativeAttr == "" {
		return fmt.Errorf("no Nix native package is currently exposed for %s; use --container or --devcontainer", target.ImageID)
	}
	if _, err := exec.LookPath("nix"); err != nil {
		return fmt.Errorf("nix was not found on PATH")
	}
	flakeRef := fmt.Sprintf("github:%s/%s/%s#%s", target.Owner, target.Repo, target.Tag, target.NativeAttr)
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	args := []string{
		"--extra-experimental-features", "nix-command flakes",
		"--accept-flake-config",
		"shell", flakeRef,
		"--command", shell,
	}
	if devOpts.command != "" {
		args = append(args, "-lc", devOpts.command)
	}
	if !GlobalOpts.Quiet {
		fmt.Fprintf(out, "Launching Nix shell %s\n", flakeRef)
	}
	return runExternal("nix", args...)
}

func runExternal(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = out
	cmd.Stderr = errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
