package commands

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/catalog"
)

const devTestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const devTestRef = "ghcr.io/acme/clearcutt/clearcutt-java21:v1.2.3-dev@" + devTestDigest

func TestDevcontainerWritesResolvedDevSiblingConfig(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "devcontainer.json")

	stdout, err := runCLI(t,
		"--catalog", devFixtureCatalog(),
		"dev", "java21-distroless",
		"--devcontainer",
		"--output", outputPath,
	)
	if err != nil {
		t.Fatalf("devcontainer generation failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "Wrote "+outputPath) {
		t.Fatalf("expected write confirmation, got:\n%s", stdout)
	}

	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg devContainerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("invalid devcontainer JSON: %v\n%s", err, raw)
	}

	if cfg.Name != "ClearCutt java21-dev" {
		t.Fatalf("name = %q", cfg.Name)
	}
	if cfg.Image != devTestRef {
		t.Fatalf("image = %q, want %q", cfg.Image, devTestRef)
	}
	if cfg.WorkspaceFolder != "/app" {
		t.Fatalf("workspaceFolder = %q", cfg.WorkspaceFolder)
	}
	if cfg.RemoteUser != "10001" {
		t.Fatalf("remoteUser = %q", cfg.RemoteUser)
	}
	if !cfg.OverrideCommand {
		t.Fatal("overrideCommand must be true so image entrypoints do not exit the devcontainer")
	}
	if got := cfg.ContainerEnv["CLEARCUTT_IMAGE_ID"]; got != "java21-dev" {
		t.Fatalf("CLEARCUTT_IMAGE_ID = %q", got)
	}
	if got := cfg.ContainerEnv["CLEARCUTT_IMAGE_TAG"]; got != "v1.2.3" {
		t.Fatalf("CLEARCUTT_IMAGE_TAG = %q", got)
	}
}

func devFixtureCatalog() string {
	return filepath.Join("..", "testdata", "dev-catalog")
}

func TestDevcontainerPrintUsesCataloglessPinnedFallback(t *testing.T) {
	missingCatalog := filepath.Join(t.TempDir(), "missing")
	stdout, err := runCLI(t,
		"--catalog", missingCatalog,
		"dev", "java21-distroless",
		"--devcontainer",
		"--tag", "v9.9.9",
		"--print",
	)
	if err != nil {
		t.Fatalf("catalogless devcontainer generation failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, `"image": "ghcr.io/northcutted/clearcutt/clearcutt-java21:v9.9.9-dev"`) {
		t.Fatalf("expected official pinned fallback image, got:\n%s", stdout)
	}
}

func TestDevRejectsDevTargetWithoutShell(t *testing.T) {
	catalogDir := writeDevCommandCatalog(t, true, false)

	stdout, err := runCLI(t,
		"--catalog", catalogDir,
		"dev", "java21-dev",
		"--devcontainer",
		"--print",
	)
	if err == nil {
		t.Fatalf("expected no-shell dev target to fail, got success:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "shellPresent=true") {
		t.Fatalf("expected shellPresent failure, got: %v\n%s", err, stdout)
	}
}

func TestDevContainerExecutesEngineWithPinnedRefAndHostUser(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	catalogDir := writeDevCommandCatalog(t, true, true)
	binDir := t.TempDir()
	logPath := filepath.Join(binDir, "docker-args.txt")
	writeExecutable(t, filepath.Join(binDir, "docker"), "#!/usr/bin/env sh\nprintf '%s\\n' \"$@\" > '"+logPath+"'\n")

	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}

	mount := filepath.Join(t.TempDir(), "workspace")
	stdout, err := runCLI(t,
		"--catalog", catalogDir,
		"dev", "java21-distroless",
		"--container",
		"--engine", "docker",
		"--mount", mount,
	)
	if err != nil {
		t.Fatalf("container launch failed: %v\n%s", err, stdout)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(raw)), "\n")
	want := []string{
		"run",
		"-it",
		"--rm",
		"-v",
		filepath.Clean(mount) + ":/app",
		"-w",
		"/app",
	}
	if user := hostUserMapping(); user != "" {
		want = append(want, "--user", user)
	}
	want = append(want, "--entrypoint", "/bin/sh", devTestRef)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("docker args mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestDevContainerCommandRunsWithoutInteractiveTTY(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	catalogDir := writeDevCommandCatalog(t, true, true)
	binDir := t.TempDir()
	logPath := filepath.Join(binDir, "docker-args.txt")
	writeExecutable(t, filepath.Join(binDir, "docker"), "#!/usr/bin/env sh\nprintf '%s\\n' \"$@\" > '"+logPath+"'\n")

	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}

	mount := filepath.Join(t.TempDir(), "workspace")
	stdout, err := runCLI(t,
		"--catalog", catalogDir,
		"dev", "java21-distroless",
		"--container",
		"--engine", "docker",
		"--mount", mount,
		"--command", "printf clearcutt-dev",
	)
	if err != nil {
		t.Fatalf("container command launch failed: %v\n%s", err, stdout)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(raw)), "\n")
	want := []string{
		"run",
		"--rm",
		"-v",
		filepath.Clean(mount) + ":/app",
		"-w",
		"/app",
	}
	if user := hostUserMapping(); user != "" {
		want = append(want, "--user", user)
	}
	want = append(want, "--entrypoint", "/bin/sh", devTestRef, "-lc", "printf clearcutt-dev")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("docker args mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestDevNixExecutesPinnedNativeAttr(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	catalogDir := writeDevCommandCatalog(t, true, true)
	binDir := t.TempDir()
	logPath := filepath.Join(binDir, "nix-args.txt")
	writeExecutable(t, filepath.Join(binDir, "nix"), "#!/usr/bin/env sh\nprintf '%s\\n' \"$@\" > '"+logPath+"'\n")

	oldPath := os.Getenv("PATH")
	oldShell := os.Getenv("SHELL")
	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPath)
		_ = os.Setenv("SHELL", oldShell)
	})
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("SHELL", "/bin/testshell"); err != nil {
		t.Fatal(err)
	}

	stdout, err := runCLI(t,
		"--catalog", catalogDir,
		"dev", "java21-distroless",
		"--nix",
	)
	if err != nil {
		t.Fatalf("nix launch failed: %v\n%s", err, stdout)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(raw)), "\n")
	want := []string{
		"--extra-experimental-features",
		"nix-command flakes",
		"--accept-flake-config",
		"develop",
		"github:acme/clearcutt/v1.2.3#java21-dev",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nix args mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestDevNixCommandExecutesThroughShell(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	catalogDir := writeDevCommandCatalog(t, true, true)
	binDir := t.TempDir()
	logPath := filepath.Join(binDir, "nix-args.txt")
	writeExecutable(t, filepath.Join(binDir, "nix"), "#!/usr/bin/env sh\nprintf '%s\\n' \"$@\" > '"+logPath+"'\n")

	oldPath := os.Getenv("PATH")
	oldShell := os.Getenv("SHELL")
	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPath)
		_ = os.Setenv("SHELL", oldShell)
	})
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("SHELL", "/bin/testshell"); err != nil {
		t.Fatal(err)
	}

	stdout, err := runCLI(t,
		"--catalog", catalogDir,
		"dev", "java21-distroless",
		"--nix",
		"--command", "java -version",
	)
	if err != nil {
		t.Fatalf("nix command launch failed: %v\n%s", err, stdout)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(raw)), "\n")
	want := []string{
		"--extra-experimental-features",
		"nix-command flakes",
		"--accept-flake-config",
		"develop",
		"github:acme/clearcutt/v1.2.3#java21-dev",
		"--command",
		"bash",
		"-lc",
		"java -version",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nix args mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}

func writeDevCommandCatalog(t *testing.T, includeDev bool, devShellPresent bool) string {
	t.Helper()
	dir := t.TempDir()
	imagesDir := filepath.Join(dir, "images")
	if err := os.MkdirAll(imagesDir, 0o755); err != nil {
		t.Fatal(err)
	}

	distShell := false
	devShell := devShellPresent
	user := "10001"
	workdir := "/app"
	lifecycle := catalog.Lifecycle{Status: "active", Support: "lts", ProductionAllowed: false}

	distSummary := catalog.CatalogImageSummary{
		ID:              "java21-distroless",
		Language:        "java",
		LanguageDisplay: "Java",
		LanguageVersion: "21",
		Tier:            "distroless",
		LatestTag:       "v1.2.3",
		Lifecycle:       lifecycle,
		RuntimeContract: catalog.RuntimeContract{User: &user, WorkingDir: &workdir, ShellPresent: &distShell, ProductionTier: true},
	}
	devSummary := catalog.CatalogImageSummary{
		ID:              "java21-dev",
		Language:        "java",
		LanguageDisplay: "Java",
		LanguageVersion: "21",
		Tier:            "dev",
		LatestTag:       "v1.2.3",
		Lifecycle:       lifecycle,
		RuntimeContract: catalog.RuntimeContract{User: &user, WorkingDir: &workdir, ShellPresent: &devShell, ProductionTier: false},
	}
	index := catalog.CatalogIndex{
		GeneratedAt:  "2026-06-01T00:00:00Z",
		Owner:        "acme",
		Repo:         "clearcutt",
		RegistryBase: "ghcr.io/acme/clearcutt",
		LatestTag:    "v1.2.3",
		Images:       []catalog.CatalogImageSummary{distSummary},
	}
	if includeDev {
		index.Images = append(index.Images, devSummary)
	}
	writeJSON(t, filepath.Join(dir, "index.json"), index)

	writeJSON(t, filepath.Join(imagesDir, "java21-distroless.json"), devCommandRecord("java21-distroless", "distroless", distShell, true))
	if includeDev {
		writeJSON(t, filepath.Join(imagesDir, "java21-dev.json"), devCommandRecord("java21-dev", "dev", devShell, false))
	}
	return dir
}

func devCommandRecord(id, tier string, shellPresent, productionTier bool) catalog.ImageRecord {
	user := "10001"
	workdir := "/app"
	lifecycle := catalog.Lifecycle{Status: "active", Support: "lts", ProductionAllowed: productionTier}
	contract := catalog.RuntimeContract{
		User:           &user,
		WorkingDir:     &workdir,
		ShellPresent:   &shellPresent,
		ProductionTier: productionTier,
	}
	return catalog.ImageRecord{
		ID:       id,
		Language: catalog.LanguageInfo{ID: "java", DisplayName: "Java", Version: "21"},
		Tier: catalog.TierInfo{
			ID:   tier,
			Name: tierDisplayName(tier),
		},
		Registry:        "ghcr.io/acme/clearcutt",
		ImageName:       "clearcutt-java21",
		FullName:        "ghcr.io/acme/clearcutt/clearcutt-java21",
		Lifecycle:       lifecycle,
		RuntimeContract: contract,
		Releases: []catalog.ReleaseEntry{
			{
				Tag:             "v1.2.3",
				IsLatest:        true,
				ManifestDigest:  stringPtr(devTestDigest),
				Lifecycle:       lifecycle,
				RuntimeContract: contract,
			},
		},
	}
}

func tierDisplayName(tier string) string {
	switch tier {
	case "dev":
		return "Dev"
	case "slim":
		return "Slim"
	case "distroless":
		return "Distroless"
	default:
		return tier
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func stringPtr(value string) *string {
	return &value
}

func TestDevModeRejectsMultipleModes(t *testing.T) {
	catalogDir := writeDevCommandCatalog(t, true, true)
	stdout, err := runCLI(t,
		"--catalog", catalogDir,
		"dev", "java21-dev",
		"--nix",
		"--container",
	)
	if err == nil {
		t.Fatalf("expected mutually exclusive mode failure, got success:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "choose only one") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDevHelperBranches(t *testing.T) {
	rec := &catalog.ImageRecord{Registry: "ghcr.io/acme/platform/", ImageName: "clearcutt-java21"}
	if got := imageFullName(rec); got != "ghcr.io/acme/platform/clearcutt-java21" {
		t.Fatalf("imageFullName registry branch = %q", got)
	}
	rec.FullName = "ghcr.io/acme/full"
	if got := imageFullName(rec); got != "ghcr.io/acme/full" {
		t.Fatalf("imageFullName fullName branch = %q", got)
	}
	if lang, version, ok := catalogRuntimeLine("java21-distroless"); !ok || lang != "java" || version != "21" {
		t.Fatalf("java runtime line = %q %q %v", lang, version, ok)
	}
	if lang, version, ok := catalogRuntimeLine("python3.14-slim"); !ok || lang != "python" || version != "3.14" {
		t.Fatalf("python runtime line = %q %q %v", lang, version, ok)
	}
	if _, _, ok := catalogRuntimeLine("not-a-runtime"); ok {
		t.Fatal("invalid runtime line should not parse")
	}
	if got := nativeAttrFromRuntime("core", "LTS"); got != "" {
		t.Fatalf("core native attr should be empty, got %q", got)
	}
	if got := stringOrDefault(stringPtr(""), "fallback"); got != "fallback" {
		t.Fatalf("empty string pointer should fall back, got %q", got)
	}
}

func TestResolveContainerEngineValidationBranches(t *testing.T) {
	old := devOpts
	t.Cleanup(func() { devOpts = old })

	devOpts.engine = "notreal"
	if _, err := resolveContainerEngine(); err == nil || !strings.Contains(err.Error(), "--engine must be docker") {
		t.Fatalf("expected invalid engine error, got %v", err)
	}

	devOpts.engine = "docker"
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	if err := os.Setenv("PATH", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveContainerEngine(); err == nil || !strings.Contains(err.Error(), "was not found on PATH") {
		t.Fatalf("expected missing configured engine error, got %v", err)
	}
}

func TestDevFallbackAndMountBranches(t *testing.T) {
	oldDev := devOpts
	oldCatalog := GlobalOpts.CatalogPath
	devOpts = devFlags{}
	GlobalOpts.CatalogPath = filepath.Join(t.TempDir(), "missing")
	t.Cleanup(func() {
		devOpts = oldDev
		GlobalOpts.CatalogPath = oldCatalog
	})

	if _, err := fallbackDevTarget("java21-distroless", os.ErrNotExist); err == nil || !strings.Contains(err.Error(), "Use --tag") {
		t.Fatalf("expected fallback without tag error, got %v", err)
	}
	devOpts.tag = "v9.9.9"
	target, err := fallbackDevTarget("java21-distroless", os.ErrNotExist)
	if err != nil {
		t.Fatalf("core fallback target failed: %v", err)
	}
	// The --tag fallback derives the dev sibling and its published ref without a
	// local catalog. (The NativeAttr=="" assertion here was specific to the old
	// coreLTS line, which shipped no native attr; language lines do.)
	if target.ImageID != "java21-dev" || !strings.Contains(target.ImageRef, "clearcutt-java21:v9.9.9-dev") {
		t.Fatalf("unexpected fallback target: %+v", target)
	}
	devOpts.mount = ""
	mount, err := resolveDevMount()
	if err != nil || mount == "" {
		t.Fatalf("default mount failed: mount=%q err=%v", mount, err)
	}
	devOpts.mount = t.TempDir()
	if mount, err = resolveDevMount(); err != nil || !filepath.IsAbs(mount) {
		t.Fatalf("explicit mount failed: mount=%q err=%v", mount, err)
	}
}

func TestDevCommandFlagRejectsDevcontainerMode(t *testing.T) {
	catalogDir := writeDevCommandCatalog(t, true, true)
	stdout, err := runCLI(t,
		"--catalog", catalogDir,
		"dev", "java21-dev",
		"--devcontainer",
		"--command", "true",
	)
	if err == nil {
		t.Fatalf("expected --command with --devcontainer to fail, got success:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "--command is only valid") {
		t.Fatalf("unexpected error: %v", err)
	}
}
