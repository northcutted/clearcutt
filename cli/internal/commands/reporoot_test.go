package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/spf13/cobra"
)

// reporootSentinel is the runtime line these tests `matrix add` to observe
// which file a write landed in. Every fixture config below filters it out, so
// the tests stay valid regardless of which lines DefaultConfig selects.
const reporootSentinel = "python3.14"

// writeFleetConfigWithoutSentinel writes a fleet config whose matrix is the
// default minus reporootSentinel, so adding the sentinel is always a real
// mutation of that file.
func writeFleetConfigWithoutSentinel(t *testing.T, dir string) string {
	t.Helper()
	cfg := fleet.DefaultConfig("acme", "platform")
	languages := make([]string, 0, len(cfg.Matrix.Languages))
	for _, lang := range cfg.Matrix.Languages {
		if lang != reporootSentinel {
			languages = append(languages, lang)
		}
	}
	cfg.Matrix.Languages = languages
	path := filepath.Join(dir, fleet.DefaultConfigPath)
	writeFleetConfigStruct(t, path, cfg)
	return path
}

// fakeRepo builds a temp checkout with clearcutt.fleet.yaml at its root (the
// repo marker) plus a nested subdirectory mimicking running from cli/internal.
func fakeRepo(t *testing.T) (root, subdir string) {
	t.Helper()
	root = t.TempDir()
	writeFleetConfigWithoutSentinel(t, root)
	subdir = filepath.Join(root, "cli", "internal")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("create subdir: %v", err)
	}
	return root, subdir
}

// samePath compares paths through symlinks (macOS temp dirs live under
// /var -> /private/var, so Getwd-derived paths differ textually).
func samePath(t *testing.T, got, want string) bool {
	t.Helper()
	gotResolved, err := filepath.EvalSymlinks(got)
	if err != nil {
		t.Fatalf("eval symlinks %q: %v", got, err)
	}
	wantResolved, err := filepath.EvalSymlinks(want)
	if err != nil {
		t.Fatalf("eval symlinks %q: %v", want, err)
	}
	return gotResolved == wantResolved
}

func TestFindRepoRootWalksUpToFleetConfigMarker(t *testing.T) {
	root, subdir := fakeRepo(t)
	t.Chdir(subdir)

	got, ok := findRepoRoot()
	if !ok {
		t.Fatalf("expected to find repo root above %s", subdir)
	}
	if !samePath(t, got, root) {
		t.Fatalf("findRepoRoot() = %q, want %q", got, root)
	}
}

func TestMatrixAddDefaultFleetConfigLandsAtRepoRoot(t *testing.T) {
	root, subdir := fakeRepo(t)
	t.Chdir(subdir)

	// The fixture config omits the sentinel, so this add must mutate a file.
	stdout, err := runCLI(t, "matrix", "add", reporootSentinel)
	if err != nil {
		t.Fatalf("matrix add from subdir failed: %v\n%s", err, stdout)
	}

	raw, err := os.ReadFile(filepath.Join(root, fleet.DefaultConfigPath))
	if err != nil {
		t.Fatalf("read root fleet config: %v", err)
	}
	if !strings.Contains(string(raw), reporootSentinel) {
		t.Fatalf("root fleet config missing %s:\n%s", reporootSentinel, raw)
	}
	if _, err := os.Stat(filepath.Join(subdir, fleet.DefaultConfigPath)); !os.IsNotExist(err) {
		t.Fatalf("matrix add scattered a stray fleet config under %s (stat err=%v)", subdir, err)
	}
}

func TestExplicitRelativeFlagKeepsCwdMeaning(t *testing.T) {
	root, subdir := fakeRepo(t)
	local := filepath.Join(subdir, "custom.fleet.yaml")
	if err := os.Rename(writeFleetConfigWithoutSentinel(t, t.TempDir()), local); err != nil {
		t.Fatalf("place local fleet config: %v", err)
	}
	t.Chdir(subdir)

	rootPath := filepath.Join(root, fleet.DefaultConfigPath)
	rootBefore, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatalf("read root fleet config: %v", err)
	}

	stdout, err := runCLI(t, "matrix", "add", reporootSentinel, "--fleet-config", "custom.fleet.yaml")
	if err != nil {
		t.Fatalf("matrix add with explicit config failed: %v\n%s", err, stdout)
	}

	raw, err := os.ReadFile(local)
	if err != nil {
		t.Fatalf("read explicit fleet config: %v", err)
	}
	if !strings.Contains(string(raw), reporootSentinel) {
		t.Fatalf("explicit cwd-relative fleet config was not updated:\n%s", raw)
	}
	rootAfter, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatalf("read root fleet config: %v", err)
	}
	if !bytes.Equal(rootBefore, rootAfter) {
		t.Fatalf("explicit --fleet-config must not redirect writes to the repo root")
	}
}

func TestResolveRepoRootDefaultGuards(t *testing.T) {
	root, subdir := fakeRepo(t)
	t.Chdir(subdir)

	abs := filepath.Join(root, "pinned.yaml")
	empty := ""
	rel := fleet.DefaultConfigPath
	cmd := &cobra.Command{Use: "guard"}
	cmd.Flags().StringVar(&abs, "abs", abs, "")
	cmd.Flags().StringVar(&empty, "empty", empty, "")
	cmd.Flags().StringVar(&rel, "rel", rel, "")

	// Absolute defaults keep their exact meaning.
	resolveRepoRootDefault(cmd, "abs", &abs)
	if abs != filepath.Join(root, "pinned.yaml") {
		t.Fatalf("absolute default was rewritten to %q", abs)
	}
	// Empty defaults (computed later by the command) are left alone.
	resolveRepoRootDefault(cmd, "empty", &empty)
	if empty != "" {
		t.Fatalf("empty default was rewritten to %q", empty)
	}
	// Unknown flag names are a no-op rather than a panic.
	missing := "untouched"
	resolveRepoRootDefault(cmd, "missing", &missing)
	if missing != "untouched" {
		t.Fatalf("missing flag lookup mutated target to %q", missing)
	}
	// Relative defaults are rebased onto the marker root.
	resolveRepoRootDefault(cmd, "rel", &rel)
	if !samePath(t, filepath.Dir(rel), root) {
		t.Fatalf("relative default %q did not land at repo root %q", rel, root)
	}
}
