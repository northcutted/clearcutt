package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
)

// Drives the native-Go build engine path (fleet certify-target --engine=go)
// through to internal/build, which fails fast on a Darwin system — covering the
// engine wiring without needing a Linux builder.
func TestFleetCertifyTargetGoEngineFailsFastOnDarwin(t *testing.T) {
	dir := t.TempDir()
	cfg := fleet.DefaultConfig("acme", "fleet")
	raw, err := fleet.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	cfgPath := filepath.Join(dir, "clearcutt.fleet.yaml")
	if err := os.WriteFile(cfgPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	coreDir := filepath.Join(dir, "core")
	if err := os.MkdirAll(filepath.Join(coreDir, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err = runCLI(t, "fleet", "certify-target", "--engine", "go",
		"--fleet-config", cfgPath, "--core-dir", coreDir,
		"--system", "aarch64-darwin", "--language", "coreLTS", "--tier", "slim")
	if err == nil {
		t.Fatal("expected the go engine to fail fast on a Darwin system")
	}
}
