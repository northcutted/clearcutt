package certify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Known-good identities used across the gate tests. Note openssl's known-good
// build reads version 3.6.2 — a patched-not-bumped build. The gate must pass it
// by IDENTITY even though its version string is below the old 3.6.3 floor.
const (
	knownOpensslOut = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-openssl-3.6.2"
	knownOpensslBin = "cccccccccccccccccccccccccccccccc-openssl-3.6.2-bin"
	knownSqliteOut  = "dddddddddddddddddddddddddddddddd-sqlite-3.53.2"
	// An off-allowlist openssl at a HIGHER version than the known-good build —
	// the gate must still reject it (identity, not version).
	offAllowlistOpenssl = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-openssl-3.6.9"
)

// testFloor writes a known-good crypto identity allowlist and loads it.
func testFloor(t *testing.T) *RuntimeFloor {
	t.Helper()
	p := filepath.Join(t.TempDir(), "floor.json")
	body := `{
  "deps": [
    {
      "name": "openssl",
      "cve": "CVE-2026-34182",
      "knownGood": [
        {"storePath": "` + knownOpensslOut + `", "system": "x86_64-linux", "output": "out", "version": "3.6.2"},
        {"storePath": "/nix/store/` + knownOpensslBin + `/bin/openssl", "system": "x86_64-linux", "output": "bin", "version": "3.6.2"}
      ]
    },
    {
      "name": "sqlite",
      "cve": "CVE-2026-11822",
      "knownGood": [
        {"storePath": "` + knownSqliteOut + `", "system": "x86_64-linux", "output": "out", "version": "3.53.2"}
      ]
    }
  ]
}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write floor: %v", err)
	}
	floor, err := LoadRuntimeDepFloor(p)
	if err != nil {
		t.Fatalf("load floor: %v", err)
	}
	return floor
}

func TestRuntimeCveIdentityGate(t *testing.T) {
	floor := testFloor(t)

	// Known-good identities pass — including a patched-not-bumped openssl-3.6.2
	// (the bin storePath was given with a full /nix/store/.../bin/openssl path,
	// which the loader normalizes to the store component).
	for _, comp := range []string{knownOpensslOut, knownOpensslBin, knownSqliteOut} {
		if msg := floor.evaluateComponent(comp); msg != "" {
			t.Errorf("expected known-good %q clean, got: %s", comp, msg)
		}
	}

	// Off-allowlist crypto fails REGARDLESS of version — even a higher openssl.
	if msg := floor.evaluateComponent(offAllowlistOpenssl); msg == "" {
		t.Errorf("expected off-allowlist %q to violate (higher version, unknown identity)", offAllowlistOpenssl)
	} else if !strings.Contains(msg, "off-allowlist openssl") {
		t.Errorf("unexpected violation message: %s", msg)
	}
	// A stock-vulnerable openssl-3.6.0 with an unknown identity also fails.
	if msg := floor.evaluateComponent("ffffffffffffffffffffffffffffffff-openssl-3.6.0"); msg == "" {
		t.Error("expected stock openssl-3.6.0 with unknown identity to violate")
	}

	// Non-crypto paths are ignored.
	if msg := floor.evaluateComponent("11111111111111111111111111111111-zlib-1.3.1"); msg != "" {
		t.Errorf("expected non-crypto zlib clean, got: %s", msg)
	}

	// Artifacts (.drv/.tar.gz/.zip/.patch/src) are not tracked crypto paths and
	// must be skipped even when off-allowlist.
	for _, artifact := range []string{
		"22222222222222222222222222222222-openssl-3.6.3.drv",
		"33333333333333333333333333333333-openssl-3.6.3.tar.gz",
		"44444444444444444444444444444444-openssl-3.6.3-bin.drv",
		"55555555555555555555555555555555-sqlite-src-3530200.zip",
		"66666666666666666666666666666666-openssl-disable-kernel-detection.patch",
	} {
		if msg := floor.evaluateComponent(artifact); msg != "" {
			t.Errorf("expected artifact %q skipped, got: %s", artifact, msg)
		}
	}
}

func TestRuntimeCveScanArchive(t *testing.T) {
	floor := testFloor(t)

	// An off-allowlist openssl ships → one violation.
	stock := buildTar(t, []tarEntry{
		{name: "nix/store/" + offAllowlistOpenssl + "/lib/libssl.so", mode: 0o644},
		{name: "nix/store/" + offAllowlistOpenssl + "/lib/libcrypto.so", mode: 0o644},
	})
	res, err := ScanImageArchiveForRuntimeCve(dockerArchive(t, stock), floor)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Clean() {
		t.Fatal("expected a violation for off-allowlist openssl")
	}
	if len(res.Violations) != 1 {
		t.Fatalf("expected 1 deduped violation, got %d", len(res.Violations))
	}
	if !strings.Contains(res.Violations[0].Message, offAllowlistOpenssl) {
		t.Errorf("unexpected message: %s", res.Violations[0].Message)
	}

	// Only known-good identities ship → clean (artifact tarball is skipped).
	patched := buildTar(t, []tarEntry{
		{name: "nix/store/" + knownOpensslOut + "/lib/libssl.so", mode: 0o644},
		{name: "nix/store/" + knownSqliteOut + "/lib/libsqlite3.so", mode: 0o644},
		{name: "nix/store/dddddddddddddddddddddddddddddddd-openssl-3.6.3.tar.gz/openssl-3.6.3.tar.gz", mode: 0o644},
	})
	res, err = ScanImageArchiveForRuntimeCve(dockerArchive(t, patched), floor)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !res.Clean() {
		t.Fatalf("expected clean, got: %v", res.Violations)
	}
}

func TestRuntimeCveWhiteoutDiscards(t *testing.T) {
	floor := testFloor(t)
	base := buildTar(t, []tarEntry{
		{name: "nix/store/" + offAllowlistOpenssl + "/lib/libssl.so", mode: 0o644},
	})
	whiteout := buildTar(t, []tarEntry{
		{name: "nix/store/.wh." + offAllowlistOpenssl, mode: 0o644},
	})
	res, err := ScanImageArchiveForRuntimeCve(dockerArchive(t, base, whiteout), floor)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !res.Clean() {
		t.Fatalf("expected whiteout to discard finding, got: %v", res.Violations)
	}
}

func TestRuntimeCveStorePathsMode(t *testing.T) {
	floor := testFloor(t)
	p := filepath.Join(t.TempDir(), "paths")
	body := "/nix/store/" + offAllowlistOpenssl + "\n/nix/store/" + knownSqliteOut + "\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write paths: %v", err)
	}
	res, err := ScanStorePathsForRuntimeCve(p, floor)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Violations) != 1 || !strings.Contains(res.Violations[0].Message, offAllowlistOpenssl) {
		t.Fatalf("expected one off-allowlist openssl violation, got: %v", res.Violations)
	}
}

func TestRuntimeCveUnsupportedArchive(t *testing.T) {
	floor := testFloor(t)
	data := buildTar(t, []tarEntry{{name: "random.txt", mode: 0o644, body: []byte("x")}})
	p := filepath.Join(t.TempDir(), "bad.tar")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ScanImageArchiveForRuntimeCve(p, floor); err == nil {
		t.Fatal("expected unsupported-archive error")
	}
}

func TestLoadRuntimeDepFloorErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Empty deps.
	if _, err := LoadRuntimeDepFloor(write("empty.json", `{"deps":[]}`)); err == nil {
		t.Error("expected error for empty deps")
	}

	// Missing file.
	if _, err := LoadRuntimeDepFloor(filepath.Join(dir, "nope.json")); err == nil {
		t.Error("expected error for missing floor file")
	}

	// Legacy version-floor model must be rejected with a migration hint.
	if _, err := LoadRuntimeDepFloor(write("legacy.json", `{"deps":[{"name":"openssl","minVersion":"3.6.3"}]}`)); err == nil {
		t.Error("expected error for legacy {name, minVersion} model")
	} else if !strings.Contains(err.Error(), "generate-crypto-allowlist") {
		t.Errorf("expected migration hint, got: %v", err)
	}

	// Empty knownGood is a vacuous (fail-open) allowlist.
	if _, err := LoadRuntimeDepFloor(write("emptykg.json", `{"deps":[{"name":"openssl","knownGood":[]}]}`)); err == nil {
		t.Error("expected error for empty knownGood")
	}

	// Identity filed under the wrong dep (sqlite path under openssl).
	wrong := `{"deps":[{"name":"openssl","knownGood":[{"storePath":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-sqlite-3.53.2"}]}]}`
	if _, err := LoadRuntimeDepFloor(write("wrong.json", wrong)); err == nil {
		t.Error("expected error for cross-dep identity")
	}

	// Invalid storePath (no hash-name component).
	bad := `{"deps":[{"name":"openssl","knownGood":[{"storePath":"openssl"}]}]}`
	if _, err := LoadRuntimeDepFloor(write("bad.json", bad)); err == nil {
		t.Error("expected error for invalid storePath")
	}

	// Empty path.
	if _, err := LoadRuntimeDepFloor(""); err == nil {
		t.Error("expected error for empty floor path")
	}
}

func TestNormalizeStoreComponent(t *testing.T) {
	cases := map[string]string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.3":                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.3",
		"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.3":     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.3",
		"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.3/bin": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.3",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.3/":               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.3",
		"":         "",
		"nohyphen": "",
	}
	for in, want := range cases {
		if got := normalizeStoreComponent(in); got != want {
			t.Errorf("normalizeStoreComponent(%q) = %q, want %q", in, got, want)
		}
	}
}
