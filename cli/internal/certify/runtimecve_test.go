package certify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testFloor writes the reference floor (openssl>=3.6.3, sqlite>=3.53.2) and
// loads it, matching core/tests/runtime-dep-floor.json.
func testFloor(t *testing.T) *RuntimeFloor {
	t.Helper()
	p := filepath.Join(t.TempDir(), "floor.json")
	body := `{"deps":[{"name":"openssl","minVersion":"3.6.3"},{"name":"sqlite","minVersion":"3.53.2"}]}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write floor: %v", err)
	}
	floor, err := LoadRuntimeDepFloor(p)
	if err != nil {
		t.Fatalf("load floor: %v", err)
	}
	return floor
}

func intsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseDottedVersion(t *testing.T) {
	cases := []struct {
		in   string
		want []int
		ok   bool
	}{
		{"3.6.3", []int{3, 6, 3}, true},
		{"3.53.2", []int{3, 53, 2}, true},
		{"3.6.3a", nil, false},
		{"3.6.3-rc1", nil, false},
		{"3.6.3rc1", nil, false},
		{"", nil, false},
	}
	for _, c := range cases {
		got, ok := parseDottedVersion(c.in)
		if ok != c.ok {
			t.Errorf("parse %q ok=%v want %v", c.in, ok, c.ok)
			continue
		}
		if ok && !intsEqual(got, c.want) {
			t.Errorf("parse %q = %v want %v", c.in, got, c.want)
		}
	}
}

func TestVersionGEIsTupleNotStringCompare(t *testing.T) {
	// 3.6.10 > 3.6.3 numerically though "3.6.10" < "3.6.3" as strings.
	if !versionGE([]int{3, 6, 10}, []int{3, 6, 3}) {
		t.Error("3.6.10 should be >= 3.6.3")
	}
	if !versionGE([]int{3, 6, 3}, []int{3, 6, 3}) {
		t.Error("3.6.3 should be >= 3.6.3")
	}
	if versionGE([]int{3, 6, 2}, []int{3, 6, 3}) {
		t.Error("3.6.2 should NOT be >= 3.6.3")
	}
	if versionGE([]int{3, 6}, []int{3, 6, 3}) {
		t.Error("3.6 (==3.6.0) should NOT be >= 3.6.3")
	}
}

func TestRuntimeCveMatcher(t *testing.T) {
	floor := testFloor(t)

	// All six openssl outputs (plus bare) at the floor pass.
	for _, suffix := range []string{"", "-bin", "-dev", "-out", "-man", "-doc", "-debug"} {
		name := "openssl-3.6.3" + suffix
		if msg := floor.evaluateComponent(name); msg != "" {
			t.Errorf("expected %q clean, got: %s", name, msg)
		}
	}
	if msg := floor.evaluateComponent("openssl-3.6.10"); msg != "" {
		t.Errorf("openssl-3.6.10 should pass (numeric > floor), got: %s", msg)
	}
	if msg := floor.evaluateComponent("sqlite-3.53.2"); msg != "" {
		t.Errorf("sqlite-3.53.2 should pass, got: %s", msg)
	}

	below := map[string]string{
		"openssl-3.6.2-bin": "floor 3.6.3",
		"openssl-3.5.6":     "floor 3.6.3",
		"openssl-3.0.20":    "floor 3.6.3",
		"openssl-3":         "floor 3.6.3",
		"openssl-3.6":       "floor 3.6.3",
		"sqlite-3.51.2":     "floor 3.53.2",
	}
	for name, want := range below {
		msg := floor.evaluateComponent(name)
		if msg == "" || !strings.Contains(msg, want) {
			t.Errorf("expected %q to violate with %q, got: %q", name, want, msg)
		}
	}

	// Artifacts (.drv/.tar.gz/.zip/.patch/src) must be skipped, not flagged.
	for _, artifact := range []string{
		"openssl-3.6.3.drv",
		"openssl-3.6.3.tar.gz",
		"openssl-3.6.3-bin.drv",
		"sqlite-src-3530200.zip",
		"openssl-disable-kernel-detection.patch",
	} {
		if msg := floor.evaluateComponent(artifact); msg != "" {
			t.Errorf("expected artifact %q skipped, got: %s", artifact, msg)
		}
	}
}

func TestRuntimeCveScanArchive(t *testing.T) {
	floor := testFloor(t)

	stock := buildTar(t, []tarEntry{
		{name: "nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.2/lib/libssl.so", mode: 0o644},
		{name: "nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.2/lib/libcrypto.so", mode: 0o644},
	})
	res, err := ScanImageArchiveForRuntimeCve(dockerArchive(t, stock), floor)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Clean() {
		t.Fatal("expected a violation for stock openssl-3.6.2")
	}
	if len(res.Violations) != 1 {
		t.Fatalf("expected 1 deduped violation, got %d", len(res.Violations))
	}
	if !strings.Contains(res.Violations[0].Message, "openssl-3.6.2 (floor 3.6.3)") {
		t.Errorf("unexpected message: %s", res.Violations[0].Message)
	}

	patched := buildTar(t, []tarEntry{
		{name: "nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-openssl-3.6.3/lib/libssl.so", mode: 0o644},
		{name: "nix/store/cccccccccccccccccccccccccccccccc-sqlite-3.53.2/lib/libsqlite3.so", mode: 0o644},
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
		{name: "nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.2/lib/libssl.so", mode: 0o644},
	})
	whiteout := buildTar(t, []tarEntry{
		{name: "nix/store/.wh.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.2", mode: 0o644},
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
	body := "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.2\n/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-sqlite-3.53.2\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write paths: %v", err)
	}
	res, err := ScanStorePathsForRuntimeCve(p, floor)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Violations) != 1 || !strings.Contains(res.Violations[0].Message, "openssl-3.6.2 (floor 3.6.3)") {
		t.Fatalf("expected one openssl-3.6.2 violation, got: %v", res.Violations)
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

	// Empty deps.
	empty := filepath.Join(dir, "empty.json")
	_ = os.WriteFile(empty, []byte(`{"deps":[]}`), 0o644)
	if _, err := LoadRuntimeDepFloor(empty); err == nil {
		t.Error("expected error for empty deps")
	}

	// Missing file.
	if _, err := LoadRuntimeDepFloor(filepath.Join(dir, "nope.json")); err == nil {
		t.Error("expected error for missing floor file")
	}

	// Unparseable minVersion.
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"deps":[{"name":"openssl","minVersion":"3.x"}]}`), 0o644)
	if _, err := LoadRuntimeDepFloor(bad); err == nil {
		t.Error("expected error for unparseable minVersion")
	}

	// Empty path.
	if _, err := LoadRuntimeDepFloor(""); err == nil {
		t.Error("expected error for empty floor path")
	}
}
