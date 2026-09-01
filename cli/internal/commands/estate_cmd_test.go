package commands

import (
	"crypto/sha256"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
)

func estateTestRegistry(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(registry.New())
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Host
}

// TestEstateRoundTripsTheRealPublicSnapshot pushes the committed public-estate
// fixture — 19 real images' worth of observations plus both graphs — into an
// in-process registry and pulls it back, byte for byte.
//
// Using the real fixture rather than toy JSON is the point: it exercises the
// actual sizes and shapes an operator will store, so a size limit or an
// encoding assumption that only holds for small hand-written files fails here.
func TestEstateRoundTripsTheRealPublicSnapshot(t *testing.T) {
	root, ok := findRepoRoot()
	if !ok {
		t.Skip("repo root not found")
	}
	fixture := filepath.Join(root, "examples", "public-estate")
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("public estate fixture not present: %v", err)
	}

	host := estateTestRegistry(t)
	ref := host + "/acme/clearcutt-estate:2026-08-31"

	stdout, err := runCLI(t, "estate", "push", ref,
		"--dir", fixture, "--generated-at", "2026-08-31T00:00:00Z", "--insecure")
	if err != nil {
		t.Fatalf("estate push: %v\n%s", err, stdout)
	}
	for _, want := range []string{"observations.json", "graph.json", "layers.json", "[estate] digest sha256:"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("push output missing %q:\n%s", want, stdout)
		}
	}

	outDir := t.TempDir()
	pullOut, err := runCLI(t, "estate", "pull", ref, "--output", outDir, "--insecure")
	if err != nil {
		t.Fatalf("estate pull: %v\n%s", err, pullOut)
	}
	if !strings.Contains(pullOut, "snapshot generated at 2026-08-31T00:00:00Z") {
		t.Errorf("pull should report the snapshot timestamp:\n%s", pullOut)
	}

	for _, fileName := range []string{"observations.json", "graph.json", "layers.json"} {
		original, err := os.ReadFile(filepath.Join(fixture, fileName))
		if err != nil {
			t.Fatal(err)
		}
		pulled, err := os.ReadFile(filepath.Join(outDir, fileName))
		if err != nil {
			t.Fatalf("expected %s to be pulled: %v", fileName, err)
		}
		if sha256.Sum256(original) != sha256.Sum256(pulled) {
			t.Errorf("%s did not round-trip byte for byte (%d bytes out, %d back)", fileName, len(original), len(pulled))
		}
	}
}

// TestEstatePushIsStableAcrossRuns is the operational property: a scheduled job
// that re-pushes an unchanged estate must not mint a new version every run.
func TestEstatePushIsStableAcrossRuns(t *testing.T) {
	root, ok := findRepoRoot()
	if !ok {
		t.Skip("repo root not found")
	}
	fixture := filepath.Join(root, "examples", "public-estate")
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("public estate fixture not present: %v", err)
	}
	host := estateTestRegistry(t)
	ref := host + "/acme/clearcutt-estate:latest"

	digestOf := func() string {
		t.Helper()
		stdout, err := runCLI(t, "estate", "push", ref, "--dir", fixture,
			"--generated-at", "2026-08-31T00:00:00Z", "--insecure")
		if err != nil {
			t.Fatalf("estate push: %v\n%s", err, stdout)
		}
		for _, line := range strings.Split(stdout, "\n") {
			if strings.HasPrefix(line, "[estate] digest ") {
				return strings.TrimSpace(strings.TrimPrefix(line, "[estate] digest "))
			}
		}
		t.Fatalf("no digest in push output:\n%s", stdout)
		return ""
	}
	if first, second := digestOf(), digestOf(); first != second {
		t.Fatalf("re-pushing an unchanged estate minted a new version: %s then %s", first, second)
	}
}

// TestEstatePushWithoutSnapshotFilesExplainsItself: an operator who runs this
// before generating a snapshot should be told what to run, not handed an
// empty-artifact error from the registry layer.
func TestEstatePushWithoutSnapshotFilesExplainsItself(t *testing.T) {
	host := estateTestRegistry(t)
	stdout, err := runCLI(t, "estate", "push", host+"/acme/empty:latest",
		"--dir", t.TempDir(), "--insecure")
	if err == nil {
		t.Fatalf("pushing an empty directory should fail:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "import observe") || !strings.Contains(err.Error(), "graph build") {
		t.Fatalf("error should say which commands produce a snapshot, got: %v", err)
	}
}
