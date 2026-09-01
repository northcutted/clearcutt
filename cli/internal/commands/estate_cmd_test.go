package commands

import (
	"crypto/sha256"
	"fmt"
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

// TestEstateHistoryCommandRendersTheTrend drives the user-facing trend output,
// which is the reason the history index exists.
func TestEstateHistoryCommandRendersTheTrend(t *testing.T) {
	host := estateTestRegistry(t)
	historyRef := host + "/acme/estate:history"

	for i, day := range []struct {
		at                              string
		images, resolved, proven, stale int
	}{
		{"2026-08-31T00:00:00Z", 19, 3, 2, 6},
		{"2026-09-01T00:00:00Z", 19, 9, 7, 1},
	} {
		dir := t.TempDir()
		graph := fmt.Sprintf(`{"summary":{"observedImages":%d,"resolvedConsumers":%d,"unresolvedConsumers":%d,
		  "staleConsumers":%d,"rootImages":2,"edgesByMethod":{"layer-prefix":%d}}}`,
			day.images, day.resolved, day.images-day.resolved, day.stale, day.proven)
		if err := os.WriteFile(filepath.Join(dir, "graph.json"), []byte(graph), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "layers.json"),
			[]byte(`{"summary":{"distinctLayers":96,"sharedLayers":12,"storedBytes":703594496}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		ref := fmt.Sprintf("%s/acme/estate:day-%d", host, i)
		if _, err := runCLI(t, "estate", "push", ref, "--dir", dir,
			"--generated-at", day.at, "--history", historyRef, "--insecure"); err != nil {
			t.Fatalf("push %s: %v", day.at, err)
		}
	}

	stdout, err := runCLI(t, "estate", "history", historyRef, "--insecure")
	if err != nil {
		t.Fatalf("history: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"2026-08-31T00:00:00Z",
		"2026-09-01T00:00:00Z",
		"provenance resolved",
		"proven by layer digests",
		"stale consumers",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("trend output missing %q:\n%s", want, stdout)
		}
	}
	// Direction matters more than the numbers: fewer stale consumers is an
	// improvement, and the output must not call it a regression.
	if !strings.Contains(stdout, "improved") {
		t.Errorf("a fleet that resolved more and went less stale should read as improved:\n%s", stdout)
	}
	if strings.Contains(stdout, "stale consumers             6 -> 1     -5 (regressed)") {
		t.Errorf("falling stale count must be an improvement, not a regression:\n%s", stdout)
	}
}

func TestEstateHistoryOnAnEmptySeriesSaysSo(t *testing.T) {
	host := estateTestRegistry(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "graph.json"), []byte(`{"summary":{"observedImages":1}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	historyRef := host + "/acme/estate:history"
	if _, err := runCLI(t, "estate", "push", host+"/acme/estate:one", "--dir", dir,
		"--generated-at", "2026-09-01T00:00:00Z", "--history", historyRef, "--insecure"); err != nil {
		t.Fatal(err)
	}
	stdout, err := runCLI(t, "estate", "history", historyRef, "--insecure")
	if err != nil {
		t.Fatalf("history: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "a trend needs at least two") {
		t.Errorf("a one-entry series should say a trend is not possible yet:\n%s", stdout)
	}
}

// TestRegistryClientsPreferEnvironmentCredentials pins the resolution order that
// dogfooding exposed. `estate push` could only authenticate from a docker
// config, so it failed in CI — the one environment it is built for, where a
// runner has REGISTRY_TOKEN or GITHUB_TOKEN and no docker config at all.
//
// The order is: explicit environment credentials, then the ambient keychain.
// That way the same command works on a laptop and on a runner without a flag.
func TestRegistryClientsPreferEnvironmentCredentials(t *testing.T) {
	for _, key := range []string{"REGISTRY_USER", "REGISTRY_TOKEN", "CLEARCUTT_REGISTRY_USER", "CLEARCUTT_REGISTRY_TOKEN", "GITHUB_ACTOR", "GITHUB_TOKEN"} {
		t.Setenv(key, "")
	}
	if user, token := registryDestCredentialPair(); user != "" || token != "" {
		t.Fatalf("with no environment set, credentials should be empty, got %q/%q", user, token)
	}

	t.Setenv("REGISTRY_USER", "ci-bot")
	t.Setenv("REGISTRY_TOKEN", "s3cret")
	user, token := registryDestCredentialPair()
	if user != "ci-bot" || token != "s3cret" {
		t.Fatalf("explicit registry credentials should win, got %q/%q", user, token)
	}

	// GITHUB_TOKEN is the CI fallback, and must be picked up when the
	// ClearCutt-specific variables are unset.
	t.Setenv("REGISTRY_USER", "")
	t.Setenv("REGISTRY_TOKEN", "")
	t.Setenv("GITHUB_ACTOR", "octocat")
	t.Setenv("GITHUB_TOKEN", "ghs_token")
	user, token = registryDestCredentialPair()
	if user != "octocat" || token != "ghs_token" {
		t.Fatalf("GITHUB_* should be the CI fallback, got %q/%q", user, token)
	}

	// And the estate client must actually use them rather than silently
	// falling back to the keychain.
	restore := estateOpts.insecure
	estateOpts.insecure = false
	t.Cleanup(func() { estateOpts.insecure = restore })
	if estateClient() == nil {
		t.Fatal("estate client should be constructible from environment credentials")
	}
}
