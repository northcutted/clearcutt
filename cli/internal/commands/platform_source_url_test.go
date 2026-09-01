package commands

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
)

func TestPlatformNewScaffoldsFromArchiveURL(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFleetConfig(t, source)
	writePlatformStatusFixture(t, source, "ghcr.io/acme/platform/clearcutt-*")
	for rel, body := range map[string]string{
		"cli/go.mod":                          "module github.com/northcutted/clearcutt\n",
		"site/package.json":                   `{"name":"clearcutt-catalog"}` + "\n",
		"schemas/clearcutt-fleet.schema.json": `{"type":"object"}` + "\n",
		"README.md":                           "# ClearCutt\n",
	} {
		path := filepath.Join(source, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	archivePath := filepath.Join(t.TempDir(), "clearcutt-source.zip")
	writePlatformSourceArchive(t, source, archivePath)
	raw, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/missing.zip"):
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "/corrupt.zip"):
			_, _ = w.Write([]byte("not a zip archive"))
		default:
			_, _ = w.Write(raw)
		}
	}))
	defer server.Close()

	outside := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(outside); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	stdout, err := runCLI(t,
		"platform", "new", "url-fleet",
		"--source", server.URL+"/clearcutt-source.zip",
		"--owner", "acme",
		"--repo", "url-fleet",
	)
	if err != nil {
		t.Fatalf("platform new from URL failed: %v\n%s", err, stdout)
	}
	if _, err := os.Stat(filepath.Join(outside, "url-fleet", fleet.DefaultConfigPath)); err != nil {
		t.Fatalf("expected URL-scaffolded fleet config: %v", err)
	}

	if _, _, err := materializePlatformSkeletonSource(server.URL + "/missing.zip"); err == nil || !strings.Contains(err.Error(), "HTTP") {
		t.Fatalf("expected HTTP status error for missing archive, got %v", err)
	}
	if _, _, err := materializePlatformSkeletonSource(server.URL + "/corrupt.zip"); err == nil {
		t.Fatal("expected error for corrupt archive body")
	}
}

func TestDefaultPlatformSourceArchiveURL(t *testing.T) {
	oldVersion := Version
	t.Cleanup(func() { Version = oldVersion })

	Version = "dev"
	if got := defaultPlatformSourceArchiveURL(); !strings.Contains(got, "refs/heads/main.zip") {
		t.Fatalf("dev build should fall back to main archive, got %s", got)
	}
	Version = "v1.2.3"
	if got := defaultPlatformSourceArchiveURL(); !strings.Contains(got, "refs/tags/v1.2.3.zip") {
		t.Fatalf("release build should use its tag archive, got %s", got)
	}
	Version = "v1.2.3-4-gabc1234-dirty"
	if got := defaultPlatformSourceArchiveURL(); !strings.Contains(got, "refs/heads/main.zip") {
		t.Fatalf("dirty describe output should fall back to main archive, got %s", got)
	}
}
