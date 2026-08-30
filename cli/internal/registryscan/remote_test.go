package registryscan

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// testRegistry starts an in-process OCI registry. go-containerregistry resolves
// loopback hosts to plain HTTP, so the production RemoteLister talks to it unchanged.
func testRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func pushRandom(t *testing.T, ref string) {
	t.Helper()
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	parsed, err := name.ParseReference(ref)
	if err != nil {
		t.Fatalf("parse %q: %v", ref, err)
	}
	if err := remote.Write(parsed, img); err != nil {
		t.Fatalf("push %q: %v", ref, err)
	}
}

func TestRemoteListerEnumeratesRepositoriesAndTags(t *testing.T) {
	host := testRegistry(t)
	pushRandom(t, host+"/acme/base/java:v1.0.0")
	pushRandom(t, host+"/acme/base/java:v1.1.0")
	pushRandom(t, host+"/acme/apps/payments:v9")
	pushRandom(t, host+"/other/thing:v1")

	lister := NewRemoteLister()

	repos, err := lister.Repositories(context.Background(), host)
	if err != nil {
		t.Fatalf("Repositories: %v", err)
	}
	if len(repos) < 3 {
		t.Fatalf("Repositories = %v, want at least the three pushed repositories", repos)
	}

	tags, err := lister.Tags(context.Background(), host+"/acme/base/java")
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if len(tags) != 2 {
		t.Fatalf("Tags = %v, want both pushed tags", tags)
	}
}

func TestScanAgainstARealRegistryFiltersByNamespace(t *testing.T) {
	host := testRegistry(t)
	pushRandom(t, host+"/acme/base/java:v1.0.0")
	pushRandom(t, host+"/acme/base/node:v2.0.0")
	pushRandom(t, host+"/other/thing:v1")

	got, err := Scan(context.Background(), NewRemoteLister(), Options{
		Registry:    host,
		Namespace:   "acme/base",
		GeneratedAt: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got.Refs) != 2 {
		t.Fatalf("Refs = %v, want only the acme/base namespace", got.Refs)
	}
	for _, ref := range got.Refs {
		if strings.Contains(ref, "other/thing") {
			t.Fatalf("namespace filter leaked: %v", got.Refs)
		}
	}
}

func TestRemoteListerRejectsMalformedTargets(t *testing.T) {
	lister := NewRemoteLister()
	if _, err := lister.Repositories(context.Background(), "NOT A REGISTRY"); err == nil {
		t.Fatal("expected an invalid-registry error")
	}
	if _, err := lister.Tags(context.Background(), "NOT A REPOSITORY"); err == nil {
		t.Fatal("expected an invalid-repository error")
	}
}

func TestNewRemoteListerWithBasicAuthIsUsable(t *testing.T) {
	host := testRegistry(t)
	pushRandom(t, host+"/acme/app:v1")

	// The in-process registry ignores credentials; this asserts the constructor
	// produces a working lister rather than asserting anything about auth itself.
	tags, err := NewRemoteListerWithBasicAuth("user", "token").Tags(context.Background(), host+"/acme/app")
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if len(tags) != 1 || tags[0] != "v1" {
		t.Fatalf("Tags = %v, want [v1]", tags)
	}
}
