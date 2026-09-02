package estate

import (
	"bytes"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// testRegistry stands up an in-process OCI registry. Everything here is
// hermetic: no network, no daemon, no credentials.
func testRegistry(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(registry.New())
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Host
}

func sampleSnapshot() Snapshot {
	return Snapshot{
		GeneratedAt: "2026-08-31T00:00:00Z",
		Files: map[string][]byte{
			"graph.json":        []byte(`{"kind":"BaseImageGraph","edges":[]}`),
			"layers.json":       []byte(`{"kind":"LayerCommonalityGraph"}`),
			"observations.json": []byte(`{"images":[]}`),
		},
	}
}

func TestPushPullRoundTrip(t *testing.T) {
	host := testRegistry(t)
	client := NewInsecureClient()
	ref := host + "/acme/clearcutt-estate:2026-08-31"

	pushed, err := client.Push(ref, sampleSnapshot())
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if !strings.HasPrefix(pushed, "sha256:") {
		t.Fatalf("push should return a manifest digest, got %q", pushed)
	}

	got, pulledDigest, err := client.Pull(ref)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if pulledDigest != pushed {
		t.Errorf("pulled digest %s != pushed %s", pulledDigest, pushed)
	}
	if got.GeneratedAt != "2026-08-31T00:00:00Z" {
		t.Errorf("generatedAt should survive the round trip, got %q", got.GeneratedAt)
	}
	want := sampleSnapshot().Files
	if len(got.Files) != len(want) {
		t.Fatalf("expected %d files, got %d (%v)", len(want), len(got.Files), keys(got.Files))
	}
	for name, body := range want {
		if !bytes.Equal(got.Files[name], body) {
			t.Errorf("file %q round-tripped as %q, want %q", name, got.Files[name], body)
		}
	}
}

// TestBuildIsDeterministic is what makes "has the estate changed?" answerable by
// comparing digests instead of diffing content. Map iteration order in Go is
// randomized, so without the explicit sort this would pass only sometimes —
// which is exactly the kind of flake that shows up as a spurious new version
// weeks later.
func TestBuildIsDeterministic(t *testing.T) {
	first, err := Build(sampleSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := first.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		again, err := Build(sampleSnapshot())
		if err != nil {
			t.Fatal(err)
		}
		againDigest, err := again.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if againDigest != firstDigest {
			t.Fatalf("Build is not deterministic: run %d produced %s, want %s", i, againDigest, firstDigest)
		}
	}
}

// TestUnchangedSnapshotRepushesToTheSameDigest is the operational consequence of
// determinism: a nightly job that re-pushes an unchanged estate must not create
// a new version every night.
func TestUnchangedSnapshotRepushesToTheSameDigest(t *testing.T) {
	host := testRegistry(t)
	client := NewInsecureClient()
	ref := host + "/acme/clearcutt-estate:latest"

	first, err := client.Push(ref, sampleSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Push(ref, sampleSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("re-pushing an unchanged snapshot produced a new digest: %s then %s", first, second)
	}
}

// TestChangedSnapshotChangesTheDigest is the other half: a real change must be
// visible as a new digest, or drift detection silently stops working.
func TestChangedSnapshotChangesTheDigest(t *testing.T) {
	base, err := Build(sampleSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	baseDigest, err := base.Digest()
	if err != nil {
		t.Fatal(err)
	}
	changed := sampleSnapshot()
	changed.Files["graph.json"] = []byte(`{"kind":"BaseImageGraph","edges":[{"consumerRef":"x"}]}`)
	next, err := Build(changed)
	if err != nil {
		t.Fatal(err)
	}
	nextDigest, err := next.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if nextDigest == baseDigest {
		t.Fatal("a changed estate must produce a different digest")
	}
}

// TestPullRejectsAForeignArtifact guards the case that matters most: pulling an
// ordinary image and treating its layers as governance evidence would be worse
// than failing outright.
func TestPullRejectsAForeignArtifact(t *testing.T) {
	host := testRegistry(t)
	client := NewInsecureClient()
	ref := host + "/acme/not-an-estate:latest"

	// A perfectly ordinary image at the reference an operator might mistype.
	target, err := name.ParseReference(ref, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(target, empty.Image); err != nil {
		t.Fatalf("seed plain image: %v", err)
	}
	if _, _, err := client.Pull(ref); err == nil {
		t.Fatal("pulling a non-estate artifact must fail rather than yield evidence")
	} else if !strings.Contains(err.Error(), "not a ClearCutt estate artifact") {
		t.Fatalf("error should name the cause, got: %v", err)
	}
}

func TestBuildRejectsEmptyAndOversizedInput(t *testing.T) {
	if _, err := Build(Snapshot{}); err == nil {
		t.Error("an empty snapshot should be rejected")
	}
	if _, err := Build(Snapshot{Files: map[string][]byte{"": []byte("x")}}); err == nil {
		t.Error("a file with an empty name should be rejected")
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
