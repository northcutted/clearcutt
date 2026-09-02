package evidence

import (
	"bytes"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

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

// seedImage pushes an ordinary image to act as the evidence subject.
func seedImage(t *testing.T, ref string) string {
	t.Helper()
	img, err := random.Image(256, 2)
	if err != nil {
		t.Fatal(err)
	}
	target, err := name.ParseReference(ref, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(target, img); err != nil {
		t.Fatal(err)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return digest.String()
}

func sampleBundle() Bundle {
	return Bundle{
		Release: "v1.4.0",
		Created: "2026-09-01T00:00:00Z",
		Files: map[string][]byte{
			"sbom.json":       []byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`),
			"provenance.json": []byte(`{"_type":"https://in-toto.io/Statement/v1"}`),
			"scan.json":       []byte(`{"matches":[]}`),
		},
	}
}

func TestAttachListFetchRoundTrip(t *testing.T) {
	host := testRegistry(t)
	client := NewInsecureClient()
	ref := host + "/acme/app:v1.4.0"
	seedImage(t, ref)

	attachmentDigest, err := client.Attach(ref, sampleBundle())
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	attachments, err := client.List(ref)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(attachments))
	}
	got := attachments[0]
	if got.Digest != attachmentDigest {
		t.Errorf("listed digest %s != attached %s", got.Digest, attachmentDigest)
	}
	if got.Release != "v1.4.0" {
		t.Errorf("release annotation lost: %q", got.Release)
	}
	if strings.Join(got.Files, ",") != "provenance.json,sbom.json,scan.json" {
		t.Errorf("file names should be listable without pulling blobs, got %v", got.Files)
	}

	bundle, err := client.Fetch(ref, attachmentDigest)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	for name, want := range sampleBundle().Files {
		if !bytes.Equal(bundle.Files[name], want) {
			t.Errorf("%s round-tripped as %q, want %q", name, bundle.Files[name], want)
		}
	}
}

// TestAttachPinsTheSubjectByDigest: evidence describes specific bytes. Attaching
// to a tag would leave the evidence pointing at whatever that tag means later.
func TestAttachPinsTheSubjectByDigest(t *testing.T) {
	host := testRegistry(t)
	client := NewInsecureClient()
	ref := host + "/acme/app:v1.4.0"
	digest := seedImage(t, ref)

	if _, err := client.Attach(ref, sampleBundle()); err != nil {
		t.Fatal(err)
	}
	attachments, err := client.List(ref)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := client.Fetch(ref, attachments[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(bundle.Subject, digest) {
		t.Errorf("evidence subject %q should pin the image digest %s", bundle.Subject, digest)
	}

	// Move the tag to different content. The evidence must still name the
	// bytes it was made about, not the new ones.
	newDigest := seedImage(t, ref)
	if newDigest == digest {
		t.Fatal("test setup: the tag did not move")
	}
	again, err := client.Fetch(ref, attachments[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(again.Subject, digest) {
		t.Errorf("after the tag moved, evidence subject is %q; it must still pin %s", again.Subject, digest)
	}
}

// TestReAttachingIdenticalEvidenceIsStable: a re-run that produces the same
// evidence must not create a second attachment saying the same thing.
func TestReAttachingIdenticalEvidenceIsStable(t *testing.T) {
	host := testRegistry(t)
	client := NewInsecureClient()
	ref := host + "/acme/app:v1.4.0"
	seedImage(t, ref)

	first, err := client.Attach(ref, sampleBundle())
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Attach(ref, sampleBundle())
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("identical evidence produced two digests: %s then %s", first, second)
	}
	attachments, err := client.List(ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(attachments) != 1 {
		t.Fatalf("identical evidence should leave one attachment, got %d", len(attachments))
	}
}

// TestExportSurvivesRegistryLoss is the reason Export exists. Registry
// lifecycle policies can delete attached evidence; this proves an export is a
// real hedge rather than a copy that only works while the original is intact.
func TestExportSurvivesRegistryLoss(t *testing.T) {
	host := testRegistry(t)
	client := NewInsecureClient()
	ref := host + "/acme/app:v1.4.0"
	seedImage(t, ref)
	if _, err := client.Attach(ref, sampleBundle()); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	manifest, err := client.Export(ref, dir)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(manifest.Attachments) != 1 {
		t.Fatalf("expected 1 exported attachment, got %d", len(manifest.Attachments))
	}
	if manifest.Note == "" {
		t.Error("the export should carry a note explaining why it exists")
	}

	// Plain files are readable without any container tooling.
	shortDigest := strings.TrimPrefix(manifest.Attachments[0].Digest, "sha256:")[:12]
	sbom, err := os.ReadFile(filepath.Join(dir, "files", shortDigest, "sbom.json"))
	if err != nil {
		t.Fatalf("exported plain files should be directly readable: %v", err)
	}
	if !bytes.Contains(sbom, []byte("SPDX-2.3")) {
		t.Errorf("exported sbom.json does not look like the original: %q", sbom)
	}

	// Now simulate the registry losing the evidence entirely, and restore it.
	fresh := testRegistry(t)
	freshRef := fresh + "/acme/app:v1.4.0"
	seedImage(t, freshRef)
	restored, err := client.Import(dir, freshRef)
	if err != nil {
		t.Fatalf("import into a fresh registry: %v", err)
	}
	if len(restored) != 1 || restored[0] != manifest.Attachments[0].Digest {
		t.Fatalf("restore should reproduce the original digest %s, got %v", manifest.Attachments[0].Digest, restored)
	}

	// And the restored evidence is byte-identical, which is what keeps any
	// signature made over it valid.
	bundle, err := client.Fetch(freshRef, restored[0])
	if err != nil {
		t.Fatalf("fetch restored evidence: %v", err)
	}
	for name, want := range sampleBundle().Files {
		if !bytes.Equal(bundle.Files[name], want) {
			t.Errorf("restored %s differs from the original", name)
		}
	}
}

// TestFetchRejectsAForeignArtifact: reading an ordinary image's layers as
// evidence would be worse than failing.
func TestFetchRejectsAForeignArtifact(t *testing.T) {
	host := testRegistry(t)
	client := NewInsecureClient()
	ref := host + "/acme/app:v1.4.0"
	digest := seedImage(t, ref)

	if _, err := client.Fetch(ref, digest); err == nil {
		t.Fatal("fetching a plain image as evidence must fail")
	} else if !strings.Contains(err.Error(), "not a ClearCutt evidence bundle") {
		t.Fatalf("error should name the cause, got: %v", err)
	}
}

var _ = mutate.Annotations
var _ = empty.Image
