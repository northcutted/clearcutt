package oci

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestPushImageIndexBuildsMultiArchIndex(t *testing.T) {
	client, host := testRegistry(t)
	amd64 := testBaseImage(t, 801, 1, v1.Platform{OS: "linux", Architecture: "amd64"})
	arm64 := testBaseImage(t, 802, 1, v1.Platform{OS: "linux", Architecture: "arm64"})
	if _, err := client.PushImage(host+"/acme/base:_stage-slim-amd64", amd64); err != nil {
		t.Fatalf("push amd64 stage: %v", err)
	}
	if _, err := client.PushImage(host+"/acme/base:_stage-slim-arm64", arm64); err != nil {
		t.Fatalf("push arm64 stage: %v", err)
	}

	digest, err := client.PushImageIndex(host+"/acme/base:slim", []IndexImage{
		{Ref: host + "/acme/base:_stage-slim-amd64", OS: "linux", Architecture: "amd64"},
		{Ref: host + "/acme/base:_stage-slim-arm64", OS: "linux", Architecture: "arm64"},
	})
	if err != nil {
		t.Fatalf("PushImageIndex: %v", err)
	}
	res, err := client.Pull(host + "/acme/base:slim")
	if err != nil {
		t.Fatalf("pull index: %v", err)
	}
	if !res.IsIndex {
		t.Fatal("pushed ref did not resolve to an index")
	}
	gotDigest, err := res.ManifestDigest()
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != digest {
		t.Fatalf("digest = %s, want %s", gotDigest, digest)
	}
	im, err := res.Index.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(im.Manifests) != 2 {
		t.Fatalf("manifest count = %d, want 2", len(im.Manifests))
	}
	for _, manifest := range im.Manifests {
		if manifest.Platform == nil || manifest.Platform.OS != "linux" {
			t.Fatalf("missing linux platform descriptor: %#v", manifest.Platform)
		}
	}
}

func TestPushImageIndexRejectsPartialPlatformOverride(t *testing.T) {
	client, host := testRegistry(t)
	img := testBaseImage(t, 803, 1, v1.Platform{OS: "linux", Architecture: "amd64"})
	if _, err := client.PushImage(host+"/acme/base:_stage-slim-amd64", img); err != nil {
		t.Fatalf("push stage: %v", err)
	}
	if _, err := client.PushImageIndex(host+"/acme/base:slim", []IndexImage{
		{Ref: host + "/acme/base:_stage-slim-amd64", OS: "linux"},
	}); err == nil {
		t.Fatal("expected partial platform override to fail")
	}
}
