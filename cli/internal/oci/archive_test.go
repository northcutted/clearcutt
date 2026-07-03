package oci

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func TestPushImageArchiveAcceptsGzippedDockerArchive(t *testing.T) {
	client, host := testRegistry(t)
	img := testBaseImage(t, 701, 2, v1.Platform{OS: "linux", Architecture: "amd64"})

	tag, err := name.NewTag("example.com/acme/base:latest")
	if err != nil {
		t.Fatal(err)
	}
	plainArchive := filepath.Join(t.TempDir(), "image.tar")
	if err := tarball.WriteToFile(plainArchive, tag, img); err != nil {
		t.Fatalf("write docker archive: %v", err)
	}
	gzArchive := filepath.Join(t.TempDir(), "image.tar.gz")
	gzipFile(t, plainArchive, gzArchive)

	ref := host + "/acme/base:_stage-dev-amd64"
	pushedDigest, err := client.PushImageArchive(ref, gzArchive)
	if err != nil {
		t.Fatalf("PushImageArchive: %v", err)
	}
	wantDigest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if pushedDigest != wantDigest.String() {
		t.Fatalf("pushed digest = %s, want %s", pushedDigest, wantDigest)
	}
	pulled, err := client.PullImage(ref)
	if err != nil {
		t.Fatalf("pull pushed image: %v", err)
	}
	gotDigest, err := pulled.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != wantDigest {
		t.Fatalf("registry digest = %s, want %s", gotDigest, wantDigest)
	}
}

func gzipFile(t *testing.T, src, dest string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
