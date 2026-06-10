package commands

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/certify"
)

func overlayLayer(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	for _, name := range names {
		content := []byte(files[name])
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content))}); err != nil {
			t.Fatalf("write layer header: %v", err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("write layer content: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close layer: %v", err)
	}
	return buf.Bytes()
}

func overlayDockerArchive(t *testing.T, layer []byte, tag string) string {
	t.Helper()
	manifest, err := json.Marshal([]certify.DockerManifest{{
		Config:   "config.json",
		RepoTags: []string{tag},
		Layers:   []string{"layer.tar"},
	}})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	config := []byte(`{"config":{"User":"10001:10001"}}`)
	path := filepath.Join(t.TempDir(), "image.tar")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	for name, body := range map[string][]byte{
		"manifest.json": manifest,
		"config.json":   config,
		"layer.tar":     layer,
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}); err != nil {
			t.Fatalf("write archive header: %v", err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("write archive body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close archive writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	return path
}

func TestOverlayVerifyEmitsClosureEquivalencePredicate(t *testing.T) {
	runtime := overlayDockerArchive(t, overlayLayer(t, map[string]string{
		"nix/store/abc-runtime/bin/java": "same-runtime-bytes",
	}), "runtime:latest")
	grafted := overlayDockerArchive(t, overlayLayer(t, map[string]string{
		"etc/os-release":                 "ubi",
		"nix/store/abc-runtime/bin/java": "same-runtime-bytes",
		"nix/store/zzz-base/bin/tool":    "unrelated-base-store-entry",
	}), "grafted:latest")

	stdout, err := runCLI(t,
		"overlay", "verify",
		"--runtime-archive", runtime,
		"--grafted-archive", grafted,
		"--runtime-ref", "ghcr.io/acme/runtime@sha256:111",
		"--grafted-ref", "ghcr.io/acme/grafted@sha256:222",
		"--target", "java21-distroless",
		"--output-predicate",
	)
	if err != nil {
		t.Fatalf("overlay verify failed: %v\n%s", err, stdout)
	}

	var statement overlayClosureEquivalenceStatement
	if err := json.Unmarshal([]byte(stdout), &statement); err != nil {
		t.Fatalf("predicate did not parse: %v\n%s", err, stdout)
	}
	if statement.PredicateType != "https://clearcutt.dev/attestations/closure-equivalence/v1" {
		t.Fatalf("unexpected predicate type: %s", statement.PredicateType)
	}
	if !statement.Predicate.Equivalent || statement.Predicate.Status != "pass" {
		t.Fatalf("expected equivalent pass predicate: %#v", statement.Predicate)
	}
	if statement.Predicate.Runtime.Digest != statement.Predicate.Grafted.Digest {
		t.Fatalf("expected matching closure digest: %#v", statement.Predicate)
	}
	if len(statement.Subject) != 2 || statement.Subject[0].Digest["sha256"] != "111" || statement.Subject[1].Digest["sha256"] != "222" {
		t.Fatalf("expected image digest subjects, got %#v", statement.Subject)
	}
	if len(statement.Predicate.Grafted.IgnoredStoreRoots) != 1 || statement.Predicate.Grafted.IgnoredStoreRoots[0] != "nix/store/zzz-base" {
		t.Fatalf("expected unrelated base store root to be reported as ignored: %#v", statement.Predicate.Grafted.IgnoredStoreRoots)
	}
}

func TestOverlayVerifyFailsOnClosureMismatch(t *testing.T) {
	runtime := overlayDockerArchive(t, overlayLayer(t, map[string]string{
		"nix/store/abc-runtime/bin/java": "runtime-a",
	}), "runtime:latest")
	grafted := overlayDockerArchive(t, overlayLayer(t, map[string]string{
		"nix/store/abc-runtime/bin/java": "runtime-b",
	}), "grafted:latest")

	stdout, err := runCLI(t,
		"overlay", "verify",
		"--runtime-archive", runtime,
		"--grafted-archive", grafted,
		"--runtime-ref", "ghcr.io/acme/runtime@sha256:111",
		"--grafted-ref", "ghcr.io/acme/grafted@sha256:222",
	)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected ErrCheckFailed, got %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "closures differ") {
		t.Fatalf("expected mismatch detail, got:\n%s", stdout)
	}
}
