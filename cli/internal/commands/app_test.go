package commands

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/northcutted/clearcutt/internal/oci"
)

func TestAppBuildCommandBuildsRebasableImage(t *testing.T) {
	client, host := commandTestRegistry(t)
	restoreOCIClient(t, client)

	base := commandTestImage(t, 601)
	baseRef := host + "/bases/java:v1.0.0"
	if _, err := client.PushImage(baseRef, base); err != nil {
		t.Fatalf("push base: %v", err)
	}
	artifact := filepath.Join(t.TempDir(), "app.jar")
	if err := os.WriteFile(artifact, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	appRef := host + "/apps/payments:1.0.0"
	stdout, err := runCLI(t, "app", "build",
		"--base", baseRef,
		"--base-id", "java21-distroless",
		"--base-version", "v1.0.0",
		"--artifact", artifact,
		"--entrypoint", `["java","-jar","/workspace/app.jar"]`,
		"--image", appRef,
		"--format", "json")
	if err != nil {
		t.Fatalf("app build command failed: %v\n%s", err, stdout)
	}
	var result AppBuildResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal app build output: %v\n%s", err, stdout)
	}
	if result.Image != appRef || result.BaseID != "java21-distroless" {
		t.Fatalf("unexpected app build result: %+v", result)
	}
	meta, err := client.ReadAppMeta(appRef)
	if err != nil {
		t.Fatalf("read app meta: %v", err)
	}
	if !meta.Rebasable {
		t.Fatal("built image was not marked rebasable")
	}
	if meta.BaseID != "java21-distroless" || meta.BaseLastLayer == "" || meta.BaseRef == "" {
		t.Fatalf("built image has incomplete lifecycle labels: %+v", meta)
	}
}

func TestAppDiffBaseOfflineCompatibility(t *testing.T) {
	stdout, err := runCLI(t, "app", "diff-base",
		"--current-base", "java21-distroless",
		"--candidate-base", "java21-distroless",
		"--catalog", fixtureCatalog(),
		"--format", "json")
	if err != nil {
		t.Fatalf("app diff-base failed: %v\n%s", err, stdout)
	}
	var result AppDiffBaseResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal diff-base output: %v\n%s", err, stdout)
	}
	if !result.Compatible {
		t.Fatalf("expected compatible base line, got: %+v", result)
	}
	if !result.VulnDeltaComputed {
		t.Fatalf("expected fixture catalog CVE delta to be computed: %+v", result)
	}

	stdout, err = runCLI(t, "app", "diff-base",
		"--current-base", "java21-distroless",
		"--candidate-base", "ghcr.io/example/python:latest",
		"--candidate-base-id", "python3.14-slim",
		"--fail-on-incompatible",
		"--format", "json")
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected incompatible base to return ErrCheckFailed, got %v\n%s", err, stdout)
	}
}

func TestRuntimeCompatAcceptsCoreLTSLine(t *testing.T) {
	ok, reason := runtimeCompat("coreLTS-slim", "coreLTS-distroless")
	if !ok {
		t.Fatalf("expected coreLTS tiers to be compatible, got %q", reason)
	}
	if !strings.Contains(reason, "coreLTS") {
		t.Fatalf("expected coreLTS compatibility reason, got %q", reason)
	}
}

func TestAppRebaseCommandVerifiesSignsAndAttestsDigestRefs(t *testing.T) {
	client, host := commandTestRegistry(t)
	restoreOCIClient(t, client)

	oldBase := commandTestImage(t, 701)
	newBase := commandTestImage(t, 702)
	oldRef := host + "/bases/java:v1.0.0"
	newRef := host + "/bases/java:v1.0.1"
	if _, err := client.PushImage(oldRef, oldBase); err != nil {
		t.Fatalf("push old base: %v", err)
	}
	if _, err := client.PushImage(newRef, newBase); err != nil {
		t.Fatalf("push new base: %v", err)
	}
	artifact := filepath.Join(t.TempDir(), "app.jar")
	if err := os.WriteFile(artifact, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	appRef := host + "/apps/payments:1.0.0"
	if _, err := client.BuildApp(oci.BuildOptions{
		BaseRef:      oldRef,
		BaseID:       "java21-distroless",
		BaseVersion:  "v1.0.0",
		ArtifactPath: artifact,
		DestPath:     "/workspace/app.jar",
		Entrypoint:   []string{"java", "-jar", "/workspace/app.jar"},
		TargetRef:    appRef,
	}); err != nil {
		t.Fatalf("build app image: %v", err)
	}

	cosignPath, cosignLog := fakeCosign(t)
	targetRef := host + "/apps/payments:1.0.0-rebased"
	stdout, err := runCLI(t, "app", "rebase",
		"--image", appRef,
		"--candidate-base", newRef,
		"--candidate-base-id", "java21-distroless",
		"--candidate-base-version", "v1.0.1",
		"--tag", targetRef,
		"--dev-identity", "https://github.com/acme/payments/.github/workflows/release.yml@refs/heads/main",
		"--cosign-path", cosignPath,
		"--sign",
		"--attest")
	if err != nil {
		t.Fatalf("app rebase command failed: %v\n%s", err, stdout)
	}
	if _, err := client.PullImage(targetRef); err != nil {
		t.Fatalf("rebased target was not pushed: %v", err)
	}

	logBytes, err := os.ReadFile(cosignLog)
	if err != nil {
		t.Fatalf("read fake cosign log: %v", err)
	}
	lines := nonEmptyLines(string(logBytes))
	if len(lines) != 3 {
		t.Fatalf("expected verify/sign/attest cosign calls, got %d:\n%s", len(lines), string(logBytes))
	}
	if !strings.HasPrefix(lines[0], "verify ") || !strings.Contains(lines[0], "/apps/payments@sha256:") {
		t.Fatalf("developer signature was not verified against the digest-pinned source ref:\n%s", lines[0])
	}
	if !strings.HasPrefix(lines[1], "sign --yes ") || !strings.Contains(lines[1], "/apps/payments@sha256:") {
		t.Fatalf("rebased image was not signed by digest ref:\n%s", lines[1])
	}
	if !strings.HasPrefix(lines[2], "attest --yes ") ||
		!strings.Contains(lines[2], "--type https://clearcutt.dev/attestations/rebase/v1") ||
		!strings.Contains(lines[2], "/apps/payments@sha256:") {
		t.Fatalf("rebase attestation was not attached to the digest-pinned target ref:\n%s", lines[2])
	}
}

func TestAppRebaseCommandRequiresPinnedDeveloperIdentity(t *testing.T) {
	client, host := commandTestRegistry(t)
	restoreOCIClient(t, client)

	base := commandTestImage(t, 801)
	baseRef := host + "/bases/java:v1.0.0"
	if _, err := client.PushImage(baseRef, base); err != nil {
		t.Fatalf("push base: %v", err)
	}
	artifact := filepath.Join(t.TempDir(), "app.jar")
	if err := os.WriteFile(artifact, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	appRef := host + "/apps/payments:1.0.0"
	if _, err := client.BuildApp(oci.BuildOptions{
		BaseRef:      baseRef,
		BaseID:       "java21-distroless",
		BaseVersion:  "v1.0.0",
		ArtifactPath: artifact,
		DestPath:     "/workspace/app.jar",
		Entrypoint:   []string{"/workspace/app.jar"},
		TargetRef:    appRef,
	}); err != nil {
		t.Fatalf("build app: %v", err)
	}

	stdout, err := runCLI(t, "app", "rebase",
		"--image", appRef,
		"--candidate-base", baseRef,
		"--candidate-base-id", "java21-distroless",
		"--tag", host+"/apps/payments:rebased",
		"--cosign-path", filepath.Join(t.TempDir(), "missing-cosign"))
	if err == nil || !strings.Contains(err.Error(), "--dev-identity is required") {
		t.Fatalf("expected missing developer identity error, got %v\n%s", err, stdout)
	}
}

func commandTestRegistry(t *testing.T) (*oci.Client, string) {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	return oci.NewInsecureClient(), strings.TrimPrefix(srv.URL, "http://")
}

func restoreOCIClient(t *testing.T, client *oci.Client) {
	t.Helper()
	old := newOCIClient
	newOCIClient = func() *oci.Client { return client }
	t.Cleanup(func() { newOCIClient = old })
}

func commandTestImage(t *testing.T, seed int64) v1.Image {
	t.Helper()
	img, err := random.Image(256, 2, random.WithSource(rand.NewSource(seed)))
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg = cfg.DeepCopy()
	cfg.OS = "linux"
	cfg.Architecture = "amd64"
	cfg.Config.User = "10001:10001"
	cfg.Config.Entrypoint = []string{"/base"}
	cfg.Config.Labels = map[string]string{"org.opencontainers.image.source": "https://github.com/northcutted/clearcutt"}
	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatalf("mutate config: %v", err)
	}
	return img
}

func fakeCosign(t *testing.T) (path, logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "cosign.log")
	path = filepath.Join(dir, "cosign")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + shellQuote(logPath) + "\nexit 0\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake cosign: %v", err)
	}
	return path, logPath
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
