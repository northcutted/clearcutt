package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMirror_GeneratesCopyScript(t *testing.T) {
	stdout, err := runCLI(t, "mirror", "java21-distroless",
		"--target", "enterprise-registry.internal/hardened", "--catalog", fixtureCatalog())
	if err != nil {
		t.Fatalf("mirror failed: %v", err)
	}
	for _, want := range []string{
		"#!/usr/bin/env bash",
		"skopeo copy",
		"cosign copy",
		"enterprise-registry.internal/hardened/clearcutt-java:v1.0.0-distroless",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("mirror script missing %q\n%s", want, stdout)
		}
	}
}

func TestMirrorWritesScriptsToFiles(t *testing.T) {
	mirrorPath := filepath.Join(t.TempDir(), "mirror.sh")
	stdout, err := runCLI(t, "mirror", "java21-distroless",
		"--target", "enterprise-registry.internal/hardened",
		"--catalog", fixtureCatalog(),
		"--output", mirrorPath)
	if err != nil {
		t.Fatalf("mirror output failed: %v\n%s", err, stdout)
	}
	raw, err := os.ReadFile(mirrorPath)
	if err != nil {
		t.Fatalf("read mirror script: %v", err)
	}
	if !strings.Contains(stdout, "Successfully generated") || !strings.Contains(string(raw), "skopeo copy") {
		t.Fatalf("unexpected mirror file/stdout:\nstdout=%s\nfile=%s", stdout, raw)
	}

	verifyPath := filepath.Join(t.TempDir(), "verify.sh")
	stdout, err = runCLI(t, "mirror", "verify",
		"--source", "ghcr.io/acme/src:tag",
		"--target", "ghcr.io/acme/dst:tag",
		"--identity", "https://github.com/acme/platform/.github/workflows/release.yml@.*",
		"--issuer", "https://issuer.example",
		"--output", verifyPath)
	if err != nil {
		t.Fatalf("mirror verify output failed: %v\n%s", err, stdout)
	}
	raw, err = os.ReadFile(verifyPath)
	if err != nil {
		t.Fatalf("read verify script: %v", err)
	}
	if !strings.Contains(string(raw), "https://issuer.example") || !strings.Contains(stdout, "verification script") {
		t.Fatalf("unexpected verify file/stdout:\nstdout=%s\nfile=%s", stdout, raw)
	}
}

// mirror verify must emit an honest verification *script*, not fabricated PASS lines.
func TestMirrorVerify_GeneratesVerificationScript(t *testing.T) {
	src := "ghcr.io/northcutted/clearcutt/clearcutt-java:v1.0.0-distroless"
	tgt := "enterprise-registry.internal/hardened/clearcutt-java:v1.0.0-distroless"

	stdout, err := runCLI(t, "mirror", "verify", "--source", src, "--target", tgt)
	if err != nil {
		t.Fatalf("mirror verify failed: %v", err)
	}
	if strings.Contains(stdout, "[✔ PASS]") {
		t.Errorf("mirror verify must not fabricate PASS result lines offline:\n%s", stdout)
	}
	for _, want := range []string{"cosign verify", "oras discover", "crane digest", src, tgt} {
		if !strings.Contains(stdout, want) {
			t.Errorf("verification script missing %q\n%s", want, stdout)
		}
	}
}
