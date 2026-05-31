package commands

import (
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
