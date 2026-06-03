package commands

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Ports test_release_evidence_verifier_discards_large_attestation_stdout: cosign
// verify-attestation streams a multi-MB DSSE payload even on success. The verifier
// must not capture it (it streams to io.Discard), so the command succeeds and its
// own output stays small. Also exercises the digest-match + immutable-ref path.
func TestVerifyReleaseEvidenceDiscardsLargeAttestationOutput(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	binDir := t.TempDir()

	// cosign: emit ~2MB on the spdxjson attestation check, "ok" otherwise.
	writeExecutable(t, filepath.Join(binDir, "cosign"), `#!/usr/bin/env bash
for a in "$@"; do
  if [ "$a" = "spdxjson" ]; then
    head -c 2097152 /dev/zero | tr '\0' 'x'
    exit 0
  fi
done
echo ok
exit 0
`)
	writeExecutable(t, filepath.Join(binDir, "crane"), "#!/usr/bin/env bash\necho 'sha256:abc123'\n")
	writeExecutable(t, filepath.Join(binDir, "slsa-verifier"), "#!/usr/bin/env bash\necho ok\n")
	writeExecutable(t, filepath.Join(binDir, "gh"), "#!/usr/bin/env bash\necho ok\n")

	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}

	stdout, err := runCLI(t, "verify", "release-evidence",
		"--ref", "ghcr.io/example/clearcutt-dotnet8:v1-dev",
		"--digest", "sha256:abc123",
		"--repo", "example/clearcutt",
		"--workflow-identity", "https://github.com/example/clearcutt/.github/workflows/release.yml@refs/heads/main",
		"--source-ref", "refs/heads/main",
		"--source-branch", "main",
	)
	if err != nil {
		t.Fatalf("expected success, got %v:\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "[evidence] ok: SPDX SBOM attestation") {
		t.Fatalf("expected SBOM attestation ok line, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "[evidence] complete: ghcr.io/example/clearcutt-dotnet8@sha256:abc123") {
		t.Fatalf("expected completion line for the immutable ref, got:\n%s", stdout)
	}
	if len(stdout) > 5000 {
		t.Fatalf("expected the 2MB attestation payload to be discarded, captured %d bytes", len(stdout))
	}
}

// A digest that does not match the crane-resolved digest must fail closed.
func TestVerifyReleaseEvidenceFailsOnDigestMismatch(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "crane"), "#!/usr/bin/env bash\necho 'sha256:actual'\n")

	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}

	stdout, err := runCLI(t, "verify", "release-evidence",
		"--ref", "ghcr.io/example/img:v1",
		"--digest", "sha256:expected",
		"--repo", "example/clearcutt",
		"--workflow-identity", "https://github.com/example/clearcutt/.github/workflows/release.yml@refs/heads/main",
	)
	if err == nil {
		t.Fatalf("expected digest mismatch to fail, got success:\n%s", stdout)
	}
	if !strings.Contains(stdout, "digest mismatch") {
		t.Fatalf("expected digest mismatch message, got:\n%s", stdout)
	}
}
