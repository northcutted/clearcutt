package commands

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseEvidenceResolveDigestUsesGoOCIClient(t *testing.T) {
	client, host := commandTestRegistry(t)
	restoreOCIClient(t, client)
	ref := host + "/acme/base:latest"
	img := commandTestImage(t, 9001)
	want, err := client.PushImage(ref, img)
	if err != nil {
		t.Fatalf("push image: %v", err)
	}
	got, err := releaseEvidenceResolveDigest(ref)
	if err != nil {
		t.Fatalf("resolve digest: %v", err)
	}
	if got != want {
		t.Fatalf("resolved digest = %s, want %s", got, want)
	}
}

// Ports test_release_evidence_verifier_discards_large_attestation_stdout: cosign
// verify-attestation streams a multi-MB DSSE payload even on success. The verifier
// must not capture it (it streams to io.Discard), so the command succeeds and its
// own output stays small. Also exercises the digest-match + immutable-ref path.
func TestVerifyReleaseEvidenceDiscardsLargeAttestationOutput(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	binDir := t.TempDir()
	oldResolve := releaseEvidenceResolveDigest
	releaseEvidenceResolveDigest = func(ref string) (string, error) {
		return "sha256:abc123", nil
	}
	t.Cleanup(func() { releaseEvidenceResolveDigest = oldResolve })

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

func TestVerifyReleaseEvidenceCoreDirRunsVerifierToolsThroughNix(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "nix.log")
	oldResolve := releaseEvidenceResolveDigest
	oldOpts := releaseEvidenceOpts
	releaseEvidenceResolveDigest = func(ref string) (string, error) {
		return "sha256:def456", nil
	}
	t.Cleanup(func() {
		releaseEvidenceResolveDigest = oldResolve
		releaseEvidenceOpts = oldOpts
	})

	writeExecutable(t, filepath.Join(binDir, "nix"), `#!/usr/bin/env bash
printf '%s\n' "$PWD :: $*" >> "$CLEARCUTT_NIX_LOG"
case "$*" in
  *"--command cosign verify "*|*"--command cosign verify-attestation "*|*"--command slsa-verifier verify-image "*|*"--command gh attestation verify "*) exit 0 ;;
  *) exit 9 ;;
esac
`)
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLEARCUTT_NIX_LOG", logPath)
	coreDir := filepath.Join(t.TempDir(), "core")
	if err := os.MkdirAll(coreDir, 0o755); err != nil {
		t.Fatalf("mkdir core dir: %v", err)
	}

	stdout, err := runCLI(t, "verify", "release-evidence",
		"--ref", "ghcr.io/example/clearcutt-java21:v1-distroless",
		"--repo", "example/clearcutt",
		"--workflow-identity", "https://github.com/example/clearcutt/.github/workflows/release.yml@refs/heads/main",
		"--source-ref", "refs/heads/main",
		"--core-dir", coreDir,
	)
	if err != nil {
		t.Fatalf("expected success, got %v:\n%s", err, stdout)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read nix log: %v", err)
	}
	log := string(raw)
	for _, want := range []string{
		coreDir + " :: develop --extra-experimental-features nix-command flakes --accept-flake-config --command cosign verify ghcr.io/example/clearcutt-java21@sha256:def456",
		"--command cosign verify-attestation ghcr.io/example/clearcutt-java21@sha256:def456 --type spdxjson",
		"--command cosign verify-attestation ghcr.io/example/clearcutt-java21@sha256:def456 --type custom",
		"--command slsa-verifier verify-image ghcr.io/example/clearcutt-java21@sha256:def456 --source-uri github.com/example/clearcutt --source-branch main",
		"--command gh attestation verify oci://ghcr.io/example/clearcutt-java21@sha256:def456 --repo example/clearcutt",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("expected wrapped verifier command %q in:\n%s", want, log)
		}
	}
}

// A digest that does not match the registry-resolved digest must fail closed.
func TestVerifyReleaseEvidenceFailsOnDigestMismatch(t *testing.T) {
	oldResolve := releaseEvidenceResolveDigest
	releaseEvidenceResolveDigest = func(ref string) (string, error) {
		return "sha256:actual", nil
	}
	t.Cleanup(func() { releaseEvidenceResolveDigest = oldResolve })

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
