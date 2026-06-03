package commands

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

// verifyreleaseevidence.go ports core/scripts/verify-release-evidence.mjs into
// the CLI. It verifies one published image ref against the registry: resolved
// digest, Sigstore keyless signature, SBOM + test-results attestations, SLSA
// provenance, and GitHub-native provenance. Identity is matched EXACTLY
// (--certificate-identity, not -regexp) — this is a security gate, so it does not
// reuse the regexp-based sign.Cosign verify helpers.

type releaseEvidenceFlags struct {
	ref              string
	digest           string
	repo             string
	workflowIdentity string
	oidcIssuer       string
	sourceRef        string
	sourceBranch     string
}

var releaseEvidenceOpts releaseEvidenceFlags

func NewVerifyReleaseEvidenceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "release-evidence",
		Short: "Verify a published image ref carries complete Sigstore + SLSA release evidence",
		Long: `Verifies one published ClearCutt image reference directly against the registry:
the crane-resolved digest (optionally matched against --digest), the Sigstore
keyless signature, the SPDX SBOM and test-results attestations, the SLSA
provenance (slsa-verifier), and the GitHub-native provenance attestation. The
signer is matched exactly against --workflow-identity. Requires cosign, crane,
slsa-verifier, and gh on PATH.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerifyReleaseEvidence()
		},
	}
	f := cmd.Flags()
	f.StringVar(&releaseEvidenceOpts.ref, "ref", "", "Image reference to verify (required)")
	f.StringVar(&releaseEvidenceOpts.digest, "digest", "", "Expected image digest (sha256:...), matched against the resolved digest")
	f.StringVar(&releaseEvidenceOpts.repo, "repo", "", "owner/repo the image was built from (required)")
	f.StringVar(&releaseEvidenceOpts.workflowIdentity, "workflow-identity", "", "Exact Sigstore certificate identity of the release workflow (required)")
	f.StringVar(&releaseEvidenceOpts.oidcIssuer, "oidc-issuer", "https://token.actions.githubusercontent.com", "Sigstore certificate OIDC issuer")
	f.StringVar(&releaseEvidenceOpts.sourceRef, "source-ref", "refs/heads/main", "Source ref for GitHub-native provenance verification")
	f.StringVar(&releaseEvidenceOpts.sourceBranch, "source-branch", "", "Source branch for slsa-verifier (defaults to --source-ref without refs/heads/)")
	_ = cmd.MarkFlagRequired("ref")
	_ = cmd.MarkFlagRequired("repo")
	_ = cmd.MarkFlagRequired("workflow-identity")
	return cmd
}

// evidenceImageRepository strips any @digest and tag, mirroring imageRepository().
func evidenceImageRepository(ref string) string {
	withoutDigest := strings.SplitN(ref, "@", 2)[0]
	lastColon := strings.LastIndex(withoutDigest, ":")
	lastSlash := strings.LastIndex(withoutDigest, "/")
	if lastColon > lastSlash {
		return withoutDigest[:lastColon]
	}
	return withoutDigest
}

// evidenceRun mirrors the .mjs run(): non-captured stdout is streamed to
// io.Discard (cosign verify-attestation prints multi-MB DSSE payloads even on
// success), prints [evidence] ok/failed, and returns captured stdout.
func evidenceRun(label, name string, args []string, captureStdout bool) (string, error) {
	cmd := exec.Command(name, args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	if captureStdout {
		cmd.Stdout = &stdoutBuf
	} else {
		cmd.Stdout = io.Discard
	}
	cmd.Stderr = &stderrBuf

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(errOut, "[evidence] failed: %s\n", label)
		detail := strings.TrimSpace(strings.Join([]string{stdoutBuf.String(), stderrBuf.String()}, "\n"))
		if detail != "" {
			fmt.Fprintln(errOut, detail)
		}
		return "", fmt.Errorf("release evidence check failed: %s", label)
	}
	fmt.Fprintf(out, "[evidence] ok: %s\n", label)
	return stdoutBuf.String(), nil
}

func runVerifyReleaseEvidence() error {
	o := releaseEvidenceOpts
	sourceBranch := o.sourceBranch
	if sourceBranch == "" {
		sourceBranch = strings.TrimPrefix(o.sourceRef, "refs/heads/")
	}

	resolved, err := evidenceRun("resolve image digest", "crane", []string{"digest", o.ref}, true)
	if err != nil {
		return err
	}
	resolvedDigest := strings.TrimSpace(resolved)
	if o.digest != "" && resolvedDigest != o.digest {
		fmt.Fprintf(errOut, "[evidence] digest mismatch for %s: got %s, expected %s\n", o.ref, resolvedDigest, o.digest)
		return ErrCheckFailed
	}

	digestToUse := resolvedDigest
	if o.digest != "" {
		digestToUse = o.digest
	}
	immutableRef := evidenceImageRepository(o.ref) + "@" + digestToUse

	if _, err := evidenceRun("Sigstore keyless signature", "cosign", []string{
		"verify", immutableRef,
		"--certificate-identity", o.workflowIdentity,
		"--certificate-oidc-issuer", o.oidcIssuer,
		"--output", "json",
	}, false); err != nil {
		return err
	}

	if _, err := evidenceRun("SPDX SBOM attestation", "cosign", []string{
		"verify-attestation", immutableRef,
		"--type", "spdxjson",
		"--certificate-identity", o.workflowIdentity,
		"--certificate-oidc-issuer", o.oidcIssuer,
	}, false); err != nil {
		return err
	}

	if _, err := evidenceRun("test-results attestation", "cosign", []string{
		"verify-attestation", immutableRef,
		"--type", "custom",
		"--certificate-identity", o.workflowIdentity,
		"--certificate-oidc-issuer", o.oidcIssuer,
	}, false); err != nil {
		return err
	}

	if _, err := evidenceRun("slsa-verifier provenance check", "slsa-verifier", []string{
		"verify-image", immutableRef,
		"--source-uri", "github.com/" + o.repo,
		"--source-branch", sourceBranch,
	}, false); err != nil {
		return err
	}

	if _, err := evidenceRun("GitHub-native provenance attestation", "gh", []string{
		"attestation", "verify", "oci://" + immutableRef,
		"--repo", o.repo,
		"--cert-identity", o.workflowIdentity,
		"--source-ref", o.sourceRef,
	}, false); err != nil {
		return err
	}

	fmt.Fprintf(out, "[evidence] complete: %s\n", immutableRef)
	return nil
}
