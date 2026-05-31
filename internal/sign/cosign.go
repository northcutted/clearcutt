// Package sign wraps the cosign CLI for keyless signing, attestation, and
// verification. Signing is delegated to cosign (rather than the sigstore Go
// libraries) on purpose: it keeps the trust roots and flags identical to the
// certify-app GitHub Action, and keeps Fulcio/Rekor wiring out of this codebase.
package sign

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Cosign drives the cosign binary. Verification flags (Identity/Issuer) are pinned
// signer constraints; an empty or wildcard identity is refused so a rebase can never
// "verify" against an anonymous signer.
type Cosign struct {
	Binary   string
	Identity string // --certificate-identity-regexp for verify operations
	Issuer   string // --certificate-oidc-issuer for verify operations
	Stdout   io.Writer
	Stderr   io.Writer

	// run is the exec seam; tests substitute it to assert argument construction
	// without a real cosign binary or network.
	run func(bin string, args []string, stdout, stderr io.Writer) error
}

// New constructs a Cosign driver. binary defaults to "cosign" when empty.
func New(binary, identity, issuer string, stdout, stderr io.Writer) *Cosign {
	if binary == "" {
		binary = "cosign"
	}
	return &Cosign{Binary: binary, Identity: identity, Issuer: issuer, Stdout: stdout, Stderr: stderr, run: execRun}
}

func execRun(bin string, args []string, stdout, stderr io.Writer) error {
	cmd := exec.Command(bin, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = os.Stdin // permit interactive keyless OIDC when run locally
	return cmd.Run()
}

// Available reports whether the cosign binary can be found on PATH.
func (c *Cosign) Available() error {
	if _, err := exec.LookPath(c.Binary); err != nil {
		return fmt.Errorf("cosign binary %q not found on PATH: install cosign (https://docs.sigstore.dev/cosign/system_config/installation) or pass --cosign-path", c.Binary)
	}
	return nil
}

// Sign keylessly signs the image at ref.
func (c *Cosign) Sign(ref string) error {
	return c.exec("sign", "--yes", ref)
}

// Attest keylessly attaches an attestation: predicatePath holds the predicate body
// (cosign wraps it in an in-toto statement under predicateType, subject = ref).
func (c *Cosign) Attest(ref, predicatePath, predicateType string) error {
	return c.exec("attest", "--yes", "--predicate", predicatePath, "--type", predicateType, ref)
}

// VerifyImage verifies a keyless signature against the pinned identity/issuer.
func (c *Cosign) VerifyImage(ref string) error {
	if err := c.validateIdentity(); err != nil {
		return err
	}
	return c.exec("verify",
		"--certificate-identity-regexp", c.Identity,
		"--certificate-oidc-issuer", c.Issuer,
		ref)
}

// VerifyAttestation verifies a keyless attestation of predicateType against the
// pinned identity/issuer.
func (c *Cosign) VerifyAttestation(ref, predicateType string) error {
	if err := c.validateIdentity(); err != nil {
		return err
	}
	return c.exec("verify-attestation",
		"--type", predicateType,
		"--certificate-identity-regexp", c.Identity,
		"--certificate-oidc-issuer", c.Issuer,
		ref)
}

func (c *Cosign) exec(args ...string) error {
	runner := c.run
	if runner == nil {
		runner = execRun
	}
	if err := runner(c.Binary, args, c.Stdout, c.Stderr); err != nil {
		return fmt.Errorf("cosign %s failed: %w", args[0], err)
	}
	return nil
}

// validateIdentity refuses verification against an empty or wildcard signer — the
// same guard the mirror-verify and certify-app paths enforce.
func (c *Cosign) validateIdentity() error {
	id := strings.TrimSpace(c.Identity)
	if id == "" || id == ".*" || id == ".+" || id == "https://github.com/.*" {
		return fmt.Errorf("refusing to verify against an empty or wildcard signer identity (%q): pin the signer (e.g. https://github.com/acme/.github/workflows/rebase.yml@refs/heads/main)", c.Identity)
	}
	if strings.TrimSpace(c.Issuer) == "" {
		return fmt.Errorf("missing certificate OIDC issuer for verification (e.g. https://token.actions.githubusercontent.com)")
	}
	return nil
}
