package sign

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestCosignBuildsDigestVerificationAndAttestationArgs(t *testing.T) {
	var calls [][]string
	c := New("cosign-test", "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main", "https://token.actions.githubusercontent.com", bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	c.run = func(bin string, args []string, stdout, stderr io.Writer) error {
		if bin != "cosign-test" {
			t.Fatalf("binary = %q", bin)
		}
		calls = append(calls, append([]string(nil), args...))
		return nil
	}

	if err := c.VerifyImage("ghcr.io/acme/app@sha256:1111"); err != nil {
		t.Fatalf("VerifyImage: %v", err)
	}
	if err := c.Sign("ghcr.io/acme/app@sha256:2222"); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := c.Attest("ghcr.io/acme/app@sha256:2222", "/tmp/predicate.json", "https://clearcutt.dev/attestations/rebase/v1"); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if err := c.VerifyAttestation("ghcr.io/acme/app@sha256:2222", "https://slsa.dev/provenance/v1"); err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}

	got := joinCalls(calls)
	for _, want := range []string{
		"verify --certificate-identity-regexp https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/acme/app@sha256:1111",
		"sign --yes ghcr.io/acme/app@sha256:2222",
		"attest --yes --predicate /tmp/predicate.json --type https://clearcutt.dev/attestations/rebase/v1 ghcr.io/acme/app@sha256:2222",
		"verify-attestation --type https://slsa.dev/provenance/v1 --certificate-identity-regexp https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/acme/app@sha256:2222",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing cosign call %q in:\n%s", want, got)
		}
	}
}

func TestCosignOutputAndErrorBranches(t *testing.T) {
	c := New("", "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main", "https://token.actions.githubusercontent.com", nil, bytes.NewBuffer(nil))
	if c.Binary != "cosign" {
		t.Fatalf("empty binary should default to cosign, got %q", c.Binary)
	}
	c.runOutput = func(bin string, args []string, stderr io.Writer) ([]byte, error) {
		if args[0] == "verify" {
			return []byte(`[{"ok":true}]`), nil
		}
		if args[0] == "download" {
			return []byte(`{"attestation":true}`), nil
		}
		return nil, errors.New("unexpected")
	}
	if raw, err := c.VerifyImageJSON("ghcr.io/acme/app@sha256:1111"); err != nil || !strings.Contains(string(raw), `"ok"`) {
		t.Fatalf("VerifyImageJSON raw=%s err=%v", raw, err)
	}
	if raw, err := c.DownloadAttestations("ghcr.io/acme/app@sha256:1111"); err != nil || !strings.Contains(string(raw), "attestation") {
		t.Fatalf("DownloadAttestations raw=%s err=%v", raw, err)
	}

	c.run = func(string, []string, io.Writer, io.Writer) error { return errors.New("boom") }
	if err := c.Sign("ghcr.io/acme/app@sha256:1111"); err == nil || !strings.Contains(err.Error(), "cosign sign failed") {
		t.Fatalf("expected wrapped sign error, got %v", err)
	}
	c.runOutput = func(string, []string, io.Writer) ([]byte, error) { return nil, errors.New("boom") }
	if _, err := c.DownloadAttestations("ghcr.io/acme/app@sha256:1111"); err == nil || !strings.Contains(err.Error(), "cosign download failed") {
		t.Fatalf("expected wrapped download error, got %v", err)
	}
}

func TestCosignVerifyRejectsWildcardIdentity(t *testing.T) {
	c := New("cosign", ".*", "https://token.actions.githubusercontent.com", nil, nil)
	c.run = func(string, []string, io.Writer, io.Writer) error {
		t.Fatal("run should not be called for wildcard identity")
		return errors.New("unreachable")
	}
	if err := c.VerifyImage("ghcr.io/acme/app@sha256:1111"); err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("expected wildcard identity rejection, got %v", err)
	}
}

func TestCosignVerifyRejectsMissingIssuer(t *testing.T) {
	c := New("cosign", "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main", "", nil, nil)
	if err := c.VerifyImage("ghcr.io/acme/app@sha256:1111"); err == nil || !strings.Contains(err.Error(), "missing certificate OIDC issuer") {
		t.Fatalf("expected missing issuer rejection, got %v", err)
	}
}

func joinCalls(calls [][]string) string {
	var lines []string
	for _, call := range calls {
		lines = append(lines, strings.Join(call, " "))
	}
	return strings.Join(lines, "\n")
}
