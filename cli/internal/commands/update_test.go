package commands

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUpdateInstallsOnlyAfterChecksumAndExactIdentityVerification(t *testing.T) {
	asset, err := updateAssetName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skip(err)
	}
	binary := []byte("verified-clearcutt-binary")
	sum := sha256.Sum256(binary)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/clearcutt/releases/latest":
			fmt.Fprintf(w, `{"tag_name":"v9.9.9","assets":[{"name":%q,"browser_download_url":%q},{"name":%q,"browser_download_url":%q},{"name":"SHA256SUMS.txt","browser_download_url":%q}]}`,
				asset, server.URL+"/assets/binary", asset+".sig", server.URL+"/assets/bundle", server.URL+"/assets/checksums")
		case "/assets/binary":
			_, _ = w.Write(binary)
		case "/assets/bundle":
			_, _ = w.Write([]byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`))
		case "/assets/checksums":
			fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), asset)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldAPI, oldClient, oldVerify, oldVersion := updateAPIBaseURL, updateHTTPClient, updateVerifyBlob, Version
	defer func() {
		updateAPIBaseURL, updateHTTPClient, updateVerifyBlob, Version = oldAPI, oldClient, oldVerify, oldVersion
	}()
	updateAPIBaseURL = server.URL
	updateHTTPClient = server.Client()
	Version = "v1.0.0"
	verified := false
	updateVerifyBlob = func(_ context.Context, cosign, binaryPath, bundlePath, identity, issuer string) error {
		verified = true
		if cosign != "test-cosign" || identity != "https://github.com/acme/clearcutt/.github/workflows/release.yml@refs/heads/main" || issuer != defaultUpdateIssuer {
			t.Fatalf("unexpected verifier contract: cosign=%q identity=%q issuer=%q", cosign, identity, issuer)
		}
		if got, _ := os.ReadFile(binaryPath); string(got) != string(binary) {
			t.Fatalf("verifier received wrong binary: %q", got)
		}
		if _, err := os.Stat(bundlePath); err != nil {
			t.Fatalf("verifier bundle missing: %v", err)
		}
		return nil
	}
	target := filepath.Join(t.TempDir(), "clearcutt")
	stdout, err := runCLI(t, "update", "--repo", "acme/clearcutt", "--output", target, "--cosign", "test-cosign")
	if err != nil {
		t.Fatalf("update failed: %v\n%s", err, stdout)
	}
	if !verified {
		t.Fatal("Sigstore verification was not called")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(binary) {
		t.Fatalf("installed binary = %q err=%v", got, err)
	}
	if !strings.Contains(stdout, "checksum and Sigstore identity verified") {
		t.Fatalf("missing verification result: %s", stdout)
	}
}

func TestUpdateChecksumMismatchPreservesExistingBinary(t *testing.T) {
	asset, err := updateAssetName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skip(err)
	}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/clearcutt/releases/tags/v2.0.0":
			fmt.Fprintf(w, `{"tag_name":"v2.0.0","assets":[{"name":%q,"browser_download_url":%q},{"name":%q,"browser_download_url":%q},{"name":"SHA256SUMS.txt","browser_download_url":%q}]}`,
				asset, server.URL+"/binary", asset+".sig", server.URL+"/bundle", server.URL+"/checksums")
		case "/binary":
			_, _ = w.Write([]byte("new-binary"))
		case "/bundle":
			_, _ = w.Write([]byte("bundle"))
		case "/checksums":
			fmt.Fprintf(w, "%s  %s\n", strings.Repeat("0", 64), asset)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldAPI, oldClient, oldVerify, oldVersion := updateAPIBaseURL, updateHTTPClient, updateVerifyBlob, Version
	defer func() {
		updateAPIBaseURL, updateHTTPClient, updateVerifyBlob, Version = oldAPI, oldClient, oldVerify, oldVersion
	}()
	updateAPIBaseURL = server.URL
	updateHTTPClient = server.Client()
	Version = "v1.0.0"
	updateVerifyBlob = func(context.Context, string, string, string, string, string) error {
		t.Fatal("signature verification must not run after a checksum mismatch")
		return nil
	}
	target := filepath.Join(t.TempDir(), "clearcutt")
	if err := os.WriteFile(target, []byte("existing-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	stdout, err := runCLI(t, "update", "--repo", "acme/clearcutt", "--version", "2.0.0", "--output", target)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got err=%v stdout=%s", err, stdout)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "existing-binary" {
		t.Fatalf("existing binary was changed: %q", got)
	}
}

func TestUpdateCheckDoesNotDownloadAssets(t *testing.T) {
	asset, err := updateAssetName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skip(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/clearcutt/releases/latest" {
			t.Fatalf("check mode unexpectedly downloaded %s", r.URL.Path)
		}
		fmt.Fprintf(w, `{"tag_name":"v3.0.0","assets":[{"name":%q,"browser_download_url":"https://example.invalid/binary"}]}`, asset)
	}))
	defer server.Close()
	oldAPI, oldClient, oldVersion := updateAPIBaseURL, updateHTTPClient, Version
	defer func() { updateAPIBaseURL, updateHTTPClient, Version = oldAPI, oldClient, oldVersion }()
	updateAPIBaseURL = server.URL
	updateHTTPClient = server.Client()
	Version = "v2.0.0"
	stdout, err := runCLI(t, "update", "--repo", "acme/clearcutt", "--check")
	if err != nil || !strings.Contains(stdout, "v3.0.0 is available") {
		t.Fatalf("check failed: err=%v stdout=%s", err, stdout)
	}
}

func TestUpdateHelperAndFailureBranches(t *testing.T) {
	if _, _, err := splitUpdateRepo("not-a-repo"); err == nil {
		t.Fatal("invalid repository should fail")
	}
	if owner, repo, err := splitUpdateRepo("acme/clearcutt"); err != nil || owner != "acme" || repo != "clearcutt" {
		t.Fatalf("valid repository parse = %q/%q err=%v", owner, repo, err)
	}
	for _, tc := range []struct {
		os, arch, want string
	}{
		{"linux", "x86_64", "clearcutt-linux-amd64"},
		{"darwin", "aarch64", "clearcutt-darwin-arm64"},
		{"windows", "amd64", "clearcutt-windows-amd64.exe"},
	} {
		if got, err := updateAssetName(tc.os, tc.arch); err != nil || got != tc.want {
			t.Fatalf("updateAssetName(%s,%s) = %q err=%v", tc.os, tc.arch, got, err)
		}
	}
	if _, err := updateAssetName("freebsd", "amd64"); err == nil {
		t.Fatal("unsupported OS should fail")
	}
	if _, err := updateAssetName("linux", "riscv64"); err == nil {
		t.Fatal("unsupported architecture should fail")
	}
	if normalizeUpdateVersion("1.2.3") != "v1.2.3" || normalizeUpdateVersion("v1.2.3") != "v1.2.3" || normalizeUpdateVersion("latest") != "latest" {
		t.Fatal("version normalization drifted")
	}

	release := githubUpdateRelease{TagName: "v1"}
	release.Assets = append(release.Assets, struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	}{Name: "asset", BrowserDownloadURL: "https://example.invalid/asset"})
	if got, err := updateReleaseAssetURL(release, "asset"); err != nil || got == "" {
		t.Fatalf("asset lookup failed: %q %v", got, err)
	}
	if _, err := updateReleaseAssetURL(release, "missing"); err == nil {
		t.Fatal("missing release asset should fail")
	}

	dir := t.TempDir()
	binary := filepath.Join(dir, "asset")
	manifest := filepath.Join(dir, "SHA256SUMS.txt")
	if err := os.WriteFile(binary, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("not-a-checksum  asset\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyUpdateChecksum(binary, manifest, "asset"); err == nil || !strings.Contains(err.Error(), "valid checksum") {
		t.Fatalf("expected invalid checksum length, got %v", err)
	}
	if err := os.WriteFile(manifest, []byte(strings.Repeat("z", 64)+"  asset\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyUpdateChecksum(binary, manifest, "asset"); err == nil || !strings.Contains(err.Error(), "invalid checksum") {
		t.Fatalf("expected invalid checksum encoding, got %v", err)
	}

	target := filepath.Join(dir, "installed")
	if err := os.WriteFile(target, []byte("old"), 0o700); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, "staged")
	if err := os.WriteFile(staged, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if mode := updateTargetMode(target); mode != 0o711 {
		t.Fatalf("target mode = %o", mode)
	}
	if err := replaceUpdateTarget(staged, target); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(target); string(got) != "new" {
		t.Fatalf("target replacement failed: %q", got)
	}
}

func TestFetchUpdateReleaseReportsHTTPAndPayloadErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/clearcutt/releases/latest":
			http.Error(w, "rate limited", http.StatusForbidden)
		case "/repos/acme/clearcutt/releases/tags/vbad-json":
			_, _ = w.Write([]byte("{"))
		case "/repos/acme/clearcutt/releases/tags/vmissing-tag":
			_, _ = w.Write([]byte(`{"assets":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	oldAPI, oldClient := updateAPIBaseURL, updateHTTPClient
	defer func() { updateAPIBaseURL, updateHTTPClient = oldAPI, oldClient }()
	updateAPIBaseURL = server.URL
	updateHTTPClient = server.Client()
	if _, err := fetchUpdateRelease(context.Background(), "acme/clearcutt", "latest"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected HTTP error, got %v", err)
	}
	if _, err := fetchUpdateRelease(context.Background(), "acme/clearcutt", "bad-json"); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("expected JSON error, got %v", err)
	}
	if _, err := fetchUpdateRelease(context.Background(), "acme/clearcutt", "missing-tag"); err == nil || !strings.Contains(err.Error(), "tag_name") {
		t.Fatalf("expected missing tag error, got %v", err)
	}
}

func TestUpdateCurrentVersionIsANoOp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v4.0.0","assets":[]}`))
	}))
	defer server.Close()
	oldAPI, oldClient, oldVersion := updateAPIBaseURL, updateHTTPClient, Version
	defer func() { updateAPIBaseURL, updateHTTPClient, Version = oldAPI, oldClient, oldVersion }()
	updateAPIBaseURL = server.URL
	updateHTTPClient = server.Client()
	Version = "v4.0.0"
	stdout, err := runCLI(t, "update", "--repo", "acme/clearcutt")
	if err != nil || !strings.Contains(stdout, "already installed") {
		t.Fatalf("current-version no-op failed: err=%v stdout=%s", err, stdout)
	}
}

func TestUpdateStructuredOutputAndTargetErrorBranches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v5.0.0","assets":[]}`))
	}))
	defer server.Close()
	oldAPI, oldClient, oldVersion, oldExecutable := updateAPIBaseURL, updateHTTPClient, Version, updateExecutable
	defer func() {
		updateAPIBaseURL, updateHTTPClient, Version, updateExecutable = oldAPI, oldClient, oldVersion, oldExecutable
	}()
	updateAPIBaseURL = server.URL
	updateHTTPClient = server.Client()
	Version = "v4.0.0"
	stdout, err := runCLI(t, "--format", "json", "update", "--repo", "acme/clearcutt", "--check")
	if err != nil || !strings.Contains(stdout, `"targetVersion": "v5.0.0"`) {
		t.Fatalf("JSON update output failed: err=%v stdout=%s", err, stdout)
	}
	stdout, err = runCLI(t, "--format", "yaml", "update", "--repo", "acme/clearcutt", "--check")
	if err != nil || !strings.Contains(stdout, "targetVersion: v5.0.0") {
		t.Fatalf("YAML update output failed: err=%v stdout=%s", err, stdout)
	}
	explicit := filepath.Join(t.TempDir(), "bin", "clearcutt")
	if got, err := updateTargetPath(explicit); err != nil || got != explicit {
		t.Fatalf("explicit target path = %q err=%v", got, err)
	}
	updateExecutable = func() (string, error) { return "", fmt.Errorf("unavailable") }
	if _, err := updateTargetPath(""); err == nil || !strings.Contains(err.Error(), "resolve running executable") {
		t.Fatalf("expected executable resolution error, got %v", err)
	}
	if _, err := fetchUpdateBytes(context.Background(), "://bad-url"); err == nil {
		t.Fatal("invalid download URL should fail")
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceUpdateTarget(filepath.Join(dir, "missing-staged"), target); err == nil {
		t.Fatal("missing staged binary should fail replacement")
	}
	if got, _ := os.ReadFile(target); string(got) != "old" {
		t.Fatalf("failed replacement did not roll back target: %q", got)
	}
}
