package fixprobe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var probeNow = time.Date(2026, 7, 2, 21, 4, 0, 0, time.UTC)

// fakeFetcher serves testdata fixtures keyed by ref; each test probes one
// source path, so the path only participates in the not-mapped error.
type fakeFetcher struct {
	files map[string]string
	errs  map[string]error
	calls []string
}

func (f *fakeFetcher) FileAt(_ context.Context, path, ref string) ([]byte, error) {
	f.calls = append(f.calls, ref)
	if err, ok := f.errs[ref]; ok {
		return nil, err
	}
	name, ok := f.files[ref]
	if !ok {
		return nil, fmt.Errorf("no fixture mapped for ref %s (path %s)", ref, path)
	}
	return os.ReadFile(filepath.Join("testdata", name))
}

func TestProbeOpensslMultiVersionMatchesInstalledLine(t *testing.T) {
	pinRev := "abc123def456abc123def456abc123def456abcd"
	fetcher := &fakeFetcher{files: map[string]string{
		pinRev:           "openssl-pin.nix",
		"nixos-unstable": "openssl-fix.nix",
		"master":         "openssl-fix.nix",
		"staging-next":   "openssl-fix.nix",
	}}
	got, err := Probe(context.Background(), fetcher, Input{
		Package:          "openssl",
		SourcePath:       "pkgs/development/libraries/openssl/default.nix",
		PinRev:           pinRev,
		PinName:          "nixpkgs",
		InstalledVersion: "3.6.2",
		FixedVersion:     "3.6.3",
		Refs: []Ref{
			{Name: "nixos-unstable", Kind: RefKindChannel},
			{Name: "master", Kind: RefKindBranch},
			{Name: "staging-next", Kind: RefKindBranch},
		},
		Now: probeNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != SchemaVersion {
		t.Fatalf("schemaVersion = %q, want %q", got.SchemaVersion, SchemaVersion)
	}
	if got.ProbedAt != "2026-07-02T21:04:00Z" {
		t.Fatalf("probedAt = %q", got.ProbedAt)
	}
	if got.Degraded {
		t.Fatal("probe with no fetch failures reported degraded")
	}
	if got.PinHasFix {
		t.Fatal("pin at 3.6.2 must not report the 3.6.3 fix")
	}
	wantRefs := []RefStatus{
		{Ref: pinRev, Kind: RefKindPin, Version: "3.6.2", HasFix: false, HydraCached: false},
		{Ref: "nixos-unstable", Kind: RefKindChannel, Version: "3.6.3", HasFix: true, HydraCached: true},
		{Ref: "master", Kind: RefKindBranch, Version: "3.6.3", HasFix: true, HydraCached: false},
		{Ref: "staging-next", Kind: RefKindBranch, Version: "3.6.3", HasFix: true, HydraCached: false},
	}
	if !reflect.DeepEqual(got.Refs, wantRefs) {
		t.Fatalf("refs drifted.\n got: %+v\nwant: %+v", got.Refs, wantRefs)
	}
	if got.OverrideRisk == nil {
		t.Fatal("fix carried elsewhere: override risk must be assessed")
	}
	if got.OverrideRisk.Level != RiskLow || got.OverrideRisk.ChangedLines != 0 {
		t.Fatalf("pure version bump graded %+v, want low/0", got.OverrideRisk)
	}
	if !strings.Contains(got.OverrideRisk.Reason, "nixos-unstable") {
		t.Fatalf("override risk reason must name the diffed ref: %q", got.OverrideRisk.Reason)
	}
}

// TestProbeEmptyRefsProbesPinOnly pins the contract that the default sweep is
// the caller's policy (fleet.DefaultProbeRefs), not the probe's: no Refs means
// the pin slot alone.
func TestProbeEmptyRefsProbesPinOnly(t *testing.T) {
	pinRev := "abc123def456abc123def456abc123def456abcd"
	fetcher := &fakeFetcher{files: map[string]string{pinRev: "openssl-pin.nix"}}
	got, err := Probe(context.Background(), fetcher, Input{
		Package:      "openssl",
		SourcePath:   "pkgs/development/libraries/openssl/default.nix",
		PinRev:       pinRev,
		FixedVersion: "3.6.3",
		Now:          probeNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Refs) != 1 || got.Refs[0].Kind != RefKindPin {
		t.Fatalf("empty Refs must probe the pin only, got %+v", got.Refs)
	}
	if got.Degraded {
		t.Fatalf("pin-only probe with a healthy fetch reported degraded: %+v", got)
	}
}

func TestProbeNodePatchChurnFlagsOverrideRisk(t *testing.T) {
	pinRev := "1111111111111111111111111111111111111111"
	fetcher := &fakeFetcher{files: map[string]string{
		pinRev:           "nodejs-v24-pin.nix",
		"nixos-unstable": "nodejs-v24-mid.nix",
		"staging-next":   "nodejs-v24-fix.nix",
		"nixos-25.11":    "nodejs-v24-fix.nix",
	}}
	got, err := Probe(context.Background(), fetcher, Input{
		Package:          "nodejs",
		SourcePath:       "pkgs/development/web/nodejs/v24.nix",
		PinRev:           pinRev,
		PinName:          "nixpkgs-node",
		InstalledVersion: "24.15.0",
		FixedVersion:     "24.17.0",
		Refs: []Ref{
			{Name: "nixos-unstable", Kind: RefKindChannel},
			{Name: "staging-next", Kind: RefKindBranch},
			{Name: "nixos-25.11", Kind: RefKindChannel},
		},
		Now: probeNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.PinHasFix {
		t.Fatal("pin at 24.15.0 must not report the 24.17.0 fix")
	}
	wantRefs := []RefStatus{
		{Ref: pinRev, Kind: RefKindPin, Version: "24.15.0", HasFix: false, HydraCached: false},
		{Ref: "nixos-unstable", Kind: RefKindChannel, Version: "24.16.0", HasFix: false, HydraCached: true},
		{Ref: "staging-next", Kind: RefKindBranch, Version: "24.18.0", HasFix: true, HydraCached: false},
		{Ref: "nixos-25.11", Kind: RefKindChannel, Version: "24.18.0", HasFix: true, HydraCached: true},
	}
	if !reflect.DeepEqual(got.Refs, wantRefs) {
		t.Fatalf("refs drifted.\n got: %+v\nwant: %+v", got.Refs, wantRefs)
	}
	if got.OverrideRisk == nil {
		t.Fatal("fix carried elsewhere: override risk must be assessed")
	}
	if got.OverrideRisk.Level != RiskHigh {
		t.Fatalf("patch-set churn graded %q, want high", got.OverrideRisk.Level)
	}
	// One local patch swapped for another between the pin and the fix.
	if got.OverrideRisk.ChangedLines != 2 {
		t.Fatalf("changedLines = %d, want 2", got.OverrideRisk.ChangedLines)
	}
	// The cached nixos-25.11 must win the "nearest fix" tiebreak over the
	// earlier uncached staging-next.
	if !strings.Contains(got.OverrideRisk.Reason, "nixos-25.11") {
		t.Fatalf("override risk diffed the wrong ref: %q", got.OverrideRisk.Reason)
	}
}

func TestProbeDegradedFetchNeverFails(t *testing.T) {
	pinRev := "2222222222222222222222222222222222222222"
	fetcher := &fakeFetcher{
		files: map[string]string{
			pinRev:           "openssl-pin.nix",
			"nixos-unstable": "openssl-fix.nix",
			"staging-next":   "openssl-fix.nix",
		},
		errs: map[string]error{"master": errors.New("403 rate limited")},
	}
	got, err := Probe(context.Background(), fetcher, Input{
		Package:          "openssl",
		SourcePath:       "pkgs/development/libraries/openssl/default.nix",
		PinRev:           pinRev,
		InstalledVersion: "3.6.2",
		FixedVersion:     "3.6.3",
		Refs: []Ref{
			{Name: "nixos-unstable", Kind: RefKindChannel},
			{Name: "master", Kind: RefKindBranch},
			{Name: "staging-next", Kind: RefKindBranch},
		},
		Now: probeNow,
	})
	if err != nil {
		t.Fatalf("per-ref fetch failures must not fail the probe: %v", err)
	}
	if !got.Degraded {
		t.Fatal("errored ref must mark the probe degraded")
	}
	master := got.Refs[2]
	if master.Ref != "master" || !strings.Contains(master.Error, "rate limited") {
		t.Fatalf("master status = %+v, want recorded fetch error", master)
	}
	if master.HasFix || master.Version != "" {
		t.Fatalf("errored ref must stay indeterminate: %+v", master)
	}
	if !got.Refs[1].HasFix {
		t.Fatal("healthy refs must still be probed around the failure")
	}
}

func TestProbePinFetchFailureMakesOverrideRiskUnknown(t *testing.T) {
	pinRev := "3333333333333333333333333333333333333333"
	fetcher := &fakeFetcher{
		files: map[string]string{
			"nixos-unstable": "openssl-fix.nix",
			"master":         "openssl-fix.nix",
			"staging-next":   "openssl-fix.nix",
		},
		errs: map[string]error{pinRev: errors.New("connect timeout")},
	}
	got, err := Probe(context.Background(), fetcher, Input{
		Package:          "openssl",
		SourcePath:       "pkgs/development/libraries/openssl/default.nix",
		PinRev:           pinRev,
		InstalledVersion: "3.6.2",
		FixedVersion:     "3.6.3",
		Refs: []Ref{
			{Name: "nixos-unstable", Kind: RefKindChannel},
			{Name: "master", Kind: RefKindBranch},
			{Name: "staging-next", Kind: RefKindBranch},
		},
		Now: probeNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.PinHasFix {
		t.Fatal("unfetchable pin must not claim the fix")
	}
	if !got.Degraded || got.Refs[0].Error == "" {
		t.Fatalf("pin fetch failure not recorded: %+v", got.Refs[0])
	}
	if got.OverrideRisk == nil || got.OverrideRisk.Level != RiskUnknown {
		t.Fatalf("override risk = %+v, want unknown when the pin file is unfetchable", got.OverrideRisk)
	}
}

func TestProbeNoFixAnywhereOmitsOverrideRisk(t *testing.T) {
	pinRev := "4444444444444444444444444444444444444444"
	fetcher := &fakeFetcher{files: map[string]string{
		pinRev:           "openssl-pin.nix",
		"nixos-unstable": "openssl-pin.nix",
		"master":         "openssl-pin.nix",
		"staging-next":   "openssl-pin.nix",
	}}
	got, err := Probe(context.Background(), fetcher, Input{
		Package:          "openssl",
		SourcePath:       "pkgs/development/libraries/openssl/default.nix",
		PinRev:           pinRev,
		InstalledVersion: "3.6.2",
		FixedVersion:     "3.6.3",
		Now:              probeNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.PinHasFix {
		t.Fatal("no ref carries 3.6.3")
	}
	if got.OverrideRisk != nil {
		t.Fatalf("nothing to override against, got %+v", got.OverrideRisk)
	}
}

func TestProbePinCarriesFixSkipsOverrideRisk(t *testing.T) {
	pinRev := "5555555555555555555555555555555555555555"
	fetcher := &fakeFetcher{files: map[string]string{
		pinRev:           "openssl-fix.nix",
		"nixos-unstable": "openssl-fix.nix",
		"master":         "openssl-fix.nix",
		"staging-next":   "openssl-fix.nix",
	}}
	got, err := Probe(context.Background(), fetcher, Input{
		Package:          "openssl",
		SourcePath:       "pkgs/development/libraries/openssl/default.nix",
		PinRev:           pinRev,
		InstalledVersion: "3.6.2",
		FixedVersion:     "3.6.3",
		Now:              probeNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.PinHasFix {
		t.Fatal("pin at 3.6.3 carries the fix")
	}
	if got.OverrideRisk != nil {
		t.Fatalf("override is moot when the pin carries the fix, got %+v", got.OverrideRisk)
	}
}

// TestProbeSweepOrderPinFirst pins that the pin slot always leads the sweep
// and caller refs follow in the order given.
func TestProbeSweepOrderPinFirst(t *testing.T) {
	pinRev := "6666666666666666666666666666666666666666"
	fetcher := &fakeFetcher{files: map[string]string{
		pinRev:           "openssl-pin.nix",
		"nixos-unstable": "openssl-pin.nix",
		"master":         "openssl-pin.nix",
		"staging-next":   "openssl-pin.nix",
	}}
	if _, err := Probe(context.Background(), fetcher, Input{
		Package:          "openssl",
		SourcePath:       "pkgs/development/libraries/openssl/default.nix",
		PinRev:           pinRev,
		InstalledVersion: "3.6.2",
		FixedVersion:     "3.6.3",
		Refs: []Ref{
			{Name: "nixos-unstable", Kind: RefKindChannel},
			{Name: "master", Kind: RefKindBranch},
			{Name: "staging-next", Kind: RefKindBranch},
		},
		Now: probeNow,
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{pinRev, "nixos-unstable", "master", "staging-next"}
	if !reflect.DeepEqual(fetcher.calls, want) {
		t.Fatalf("sweep order = %v, want %v", fetcher.calls, want)
	}
}

func TestProbeInputValidation(t *testing.T) {
	valid := Input{
		SourcePath:   "pkgs/development/libraries/openssl/default.nix",
		PinRev:       "abc",
		FixedVersion: "3.6.3",
	}
	cases := []struct {
		name    string
		fetcher Fetcher
		mutate  func(*Input)
		wantErr string
	}{
		{name: "nil fetcher", fetcher: nil, mutate: func(*Input) {}, wantErr: "Fetcher"},
		{name: "missing source path", fetcher: &fakeFetcher{}, mutate: func(in *Input) { in.SourcePath = " " }, wantErr: "SourcePath"},
		{name: "missing pin rev", fetcher: &fakeFetcher{}, mutate: func(in *Input) { in.PinRev = "" }, wantErr: "PinRev"},
		{name: "missing fixed version", fetcher: &fakeFetcher{}, mutate: func(in *Input) { in.FixedVersion = "" }, wantErr: "FixedVersion"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := valid
			tc.mutate(&in)
			if _, err := Probe(context.Background(), tc.fetcher, in); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want mention of %s", err, tc.wantErr)
			}
		})
	}
}

func TestExtractVersion(t *testing.T) {
	multi := `
  openssl_3_0 = common {
    version = "3.0.18";
  };
  openssl_3_5 = common {
    version = "3.5.4";
  };
  openssl_3_6 = common {
    version = "3.6.2";
  };
`
	cases := []struct {
		name      string
		content   string
		installed string
		want      string
	}{
		{name: "single version taken at face value", content: `  version = "24.15.0";`, installed: "24.15.0", want: "24.15.0"},
		{name: "single version even without installed anchor", content: `  version = "24.15.0";`, installed: "", want: "24.15.0"},
		{name: "interpolation is not a version", content: `  version = "${lib.getVersion src}";`, installed: "1.2.3", want: ""},
		{name: "multi-version anchored to installed major.minor", content: multi, installed: "3.5.1", want: "3.5.4"},
		{name: "multi-version anchored to newest line", content: multi, installed: "3.6.2", want: "3.6.2"},
		{name: "multi-version with no matching line", content: multi, installed: "1.1.1w", want: ""},
		{name: "multi-version without installed anchor", content: multi, installed: "", want: ""},
		{name: "ambiguous stanzas on the installed line", content: "version = \"3.6.1\";\nversion = \"3.6.2\";", installed: "3.6.2", want: ""},
		{name: "no version assignment", content: `pname = "openssl";`, installed: "3.6.2", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractVersion([]byte(tc.content), tc.installed); got != tc.want {
				t.Fatalf("extractVersion = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"24.16.0", "24.18.0", -1},
		{"24.18.0", "24.17.0", 1},
		{"3.6.2", "3.6.3", -1},
		{"3.6.3", "3.6.3", 0},
		{"1.1.1w", "1.1.1v", 1},
		{"1.1.1", "1.1.1a", -1},
		{"3.0.13+quic", "3.0.13", 1},
		{"v24.18.0", "24.17.0", 1},
		{"3.6", "3.6.0", 0},
		{"3.6", "3.6.1", -1},
		{"10.0.0", "9.9.9", 1},
		// A ref carrying only a pre-release must not satisfy HasFix for the
		// release: pre-release residues sort below the bare version.
		{"3.7.0-rc1", "3.7.0", -1},
		{"1.0.0-beta", "1.0.0", -1},
		{"18beta1", "18", -1},
		{"2.0.0~alpha2", "2.0.0", -1},
		{"3.7.0-rc1", "3.7.0-rc2", -1},
		{"3.7.0-rc1", "3.6.9", 1},
	}
	for _, tc := range cases {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			if got := CompareVersions(tc.a, tc.b); got != tc.want {
				t.Fatalf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
			if got := CompareVersions(tc.b, tc.a); got != -tc.want {
				t.Fatalf("CompareVersions(%q, %q) = %d, want %d", tc.b, tc.a, got, -tc.want)
			}
		})
	}
}

func TestGitHubFetcherFileAt(t *testing.T) {
	const wantPath = "/repos/NixOS/nixpkgs/contents/pkgs/development/libraries/openssl/default.nix"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wantPath {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		if got := r.URL.Query().Get("ref"); got != "nixos-unstable" {
			http.Error(w, "unexpected ref "+got, http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Accept"); got != "application/vnd.github.raw" {
			http.Error(w, "unexpected accept "+got, http.StatusNotAcceptable)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			http.Error(w, "unexpected auth "+got, http.StatusUnauthorized)
			return
		}
		io.WriteString(w, `version = "3.6.3";`)
	}))
	defer srv.Close()

	fetcher := &GitHubFetcher{BaseURL: srv.URL, Token: "test-token", Client: srv.Client()}
	body, err := fetcher.FileAt(context.Background(), "pkgs/development/libraries/openssl/default.nix", "nixos-unstable")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `version = "3.6.3";` {
		t.Fatalf("body = %q", body)
	}
}

func TestGitHubFetcherErrorIncludesStatusAndBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}))
	defer srv.Close()

	fetcher := &GitHubFetcher{BaseURL: srv.URL, Client: srv.Client()}
	_, err := fetcher.FileAt(context.Background(), "pkgs/nope.nix", "master")
	if err == nil {
		t.Fatal("want error on 404")
	}
	if !strings.Contains(err.Error(), "404") || !strings.Contains(err.Error(), "Not Found") {
		t.Fatalf("error must carry status and body: %v", err)
	}
	if !strings.Contains(err.Error(), "pkgs/nope.nix@master") {
		t.Fatalf("error must identify the file and ref: %v", err)
	}
}

func TestNewGitHubFetcherHonorsTokenEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "gha-token")
	t.Setenv("GH_TOKEN", "gh-cli-token")
	if got := NewGitHubFetcher().Token; got != "gha-token" {
		t.Fatalf("Token = %q, want GITHUB_TOKEN to win", got)
	}
	t.Setenv("GITHUB_TOKEN", "")
	if got := NewGitHubFetcher().Token; got != "gh-cli-token" {
		t.Fatalf("Token = %q, want GH_TOKEN fallback", got)
	}
	if client := NewGitHubFetcher().Client; client == nil || client.Timeout != githubFetchTimeout {
		t.Fatalf("Client = %+v, want %s timeout", client, githubFetchTimeout)
	}
}
