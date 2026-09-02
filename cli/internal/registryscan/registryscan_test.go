package registryscan

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

type fakeLister struct {
	repos     []string
	reposErr  error
	tags      map[string][]string
	tagErrors map[string]error
	tagCalls  []string
}

func (f *fakeLister) Repositories(_ context.Context, _ string) ([]string, error) {
	if f.reposErr != nil {
		return nil, f.reposErr
	}
	return f.repos, nil
}

func (f *fakeLister) Tags(_ context.Context, repository string) ([]string, error) {
	f.tagCalls = append(f.tagCalls, repository)
	if err, ok := f.tagErrors[repository]; ok {
		return nil, err
	}
	return f.tags[repository], nil
}

func TestScanEnumeratesNamespaceAndSkipsSidecarTags(t *testing.T) {
	lister := &fakeLister{
		repos: []string{"acme/base/java21", "acme/base/node22", "other/thing"},
		tags: map[string][]string{
			"reg.test/acme/base/java21": {
				"v1.0.0", "v1.1.0", "latest",
				"sha256-abc.sig", "sha256-abc.att", "sha256-abc.sbom",
			},
			"reg.test/acme/base/node22": {"v2.0.0"},
		},
	}

	got, err := Scan(context.Background(), lister, Options{
		Registry:    "reg.test",
		Namespace:   "acme/base",
		GeneratedAt: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// "other/thing" is outside the namespace and must never be listed.
	for _, call := range lister.tagCalls {
		if strings.Contains(call, "other/thing") {
			t.Fatalf("scanned repository outside namespace: %v", lister.tagCalls)
		}
	}
	wantRefs := []string{
		"reg.test/acme/base/java21:latest",
		"reg.test/acme/base/java21:v1.0.0",
		"reg.test/acme/base/java21:v1.1.0",
		"reg.test/acme/base/node22:v2.0.0",
	}
	if len(got.Refs) != len(wantRefs) {
		t.Fatalf("refs = %v, want %v", got.Refs, wantRefs)
	}
	for i, want := range wantRefs {
		if got.Refs[i] != want {
			t.Fatalf("refs[%d] = %q, want %q", i, got.Refs[i], want)
		}
	}
	if got.Summary.SidecarTagsSkipped != 3 {
		t.Fatalf("SidecarTagsSkipped = %d, want 3", got.Summary.SidecarTagsSkipped)
	}
	if got.Summary.RepositoriesScanned != 2 {
		t.Fatalf("RepositoriesScanned = %d, want 2", got.Summary.RepositoriesScanned)
	}
	if got.GeneratedAt != "2026-01-01T00:00:00Z" {
		t.Fatalf("GeneratedAt not pinned: %q", got.GeneratedAt)
	}
}

func TestScanIncludesSidecarTagsWhenAsked(t *testing.T) {
	lister := &fakeLister{
		repos: []string{"acme/app"},
		tags:  map[string][]string{"reg.test/acme/app": {"v1", "sha256-abc.sig"}},
	}
	got, err := Scan(context.Background(), lister, Options{
		Registry: "reg.test", Namespace: "acme", IncludeSidecarTags: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got.Refs) != 2 {
		t.Fatalf("refs = %v, want both tags kept", got.Refs)
	}
	if got.Summary.SidecarTagsSkipped != 0 {
		t.Fatalf("SidecarTagsSkipped = %d, want 0", got.Summary.SidecarTagsSkipped)
	}
}

func TestScanAppliesIncludeAndExcludeGlobs(t *testing.T) {
	lister := &fakeLister{
		repos: []string{"acme/app"},
		tags: map[string][]string{
			"reg.test/acme/app": {"v1.0.0", "v1.1.0", "v1.1.0-rc1", "nightly", "latest"},
		},
	}
	got, err := Scan(context.Background(), lister, Options{
		Registry:           "reg.test",
		Namespace:          "acme",
		TagPatterns:        []string{"v*"},
		ExcludeTagPatterns: []string{"*-rc*"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	want := []string{"reg.test/acme/app:v1.0.0", "reg.test/acme/app:v1.1.0"}
	if fmt.Sprint(got.Refs) != fmt.Sprint(want) {
		t.Fatalf("refs = %v, want %v", got.Refs, want)
	}
}

func TestScanCapsTagsPerRepositoryKeepingHighestSorting(t *testing.T) {
	lister := &fakeLister{
		repos: []string{"acme/app"},
		tags:  map[string][]string{"reg.test/acme/app": {"v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0"}},
	}
	got, err := Scan(context.Background(), lister, Options{
		Registry: "reg.test", Namespace: "acme", MaxTagsPerRepo: 2,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	want := []string{"reg.test/acme/app:v1.2.0", "reg.test/acme/app:v1.3.0"}
	if fmt.Sprint(got.Refs) != fmt.Sprint(want) {
		t.Fatalf("refs = %v, want %v", got.Refs, want)
	}
	if !got.Repositories[0].Truncated {
		t.Fatal("expected repository to be marked truncated")
	}
}

func TestScanRecordsRepositoryFailureWithoutAbortingScan(t *testing.T) {
	lister := &fakeLister{
		repos: []string{"acme/broken", "acme/ok"},
		tags:  map[string][]string{"reg.test/acme/ok": {"v1"}},
		tagErrors: map[string]error{
			"reg.test/acme/broken": fmt.Errorf("403 forbidden"),
		},
	}
	got, err := Scan(context.Background(), lister, Options{Registry: "reg.test", Namespace: "acme"})
	if err != nil {
		t.Fatalf("Scan should not abort on one unreadable repository: %v", err)
	}
	if got.Summary.RepositoriesFailed != 1 {
		t.Fatalf("RepositoriesFailed = %d, want 1", got.Summary.RepositoriesFailed)
	}
	if len(got.Refs) != 1 || got.Refs[0] != "reg.test/acme/ok:v1" {
		t.Fatalf("healthy repository must still be scanned, got %v", got.Refs)
	}
	var broken *Repository
	for i := range got.Repositories {
		if got.Repositories[i].Name == "acme/broken" {
			broken = &got.Repositories[i]
		}
	}
	if broken == nil || len(broken.Warnings) == 0 {
		t.Fatal("expected a warning recorded against the failed repository")
	}
}

func TestScanExplicitRepositoriesSkipCatalogAndQualifyAgainstNamespace(t *testing.T) {
	lister := &fakeLister{
		reposErr: fmt.Errorf("_catalog not supported"),
		tags: map[string][]string{
			"reg.test/acme/app":   {"v1"},
			"reg.test/acme/other": {"v2"},
		},
	}
	got, err := Scan(context.Background(), lister, Options{
		Registry:     "reg.test",
		Namespace:    "acme",
		Repositories: []string{"app", "acme/other", "app"},
	})
	if err != nil {
		t.Fatalf("explicit repositories must not consult the catalog endpoint: %v", err)
	}
	want := []string{"reg.test/acme/app:v1", "reg.test/acme/other:v2"}
	if fmt.Sprint(got.Refs) != fmt.Sprint(want) {
		t.Fatalf("refs = %v, want %v (bare name qualified, duplicate collapsed)", got.Refs, want)
	}
}

func TestScanCatalogFailureNamesTheWorkaroundFlag(t *testing.T) {
	lister := &fakeLister{reposErr: fmt.Errorf("GET /v2/_catalog: 404")}
	_, err := Scan(context.Background(), lister, Options{Registry: "ghcr.io", Namespace: "acme"})
	if err == nil {
		t.Fatal("expected catalog enumeration failure")
	}
	if !strings.Contains(err.Error(), "--repository") {
		t.Fatalf("error must point at the workaround flag, got: %v", err)
	}
}

func TestScanRequiresRegistryAndLister(t *testing.T) {
	if _, err := Scan(context.Background(), &fakeLister{}, Options{}); err == nil {
		t.Fatal("expected error for missing registry")
	}
	if _, err := Scan(context.Background(), nil, Options{Registry: "reg.test"}); err == nil {
		t.Fatal("expected error for nil lister")
	}
}

func TestScanWarnsWhenNothingMatches(t *testing.T) {
	lister := &fakeLister{repos: []string{"acme/app"}, tags: map[string][]string{"reg.test/acme/app": {"latest"}}}
	got, err := Scan(context.Background(), lister, Options{
		Registry: "reg.test", Namespace: "acme", TagPatterns: []string{"v*"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got.Warnings) == 0 {
		t.Fatal("expected a warning when no tags matched")
	}
}

func TestIsSidecarTag(t *testing.T) {
	for _, tag := range []string{"sha256-abc.sig", "sha256-abc.att", "sha256-abc.sbom"} {
		if !isSidecarTag(tag) {
			t.Fatalf("%q should be a sidecar tag", tag)
		}
	}
	for _, tag := range []string{"v1.0.0", "latest", "sha256-abc", "release.sig"} {
		if isSidecarTag(tag) {
			t.Fatalf("%q should not be a sidecar tag", tag)
		}
	}
}
