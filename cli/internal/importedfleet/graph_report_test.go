package importedfleet

import (
	"strings"
	"testing"
)

func TestGraphMarkdownEmptyGraphStillRendersAnHonestReport(t *testing.T) {
	graph, err := BuildGraph(Observations{}, GraphOptions{GeneratedAt: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}
	md := GraphMarkdown(graph)
	for _, want := range []string{
		"No base family had an observed consumer.",
		"No base relationships were detected.",
		"No root images were identified.",
		"Every observed image was either placed in the graph or identified as a root.",
		"## Scan warnings",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("empty report missing %q:\n%s", want, md)
		}
	}
}

func TestGraphMarkdownSeparatesProofFromClaims(t *testing.T) {
	proven := obs("reg.test/base/java21:v1", "2026-01-01T00:00:00Z", "os", "jdk")
	provenApp := obs("reg.test/apps/pay:v1", "2026-02-01T00:00:00Z", "os", "jdk", "app")
	claimedBase := obs("reg.test/base/go:v1", "2026-01-01T00:00:00Z", "gos")
	claimedApp := obs("reg.test/apps/svc:v1", "2026-02-01T00:00:00Z", "squashed")
	claimedApp.Labels["org.opencontainers.image.base.digest"] = claimedBase.ManifestDigest

	graph := graphOf(t, GraphOptions{}, proven, provenApp, claimedBase, claimedApp)
	md := GraphMarkdown(graph)

	if !strings.Contains(md, "Only `layer-prefix` is proof") {
		t.Fatalf("report must state which method is proof:\n%s", md)
	}
	if !strings.Contains(md, "| `layer-prefix` | 1 |") {
		t.Fatalf("expected one proven edge in the method table:\n%s", md)
	}
	if !strings.Contains(md, "| `oci-base-digest` | 1 |") {
		t.Fatalf("expected one declared edge in the method table:\n%s", md)
	}
	if !strings.Contains(md, "rests on metadata the image's author supplied") {
		t.Fatalf("report must caveat self-reported edges:\n%s", md)
	}
}

func TestGraphMarkdownListsStaleConsumersWorstFirst(t *testing.T) {
	v1 := obs("reg.test/base/java21:v1", "2026-01-01T00:00:00Z", "os-v1")
	v2 := obs("reg.test/base/java21:v2", "2026-02-01T00:00:00Z", "os-v2")
	v3 := obs("reg.test/base/java21:v3", "2026-03-01T00:00:00Z", "os-v3")
	worst := obs("reg.test/apps/worst:v1", "2026-01-02T00:00:00Z", "os-v1", "app")
	nearer := obs("reg.test/apps/nearer:v1", "2026-02-02T00:00:00Z", "os-v2", "app")

	graph := graphOf(t, GraphOptions{}, v1, v2, v3, worst, nearer)
	md := GraphMarkdown(graph)

	worstAt := strings.Index(md, "reg.test/apps/worst:v1")
	nearerAt := strings.Index(md, "reg.test/apps/nearer:v1")
	if worstAt < 0 || nearerAt < 0 {
		t.Fatalf("both stale consumers should appear:\n%s", md)
	}
	if worstAt > nearerAt {
		t.Fatalf("the most-behind consumer must be listed first:\n%s", md)
	}
	if !strings.Contains(md, "Consumers on a stale base") {
		t.Fatalf("missing the stale section:\n%s", md)
	}
}

func TestGraphMarkdownReportsOrphansAsFindings(t *testing.T) {
	base := obs("reg.test/base/java21:v1", "2026-01-01T00:00:00Z", "os")
	app := obs("reg.test/apps/pay:v1", "2026-02-01T00:00:00Z", "os", "app")
	orphan := obs("reg.test/apps/mystery:v1", "2026-02-01T00:00:00Z", "nothing-in-common")

	graph := graphOf(t, GraphOptions{}, base, app, orphan)
	md := GraphMarkdown(graph)

	if !strings.Contains(md, "These are audit findings, not omissions.") {
		t.Fatalf("orphans must be framed as findings:\n%s", md)
	}
	if !strings.Contains(md, "reg.test/apps/mystery:v1") {
		t.Fatalf("the orphan must be named:\n%s", md)
	}
	if !strings.Contains(md, "Why it is a root") {
		t.Fatalf("expected the roots table:\n%s", md)
	}
}

func TestGraphMarkdownSurfacesUndatedVersionWarning(t *testing.T) {
	dated := obs("reg.test/base/java21:v1", "2026-01-01T00:00:00Z", "os-v1")
	undated := obs("reg.test/base/java21:v2", "", "os-v2")
	app := obs("reg.test/apps/pay:v1", "2026-02-01T00:00:00Z", "os-v1", "app")

	md := GraphMarkdown(graphOf(t, GraphOptions{}, dated, undated, app))

	if !strings.Contains(md, "currency was decided by tag order") {
		t.Fatalf("family warning must reach the report:\n%s", md)
	}
}

func TestTagOfShortensReferencesForDisplay(t *testing.T) {
	cases := map[string]string{
		"reg.test/base/java21:v1.2.3":                        "v1.2.3",
		"reg.test/base/java21@sha256:abcdef0123456789abcdef": "sha256:abcdef012345",
		"reg.test/base/java21":                               "reg.test/base/java21",
		"":                                                   "unknown",
		"localhost:5000/app:v1":                              "v1",
	}
	for input, want := range cases {
		if got := tagOf(input); got != want {
			t.Fatalf("tagOf(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestTagOfKeepsShortDigestsWhole(t *testing.T) {
	if got := tagOf("reg.test/app@sha256:abc"); got != "sha256:abc" {
		t.Fatalf("tagOf short digest = %q", got)
	}
}

func TestGraphMarkdownRendersBlastRadiusAndItsCaveat(t *testing.T) {
	left := obs("reg.test/a/slim:v1", "2026-01-01T00:00:00Z", "common", "left")
	right := obs("reg.test/b/dev:v1", "2026-01-01T00:00:00Z", "common", "right", "more")

	md := GraphMarkdown(graphOf(t, GraphOptions{}, left, right))

	for _, want := range []string{
		"## Shared layer blast radius",
		"if a layer carries a vulnerable package, these are the images that ship it",
		"The widest-reaching layer is in 2 of 2 observed images.",
		"A shared layer means shared content, not a base relationship.",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("report missing %q:\n%s", want, md)
		}
	}
}

func TestGraphMarkdownStatesWhenNothingIsShared(t *testing.T) {
	only := obs("reg.test/a/one:v1", "2026-01-01T00:00:00Z", "solo")
	md := GraphMarkdown(graphOf(t, GraphOptions{}, only))
	if !strings.Contains(md, "No layer is carried by more than one observed image.") {
		t.Fatalf("expected the empty blast-radius line:\n%s", md)
	}
}

func TestSummariseImagesNamesAFewThenCounts(t *testing.T) {
	if got := summariseImages([]string{"a", "b"}); got != "`a`, `b`" {
		t.Fatalf("two carriers should both be named, got %q", got)
	}
	got := summariseImages([]string{"a", "b", "c", "d"})
	if !strings.Contains(got, "and 2 more") {
		t.Fatalf("long lists should be summarised, got %q", got)
	}
}

func TestShortDigestTrimsOnlyLongDigests(t *testing.T) {
	if got := shortDigest("sha256:abc"); got != "sha256:abc" {
		t.Fatalf("short digest should pass through, got %q", got)
	}
	long := "sha256:0123456789abcdef0123456789abcdef"
	if got := shortDigest(long); len(got) != 26 {
		t.Fatalf("long digest should trim to 26, got %q", got)
	}
}
