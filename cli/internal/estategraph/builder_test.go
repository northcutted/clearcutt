package estategraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectBuilderFromRealMetadataShapes(t *testing.T) {
	cases := []struct {
		name   string
		obs    Observation
		want   string
		stacks bool
	}{
		{
			// Nix dockerTools writes one history entry per layer naming the
			// store paths it carries. Nothing else produces this.
			name: "nix dockerTools",
			obs: Observation{
				Created: "1970-01-01T00:00:01Z",
				History: []HistoryObservation{{Comment: "store paths: ['/nix/store/xn70pn0-zlib-1.3.2']"}},
			},
			want: "nix", stacks: false,
		},
		{
			name: "apko names itself",
			obs: Observation{
				History: []HistoryObservation{{CreatedBy: "apko", Comment: "static by Chainguard"}},
			},
			want: "apko", stacks: false,
		},
		{
			name: "apko via chainguard labels",
			obs:  Observation{Labels: map[string]string{"dev.chainguard.package.main": ""}},
			want: "apko", stacks: false,
		},
		{
			name: "buildpacks",
			obs:  Observation{Labels: map[string]string{"io.buildpacks.stack.id": "io.buildpacks.stacks.jammy"}},
			want: "buildpacks", stacks: true,
		},
		{
			name: "buildkit",
			obs: Observation{
				History: []HistoryObservation{{CreatedBy: "RUN /bin/sh -c groupadd", Comment: "buildkit.dockerfile.v0"}},
			},
			want: "buildkit", stacks: true,
		},
		{
			name: "debian official base",
			obs: Observation{
				History: []HistoryObservation{{CreatedBy: "# debian.sh --arch 'amd64'", Comment: "debuerreotype 0.17"}},
			},
			want: "debuerreotype", stacks: true,
		},
		{
			name: "classic docker",
			obs:  Observation{History: []HistoryObservation{{CreatedBy: "/bin/sh -c #(nop)  ARG RELEASE"}}},
			want: "docker", stacks: true,
		},
		{
			// A reproducible epoch and nothing else still says the builder
			// refused to record a build time, which stacking builders do not.
			name: "reproducible epoch alone",
			obs:  Observation{Created: "1970-01-01T00:00:01Z"},
			want: "", stacks: false,
		},
		{
			// Unknown must default to STACKING. Assuming composed would exempt
			// an image from base detection on no evidence, which is the one
			// direction that silently loses coverage.
			name: "unknown defaults to stacking",
			obs:  Observation{Created: "2026-09-01T00:00:00Z"},
			want: "", stacks: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectBuilder(tc.obs)
			if got.Name != tc.want {
				t.Errorf("builder name = %q, want %q", got.Name, tc.want)
			}
			if got.Stacks != tc.stacks {
				t.Errorf("stacks = %v, want %v", got.Stacks, tc.stacks)
			}
		})
	}
}

// TestComposedEstateNoteOnlyFiresWhenItShould. The note reframes every other
// number in the report, so firing it on a stacking estate would tell an
// operator to stop looking for provenance that is genuinely missing.
func TestComposedEstateNoteOnlyFiresWhenItShould(t *testing.T) {
	composed := BuilderProfile{ByBuilder: map[string]int{"nix": 100}, Composed: 100}
	if note := ComposedEstateNote(composed, 0); note == "" {
		t.Error("a fully composed estate with nothing resolved should be explained")
	} else {
		for _, want := range []string{"correct answer rather than a gap", "nix", "layer view"} {
			if !strings.Contains(note, want) {
				t.Errorf("note should mention %q, got: %s", want, note)
			}
		}
	}

	// Resolved edges mean base detection worked; do not explain it away.
	if note := ComposedEstateNote(composed, 3); note != "" {
		t.Errorf("an estate with resolved edges needs no excuse, got: %s", note)
	}

	// A stacking estate with nothing resolved has a REAL gap and must not be
	// told otherwise.
	stacking := BuilderProfile{ByBuilder: map[string]int{"buildkit": 100}, Stacking: 100}
	if note := ComposedEstateNote(stacking, 0); note != "" {
		t.Errorf("a stacking estate with 0 resolved has a genuine gap, got: %s", note)
	}

	// A mixed estate still wants its stacking images resolved.
	mixed := BuilderProfile{ByBuilder: map[string]int{"nix": 50, "buildkit": 50}, Composed: 50, Stacking: 50}
	if note := ComposedEstateNote(mixed, 0); note != "" {
		t.Errorf("a half-stacking estate should not be excused, got: %s", note)
	}

	// Multiple composed builders are named together.
	both := BuilderProfile{ByBuilder: map[string]int{"nix": 50, "apko": 50}, Composed: 100}
	if note := ComposedEstateNote(both, 0); !strings.Contains(note, "apko and nix") {
		t.Errorf("both composed builders should be named, got: %s", note)
	}
}

// TestPublicEstateIsClassifiedAsStacking runs the classifier over real registry
// output rather than hand-made shapes.
func TestPublicEstateIsClassifiedAsStacking(t *testing.T) {
	path := filepath.Join("..", "..", "..", "examples", "public-estate", "observations.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("fixture not present: %v", err)
	}
	obs, err := ReadObservations(path)
	if err != nil {
		t.Fatal(err)
	}
	profile := ProfileBuilders(obs)
	if profile.Stacking <= profile.Composed {
		t.Fatalf("the public estate is predominantly stacking, got %+v", profile)
	}
	// The mix should be recognised, not lumped into "unidentified".
	for _, want := range []string{"buildkit", "debuerreotype", "apko", "buildpacks"} {
		if profile.ByBuilder[want] == 0 {
			t.Errorf("expected to identify at least one %s image, got %v", want, profile.ByBuilder)
		}
	}
	if note := ComposedEstateNote(profile, 3); note != "" {
		t.Errorf("the public estate resolves bases and must not be excused: %s", note)
	}
}
