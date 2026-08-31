package fleet

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func loadConfigYAML(t *testing.T, body string) Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "clearcutt.fleet.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}

const baseHeader = `apiVersion: clearcutt.dev/v1
kind: FleetConfig
registry:
  host: ghcr.io
  owner: acme
  repository: platform
`

// Legacy flat-list configs keep working byte-for-byte: explicit lines, no
// selectors, and the same compiled matrix.
func TestMatrixLanguagesLegacyForm(t *testing.T) {
	cfg := loadConfigYAML(t, baseHeader+`matrix:
  systems: [x86_64-linux]
  languages: [java21, java25, python3.13]
  tiers: [dev, slim, distroless]
`)
	if len(cfg.Matrix.LanguageSelectors) != 0 {
		t.Fatalf("legacy form must not populate selectors, got %v", cfg.Matrix.LanguageSelectors)
	}
	if got := strings.Join(cfg.Matrix.Languages, ","); got != "java21,java25,python3.13" {
		t.Fatalf("legacy languages = %q", got)
	}
	m, err := cfg.CompileMatrix(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Cells) != 9 { // 3 lines x 3 tiers
		t.Fatalf("expected 9 cells, got %d", len(m.Cells))
	}
}

// Language-level entries resolve through the version policy: lts/current pick
// the matching channel; --allow-preview (CompileMatrix true) unions preview.
func TestMatrixLanguagesLanguageLevelForm(t *testing.T) {
	cfg := loadConfigYAML(t, baseHeader+`matrix:
  systems: [x86_64-linux]
  languages:
    - {language: java, channel: lts}
    - {language: python, channel: current}
  tiers: [dev, slim, distroless]
`)
	if len(cfg.Matrix.LanguageSelectors) != 2 {
		t.Fatalf("expected 2 selectors, got %d", len(cfg.Matrix.LanguageSelectors))
	}
	// Persistent (preview=false) resolution. Both java lines are LTS releases.
	if got := strings.Join(cfg.Matrix.Languages, ","); got != "java21,java25,python3.13" {
		t.Fatalf("resolved languages = %q, want java21,java25,python3.13", got)
	}

	// --allow-preview unions preview lines; neither java nor python has one.
	lines, err := cfg.Matrix.ResolveRuntimeLines(true)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	if got := strings.Join(lines, ","); got != "java21,java25,python3.13" {
		t.Fatalf("--allow-preview resolved = %q, want java21,java25,python3.13", got)
	}
}

// The persistent matrix.preview toggle unions preview at load time.
func TestMatrixLanguagesPersistentPreview(t *testing.T) {
	cfg := loadConfigYAML(t, baseHeader+`matrix:
  systems: [x86_64-linux]
  languages:
    - {language: node, channel: lts}
  tiers: [slim]
  preview: true
`)
	if !cfg.Matrix.Preview {
		t.Fatal("expected matrix.preview to be true")
	}
	lines := append([]string{}, cfg.Matrix.Languages...)
	sort.Strings(lines)
	if got := strings.Join(lines, ","); got != "node22,node24" {
		t.Fatalf("persistent preview resolved = %q, want node22,node24", got)
	}
}

func TestMatrixLanguagesChannelErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"channel-selects-nothing", "- {language: go, channel: preview}", "selects no versions"},
		{"unknown-language", "- {language: kotlin, channel: lts}", "unknown language"},
		{"invalid-channel", "- {language: java, channel: stable}", "invalid channel"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "f.yaml")
			body := baseHeader + "matrix:\n  systems: [x86_64-linux]\n  tiers: [slim]\n  languages:\n    " + c.body + "\n"
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), c.want)
			}
		})
	}
}

// Marshalling preserves the original form so config round-trips are lossless.
func TestMatrixLanguagesRoundTrip(t *testing.T) {
	cfg := loadConfigYAML(t, baseHeader+`matrix:
  systems: [x86_64-linux]
  languages:
    - {language: java, channel: lts}
  tiers: [slim]
  preview: true
`)
	raw, err := Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	if !strings.Contains(out, "language: java") || !strings.Contains(out, "channel: lts") {
		t.Fatalf("round-trip lost the language-level form:\n%s", out)
	}
	if !strings.Contains(out, "preview: true") {
		t.Fatalf("round-trip lost preview:\n%s", out)
	}

	// Reload the marshalled output: selectors must survive.
	dir := t.TempDir()
	path := filepath.Join(dir, "rt.yaml")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Matrix.LanguageSelectors) != 1 || reloaded.Matrix.LanguageSelectors[0].Channel != "lts" {
		t.Fatalf("selectors did not survive round-trip: %+v", reloaded.Matrix.LanguageSelectors)
	}

	// A legacy config marshals back as a flat string list (no selectors/preview).
	legacy := loadConfigYAML(t, baseHeader+`matrix:
  systems: [x86_64-linux]
  languages: [java21, java25]
  tiers: [slim]
`)
	lraw, err := Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(lraw), "language:") || strings.Contains(string(lraw), "preview:") {
		t.Fatalf("legacy config gained language-level/preview keys on marshal:\n%s", lraw)
	}
}

// The language-level form resolves channel selectors into concrete runtime lines.
func TestMatrixLanguagesNewFormReproducesLegacySet(t *testing.T) {
	cfg := loadConfigYAML(t, baseHeader+`matrix:
  systems: [x86_64-linux, aarch64-linux]
  languages:
    - {language: java, channel: lts}
    - {language: node, channel: lts}
    - {language: python, channel: lts}
    - {language: go, channel: lts}
  tiers: [dev, slim, distroless]
`)
	got := append([]string{}, cfg.Matrix.Languages...)
	sort.Strings(got)
	// channel:lts resolves every line the policy marks lts — both java LTS
	// releases, node22, python3.14 and go1.26. It is deliberately NOT compared
	// against DefaultConfig: the reference fleet selects the newest lines
	// (node26, go1.27), which are "current", not "lts".
	want := []string{"go1.26", "java21", "java25", "node22", "python3.14"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("new-form resolved set\n  got:  %v\n  want: %v", got, want)
	}
}
