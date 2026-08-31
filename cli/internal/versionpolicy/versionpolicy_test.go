package versionpolicy

import (
	"sort"
	"strings"
	"testing"
)

// TestLifecycleForClassification is the regression lock for runtime-line
// classification. It encodes the intended lifecycle for every built-in line and
// tier, including the python3.14 -> LTS and go1.26 -> LTS reclassifications.
func TestLifecycleForClassification(t *testing.T) {
	cases := []struct {
		line   string
		tier   string
		status string
		supp   string
		prod   bool
	}{
		// The LTS language lines: active/lts, production on non-dev.
		{"java21", "dev", "active", "lts", false},
		{"java21", "slim", "active", "lts", true},
		{"java21", "distroless", "active", "lts", true},
		{"node22", "slim", "active", "lts", true},

		// python3.13 stays the non-LTS current line.
		{"python3.13", "dev", "active", "current", false},
		{"python3.13", "slim", "active", "current", true},
		{"python3.13", "distroless", "active", "current", true},

		// python3.14 is now LTS: active/lts, production on non-dev tiers.
		{"python3.14", "dev", "active", "lts", false},
		{"python3.14", "slim", "active", "lts", true},
		{"python3.14", "distroless", "active", "lts", true},

		// Preview lines stay preview, never production.
		{"java25", "slim", "active", "lts", true},
		{"node24", "distroless", "preview", "preview", false},

		// go1.26 is now LTS, but go is omitInProduction (toolchain not shipped in
		// production tiers), so it is active/lts yet never productionAllowed.
		{"go1.26", "dev", "active", "lts", false},
		{"go1.26", "slim", "active", "lts", false},
		{"go1.26", "distroless", "active", "lts", false},

		// go1.25 stays an experimental toolchain line.
		{"go1.25", "slim", "experimental", "unsupported", false},

		// Unknown lines fall back to the conservative preview default.
		{"madeup99", "slim", "preview", "preview", false},
	}

	for _, c := range cases {
		got := LifecycleFor(c.line, c.tier)
		if got.Status != c.status || got.Support != c.supp || got.ProductionAllowed != c.prod {
			t.Errorf("LifecycleFor(%q, %q) = {%s, %s, %v}, want {%s, %s, %v}",
				c.line, c.tier, got.Status, got.Support, got.ProductionAllowed,
				c.status, c.supp, c.prod)
		}
	}
}

func TestResolve(t *testing.T) {
	cases := []struct {
		language       string
		channel        string
		includePreview bool
		want           string // comma-joined sorted versions
	}{
		{"java", "lts", false, "21,25"}, // both java LTS releases
		{"java", "lts", true, "21,25"},  // java has no preview line to union
		{"node", "lts", false, "22"},
		{"node", "lts", true, "22,24"},   // preview unions node24
		{"node", "preview", false, "24"}, // preview as base channel
		{"node", "current", false, "26"},
		{"python", "lts", false, "3.14"}, // 3.14 is the LTS line
		{"python", "current", false, "3.13"},
		{"python", "current", true, "3.13"}, // python has no preview bucket
		{"go", "lts", false, "1.26"},
		{"go", "experimental", false, "1.25"},
	}
	for _, c := range cases {
		got, err := Resolve(c.language, c.channel, c.includePreview)
		if err != nil {
			t.Errorf("Resolve(%q,%q,%v) error: %v", c.language, c.channel, c.includePreview, err)
			continue
		}
		sorted := append([]string{}, got...)
		sort.Strings(sorted)
		if joined := strings.Join(sorted, ","); joined != c.want {
			t.Errorf("Resolve(%q,%q,%v) = %q, want %q", c.language, c.channel, c.includePreview, joined, c.want)
		}
	}

	if _, err := Resolve("kotlin", "lts", false); err == nil {
		t.Error("Resolve(unknown language) should error")
	}
	if _, err := Resolve("java", "bogus", false); err == nil {
		t.Error("Resolve(invalid channel) should error")
	}
}

func TestChannelFor(t *testing.T) {
	cases := map[string]Channel{
		"java21":     ChannelLTS,
		"java25":     ChannelLTS,
		"node26":     ChannelCurrent,
		"python3.14": ChannelLTS,
		"python3.13": ChannelCurrent,
		"go1.26":     ChannelLTS,
		"go1.25":     ChannelExperimental,
	}
	for line, want := range cases {
		got, ok := ChannelFor(line)
		if !ok || got != want {
			t.Errorf("ChannelFor(%q) = %q, %v; want %q, true", line, got, ok, want)
		}
	}
	if _, ok := ChannelFor("madeup99"); ok {
		t.Errorf("ChannelFor(unknown) should report not found")
	}
}
