package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStageEstateArtifactsCopiesOnlyWhatWasAsked covers the optional-by-design
// contract: the estate view is populated by explicit flags, and a site with no
// estate scan must stage nothing rather than fail.
func TestStageEstateArtifactsCopiesOnlyWhatWasAsked(t *testing.T) {
	old := catalogSiteOpts
	t.Cleanup(func() { catalogSiteOpts = old })

	src := t.TempDir()
	graph := filepath.Join(src, "graph.json")
	layers := filepath.Join(src, "layers.json")
	if err := os.WriteFile(graph, []byte(`{"kind":"BaseImageGraph"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layers, []byte(`{"kind":"LayerCommonalityGraph"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("neither flag stages nothing", func(t *testing.T) {
		catalogSiteOpts = catalogSiteFlags{}
		dst := filepath.Join(t.TempDir(), "estate")
		if err := stageEstateArtifacts(dst); err != nil {
			t.Fatalf("stageEstateArtifacts: %v", err)
		}
		if _, err := os.Stat(dst); !os.IsNotExist(err) {
			t.Fatalf("no flags should leave the estate directory uncreated, got err=%v", err)
		}
	})

	t.Run("one flag stages one artifact", func(t *testing.T) {
		catalogSiteOpts = catalogSiteFlags{graphFile: graph}
		dst := filepath.Join(t.TempDir(), "estate")
		if err := stageEstateArtifacts(dst); err != nil {
			t.Fatalf("stageEstateArtifacts: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dst, "graph.json")); err != nil {
			t.Fatalf("graph.json not staged: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dst, "layers.json")); !os.IsNotExist(err) {
			t.Fatalf("layers.json should not be staged when unset, got err=%v", err)
		}
	})

	t.Run("both flags stage both under fixed names", func(t *testing.T) {
		catalogSiteOpts = catalogSiteFlags{graphFile: graph, layersFile: layers}
		dst := filepath.Join(t.TempDir(), "estate")
		if err := stageEstateArtifacts(dst); err != nil {
			t.Fatalf("stageEstateArtifacts: %v", err)
		}
		// The site loader resolves these by exact name, so the destination
		// filenames must not follow the source paths.
		for name, want := range map[string]string{
			"graph.json":  `{"kind":"BaseImageGraph"}`,
			"layers.json": `{"kind":"LayerCommonalityGraph"}`,
		} {
			got, err := os.ReadFile(filepath.Join(dst, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			if string(got) != want {
				t.Fatalf("%s = %s, want %s", name, got, want)
			}
		}
	})

	t.Run("a missing artifact is an error, not a silent skip", func(t *testing.T) {
		catalogSiteOpts = catalogSiteFlags{graphFile: filepath.Join(src, "absent.json")}
		err := stageEstateArtifacts(filepath.Join(t.TempDir(), "estate"))
		if err == nil {
			t.Fatal("an explicitly passed --graph path that does not exist must fail")
		}
	})
}

// TestCatalogSiteBuildExposesEstateFlags keeps the flags reachable from the two
// commands that materialize a site.
func TestCatalogSiteBuildExposesEstateFlags(t *testing.T) {
	for _, path := range [][]string{{"catalog", "site", "build"}, {"catalog", "site", "preview"}} {
		stdout, err := runCLI(t, append(path, "--help")...)
		if err != nil {
			t.Fatalf("%v --help: %v", path, err)
		}
		for _, flag := range []string{"--graph", "--layers"} {
			if !containsFlag(stdout, flag) {
				t.Fatalf("%v --help is missing %s:\n%s", path, flag, stdout)
			}
		}
	}
}

func containsFlag(help, flag string) bool {
	return strings.Contains(help, flag)
}
