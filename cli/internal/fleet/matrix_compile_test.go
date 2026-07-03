package fleet

import "testing"

func compiledForTest(t *testing.T) CompiledMatrix {
	t.Helper()
	m, err := DefaultConfig("acme", "platform").CompileMatrix(false)
	if err != nil {
		t.Fatalf("CompileMatrix: %v", err)
	}
	return m
}

func TestCompileMatrixCells(t *testing.T) {
	m := compiledForTest(t)

	// 13 runtime lines × 3 tiers.
	if len(m.Cells) != 39 {
		t.Fatalf("expected 39 cells, got %d", len(m.Cells))
	}

	index := map[string]CompiledCell{}
	for _, c := range m.Cells {
		index[c.Line+"-"+c.Tier] = c
	}

	want := []struct {
		key     string
		lang    string
		version string
		status  string
		support string
		prod    bool
	}{
		{"python3.14-slim", "python", "3.14", "active", "lts", true},     // reclassified to LTS
		{"python3.14-dev", "python", "3.14", "active", "lts", false},     // dev never production
		{"python3.13-slim", "python", "3.13", "active", "current", true}, // unchanged current line
		{"go1.26-distroless", "go", "1.26", "active", "lts", false},      // LTS but omitInProduction
		{"go1.25-slim", "go", "1.25", "experimental", "unsupported", false},
		{"java25-distroless", "java", "25", "preview", "preview", false},
		{"coreLTS-distroless", "core", "LTS", "active", "lts", true},
	}
	for _, w := range want {
		got, ok := index[w.key]
		if !ok {
			t.Errorf("missing cell %q", w.key)
			continue
		}
		if got.Language != w.lang || got.Version != w.version ||
			got.Lifecycle.Status != w.status || got.Lifecycle.Support != w.support ||
			got.Lifecycle.ProductionAllowed != w.prod {
			t.Errorf("cell %q = {%s %s %s/%s prod=%v}, want {%s %s %s/%s prod=%v}",
				w.key, got.Language, got.Version, got.Lifecycle.Status, got.Lifecycle.Support, got.Lifecycle.ProductionAllowed,
				w.lang, w.version, w.status, w.support, w.prod)
		}
	}
}

// TestCompileMatrixReproducesFlakeGateTargets is the Phase 2 invariant: the
// generated gate-target lists must COVER (be a superset of) the hand-maintained
// lists currently in core/flake.nix. Generation may only ever add coverage, so
// flipping the flake to read these lists in a later phase cannot drop a gate.
func TestCompileMatrixReproducesFlakeGateTargets(t *testing.T) {
	m := compiledForTest(t)

	flakeRuntimePatch := []string{
		"coreLTS-slim", "coreLTS-distroless",
		"node22-slim", "node22-distroless",
		"node24-slim", "node24-distroless",
		"java21-slim", "java21-distroless",
		"java25-slim", "java25-distroless",
		"python3.13-slim", "python3.13-distroless",
		"python3.14-slim", "python3.14-distroless",
		"dotnet8-slim", "dotnet8-distroless",
		"dotnet10-slim", "dotnet10-distroless",
	}
	assertSuperset(t, "runtimePatchTargets", m.RuntimePatchTargets, flakeRuntimePatch)

	flakeClosurePurity := []string{
		"coreLTS-distroless",
		"node22-distroless",
		"java21-distroless",
		"python3.13-distroless",
	}
	assertSuperset(t, "closurePurityTargets", m.ClosurePurityTargets, flakeClosurePurity)
}

// TestCompileMatrixOmitsToolchainGateTargets proves omitInProduction lines
// (go/rust/cc) never appear in a realized-closure gate list: they ship no
// runtime in production, so there is nothing to gate.
func TestCompileMatrixOmitsToolchainGateTargets(t *testing.T) {
	m := compiledForTest(t)
	all := append(append([]string{}, m.RuntimePatchTargets...), m.ClosurePurityTargets...)
	for _, target := range all {
		for _, omit := range []string{"go1.25", "go1.26", "rust1.95", "cc15"} {
			if hasPrefixLine(target, omit) {
				t.Errorf("toolchain line %q must not be a gate target, found %q", omit, target)
			}
		}
	}
}

func TestRenderMatrixNixDeterministic(t *testing.T) {
	cfg := DefaultConfig("acme", "platform")
	m1, err := cfg.CompileMatrix(false)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := cfg.CompileMatrix(false)
	if err != nil {
		t.Fatal(err)
	}
	if a, b := RenderMatrixNix(m1), RenderMatrixNix(m2); a != b {
		t.Fatalf("RenderMatrixNix is not deterministic:\n--- a ---\n%s\n--- b ---\n%s", a, b)
	}
}

func TestCompileMatrixRejectsUnknownLine(t *testing.T) {
	cfg := DefaultConfig("acme", "platform")
	cfg.Matrix.Languages = append(cfg.Matrix.Languages, "kotlin99")
	if _, err := cfg.CompileMatrix(false); err == nil {
		t.Fatal("expected CompileMatrix to reject an unsupported runtime line")
	}
}

func assertSuperset(t *testing.T, name string, got, want []string) {
	t.Helper()
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			t.Errorf("%s: generated set is missing flake hand-list entry %q", name, w)
		}
	}
}

func hasPrefixLine(target, line string) bool {
	return target == line+"-slim" || target == line+"-distroless" || target == line+"-dev"
}
