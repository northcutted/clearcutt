package config

import "testing"

// compilerLines is a test fixture, deliberately NOT the shipped default. The
// shipped fleet builds one runtime line, because ClearCutt governs estates
// rather than publishing images — but the matrix compiler still has to classify
// every line the recipe library offers, including ones no fleet currently
// builds. Pinning these tests to DefaultConfig would silently delete coverage
// of the LTS reclassification and omitInProduction paths the moment the shipped
// fleet narrowed. What we ship and what the compiler must handle are different
// questions, and this fixture keeps them separate.
var compilerLines = []string{"java25", "node24", "python3.14", "go1.27"}

func compiledForTest(t *testing.T) CompiledMatrix {
	t.Helper()
	cfg := DefaultConfig("acme", "platform")
	cfg.Matrix.Languages = append([]string(nil), compilerLines...)
	m, err := cfg.CompileMatrix(false)
	if err != nil {
		t.Fatalf("CompileMatrix: %v", err)
	}
	return m
}

func TestCompileMatrixCells(t *testing.T) {
	m := compiledForTest(t)

	if want := len(compilerLines) * 3; len(m.Cells) != want {
		t.Fatalf("expected %d cells (%d lines x 3 tiers), got %d", want, len(compilerLines), len(m.Cells))
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
		{"python3.14-slim", "python", "3.14", "active", "lts", true},    // reclassified to LTS
		{"python3.14-dev", "python", "3.14", "active", "lts", false},    // dev never production
		{"go1.27-distroless", "go", "1.27", "active", "current", false}, // omitInProduction
		{"node24-distroless", "node", "24", "active", "lts", true},
		{"java25-slim", "java", "25", "active", "lts", true},
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

// TestCompileMatrixOmitsToolchainGateTargets proves omitInProduction lines
// (go) never appear in a realized-closure gate list: they ship no runtime in
// production, so there is nothing to gate.
func TestCompileMatrixOmitsToolchainGateTargets(t *testing.T) {
	m := compiledForTest(t)
	all := append([]string{}, m.ClosurePurityTargets...)
	for _, target := range all {
		for _, omit := range []string{"go1.25", "go1.26"} {
			if hasPrefixLine(target, omit) {
				t.Errorf("toolchain line %q must not be a gate target, found %q", omit, target)
			}
		}
	}
}

func TestRenderMatrixNixDeterministic(t *testing.T) {
	cfg := DefaultConfig("acme", "platform")
	cfg.Matrix.Languages = append([]string(nil), compilerLines...)
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

func hasPrefixLine(target, line string) bool {
	return target == line+"-slim" || target == line+"-distroless" || target == line+"-dev"
}
