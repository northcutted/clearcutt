package commands

import (
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
)

// TestAppTemplatesTargetLinesTheFleetBuilds guards a bug class that reached CI
// three times on this branch: a runtime-line literal hardcoded somewhere that
// keeps compiling and passing tests after the fleet matrix moves off that line,
// then fails at nix eval with "flake does not provide attribute".
//
// `verify boundary-suite` now derives its targets from the compiled matrix, so
// it cannot drift. App templates still need a concrete pin — a scaffolded app
// has to name one base image — so the pin is checked against the fleet instead.
// A template that scaffolds onto a line the fleet does not publish hands the
// user a Dockerfile whose FROM does not resolve.
func TestAppTemplatesTargetLinesTheFleetBuilds(t *testing.T) {
	cfg := fleet.DefaultConfig("acme", "platform")
	built := map[string]bool{}
	for _, line := range cfg.Matrix.Languages {
		built[line] = true
	}
	tiers := map[string]bool{}
	for _, tier := range cfg.Matrix.Tiers {
		tiers[tier] = true
	}

	for _, runtime := range cfg.Templates.Runtimes {
		spec, err := buildAppTemplateSpec(cfg, runtime, "sample-app")
		if err != nil {
			t.Fatalf("app template %q: %v", runtime, err)
		}
		if !built[spec.RuntimeLine] {
			t.Errorf("app template %q scaffolds onto runtime line %q, which the fleet does not build (fleet: %v)",
				runtime, spec.RuntimeLine, cfg.Matrix.Languages)
		}
		// Split on the LAST hyphen so python3.14-distroless yields the tier, not
		// a fragment of the version.
		cut := strings.LastIndex(spec.BaseID, "-")
		if cut < 0 {
			t.Errorf("app template %q base id %q is not <line>-<tier>", runtime, spec.BaseID)
			continue
		}
		tier := spec.BaseID[cut+1:]
		if !strings.HasPrefix(spec.BaseID, spec.RuntimeLine+"-") {
			t.Errorf("app template %q base id %q does not belong to its runtime line %q", runtime, spec.BaseID, spec.RuntimeLine)
		}
		if !tiers[tier] {
			t.Errorf("app template %q base id %q targets tier %q, which the fleet does not build (tiers: %v)",
				runtime, spec.BaseID, tier, cfg.Matrix.Tiers)
		}
	}
}
