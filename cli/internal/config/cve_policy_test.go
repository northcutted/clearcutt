package config

import "testing"

func epss(v float64) *float64 { return &v }

func TestMateriality(t *testing.T) {
	pol := DefaultRemediationPolicy() // runtime, epss>=0.90, kev=always, sev>=high, prod=[slim,distroless]

	cases := []struct {
		name   string
		in     MaterialityInput
		want   RiskDisposition
		reason string
	}{
		// In scope by severity.
		{"high-sev-fixable", MaterialityInput{Severity: "high", Layer: "runtime", HasFix: true, ProductionTier: true}, DispositionMustFix, "severity"},
		// In scope by severity but unfixable -> must acknowledge (never silent).
		{"high-sev-nofix", MaterialityInput{Severity: "high", Layer: "runtime", HasFix: false, ProductionTier: true}, DispositionMustAcknowledge, "severity_no_fix"},
		// Medium severity rescued by high EPSS.
		{"medium-high-epss", MaterialityInput{Severity: "medium", EPSSPercentile: epss(0.95), Layer: "runtime", HasFix: true, ProductionTier: true}, DispositionMustFix, "epss"},
		// Medium severity, low EPSS, no KEV -> accepted.
		{"medium-low-epss", MaterialityInput{Severity: "medium", EPSSPercentile: epss(0.50), Layer: "runtime", HasFix: true, ProductionTier: true}, DispositionAutoAccept, "below_risk_threshold"},
		// KEV always wins regardless of severity/EPSS.
		{"kev-medium", MaterialityInput{Severity: "medium", KEV: true, Layer: "runtime", HasFix: true, ProductionTier: true}, DispositionMustFix, "kev"},
		{"kev-nofix", MaterialityInput{Severity: "low", KEV: true, Layer: "runtime", HasFix: false, ProductionTier: true}, DispositionMustAcknowledge, "kev_no_fix"},
		// EPSS missing -> falls back to severity. critical >= high.
		{"epss-missing-critical", MaterialityInput{Severity: "critical", EPSSPercentile: nil, Layer: "runtime", HasFix: true, ProductionTier: true}, DispositionMustFix, "severity"},
		// EPSS missing, medium, no KEV -> below the bar.
		{"epss-missing-medium", MaterialityInput{Severity: "medium", EPSSPercentile: nil, Layer: "runtime", HasFix: true, ProductionTier: true}, DispositionAutoAccept, "below_risk_threshold"},
		// Reachability: base-layer finding is out of scope under runtime reachability.
		{"base-layer", MaterialityInput{Severity: "critical", Layer: "usr", HasFix: true, ProductionTier: true}, DispositionAutoAccept, "not_reachable_base_layer"},
		// Non-production tier is out of scope.
		{"non-production", MaterialityInput{Severity: "critical", KEV: true, Layer: "runtime", HasFix: true, ProductionTier: false}, DispositionAutoAccept, "non_production"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Materiality(c.in, pol)
			if got.Disposition != c.want || got.Reason != c.reason {
				t.Errorf("Materiality = {%s, %s}, want {%s, %s}", got.Disposition, got.Reason, c.want, c.reason)
			}
		})
	}
}

// Deprecated boost-era fields must normalize into the gating fields.
func TestMaterialityBackCompat(t *testing.T) {
	// Only deprecated fields set: reachability any, KEV off, EPSS gate 0.5.
	pol := RemediationPolicy{
		RequireRuntimeLayer:   boolPtr(false), // -> reachability: any
		KEVBoost:              boolPtr(false), // -> kev: off
		EPSSPercentileBoostAt: 0.50,           // -> epssPercentile: 0.50
		MinimumSeverity:       "critical",     // only critical by severity
	}
	eff := EffectiveRemediationPolicy(pol)
	if eff.Reachability != "any" || eff.KEV != "off" || eff.EPSSPercentile != 0.50 {
		t.Fatalf("back-compat normalization failed: %+v", eff)
	}

	// reachability any => a base-layer finding is now considered.
	// kev off => a KEV-only finding is NOT auto-in-scope.
	// epss 0.50 gate => epss 0.6 qualifies.
	base := MaterialityInput{Severity: "low", EPSSPercentile: epss(0.60), Layer: "base", HasFix: true, ProductionTier: true}
	if d := Materiality(base, pol); d.Disposition != DispositionMustFix || d.Reason != "epss" {
		t.Errorf("any-reachability + epss-gate: got {%s,%s}, want must_fix/epss", d.Disposition, d.Reason)
	}
	// KEV off: a KEV finding with low severity + no qualifying EPSS is accepted.
	kev := MaterialityInput{Severity: "low", KEV: true, Layer: "runtime", HasFix: true, ProductionTier: true}
	if d := Materiality(kev, pol); d.Disposition != DispositionAutoAccept {
		t.Errorf("kev off should not force in-scope: got %s", d.Disposition)
	}
}

// requireFixedVersion:false is the operator escape hatch (e.g. a line that must
// run with an unbackported CVE): a non-KEV, in-scope, unfixable finding becomes
// an auto-accept (expiring record) instead of blocking. KEV stays non-loosenable.
func TestMaterialityRequireFixedVersionFalse(t *testing.T) {
	pol := DefaultRemediationPolicy()
	f := false
	pol.RequireFixedVersion = &f

	nonKev := MaterialityInput{Severity: "high", Layer: "runtime", HasFix: false, ProductionTier: true}
	if d := Materiality(nonKev, pol); d.Disposition != DispositionAutoAccept || d.Reason != "no_fix_unrequired" {
		t.Fatalf("requireFixedVersion:false should auto-accept a non-KEV unfixable finding, got {%s,%s}", d.Disposition, d.Reason)
	}

	kev := MaterialityInput{Severity: "low", KEV: true, Layer: "runtime", HasFix: false, ProductionTier: true}
	if d := Materiality(kev, pol); d.Disposition != DispositionMustAcknowledge || d.Reason != "kev_no_fix" {
		t.Fatalf("KEV must stay must_acknowledge even with requireFixedVersion:false, got {%s,%s}", d.Disposition, d.Reason)
	}

	// Default (requireFixedVersion:true) still blocks an unfixable finding.
	if d := Materiality(nonKev, DefaultRemediationPolicy()); d.Disposition != DispositionMustAcknowledge {
		t.Fatalf("default policy should still block an unfixable finding, got %s", d.Disposition)
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !SeverityAtLeast("critical", "high") {
		t.Error("critical >= high")
	}
	if SeverityAtLeast("medium", "high") {
		t.Error("medium should be < high")
	}
	if !SeverityAtLeast("high", "high") {
		t.Error("high >= high")
	}
	// Unknown ranks above negligible (never silently dropped below a negligible bar).
	if !SeverityAtLeast("unknown", "negligible") {
		t.Error("unknown >= negligible")
	}
}

func TestKnownSeverity(t *testing.T) {
	for _, s := range []string{"critical", "High", " medium ", "low", "negligible", "unknown"} {
		if !KnownSeverity(s) {
			t.Errorf("KnownSeverity(%q) = false, want true", s)
		}
	}
	// severityRank maps these to the unknown rank; validation must still reject
	// them so a threshold typo cannot silently move the bar.
	for _, s := range []string{"", "urgent", "moderate"} {
		if KnownSeverity(s) {
			t.Errorf("KnownSeverity(%q) = true, want false", s)
		}
	}
}
