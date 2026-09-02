package config

import "strings"

// RiskDisposition is the outcome of applying the risk policy to one finding.
type RiskDisposition string

const (
	// DispositionMustFix: reachable, materially risky, fixable, production —
	// remediate or block. For a crypto dep this is what puts it in the floor.
	DispositionMustFix RiskDisposition = "must_fix"
	// DispositionMustAcknowledge: reachable, materially risky, but no fix exists —
	// blocks until explicitly acknowledged (owner + expiry), then warns. Never a
	// silent pass.
	DispositionMustAcknowledge RiskDisposition = "must_acknowledge"
	// DispositionAutoAccept: out of scope (not reachable, not production, or below
	// the materiality bar) — recorded as an expiring acceptance, not blocking.
	DispositionAutoAccept RiskDisposition = "auto_accept"
)

// MaterialityInput is the minimal finding data the risk policy needs. It is
// decoupled from the scanner/catalog types so the policy is a pure function.
type MaterialityInput struct {
	Severity       string   // critical/high/medium/low/negligible/unknown
	EPSSPercentile *float64 // nil when the scanner has no EPSS score (fresh CVEs)
	KEV            bool     // present in the CISA KEV catalog
	Layer          string   // "runtime" for the shipped runtime closure, else a base layer
	HasFix         bool     // a fixed version is available
	ProductionTier bool     // the image tier is production-eligible
}

// RiskDecision is the policy verdict plus the reason that drove it (for evidence).
type RiskDecision struct {
	Disposition RiskDisposition
	Reason      string
}

// Materiality applies the risk policy to a single finding. A finding is in scope
// when it is reachable (closure presence, per policy.Reachability) AND in a
// production tier AND materially risky (KEV when policy.KEV=="always", OR EPSS
// percentile >= policy.EPSSPercentile, OR severity >= policy.MinimumSeverity).
// In-scope findings split must_fix vs must_acknowledge on fixability; everything
// else auto-accepts. A missing EPSS score falls back to KEV/severity.
func Materiality(in MaterialityInput, policy RemediationPolicy) RiskDecision {
	policy = EffectiveRemediationPolicy(policy)

	if !in.ProductionTier {
		return RiskDecision{DispositionAutoAccept, "non_production"}
	}
	if strings.EqualFold(policy.Reachability, "runtime") && !strings.EqualFold(in.Layer, "runtime") {
		return RiskDecision{DispositionAutoAccept, "not_reachable_base_layer"}
	}

	// Materiality (OR): any one signal makes the finding risky.
	reason := ""
	switch {
	case strings.EqualFold(policy.KEV, "always") && in.KEV:
		reason = "kev"
	case in.EPSSPercentile != nil && *in.EPSSPercentile >= policy.EPSSPercentile:
		reason = "epss"
	case SeverityAtLeast(in.Severity, policy.MinimumSeverity):
		reason = "severity"
	}
	if reason == "" {
		return RiskDecision{DispositionAutoAccept, "below_risk_threshold"}
	}

	// In scope. Fixability splits remediate-or-block (a fix exists) from
	// acknowledge-or-block (above the bar but unfixable). By default an unfixable
	// in-scope finding blocks until explicitly acknowledged — never a silent
	// pass. An operator who must run a line carrying an unbackported CVE can set
	// requireFixedVersion:false, which downgrades the NON-KEV unfixable case to
	// an auto-accept (still recorded as an expiring VEX record, not silenced).
	// KEV is non-loosenable: a known-exploited finding always blocks-until-ack.
	if !in.HasFix {
		if reason != "kev" && policy.RequireFixedVersion != nil && !*policy.RequireFixedVersion {
			return RiskDecision{DispositionAutoAccept, "no_fix_unrequired"}
		}
		return RiskDecision{DispositionMustAcknowledge, reason + "_no_fix"}
	}
	return RiskDecision{DispositionMustFix, reason}
}

// severityRank orders grype/CVSS severities; higher is more severe. Unknown
// severities rank above negligible so an unclassified finding is never quietly
// dropped below the bar.
func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "unknown", "":
		return 1
	case "negligible":
		return 0
	default:
		return 1
	}
}

// SeverityAtLeast reports whether severity is at or above threshold.
func SeverityAtLeast(severity, threshold string) bool {
	return severityRank(severity) >= severityRank(threshold)
}

// KnownSeverity reports whether severity names one of the ranked levels above
// (case-insensitive). Policy thresholds (minimumSeverity, waitMaxSeverity)
// reject anything else so a typo cannot silently move the bar — severityRank
// alone can't tell a typo from "unknown".
func KnownSeverity(severity string) bool {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high", "medium", "low", "negligible", "unknown":
		return true
	default:
		return false
	}
}
