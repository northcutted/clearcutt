package commands

import (
	"path/filepath"
	"strings"

	"github.com/northcutted/clearcutt/internal/fleet"
)

// Phase 4 of the crypto-CVE provenance reshape: route every CVE through the
// policy. A remediation campaign is classified into one of the routes below so
// the auto-patch dispatcher and the aggregated PR record HOW each finding gets
// fixed, not just that it should be. The decision tree:
//
//	Fix location                                   -> Route
//	in the pinned channel (patched, maybe not bumped, crypto) -> substitute_vex
//	a normal version bump in the pinned channel    -> version_bump
//	in a newer nixpkgs (unstable), scoped opt-in   -> unstable_optin
//	nowhere in nixpkgs yet, crypto                 -> fetchpatch_rebuild (rare)
//	nowhere in nixpkgs yet, anything else          -> scanner_ignore (expiring)
//
// This is a STATIC classifier driven by committed policy data — the crypto
// identity allowlist (which crypto CVEs are already patched+provenance-vetted),
// the unstable soft opt-ins, and fixability. The live scan-time probe that
// queries nixpkgs-unstable for an arbitrary CVE's fix is a future slice; until
// then a fixable finding with no opt-in routes to version_bump.
const (
	RouteVersionBump       = "version_bump"
	RouteSubstituteVEX     = "substitute_vex"
	RouteUnstableOptIn     = "unstable_optin"
	RouteFetchpatchRebuild = "fetchpatch_rebuild"
	RouteScannerIgnore     = "scanner_ignore"
	// RouteWait is the sixth route, offered only by `remediation triage`
	// (docs/analysis/cve-triage-design.md): do nothing now because the
	// fix-availability probe can SEE the fix progressing on an uncached ref, and
	// the finding sits at/below the policy's wait severity ceiling. It is
	// probe-gated by construction, so this static classifier never emits it.
	RouteWait = "wait"
)

// cryptoTrackedDeps are the packages the runtime crypto overlay patches; a
// no-fix CVE on one of these routes to the bespoke-rebuild exception rather than
// a scanner ignore.
var cryptoTrackedDeps = map[string]bool{"openssl": true, "sqlite": true}

// RouteContext is the committed policy data the classifier consults. A zero
// value is valid: with no crypto allowlist and no opt-ins, every campaign routes
// on fixability alone (version_bump / scanner_ignore).
type RouteContext struct {
	// cryptoCVEs maps a provenance-allowlisted crypto CVE to its dep name.
	cryptoCVEs map[string]string
	// unstableCVEs maps a CVE cleared by a soft opt-in to that opt-in.
	unstableCVEs map[string]fleet.RemediationUnstableOptIn
	// unstablePkgs maps a soft-opt-in package name to that opt-in.
	unstablePkgs map[string]fleet.RemediationUnstableOptIn
	cryptoTrust  string
}

// LoadRouteContext assembles the routing context from the committed crypto
// allowlist and the fleet config. Both are best-effort: a missing file yields an
// emptier context, never an error, so route enrichment never blocks planning.
func LoadRouteContext(coreDir, fleetConfigPath string) RouteContext {
	ctx := RouteContext{
		cryptoCVEs:   map[string]string{},
		unstableCVEs: map[string]fleet.RemediationUnstableOptIn{},
		unstablePkgs: map[string]fleet.RemediationUnstableOptIn{},
		cryptoTrust:  fleet.CryptoTrustNixpkgs,
	}

	if coreDir != "" {
		if allowlist, err := loadCryptoAllowlistFile(filepath.Join(coreDir, "tests", "runtime-dep-floor.json")); err == nil {
			for _, dep := range allowlist.Deps {
				if cve := strings.TrimSpace(dep.CVE); cve != "" {
					ctx.cryptoCVEs[strings.ToUpper(cve)] = dep.Name
				}
			}
			if t := strings.TrimSpace(allowlist.Trust); t != "" {
				ctx.cryptoTrust = strings.ToLower(t)
			}
		}
	}

	if fleetConfigPath != "" {
		if cfg, err := fleet.Load(fleetConfigPath); err == nil {
			for _, optin := range cfg.Remediation.Unstable.SoftOptIns {
				if pkg := strings.TrimSpace(optin.Package); pkg != "" {
					ctx.unstablePkgs[pkg] = optin
				}
				for _, fix := range optin.Fixes {
					if cve := strings.TrimSpace(fix.CVE); cve != "" {
						ctx.unstableCVEs[strings.ToUpper(cve)] = optin
					}
				}
			}
			if t := strings.TrimSpace(cfg.Remediation.Policy.CryptoTrust); t != "" {
				ctx.cryptoTrust = strings.ToLower(t)
			}
		}
	}
	return ctx
}

// classifyCampaignRoute returns the route + a human reason for one campaign.
func (ctx RouteContext) classifyCampaignRoute(c RemediationCampaign) (string, string) {
	cves := append([]string{}, c.CVEs...)
	if c.CVE != "" {
		cves = append(cves, c.CVE)
	}

	// 1. Crypto fix already in the pinned channel, provenance-allowlisted.
	for _, cve := range cves {
		if dep, ok := ctx.cryptoCVEs[strings.ToUpper(strings.TrimSpace(cve))]; ok {
			trust := ctx.cryptoTrust
			if trust == "" {
				trust = fleet.CryptoTrustNixpkgs
			}
			reason := "fix is in the pinned channel; ship the provenance-allowlisted patched " + dep + " and clear the scanner with VEX"
			if trust == fleet.CryptoTrustReproduce {
				reason += " (cryptoTrust=reproduce: also rebuild-and-compare)"
			}
			return RouteSubstituteVEX, reason
		}
	}

	// 2. Fix in a newer nixpkgs via a scoped soft opt-in.
	for _, cve := range cves {
		if optin, ok := ctx.unstableCVEs[strings.ToUpper(strings.TrimSpace(cve))]; ok {
			return RouteUnstableOptIn, "fix is in a newer nixpkgs; scope " + optin.Package + " to the pinned unstable ref"
		}
	}
	if optin, ok := ctx.unstablePkgs[c.Package]; ok {
		return RouteUnstableOptIn, "package has a soft opt-in to " + optin.Ref + " for a newer fixed build"
	}

	// 3. Normal version bump available in the pinned channel.
	if strings.TrimSpace(c.FixedVersion) != "" {
		return RouteVersionBump, "a fixed version is available in the pinned channel"
	}

	// 4. No fix anywhere yet.
	if cryptoTrackedDeps[strings.ToLower(c.Package)] {
		return RouteFetchpatchRebuild, "no upstream fix yet for crypto; bespoke fetchpatch rebuild (rare, evidence-backed)"
	}
	return RouteScannerIgnore, "no upstream fix yet; record a narrow, owned, expiring scanner suppression"
}

// enrichPlanRoutesBestEffort stamps routes onto the plan using auto-detected
// policy data. It never errors: if the core dir or fleet config can't be found,
// campaigns keep routing on fixability alone.
func enrichPlanRoutesBestEffort(plan *RemediationPlan, coreDir string) {
	if coreDir == "" {
		if resolved, err := resolveCoreDir(""); err == nil {
			coreDir = resolved
		}
	}
	fleetPath := fleet.DefaultConfigPath
	if coreDir != "" {
		if candidate := filepath.Join(filepath.Dir(coreDir), fleet.DefaultConfigPath); fileExists(candidate) {
			fleetPath = candidate
		}
	}
	applyRoutesToPlan(plan, LoadRouteContext(coreDir, fleetPath))
}

// applyRoutesToPlan classifies and stamps a route + reason onto every campaign.
func applyRoutesToPlan(plan *RemediationPlan, ctx RouteContext) {
	if plan == nil {
		return
	}
	for i := range plan.Campaigns {
		route, reason := ctx.classifyCampaignRoute(plan.Campaigns[i])
		plan.Campaigns[i].RecommendedRoute = route
		plan.Campaigns[i].RouteReason = reason
	}
}
