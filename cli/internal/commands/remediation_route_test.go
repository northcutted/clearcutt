package commands

import (
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/fleet"
)

func routeCtx() RouteContext {
	return RouteContext{
		cryptoCVEs: map[string]string{
			"CVE-2026-34182": "openssl",
			"CVE-2026-11822": "sqlite",
		},
		unstableCVEs: map[string]fleet.RemediationUnstableOptIn{
			"CVE-2026-48617": {Package: "nodejs_22", Ref: "github:NixOS/nixpkgs/abc"},
		},
		unstablePkgs: map[string]fleet.RemediationUnstableOptIn{
			"nodejs_22": {Package: "nodejs_22", Ref: "github:NixOS/nixpkgs/abc"},
		},
		cryptoTrust: fleet.CryptoTrustNixpkgs,
	}
}

func TestClassifyCampaignRoute(t *testing.T) {
	ctx := routeCtx()
	cases := []struct {
		name      string
		campaign  RemediationCampaign
		wantRoute string
	}{
		{"crypto in pinned channel -> substitute_vex",
			RemediationCampaign{Package: "openssl", CVE: "CVE-2026-34182", FixedVersion: "3.6.3"}, RouteSubstituteVEX},
		{"unstable opt-in by CVE -> unstable_optin",
			RemediationCampaign{Package: "nodejs_22", CVE: "CVE-2026-48617"}, RouteUnstableOptIn},
		{"unstable opt-in by package -> unstable_optin",
			RemediationCampaign{Package: "nodejs_22", CVE: "CVE-2026-99999"}, RouteUnstableOptIn},
		{"plain fixable -> version_bump",
			RemediationCampaign{Package: "zlib", CVE: "CVE-2026-1", FixedVersion: "1.3.2"}, RouteVersionBump},
		{"no-fix non-crypto -> scanner_ignore",
			RemediationCampaign{Package: "zlib", CVE: "CVE-2026-2", FixedVersion: ""}, RouteScannerIgnore},
		{"no-fix crypto -> fetchpatch_rebuild",
			RemediationCampaign{Package: "openssl", CVE: "CVE-2026-3", FixedVersion: ""}, RouteFetchpatchRebuild},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			route, reason := ctx.classifyCampaignRoute(tc.campaign)
			if route != tc.wantRoute {
				t.Errorf("route = %q, want %q", route, tc.wantRoute)
			}
			if reason == "" {
				t.Error("expected a non-empty route reason")
			}
		})
	}
}

// Crypto routing wins even when a higher version would otherwise look like a
// version bump — the substitute+VEX path is preferred over a rebuild.
func TestClassifyCryptoBeatsVersionBump(t *testing.T) {
	ctx := routeCtx()
	route, _ := ctx.classifyCampaignRoute(RemediationCampaign{
		Package: "openssl", CVE: "CVE-2026-34182", FixedVersion: "3.6.9",
	})
	if route != RouteSubstituteVEX {
		t.Errorf("crypto allowlisted CVE should route substitute_vex, got %q", route)
	}
}

func TestClassifyCryptoMatchesViaCVEsList(t *testing.T) {
	ctx := routeCtx()
	// The allowlisted CVE is in the multi-CVE campaign's CVEs slice, not CVE.
	route, _ := ctx.classifyCampaignRoute(RemediationCampaign{
		Package: "openssl", CVE: "CVE-2026-0001", CVEs: []string{"CVE-2026-0001", "CVE-2026-34182"},
	})
	if route != RouteSubstituteVEX {
		t.Errorf("expected substitute_vex via CVEs list, got %q", route)
	}
}

func TestReproduceTrustAnnotatesReason(t *testing.T) {
	ctx := routeCtx()
	ctx.cryptoTrust = fleet.CryptoTrustReproduce
	_, reason := ctx.classifyCampaignRoute(RemediationCampaign{Package: "sqlite", CVE: "CVE-2026-11822"})
	if !strings.Contains(reason, "reproduce") {
		t.Errorf("reproduce trust should annotate reason, got %q", reason)
	}
}

func TestApplyRoutesToPlanStampsEveryCampaign(t *testing.T) {
	plan := &RemediationPlan{Campaigns: []RemediationCampaign{
		{Package: "openssl", CVE: "CVE-2026-34182"},
		{Package: "zlib", CVE: "CVE-2026-1", FixedVersion: "1.3.2"},
	}}
	applyRoutesToPlan(plan, routeCtx())
	if plan.Campaigns[0].RecommendedRoute != RouteSubstituteVEX {
		t.Errorf("campaign 0 route = %q", plan.Campaigns[0].RecommendedRoute)
	}
	if plan.Campaigns[1].RecommendedRoute != RouteVersionBump {
		t.Errorf("campaign 1 route = %q", plan.Campaigns[1].RecommendedRoute)
	}
	for i, c := range plan.Campaigns {
		if c.RouteReason == "" {
			t.Errorf("campaign %d missing route reason", i)
		}
	}
}

// An empty context (no allowlist, no opt-ins) must not panic and routes on
// fixability alone.
func TestEmptyContextRoutesOnFixability(t *testing.T) {
	var ctx RouteContext
	route, _ := ctx.classifyCampaignRoute(RemediationCampaign{Package: "zlib", FixedVersion: "1.0"})
	if route != RouteVersionBump {
		t.Errorf("empty ctx fixable -> version_bump, got %q", route)
	}
	route, _ = ctx.classifyCampaignRoute(RemediationCampaign{Package: "zlib"})
	if route != RouteScannerIgnore {
		t.Errorf("empty ctx no-fix -> scanner_ignore, got %q", route)
	}
}
