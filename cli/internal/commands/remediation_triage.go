package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/northcutted/clearcutt/internal/fixprobe"
	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
)

// TriageSchemaVersion identifies the clearcutt.triage/v1 report contract
// (schemas/triage.v1.schema.json) — the published artifact a CI fan-out posts
// as a PR comment and a future agent consumes.
const TriageSchemaVersion = "clearcutt.triage/v1"

// CostNow vocabulary for a route option (schemas/triage.v1.schema.json).
const (
	triageCostNone          = "none"
	triageCostSubstitutable = "none_substitutable"
	triageCostScopedRebuild = "scoped_rebuild"
	triageCostColdBuild     = "cold_source_build"
)

// RiskCarried vocabulary for a route option.
const (
	triageRiskNone          = "none"
	triageRiskUntilExpiry   = "cve_ships_until_expiry"
	triageRiskUntilRefLands = "cve_ships_until_ref_lands"
	triageRiskOverrideChurn = "override_patch_churn"
)

// Retirement kinds — the conditions `remediation status --check-retirements`
// evaluates. Kept as string literals in remediation_report.go's validator maps;
// these constants are the writer side of the same contract.
const (
	retirementPinCarriesFix = "pin_carries_fix"
	retirementRefCarriesFix = "ref_carries_fix"
	retirementExpiry        = "expiry"
)

// RouteOption is one priced route for a finding: whether it is available under
// policy + probe evidence, what it costs to take now, what risk it carries
// while it stands, and the condition under which it retires.
type RouteOption struct {
	Route       string      `json:"route"`
	Available   bool        `json:"available"`
	Why         string      `json:"why"`
	CostNow     string      `json:"costNow"`
	RiskCarried string      `json:"riskCarried"`
	Retirement  *Retirement `json:"retirement,omitempty"`
	Recommended bool        `json:"recommended"`
}

// Retirement is the condition under which a carried decision retires. It is
// recorded at decision time so no context reconstruction is needed when
// `remediation status --check-retirements` evaluates it later.
type Retirement struct {
	Kind    string `json:"kind"`
	Package string `json:"package,omitempty"`
	Version string `json:"version,omitempty"` // fix version the condition watches
	Ref     string `json:"ref,omitempty"`     // watched nixpkgs ref for ref_carries_fix
	Expires string `json:"expires,omitempty"` // YYYY-MM-DD
}

// TriageReport is the clearcutt.triage/v1 document emitted by --format json.
type TriageReport struct {
	SchemaVersion string          `json:"schemaVersion"`
	GeneratedAt   string          `json:"generatedAt"`
	Degraded      bool            `json:"degraded"`
	Findings      []TriageFinding `json:"findings"`
}

// TriageFinding is one campaign's priced option space plus the evidence behind
// it and, once --decide ran, the recorded decision.
type TriageFinding struct {
	CVE              string                 `json:"cve"`
	Package          string                 `json:"package"`
	InstalledVersion string                 `json:"installedVersion,omitempty"`
	FixedVersion     string                 `json:"fixedVersion,omitempty"`
	Severity         string                 `json:"severity"`
	Exposure         *TriageExposure        `json:"exposure,omitempty"`
	Materiality      *TriageMateriality     `json:"materiality,omitempty"`
	Probe            *fixprobe.Availability `json:"probe,omitempty"`
	Options          []RouteOption          `json:"options"`
	RecommendedRoute string                 `json:"recommendedRoute"`
	Decision         *TriageDecision        `json:"decision,omitempty"`
}

// TriageExposure records which tiers ship the finding.
type TriageExposure struct {
	Production bool     `json:"production"`
	Tiers      []string `json:"tiers,omitempty"`
}

// TriageMateriality is the fleet risk-policy verdict — the same
// fleet.Materiality decision the planner, verify gate, and VEX emitter share.
type TriageMateriality struct {
	Disposition string `json:"disposition"`
	Reason      string `json:"reason"`
}

// TriageDecision is the applied-route record embedded in the report; the same
// content is stamped as the `triage` block onto evidence files.
type TriageDecision struct {
	Route      string      `json:"route"`
	DecidedBy  string      `json:"decidedBy"`
	DecidedAt  string      `json:"decidedAt,omitempty"`
	Owner      string      `json:"owner,omitempty"`
	Reason     string      `json:"reason,omitempty"`
	Retirement *Retirement `json:"retirement,omitempty"`
}

// triageEvidence is the `triage` block written onto evidence files
// (.ignore.evidence.json and .decision.evidence.json). decidedBy is the
// agentic seam: human | policy | agent:<identifier>, nothing else changes when
// an agent starts deciding.
type triageEvidence struct {
	SchemaVersion string                 `json:"schemaVersion"`
	Route         string                 `json:"route"`
	DecidedBy     string                 `json:"decidedBy"`
	DecidedAt     string                 `json:"decidedAt"`
	Retirement    *Retirement            `json:"retirement,omitempty"`
	Probe         *fixprobe.Availability `json:"probe,omitempty"`
}

// triageDecisionRecord is the standalone cve-<id>-<pkg>.decision.evidence.json
// written for routes that leave no other artifact (wait, pin-hop snippets,
// remediation-run hand-offs). validate-overlays sweeps these files.
type triageDecisionRecord struct {
	SchemaVersion    string         `json:"schemaVersion"`
	Status           string         `json:"status"`
	CVE              string         `json:"cve"`
	Package          string         `json:"package"`
	InstalledVersion string         `json:"installedVersion,omitempty"`
	FixedVersion     string         `json:"fixedVersion,omitempty"`
	Owner            string         `json:"owner"`
	Reason           string         `json:"reason"`
	GeneratedBy      string         `json:"generatedBy"`
	Triage           triageEvidence `json:"triage"`
}

type remediationTriageFlags struct {
	cves        []string
	pkg         string
	scanDir     string
	planPath    string
	coreDir     string
	fleetConfig string
	noProbe     bool
	decide      string
	owner       string
	reason      string
	expires     string
	decidedBy   string
	strict      bool
}

var remediationTriageOpts remediationTriageFlags

// Test seams: the production fetcher hits the GitHub contents API and the
// source-path resolver shells out to nix; tests swap both (the same pattern as
// the out/errOut writer swap) so triage stays exercisable offline.
var triageNewFetcher = func() fixprobe.Fetcher { return fixprobe.NewGitHubFetcher() }

// triageResolveSourcePath resolves a package's raw meta.position by evaluating
// it against the local pin (pure eval — the pin source is already in the
// store, no download). The store-prefixed position carries two facts the
// caller splits apart: WHICH input source tree the file lives in
// (nixpkgsStoreSource — the pin attribution) and the repo-relative path inside
// it (nixpkgsSourcePath — what the probe fetches at other refs). Best-effort
// by contract: any failure degrades the probe for that finding, never the
// command, so unlike nixEvalResolver the nix stderr is not forwarded (an
// unresolvable attr is an expected miss, not an operator-facing failure).
var triageResolveSourcePath = func(coreDir, attr string) (string, error) {
	ref := fmt.Sprintf("%s#%s.meta.position", flakeRef(coreDir), attr)
	raw, err := exec.Command("nix", "eval", "--no-warn-dirty", "--raw", ref).Output()
	if err != nil {
		return "", fmt.Errorf("nix eval %s failed: %w (is nix installed and the flake evaluable?)", ref, err)
	}
	position := strings.TrimSpace(string(raw))
	if nixpkgsSourcePath(position) == "" {
		return "", fmt.Errorf("nix eval %s returned no usable position", ref)
	}
	return position, nil
}

// triageResolveInputSources maps each flake input's realized store source path
// to its input name via `nix flake archive --json`. An evaluable flake already
// has its inputs in the store, so this copies nothing new. Best-effort: a
// failure means pin attribution falls back to the main nixpkgs pin — exactly
// the pre-attribution behavior, never an error.
var triageResolveInputSources = func(coreDir string) (map[string]string, error) {
	raw, err := exec.Command("nix", "flake", "archive", "--json", flakeRef(coreDir)).Output()
	if err != nil {
		return nil, fmt.Errorf("nix flake archive %s failed: %w", flakeRef(coreDir), err)
	}
	var doc struct {
		Inputs map[string]struct {
			Path string `json:"path"`
		} `json:"inputs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse nix flake archive output: %w", err)
	}
	sources := map[string]string{}
	for name, input := range doc.Inputs {
		if strings.TrimSpace(input.Path) != "" {
			sources[input.Path] = name
		}
	}
	return sources, nil
}

// NewRemediationTriageCmd builds `clearcutt remediation triage`: the priced
// route decision surface of docs/analysis/cve-triage-design.md. The CLI
// computes the option space and prices it; the policy picks defaults; --decide
// records the chosen route as a durable, self-retiring artifact.
func NewRemediationTriageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "triage",
		Short: "Price the remediation routes for CVE findings and record route decisions",
		Long: `Composes the remediation plan, the static route classifier, the fleet risk
policy, and a live fix-availability probe of nixpkgs into one priced option
table per finding: which routes are available, what each costs now, what risk
it carries, and when it retires. --decide applies a route non-interactively and
records it as expiring, self-retiring evidence. Probe failures degrade to the
static classification — triage is never less available than planning.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemediationTriage()
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&remediationTriageOpts.cves, "cve", nil, "Limit triage to this CVE id; repeatable")
	f.StringVar(&remediationTriageOpts.pkg, "package", "", "Limit triage to this package name")
	f.StringVar(&remediationTriageOpts.scanDir, "scan-dir", "", "Specific vulnerability scan directory to plan from (defaults to the latest under the vuln root)")
	f.StringVar(&remediationTriageOpts.planPath, "plan", "", "Load an existing remediation plan JSON instead of building one from scans")
	f.StringVar(&remediationTriageOpts.coreDir, "core-dir", "", "Core workspace directory (auto-detected when omitted)")
	f.StringVar(&remediationTriageOpts.fleetConfig, "fleet-config", "", "Path to clearcutt.fleet.yaml (auto-detected when omitted)")
	f.BoolVar(&remediationTriageOpts.noProbe, "no-probe", false, "Skip the live fix-availability probe; triage falls back to the static route classifier")
	f.StringVar(&remediationTriageOpts.decide, "decide", "", "Apply this route to the single in-scope finding and record the decision")
	f.StringVar(&remediationTriageOpts.owner, "owner", "", "Owner accountable for the decision (required with --decide)")
	f.StringVar(&remediationTriageOpts.reason, "reason", "", "Why this route was chosen (required with --decide)")
	f.StringVar(&remediationTriageOpts.expires, "expires", "", "Expiry date YYYY-MM-DD overriding the policy default backstop")
	f.StringVar(&remediationTriageOpts.decidedBy, "decided-by", "human", "Who decided: human | policy | agent:<identifier>")
	f.BoolVar(&remediationTriageOpts.strict, "strict", false, "Exit 2 when any in-scope finding has no available route under policy")
	return cmd
}

func runRemediationTriage() error {
	o := remediationTriageOpts
	now := time.Now().UTC()

	// The core dir is best-effort for a read-only triage (only the probe and
	// --decide need it); a miss degrades rather than blocks.
	coreDir := o.coreDir
	if coreDir == "" {
		if resolved, err := resolveCoreDir(""); err == nil {
			coreDir = resolved
		}
	}
	fleetPath := triageFleetConfigPath(o.fleetConfig, coreDir)
	remediationCfg := fleet.Remediation{}
	if cfg, err := fleet.Load(fleetPath); err == nil {
		remediationCfg = cfg.Remediation
	}
	policy := fleet.EffectiveRemediationPolicy(remediationCfg.Policy)

	plan, err := loadOrBuildTriagePlan(o, policy)
	if err != nil {
		return err
	}
	// A loaded plan already carries the policy its campaigns were selected
	// under; pricing against a different one would let the two disagree.
	if o.planPath != "" {
		policy = fleet.EffectiveRemediationPolicy(plan.Policy)
	}
	routeCtx := LoadRouteContext(coreDir, fleetPath)
	applyRoutesToPlan(plan, routeCtx)

	campaigns := filterTriageCampaigns(plan.Campaigns, o.cves, o.pkg)
	if len(campaigns) == 0 && (len(o.cves) > 0 || o.pkg != "") {
		return fmt.Errorf("no in-scope finding matches the requested filter (cve=%v package=%q) in %s", o.cves, o.pkg, plan.SourceDir)
	}

	prober := newTriageProber(o, remediationCfg, coreDir, now)
	report := &TriageReport{
		SchemaVersion: TriageSchemaVersion,
		GeneratedAt:   now.Format(time.RFC3339),
		Degraded:      prober == nil,
		Findings:      []TriageFinding{},
	}
	for _, campaign := range campaigns {
		finding := buildTriageFinding(campaign, policy, prober, now)
		if prober != nil && (finding.Probe == nil || finding.Probe.Degraded) {
			report.Degraded = true
		}
		report.Findings = append(report.Findings, finding)
	}

	if strings.TrimSpace(o.decide) != "" {
		if len(report.Findings) != 1 {
			return fmt.Errorf("--decide applies to exactly one finding; narrow with --cve/--package (matched %d)", len(report.Findings))
		}
		if err := applyTriageDecision(&report.Findings[0], o, coreDir, now, triageDecisionWriter()); err != nil {
			return err
		}
	}

	if structuredFormat() {
		if err := printStructured(report); err != nil {
			return err
		}
	} else if err := printTriageReportTable(report); err != nil {
		return err
	}

	if o.strict {
		blocked := 0
		for _, f := range report.Findings {
			if f.RecommendedRoute == "" {
				blocked++
				fmt.Fprintf(errOut, "[triage] escalation: %s (%s) has no available route under policy\n", f.CVE, f.Package)
			}
		}
		if blocked > 0 {
			return ErrCheckFailed
		}
	}
	return nil
}

// triageDecisionWriter keeps stdout parseable: decision commentary joins the
// table in human mode but moves to stderr when --format selects json/yaml.
func triageDecisionWriter() io.Writer {
	if structuredFormat() {
		return errOut
	}
	return out
}

// triageFleetConfigPath mirrors enrichPlanRoutesBestEffort's detection: an
// explicit flag wins, then the file next to the core workspace, then the
// default path relative to the working directory.
func triageFleetConfigPath(explicit, coreDir string) string {
	if explicit != "" {
		return explicit
	}
	if coreDir != "" {
		if candidate := filepath.Join(filepath.Dir(coreDir), fleet.DefaultConfigPath); fileExists(candidate) {
			return candidate
		}
	}
	return fleet.DefaultConfigPath
}

func loadOrBuildTriagePlan(o remediationTriageFlags, policy fleet.RemediationPolicy) (*RemediationPlan, error) {
	if o.planPath != "" {
		raw, err := os.ReadFile(o.planPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read remediation plan %s: %w", o.planPath, err)
		}
		var plan RemediationPlan
		if err := json.Unmarshal(raw, &plan); err != nil {
			return nil, fmt.Errorf("failed to parse remediation plan %s: %w", o.planPath, err)
		}
		return &plan, nil
	}
	vulnDir, err := resolveRemediationVulnDir(envOr("VULN_ROOT", remediationDefaultVulnRoot), o.scanDir)
	if err != nil {
		return nil, err
	}
	// Triage is a decision surface, not the automated-remediation selector:
	// include dev-only campaigns and never cap, so any finding can be asked
	// about (the node-24 preview-tier case).
	return buildRemediationPlanWithPolicy(vulnDir, 0, true, policy)
}

func filterTriageCampaigns(campaigns []RemediationCampaign, cves []string, pkg string) []RemediationCampaign {
	wantCVE := map[string]bool{}
	for _, cve := range cves {
		if s := strings.ToUpper(strings.TrimSpace(cve)); s != "" {
			wantCVE[s] = true
		}
	}
	pkg = strings.TrimSpace(pkg)
	selected := []RemediationCampaign{}
	for _, c := range campaigns {
		if pkg != "" && !strings.EqualFold(c.Package, pkg) {
			continue
		}
		if len(wantCVE) > 0 && !campaignMatchesCVEs(c, wantCVE) {
			continue
		}
		selected = append(selected, c)
	}
	return selected
}

func campaignMatchesCVEs(c RemediationCampaign, want map[string]bool) bool {
	for _, cve := range append(append([]string{}, c.CVEs...), c.CVE, c.PrimaryCVE) {
		if want[strings.ToUpper(strings.TrimSpace(cve))] {
			return true
		}
	}
	return false
}

// triageProber carries everything one probe call needs. nil means the probe is
// off (--no-probe, policy-disabled, or the pin rev could not be read) and
// triage runs on the static classifier alone.
type triageProber struct {
	fetcher fixprobe.Fetcher
	coreDir string
	pins    triagePinMap
	refs    []fixprobe.Ref
	now     time.Time
}

// triagePinMap attributes a package to the flake input that sources it, so a
// dedicated-pin runtime (nixpkgs-node, nixpkgs-dotnet) is priced and retired
// against ITS pin, not the main one.
type triagePinMap struct {
	revs  map[string]string // flake input -> locked rev
	bySrc map[string]string // input store source path -> input name
}

// attribute resolves the sourcing pin for a meta.position store source. An
// unknown or empty source falls back to the main nixpkgs pin — the safe
// pre-attribution behavior for stub resolvers and degraded archive calls.
func (m triagePinMap) attribute(storeSource string) (string, string) {
	if name, ok := m.bySrc[storeSource]; ok {
		if rev := strings.TrimSpace(m.revs[name]); rev != "" {
			return name, rev
		}
	}
	return "nixpkgs", m.revs["nixpkgs"]
}

// loadTriagePinMap reads every locked rev and maps input source trees to
// input names. The rev read is load-bearing (no main pin, no probe); the
// source attribution is best-effort and degrades to main-pin behavior.
func loadTriagePinMap(coreDir string) (triagePinMap, error) {
	revs, err := flakeLockRevs(filepath.Join(coreDir, "flake.lock"))
	if err != nil {
		return triagePinMap{}, err
	}
	if strings.TrimSpace(revs["nixpkgs"]) == "" {
		return triagePinMap{}, fmt.Errorf("%s: input %q has no locked rev", filepath.Join(coreDir, "flake.lock"), "nixpkgs")
	}
	pins := triagePinMap{revs: revs, bySrc: map[string]string{}}
	if sources, err := triageResolveInputSources(coreDir); err == nil {
		pins.bySrc = sources
	} else {
		fmt.Fprintf(errOut, "[triage] pin attribution degraded (probing against the main pin): %v\n", err)
	}
	return pins, nil
}

func newTriageProber(o remediationTriageFlags, remediationCfg fleet.Remediation, coreDir string, now time.Time) *triageProber {
	if o.noProbe || !remediationCfg.ProbeEnabled() {
		return nil
	}
	if coreDir == "" {
		fmt.Fprintln(errOut, "[triage] probe degraded: no core workspace found for the pin lock (pass --core-dir)")
		return nil
	}
	pins, err := loadTriagePinMap(coreDir)
	if err != nil {
		fmt.Fprintf(errOut, "[triage] probe degraded: %v\n", err)
		return nil
	}
	return &triageProber{
		fetcher: triageNewFetcher(),
		coreDir: coreDir,
		pins:    pins,
		refs:    triageProbeRefs(remediationCfg),
		now:     now,
	}
}

// probe returns nil on any failure — the caller then prices against the static
// classifier, per the design's degradation contract.
func (p *triageProber) probe(c RemediationCampaign) *fixprobe.Availability {
	if p == nil || p.fetcher == nil {
		return nil
	}
	position, err := triageResolveSourcePath(p.coreDir, c.Package)
	if err != nil {
		fmt.Fprintf(errOut, "[triage] probe degraded for %s: %v\n", c.Package, err)
		return nil
	}
	pinName, pinRev := p.pins.attribute(nixpkgsStoreSource(position))
	av, err := fixprobe.Probe(context.Background(), p.fetcher, fixprobe.Input{
		Package:          c.Package,
		SourcePath:       nixpkgsSourcePath(position),
		PinRev:           pinRev,
		PinName:          pinName,
		InstalledVersion: c.InstalledVersion,
		FixedVersion:     c.FixedVersion,
		Refs:             p.refs,
		Now:              p.now,
	})
	if err != nil {
		fmt.Fprintf(errOut, "[triage] probe degraded for %s: %v\n", c.Package, err)
		return nil
	}
	return av
}

// triageProbeRefs maps the configured ref names onto probe refs. nixos-*
// names are Hydra-published channels (a fix pulled from one is substitutable);
// anything else is a bare branch a fix reaches before any channel does.
func triageProbeRefs(remediationCfg fleet.Remediation) []fixprobe.Ref {
	names := remediationCfg.EffectiveProbeRefs()
	refs := make([]fixprobe.Ref, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		kind := fixprobe.RefKindBranch
		if strings.HasPrefix(name, "nixos-") {
			kind = fixprobe.RefKindChannel
		}
		refs = append(refs, fixprobe.Ref{Name: name, Kind: kind})
	}
	return refs
}

// flakeLockRevs reads every input's locked rev from a flake.lock — the pin
// revs the probe compares other refs against, keyed by input name.
func flakeLockRevs(lockPath string) (map[string]string, error) {
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", lockPath, err)
	}
	var lock struct {
		Nodes map[string]struct {
			Locked struct {
				Rev string `json:"rev"`
			} `json:"locked"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", lockPath, err)
	}
	revs := make(map[string]string, len(lock.Nodes))
	for name, node := range lock.Nodes {
		if rev := strings.TrimSpace(node.Locked.Rev); rev != "" {
			revs[name] = rev
		}
	}
	return revs, nil
}

// nixpkgsStoreSource returns the store source tree a meta.position value lives
// in (/nix/store/<hash>-source), or "" for a position that carries no store
// prefix — the pin-attribution key triagePinMap.attribute consumes.
func nixpkgsStoreSource(position string) string {
	if i := strings.LastIndex(position, ":"); i >= 0 && !strings.Contains(position[i+1:], "/") {
		position = position[:i]
	}
	const storePrefix = "/nix/store/"
	if !strings.HasPrefix(position, storePrefix) {
		return ""
	}
	rest := position[len(storePrefix):]
	if j := strings.Index(rest, "/"); j >= 0 {
		return storePrefix + rest[:j]
	}
	return position
}

// nixpkgsSourcePath turns a meta.position value
// (/nix/store/<hash>-source/pkgs/…/default.nix:123) into the repo-relative
// path the probe fetches at other refs: drop the :line suffix, then the store
// prefix's first path component.
func nixpkgsSourcePath(position string) string {
	if i := strings.LastIndex(position, ":"); i >= 0 && !strings.Contains(position[i+1:], "/") {
		position = position[:i]
	}
	const storePrefix = "/nix/store/"
	if strings.HasPrefix(position, storePrefix) {
		rest := position[len(storePrefix):]
		if j := strings.Index(rest, "/"); j >= 0 {
			return rest[j+1:]
		}
		return ""
	}
	return strings.TrimPrefix(position, "/")
}

func buildTriageFinding(c RemediationCampaign, policy fleet.RemediationPolicy, prober *triageProber, now time.Time) TriageFinding {
	// Unlike the planner (which forces ProductionTier true and splits dev/prod
	// downstream), triage prices against the finding's REAL exposure: the
	// wait/ignore gates hinge on whether policy would block it as shipped.
	decision := fleet.Materiality(fleet.MaterialityInput{
		Severity:       c.Severity,
		EPSSPercentile: c.EPSSPercentile,
		KEV:            c.RiskFactors.KnownExploited,
		Layer:          c.Layer,
		HasFix:         strings.TrimSpace(c.FixedVersion) != "",
		ProductionTier: c.ProductionTargetCount > 0,
	}, policy)

	av := prober.probe(c)
	options, recommended := triageRouteOptions(c, policy, decision, av, now)
	return TriageFinding{
		CVE:              c.CVE,
		Package:          c.Package,
		InstalledVersion: c.InstalledVersion,
		FixedVersion:     c.FixedVersion,
		Severity:         strings.ToLower(c.Severity),
		Exposure:         triageExposure(c),
		Materiality:      &TriageMateriality{Disposition: string(decision.Disposition), Reason: decision.Reason},
		Probe:            av,
		Options:          options,
		RecommendedRoute: recommended,
	}
}

func triageExposure(c RemediationCampaign) *TriageExposure {
	seen := map[string]bool{}
	tiers := []string{}
	for _, target := range c.AffectedTargets {
		if target.Tier == "" || seen[target.Tier] {
			continue
		}
		seen[target.Tier] = true
		tiers = append(tiers, target.Tier)
	}
	sort.Strings(tiers)
	return &TriageExposure{Production: c.ProductionTargetCount > 0, Tiers: tiers}
}

// triageRouteOptions prices the six routes for one finding and picks the
// recommended one. Deterministic, no LLM anywhere (design decision D5): the
// inputs are the campaign, the risk policy, the static classification, and the
// probe snapshot; a nil probe collapses everything to the static classifier so
// triage is never less available than today's planning.
func triageRouteOptions(c RemediationCampaign, policy fleet.RemediationPolicy, decision fleet.RiskDecision, av *fixprobe.Availability, now time.Time) ([]RouteOption, string) {
	staticRoute, staticReason := c.RecommendedRoute, c.RouteReason
	kev := c.RiskFactors.KnownExploited
	hasFix := strings.TrimSpace(c.FixedVersion) != ""
	pinKnown := av != nil && av.Refs[0].Error == ""
	pinHasFix := pinKnown && av.PinHasFix
	var cachedFix, uncachedFix *fixprobe.RefStatus
	if av != nil {
		for i := 1; i < len(av.Refs); i++ {
			ref := av.Refs[i]
			if !ref.HasFix {
				continue
			}
			if ref.HydraCached && cachedFix == nil {
				cachedFix = &av.Refs[i]
			}
			if !ref.HydraCached && uncachedFix == nil {
				uncachedFix = &av.Refs[i]
			}
		}
	}
	pinRetirement := &Retirement{Kind: retirementPinCarriesFix, Package: c.Package, Version: c.FixedVersion}

	sub := RouteOption{Route: RouteSubstituteVEX, CostNow: triageCostSubstitutable, RiskCarried: triageRiskNone}
	if staticRoute == RouteSubstituteVEX {
		sub.Available = true
		sub.Why = staticReason
		sub.Retirement = pinRetirement
	} else {
		sub.Why = "not a provenance-allowlisted crypto finding; the substitute+VEX bridge does not apply"
	}

	bump := RouteOption{Route: RouteVersionBump, CostNow: triageCostSubstitutable, RiskCarried: triageRiskNone}
	switch {
	case pinHasFix:
		bump.Available = true
		bump.Why = fmt.Sprintf("the pin already carries %s (>= fix %s); a normal bump closes the finding", av.Refs[0].Version, c.FixedVersion)
	case pinKnown:
		pinVersion := av.Refs[0].Version
		if pinVersion == "" {
			pinVersion = "an indeterminate version"
		}
		bump.Why = fmt.Sprintf("the pin still builds %s, below the scanner fix %s", pinVersion, c.FixedVersion)
	case hasFix:
		bump.Available = true
		bump.Why = fmt.Sprintf("scanner reports fixed version %s; probe unavailable, assuming the pinned channel carries it (static classification)", c.FixedVersion)
	default:
		bump.Why = "no fixed version is available to bump to"
	}

	optin := RouteOption{Route: RouteUnstableOptIn, CostNow: triageCostScopedRebuild, RiskCarried: triageRiskNone}
	switch {
	case cachedFix != nil:
		optin.Available = true
		optin.Why = fmt.Sprintf("%s (Hydra-cached) carries %s; scope %s to that ref", cachedFix.Ref, cachedFix.Version, c.Package)
		optin.Retirement = pinRetirement
	case staticRoute == RouteUnstableOptIn:
		optin.Available = true
		optin.Why = staticReason
		optin.Retirement = pinRetirement
	case av != nil:
		optin.Why = "no Hydra-cached ref carries the fix yet"
	default:
		optin.Why = "probe unavailable and no committed soft opt-in covers this finding"
	}

	rebuild := RouteOption{Route: RouteFetchpatchRebuild, CostNow: triageCostColdBuild, RiskCarried: triageRiskNone}
	churn := av != nil && av.OverrideRisk != nil && av.OverrideRisk.Level == fixprobe.RiskHigh
	if churn {
		rebuild.RiskCarried = triageRiskOverrideChurn
	}
	switch {
	case pinKnown && pinHasFix:
		rebuild.Why = "the pin already carries the fix; no bespoke rebuild needed"
	case pinKnown && hasFix:
		rebuild.Available = true
		rebuild.Why = fmt.Sprintf("upstream fix %s exists but the pin lacks it; rebuild from source via an in-place override", c.FixedVersion)
		if churn {
			rebuild.Why += " — flagged: " + av.OverrideRisk.Reason
		}
		rebuild.Retirement = pinRetirement
	case staticRoute == RouteFetchpatchRebuild:
		rebuild.Available = true
		rebuild.Why = staticReason
		rebuild.Retirement = pinRetirement
	default:
		rebuild.Why = "a bespoke rebuild is only offered when the probe confirms the pin lacks the fix (crypto no-fix findings excepted)"
	}

	wait := RouteOption{Route: RouteWait, CostNow: triageCostNone, RiskCarried: triageRiskUntilRefLands}
	switch {
	case av == nil:
		wait.Why = "probe unavailable; wait requires seeing the fix progress on an uncached ref"
	case uncachedFix == nil:
		wait.Why = "no uncached ref (master/staging-next) shows the fix progressing"
	case kev:
		wait.Why = "KEV finding: a known-exploited CVE never gets a bare wait"
	case !fleet.SeverityAtLeast(policy.WaitMaxSeverity, c.Severity):
		wait.Why = fmt.Sprintf("severity %s is above the wait ceiling (%s)", strings.ToLower(c.Severity), policy.WaitMaxSeverity)
	case decision.Disposition == fleet.DispositionMustFix:
		wait.Why = "policy blocks: an in-scope, fixable production finding must be fixed, not waited out"
	default:
		wait.Available = true
		wait.Why = fmt.Sprintf("fix %s is on %s (uncached) and severity %s is at/below the wait ceiling (%s)", uncachedFix.Version, uncachedFix.Ref, strings.ToLower(c.Severity), policy.WaitMaxSeverity)
		// The policy is normalized by the caller, so nil only means a raw
		// policy leaked in — fall back to the default rather than panic.
		waitDays := 30
		if policy.WaitMaxDays != nil {
			waitDays = *policy.WaitMaxDays
		}
		wait.Retirement = &Retirement{
			Kind:    retirementRefCarriesFix,
			Package: c.Package,
			Version: c.FixedVersion,
			Ref:     triageWatchRef(av),
			Expires: now.AddDate(0, 0, waitDays).Format("2006-01-02"),
		}
	}

	ignore := RouteOption{Route: RouteScannerIgnore, CostNow: triageCostNone, RiskCarried: triageRiskUntilExpiry}
	switch {
	case kev:
		ignore.Why = "KEV finding: never ignorable"
	case decision.Disposition == fleet.DispositionMustFix:
		ignore.Why = "policy blocks: reachable, materially risky, and fixable in a production tier"
	default:
		ignore.Available = true
		ignore.Why = fmt.Sprintf("policy permits an owned, expiring suppression (%s: %s)", decision.Disposition, decision.Reason)
		ignore.Retirement = &Retirement{Kind: retirementExpiry, Expires: now.AddDate(0, 0, policy.AcceptedExpiryDays).Format("2006-01-02")}
	}

	options := []RouteOption{sub, bump, optin, rebuild, wait, ignore}
	recommended := recommendTriageRoute(options, staticRoute, policy, av == nil)
	if idx := triageOptionIndex(options, recommended); idx >= 0 {
		options[idx].Recommended = true
	}
	return options, recommended
}

// recommendTriageRoute picks the route to flag: prefer no-cost substitutable
// routes, then the cached pin-hop, then a rebuild, then wait/ignore (which are
// only available when policy would not block). preferSubstitutable breaks the
// pin-hop-vs-rebuild tie. A degraded probe collapses to the static
// classifier's answer — never worse than probe-less planning.
func recommendTriageRoute(options []RouteOption, staticRoute string, policy fleet.RemediationPolicy, degraded bool) string {
	if degraded {
		if idx := triageOptionIndex(options, staticRoute); idx >= 0 && options[idx].Available {
			return staticRoute
		}
	}
	preference := []string{RouteSubstituteVEX, RouteVersionBump, RouteUnstableOptIn, RouteFetchpatchRebuild, RouteWait, RouteScannerIgnore}
	if policy.PreferSubstitutable != nil && !*policy.PreferSubstitutable {
		preference = []string{RouteSubstituteVEX, RouteVersionBump, RouteFetchpatchRebuild, RouteUnstableOptIn, RouteWait, RouteScannerIgnore}
	}
	for _, route := range preference {
		if idx := triageOptionIndex(options, route); idx >= 0 && options[idx].Available {
			return route
		}
	}
	return ""
}

func triageOptionIndex(options []RouteOption, route string) int {
	for i := range options {
		if options[i].Route == route {
			return i
		}
	}
	return -1
}

// triageWatchRef picks the cached ref a wait decision watches: the first
// channel that does not yet carry the fix (the one that will graduate the
// wait), else the first channel in the sweep.
func triageWatchRef(av *fixprobe.Availability) string {
	fallback := ""
	for i := 1; i < len(av.Refs); i++ {
		ref := av.Refs[i]
		if ref.Kind != fixprobe.RefKindChannel {
			continue
		}
		if fallback == "" {
			fallback = ref.Ref
		}
		if !ref.HasFix {
			return ref.Ref
		}
	}
	if fallback == "" {
		return "nixos-unstable"
	}
	return fallback
}

func applyTriageDecision(f *TriageFinding, o remediationTriageFlags, coreDir string, now time.Time, w io.Writer) error {
	route := strings.TrimSpace(o.decide)
	idx := triageOptionIndex(f.Options, route)
	if idx < 0 {
		return fmt.Errorf("--decide %q is not a known route (version_bump, substitute_vex, unstable_optin, fetchpatch_rebuild, scanner_ignore, wait)", route)
	}
	option := f.Options[idx]
	if !option.Available {
		return fmt.Errorf("route %s is not available for %s (%s): %s", route, f.CVE, f.Package, option.Why)
	}
	if strings.TrimSpace(o.owner) == "" || strings.TrimSpace(o.reason) == "" {
		return fmt.Errorf("--decide requires --owner and --reason so the decision is never silent")
	}
	if o.expires != "" {
		if _, err := time.Parse("2006-01-02", o.expires); err != nil {
			return fmt.Errorf("--expires must be YYYY-MM-DD: %w", err)
		}
	}
	if coreDir == "" {
		return fmt.Errorf("could not locate ClearCutt core workspace; pass --core-dir to record the decision")
	}

	retirement := cloneTriageRetirement(option.Retirement)
	if o.expires != "" && retirement != nil {
		if retirement.Kind == retirementExpiry {
			retirement = &Retirement{Kind: retirementExpiry, Expires: o.expires}
		} else {
			retirement.Expires = o.expires
		}
	}
	decidedBy := strings.TrimSpace(o.decidedBy)
	if decidedBy == "" {
		decidedBy = "human"
	}
	triage := triageEvidence{
		SchemaVersion: TriageSchemaVersion,
		Route:         route,
		DecidedBy:     decidedBy,
		DecidedAt:     now.Format(time.RFC3339),
		Retirement:    retirement,
		Probe:         f.Probe,
	}

	switch route {
	case RouteScannerIgnore:
		if strings.TrimSpace(f.InstalledVersion) == "" {
			return fmt.Errorf("installed version unknown for %s (%s); use `clearcutt remediation ignore --version` directly", f.CVE, f.Package)
		}
		expires := o.expires
		if expires == "" && retirement != nil {
			expires = retirement.Expires
		}
		if err := runRemediationIgnoreWith(remediationIgnoreFlags{
			cve:      f.CVE,
			pkg:      f.Package,
			versions: []string{f.InstalledVersion},
			pkgType:  "UnknownPackage",
			reason:   o.reason,
			owner:    o.owner,
			expires:  expires,
			coreDir:  coreDir,
		}, &triage, w); err != nil {
			return err
		}
	case RouteWait:
		path, err := writeTriageDecisionRecord(coreDir, f, o, "triage_wait", triage)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "[triage] wait decision -> %s (retires when %s carries %s; expiry backstop %s)\n", path, retirement.Ref, retirement.Version, retirement.Expires)
	case RouteUnstableOptIn:
		path, err := writeTriageDecisionRecord(coreDir, f, o, "triage_decided", triage)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "[triage] pin-hop decision -> %s\n", path)
		// v1 records the decision and emits the exact snippet instead of
		// rewriting clearcutt.fleet.yaml (comment-preserving YAML surgery is
		// deferred; the snippet + record keep the action auditable).
		fmt.Fprintf(w, "[triage] add this to clearcutt.fleet.yaml:\n%s", unstableOptInSnippet(f, o))
	default:
		path, err := writeTriageDecisionRecord(coreDir, f, o, "triage_decided", triage)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "[triage] decision recorded -> %s\n", path)
		fmt.Fprintf(w, "[triage] hand-off: run `clearcutt remediation run --package %s --cve %s` to draft the mechanical change\n", f.Package, f.CVE)
	}

	f.Decision = &TriageDecision{
		Route:      route,
		DecidedBy:  decidedBy,
		DecidedAt:  triage.DecidedAt,
		Owner:      o.owner,
		Reason:     o.reason,
		Retirement: retirement,
	}
	return nil
}

func cloneTriageRetirement(r *Retirement) *Retirement {
	if r == nil {
		return nil
	}
	clone := *r
	return &clone
}

func triageDecisionRecordPath(coreDir, cve, packageName string) string {
	slug := campaignSlug(RemediationCampaign{CVE: cve, Package: packageName})
	return filepath.Join(coreDir, "overlays", "cve", slug+".decision.evidence.json")
}

func writeTriageDecisionRecord(coreDir string, f *TriageFinding, o remediationTriageFlags, status string, triage triageEvidence) (string, error) {
	path := triageDecisionRecordPath(coreDir, f.CVE, f.Package)
	record := triageDecisionRecord{
		SchemaVersion:    "clearcutt.remediation.evidence/v1",
		Status:           status,
		CVE:              f.CVE,
		Package:          f.Package,
		InstalledVersion: f.InstalledVersion,
		FixedVersion:     f.FixedVersion,
		Owner:            o.owner,
		Reason:           o.reason,
		GeneratedBy:      "clearcutt remediation triage",
		Triage:           triage,
	}
	if err := writeRemediationJSONFile(path, record); err != nil {
		return "", fmt.Errorf("write decision record %s: %w", path, err)
	}
	return path, nil
}

// unstableOptInSnippet renders the exact remediation.unstable.softOptIns entry
// the operator pastes; field order matches the examples in fleet docs.
func unstableOptInSnippet(f *TriageFinding, o remediationTriageFlags) string {
	ref := triageCachedFixRef(f.Probe)
	if ref == "" {
		ref = "nixos-unstable"
	}
	var b strings.Builder
	b.WriteString("remediation:\n")
	b.WriteString("  unstable:\n")
	b.WriteString("    softOptIns:\n")
	fmt.Fprintf(&b, "      - package: %s\n", f.Package)
	fmt.Fprintf(&b, "        ref: %s\n", ref)
	fmt.Fprintf(&b, "        reason: %q\n", o.reason)
	fmt.Fprintf(&b, "        owner: %q\n", o.owner)
	b.WriteString("        fixes:\n")
	fmt.Fprintf(&b, "          - cve: %s\n", f.CVE)
	if f.InstalledVersion != "" {
		fmt.Fprintf(&b, "            installedVersion: %s\n", f.InstalledVersion)
	}
	if f.FixedVersion != "" {
		fmt.Fprintf(&b, "            fixedVersion: %s\n", f.FixedVersion)
	}
	return b.String()
}

func triageCachedFixRef(av *fixprobe.Availability) string {
	if av == nil {
		return ""
	}
	for i := 1; i < len(av.Refs); i++ {
		if av.Refs[i].HasFix && av.Refs[i].HydraCached {
			return av.Refs[i].Ref
		}
	}
	return ""
}

func printTriageReportTable(report *TriageReport) error {
	if report.Degraded {
		fmt.Fprintln(out, "Triage (probe degraded: recommendations follow the static route classifier)")
	} else {
		fmt.Fprintln(out, "Triage")
	}
	if len(report.Findings) == 0 {
		fmt.Fprintln(out, "No findings in scope.")
		return nil
	}
	for i := range report.Findings {
		f := &report.Findings[i]
		fmt.Fprintf(out, "\n%s %s %s -> %s  severity=%s  exposure=%s  disposition=%s\n",
			f.CVE, f.Package,
			triageOrDash(f.InstalledVersion), triageOrDash(f.FixedVersion),
			f.Severity, renderTriageExposure(f.Exposure), renderTriageMateriality(f.Materiality))
		if f.Probe != nil {
			fmt.Fprintf(out, "probe: %s\n", renderTriageProbeSummary(f.Probe))
		}
		tp := output.NewTablePrinter("", "ROUTE", "AVAILABLE", "COST NOW", "RISK CARRIED", "RETIRES", "WHY")
		for _, option := range f.Options {
			marker := " "
			if option.Recommended {
				marker = "▸"
			}
			available := "no"
			if option.Available {
				available = "yes"
			}
			tp.AddRow(marker, option.Route, available, option.CostNow, option.RiskCarried, renderTriageRetirement(option.Retirement), option.Why)
		}
		if err := tp.Print(out); err != nil {
			return err
		}
		if f.RecommendedRoute == "" {
			fmt.Fprintln(out, "no route available under policy — escalate")
		}
		if f.Decision != nil {
			fmt.Fprintf(out, "decided: %s by %s (owner %s)\n", f.Decision.Route, f.Decision.DecidedBy, f.Decision.Owner)
		}
	}
	return nil
}

func triageOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func renderTriageExposure(e *TriageExposure) string {
	if e == nil {
		return "-"
	}
	scope := "dev-only"
	if e.Production {
		scope = "production"
	}
	if len(e.Tiers) == 0 {
		return scope
	}
	return scope + "(" + strings.Join(e.Tiers, ",") + ")"
}

func renderTriageMateriality(m *TriageMateriality) string {
	if m == nil {
		return "-"
	}
	return m.Disposition + "(" + m.Reason + ")"
}

func renderTriageProbeSummary(av *fixprobe.Availability) string {
	parts := make([]string, 0, len(av.Refs))
	for i, ref := range av.Refs {
		name := ref.Ref
		if i == 0 {
			name = "pin"
			// A dedicated pin is named so the reader knows which pin the
			// retirement predicate speaks for.
			if av.PinName != "" && av.PinName != "nixpkgs" {
				name = "pin(" + av.PinName + ")"
			}
		}
		switch {
		case ref.Error != "":
			parts = append(parts, name+" !error")
		case ref.HasFix && ref.HydraCached:
			parts = append(parts, name+" ✓ cached")
		case ref.HasFix:
			parts = append(parts, name+" ✓ uncached")
		default:
			parts = append(parts, name+" ✗")
		}
	}
	summary := strings.Join(parts, " · ")
	if av.OverrideRisk != nil {
		summary += "  override-risk=" + av.OverrideRisk.Level
	}
	return summary
}

func renderTriageRetirement(r *Retirement) string {
	if r == nil {
		return "-"
	}
	switch r.Kind {
	case retirementPinCarriesFix:
		if r.Version == "" {
			return "pin carries fix"
		}
		return "pin >= " + r.Version
	case retirementRefCarriesFix:
		rendered := r.Ref + " >= " + r.Version
		if r.Expires != "" {
			rendered += " (by " + r.Expires + ")"
		}
		return rendered
	case retirementExpiry:
		return "expires " + r.Expires
	}
	return r.Kind
}
