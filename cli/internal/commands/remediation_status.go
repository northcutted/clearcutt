package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/northcutted/clearcutt/internal/fixprobe"
	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
)

// RemediationStatusReport is the machine-readable ledger `remediation status`
// emits with --format json/yaml: every carried decision plus, with
// --check-retirements, the conditions that fired.
type RemediationStatusReport struct {
	GeneratedAt string                        `json:"generatedAt"`
	Entries     []RemediationStatusEntry      `json:"entries"`
	Fired       []RemediationRetirementFiring `json:"fired,omitempty"`
}

// RemediationStatusEntry is one carried decision: what we carry, from which
// governance surface, why (route), and when it retires.
type RemediationStatusEntry struct {
	Source           string      `json:"source"` // overlay | ignore | decision | fleet | crypto
	CVE              string      `json:"cve,omitempty"`
	Package          string      `json:"package,omitempty"`
	Route            string      `json:"route,omitempty"`
	Owner            string      `json:"owner,omitempty"`
	State            string      `json:"state"` // active | waiting | expired | retire | act
	InstalledVersion string      `json:"installedVersion,omitempty"`
	FixedVersion     string      `json:"fixedVersion,omitempty"`
	Retirement       *Retirement `json:"retirement,omitempty"`
	Path             string      `json:"path,omitempty"`
}

// RemediationRetirementFiring is one retirement condition that holds NOW —
// the hook a scheduled workflow turns into a retirement PR.
type RemediationRetirementFiring struct {
	Action  string `json:"action"` // retire | act | expired
	CVE     string `json:"cve,omitempty"`
	Package string `json:"package,omitempty"`
	Kind    string `json:"kind"`
	Detail  string `json:"detail"`
}

type remediationStatusFlags struct {
	coreDir          string
	overlayDir       string
	fleetConfig      string
	checkRetirements bool
	strict           bool
}

var remediationStatusOpts remediationStatusFlags

// NewRemediationStatusCmd builds `clearcutt remediation status`: the ledger of
// every carried CVE decision (overlay evidence, scanner suppressions, triage
// decision records, fleet soft opt-ins, crypto allowlist entries) and the
// evaluator of their recorded retirement conditions.
func NewRemediationStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "List every carried CVE decision and evaluate its retirement condition",
		Long: `Aggregates all carried remediation decisions — CVE overlay evidence, tracked
scanner suppressions, triage decision records, fleet unstable soft opt-ins, and
crypto allowlist entries — into one ledger: what we carry, why, and when it
retires. With --check-retirements each recorded condition is evaluated now
(pin_carries_fix and ref_carries_fix via the fix-availability probe, expiry by
date); fired conditions print an action line and, with --strict, exit 2.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemediationStatus()
		},
	}
	f := cmd.Flags()
	f.StringVar(&remediationStatusOpts.coreDir, "core-dir", "", "Core workspace directory (auto-detected when omitted)")
	f.StringVar(&remediationStatusOpts.overlayDir, "overlay-dir", "", "Directory containing CVE overlay/ignore/decision evidence (defaults to <core-dir>/overlays/cve)")
	f.StringVar(&remediationStatusOpts.fleetConfig, "fleet-config", "", "Path to clearcutt.fleet.yaml (auto-detected when omitted)")
	f.BoolVar(&remediationStatusOpts.checkRetirements, "check-retirements", false, "Evaluate each recorded retirement condition now (probes nixpkgs)")
	f.BoolVar(&remediationStatusOpts.strict, "strict", false, "Exit 2 when any retirement condition fired")
	return cmd
}

func runRemediationStatus() error {
	o := remediationStatusOpts
	now := time.Now().UTC()

	coreDir := o.coreDir
	if coreDir == "" {
		if resolved, err := resolveCoreDir(""); err == nil {
			coreDir = resolved
		}
	}
	overlayDir := o.overlayDir
	if overlayDir == "" {
		if coreDir == "" {
			return fmt.Errorf("could not locate ClearCutt core workspace; pass --core-dir or --overlay-dir")
		}
		overlayDir = filepath.Join(coreDir, "overlays", "cve")
	}
	fleetPath := triageFleetConfigPath(o.fleetConfig, coreDir)

	entries, err := gatherStatusEvidenceEntries(overlayDir, now)
	if err != nil {
		return err
	}
	if cfg, err := fleet.Load(fleetPath); err == nil {
		entries = append(entries, statusFleetOptInEntries(cfg.Remediation.Unstable.SoftOptIns)...)
	}
	if coreDir != "" {
		entries = append(entries, statusCryptoAllowlistEntries(filepath.Join(coreDir, "tests", "runtime-dep-floor.json"))...)
	}

	report := RemediationStatusReport{
		GeneratedAt: now.Format(time.RFC3339),
		Entries:     entries,
	}
	if o.checkRetirements {
		if coreDir == "" {
			return fmt.Errorf("--check-retirements needs the core workspace for the pin lock; pass --core-dir")
		}
		report.Fired = checkStatusRetirements(report.Entries, coreDir, now)
	}

	firedOut := out
	if structuredFormat() {
		firedOut = errOut
		if err := printStructured(report); err != nil {
			return err
		}
	} else if err := printRemediationStatusTable(&report); err != nil {
		return err
	}
	for _, fired := range report.Fired {
		fmt.Fprintf(firedOut, "[retirement] %s: %s (%s) %s — %s\n", fired.Action, fired.CVE, fired.Package, fired.Kind, fired.Detail)
	}

	if o.strict && len(report.Fired) > 0 {
		return ErrCheckFailed
	}
	return nil
}

// gatherStatusEvidenceEntries reads every *.evidence.json under the overlay
// dir and classifies by filename suffix. The ledger is a read surface, not a
// gate: a malformed file is warned about and skipped; validate-overlays owns
// rejecting it.
func gatherStatusEvidenceEntries(overlayDir string, now time.Time) ([]RemediationStatusEntry, error) {
	files, err := filepath.Glob(filepath.Join(overlayDir, "*.evidence.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to list remediation evidence: %w", err)
	}
	sort.Strings(files)
	entries := []RemediationStatusEntry{}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(errOut, "[status] skipping %s: %v\n", path, err)
			continue
		}
		var data map[string]any
		if err := json.Unmarshal(raw, &data); err != nil {
			fmt.Fprintf(errOut, "[status] skipping %s: %v\n", path, err)
			continue
		}
		entries = append(entries, statusEvidenceEntry(path, data, now))
	}
	return entries, nil
}

func statusEvidenceEntry(path string, data map[string]any, now time.Time) RemediationStatusEntry {
	source := "overlay"
	switch {
	case strings.HasSuffix(path, ".ignore.evidence.json"):
		source = "ignore"
	case strings.HasSuffix(path, ".decision.evidence.json"):
		source = "decision"
	}
	route, retirement := statusTriageBlock(data)
	if route == "" {
		route = evidenceField(data, "route")
	}
	if route == "" && source == "ignore" {
		route = RouteScannerIgnore
	}
	// A bare expires field (pre-triage ignore/overlay evidence) is an expiry
	// retirement in all but name; surface it so the sweep can evaluate it.
	if retirement == nil {
		if expires := evidenceField(data, "expires"); expires != "" {
			retirement = &Retirement{Kind: retirementExpiry, Expires: expires}
		}
	}
	entry := RemediationStatusEntry{
		Source:           source,
		CVE:              evidenceField(data, "cve"),
		Package:          evidenceField(data, "package"),
		Route:            route,
		Owner:            evidenceField(data, "owner"),
		InstalledVersion: evidenceField(data, "installedVersion"),
		FixedVersion:     evidenceField(data, "fixedVersion"),
		Retirement:       retirement,
		Path:             path,
	}
	entry.State = statusEntryState(evidenceField(data, "status"), retirement, now)
	return entry
}

func statusTriageBlock(data map[string]any) (string, *Retirement) {
	triage, ok := data["triage"].(map[string]any)
	if !ok {
		return "", nil
	}
	route := evidenceField(triage, "route")
	retirementData, ok := triage["retirement"].(map[string]any)
	if !ok {
		return route, nil
	}
	return route, &Retirement{
		Kind:    evidenceField(retirementData, "kind"),
		Package: evidenceField(retirementData, "package"),
		Version: evidenceField(retirementData, "version"),
		Ref:     evidenceField(retirementData, "ref"),
		Expires: evidenceField(retirementData, "expires"),
	}
}

func statusEntryState(status string, retirement *Retirement, now time.Time) string {
	if retirement != nil && retirement.Expires != "" {
		if expires, err := time.Parse("2006-01-02", retirement.Expires); err == nil && !expires.After(truncateDate(now)) {
			return "expired"
		}
	}
	if strings.EqualFold(status, "triage_wait") {
		return "waiting"
	}
	return "active"
}

func statusFleetOptInEntries(optIns []fleet.RemediationUnstableOptIn) []RemediationStatusEntry {
	entries := []RemediationStatusEntry{}
	for _, optIn := range optIns {
		if strings.TrimSpace(optIn.Package) == "" {
			continue
		}
		if len(optIn.Fixes) == 0 {
			entries = append(entries, RemediationStatusEntry{
				Source:     "fleet",
				Package:    optIn.Package,
				Route:      RouteUnstableOptIn,
				Owner:      optIn.Owner,
				State:      "active",
				Retirement: &Retirement{Kind: retirementPinCarriesFix, Package: optIn.Package},
			})
			continue
		}
		for _, fix := range optIn.Fixes {
			entries = append(entries, RemediationStatusEntry{
				Source:           "fleet",
				CVE:              fix.CVE,
				Package:          optIn.Package,
				Route:            RouteUnstableOptIn,
				Owner:            optIn.Owner,
				State:            "active",
				InstalledVersion: fix.InstalledVersion,
				FixedVersion:     fix.FixedVersion,
				Retirement:       &Retirement{Kind: retirementPinCarriesFix, Package: optIn.Package, Version: fix.FixedVersion},
			})
		}
	}
	return entries
}

func statusCryptoAllowlistEntries(path string) []RemediationStatusEntry {
	allowlist, err := loadCryptoAllowlistFile(path)
	if err != nil {
		return nil
	}
	entries := []RemediationStatusEntry{}
	for _, dep := range allowlist.Deps {
		if strings.TrimSpace(dep.CVE) == "" {
			continue
		}
		// The allowlist records the patched identity, not the version the pin
		// must reach to retire it — so the retirement carries no version and
		// the sweep reports it as informational only.
		entries = append(entries, RemediationStatusEntry{
			Source:     "crypto",
			CVE:        dep.CVE,
			Package:    dep.Name,
			Route:      RouteSubstituteVEX,
			State:      "active",
			Retirement: &Retirement{Kind: retirementPinCarriesFix, Package: dep.Name},
			Path:       path,
		})
	}
	return entries
}

// checkStatusRetirements evaluates every recorded retirement condition NOW.
// pin_carries_fix probes the CURRENT pin in core/flake.lock (has the pin
// caught up?), ref_carries_fix probes the watched cached ref, and any recorded
// expires date acts as a backstop regardless of kind. Probe failures are
// warned, not fired: a rate-limited sweep must not fabricate retirements.
func checkStatusRetirements(entries []RemediationStatusEntry, coreDir string, now time.Time) []RemediationRetirementFiring {
	fetcher := triageNewFetcher()
	pins, pinErr := loadTriagePinMap(coreDir)
	positions := map[string]string{}
	resolveSource := func(pkg string) (string, bool) {
		if cached, ok := positions[pkg]; ok {
			return cached, cached != ""
		}
		position, err := triageResolveSourcePath(coreDir, pkg)
		if err != nil {
			fmt.Fprintf(errOut, "[status] retirement check skipped for %s: %v\n", pkg, err)
			position = ""
		}
		positions[pkg] = position
		return position, position != ""
	}

	fired := []RemediationRetirementFiring{}
	for i := range entries {
		entry := &entries[i]
		retirement := entry.Retirement
		if retirement == nil {
			continue
		}
		if retirement.Expires != "" {
			if expires, err := time.Parse("2006-01-02", retirement.Expires); err == nil && !expires.After(truncateDate(now)) {
				fired = append(fired, RemediationRetirementFiring{
					Action:  "expired",
					CVE:     entry.CVE,
					Package: entry.Package,
					Kind:    retirement.Kind,
					Detail:  fmt.Sprintf("expired %s — renew or remove", retirement.Expires),
				})
				entry.State = "expired"
				if retirement.Kind == retirementExpiry {
					continue
				}
			}
		}
		pkg := retirement.Package
		if pkg == "" {
			pkg = entry.Package
		}
		version := retirement.Version
		if version == "" {
			version = entry.FixedVersion
		}
		// The extractor anchors multi-version files to the installed line;
		// the fix version shares that line when the installed one is unknown.
		anchor := entry.InstalledVersion
		if anchor == "" {
			anchor = version
		}

		switch retirement.Kind {
		case retirementPinCarriesFix:
			if pinErr != nil {
				fmt.Fprintf(errOut, "[status] retirement check skipped for %s (%s): %v\n", entry.CVE, pkg, pinErr)
				continue
			}
			if pkg == "" || version == "" {
				continue
			}
			position, ok := resolveSource(pkg)
			if !ok {
				continue
			}
			// pin_carries_fix means "the pin that SOURCES this package" — a
			// dedicated-pin runtime retires against its own pin, so the pin is
			// attributed at check time, not read from the recorded condition.
			pinName, pinRev := pins.attribute(nixpkgsStoreSource(position))
			ref, err := probeStatusRef(fetcher, nixpkgsSourcePath(position), pinRev, anchor, version)
			if err != nil {
				fmt.Fprintf(errOut, "[status] retirement check failed for %s (%s): %v\n", entry.CVE, pkg, err)
				continue
			}
			if ref.HasFix {
				fired = append(fired, RemediationRetirementFiring{
					Action:  "retire",
					CVE:     entry.CVE,
					Package: pkg,
					Kind:    retirement.Kind,
					Detail:  fmt.Sprintf("pin %s now carries %s (>= %s): drop the overlay/opt-in", pinName, ref.Version, version),
				})
				entry.State = "retire"
			}
		case retirementRefCarriesFix:
			if pkg == "" || version == "" || retirement.Ref == "" {
				continue
			}
			position, ok := resolveSource(pkg)
			if !ok {
				continue
			}
			ref, err := probeStatusRef(fetcher, nixpkgsSourcePath(position), retirement.Ref, anchor, version)
			if err != nil {
				fmt.Fprintf(errOut, "[status] retirement check failed for %s (%s): %v\n", entry.CVE, pkg, err)
				continue
			}
			if ref.HasFix {
				fired = append(fired, RemediationRetirementFiring{
					Action:  "act",
					CVE:     entry.CVE,
					Package: pkg,
					Kind:    retirement.Kind,
					Detail:  fmt.Sprintf("%s now carries %s (>= %s): pin-hop available, graduate the wait", retirement.Ref, ref.Version, version),
				})
				entry.State = "act"
			}
		}
	}
	return fired
}

// probeStatusRef asks the probe about exactly one ref: the ref rides the pin
// slot (always probed first) and empty Refs means pin-only probing.
func probeStatusRef(fetcher fixprobe.Fetcher, sourcePath, ref, anchorVersion, fixedVersion string) (fixprobe.RefStatus, error) {
	availability, err := fixprobe.Probe(context.Background(), fetcher, fixprobe.Input{
		SourcePath:       sourcePath,
		PinRev:           ref,
		InstalledVersion: anchorVersion,
		FixedVersion:     fixedVersion,
	})
	if err != nil {
		return fixprobe.RefStatus{}, err
	}
	status := availability.Refs[0]
	if status.Error != "" {
		return status, errors.New(status.Error)
	}
	return status, nil
}

func printRemediationStatusTable(report *RemediationStatusReport) error {
	if len(report.Entries) == 0 {
		fmt.Fprintln(out, "No carried remediation decisions found.")
		return nil
	}
	tp := output.NewTablePrinter("SOURCE", "CVE", "PACKAGE", "ROUTE", "RETIRES", "STATE")
	for _, entry := range report.Entries {
		tp.AddRow(
			entry.Source,
			triageOrDash(entry.CVE),
			triageOrDash(entry.Package),
			triageOrDash(entry.Route),
			renderTriageRetirement(entry.Retirement),
			entry.State,
		)
	}
	return tp.Print(out)
}
