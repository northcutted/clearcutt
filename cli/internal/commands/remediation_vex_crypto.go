package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/northcutted/clearcutt/internal/fleet"
	"github.com/spf13/cobra"
)

// Phase 3 of the crypto-CVE provenance reshape: auto-VEX the scanner version
// gap. When the pin's patched openssl/sqlite reads an old version string
// (patched-not-bumped), a version-keyed scanner like Grype false-positives on
// the CVE even though the upstream fix is present. This command turns the
// known-good crypto identity allowlist (runtime-dep-floor.json) into an OpenVEX
// `not_affected` statement per crypto CVE — justification
// `vulnerable_code_not_present`, with the store-path provenance as evidence —
// and (optionally) derives the .grype.yaml suppression FROM that VEX, so the
// scanner clears honestly: the ignore always has a VEX behind it, never a bare
// suppression. This supersedes `remediation ignore` for the patched-but-
// mislabeled case (keep `ignore` for the truly-no-fix case).

type remediationVexCryptoFlags struct {
	allowlist   string
	product     string
	vexOut      string
	grypeConfig string
	pkgType     string
	coreDir     string
}

var remediationVexCryptoOpts remediationVexCryptoFlags

// NewRemediationVexCryptoCmd builds `clearcutt remediation vex-crypto`.
func NewRemediationVexCryptoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vex-crypto",
		Short: "Auto-VEX the scanner version gap for provenance-allowlisted crypto (openssl/sqlite)",
		Long: `Reads the known-good crypto identity allowlist (core/tests/runtime-dep-floor.json)
and emits an OpenVEX not_affected statement per crypto CVE, justified
vulnerable_code_not_present, with the patched store-path identity + pin
provenance as evidence. Optionally derives the .grype.yaml suppression FROM the
VEX (--grype-config), so the scanner clears the patched-but-mislabeled crypto
honestly — the suppression always has a VEX behind it.

Use this for a crypto CVE that IS fixed in the pin (patched, maybe not version
bumped). Use 'remediation ignore' only for the truly-no-fix case.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemediationVexCrypto()
		},
	}
	f := cmd.Flags()
	f.StringVar(&remediationVexCryptoOpts.allowlist, "allowlist", "", "Path to runtime-dep-floor.json (defaults to <core-dir>/tests/runtime-dep-floor.json)")
	f.StringVar(&remediationVexCryptoOpts.product, "product", "pkg:nix/clearcutt-fleet", "OpenVEX product @id the statements are about")
	f.StringVar(&remediationVexCryptoOpts.vexOut, "vex-out", "", "Write the OpenVEX document to this path (stdout when omitted)")
	f.StringVar(&remediationVexCryptoOpts.grypeConfig, "grype-config", "", "Also derive the .grype.yaml suppression from the VEX at this path")
	f.StringVar(&remediationVexCryptoOpts.pkgType, "type", "binary", "Grype package type for the derived suppression")
	f.StringVar(&remediationVexCryptoOpts.coreDir, "core-dir", "", "Core workspace directory (auto-detected when omitted)")
	return cmd
}

func runRemediationVexCrypto() error {
	o := remediationVexCryptoOpts
	coreDir := o.coreDir
	if coreDir == "" {
		resolved, err := resolveCoreDir("")
		if err != nil {
			return err
		}
		coreDir = resolved
	}
	allowlistPath := o.allowlist
	if allowlistPath == "" {
		allowlistPath = filepath.Join(coreDir, "tests", "runtime-dep-floor.json")
	}

	allowlist, err := loadCryptoAllowlistFile(allowlistPath)
	if err != nil {
		return err
	}

	doc, ignoreRules, err := buildCryptoVex(allowlist, o.product, o.pkgType, time.Now().UTC())
	if err != nil {
		return err
	}
	if len(doc.Statements) == 0 {
		return fmt.Errorf("no crypto CVE found in %s: every tracked dep needs a 'cve' to VEX", allowlistPath)
	}

	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encode OpenVEX: %w", err)
	}
	if o.vexOut != "" {
		if dir := filepath.Dir(o.vexOut); dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
		if err := os.WriteFile(o.vexOut, append(encoded, '\n'), 0o644); err != nil {
			return fmt.Errorf("write OpenVEX %s: %w", o.vexOut, err)
		}
		fmt.Fprintf(out, "[vex-crypto] wrote OpenVEX (%d statement(s)) -> %s\n", len(doc.Statements), o.vexOut)
	} else if o.grypeConfig == "" {
		out.Write(encoded)
		fmt.Fprintln(out)
	}

	if o.grypeConfig != "" {
		added, err := addGrypeIgnoreRules(o.grypeConfig, ignoreRules)
		if err != nil {
			return fmt.Errorf("derive .grype.yaml suppression from VEX: %w", err)
		}
		fmt.Fprintf(out, "[vex-crypto] %d VEX-backed suppression(s) for crypto CVE(s) -> %s\n", added, o.grypeConfig)
	}
	return nil
}

// loadCryptoAllowlistFile reads runtime-dep-floor.json into the rich allowlist
// type (CryptoAllowlistFile) — including CVE/version/provenance, which the gate
// loader does not expose.
func loadCryptoAllowlistFile(path string) (*CryptoAllowlistFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read crypto allowlist %s: %w", path, err)
	}
	var f CryptoAllowlistFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse crypto allowlist %s: %w", path, err)
	}
	if len(f.Deps) == 0 {
		return nil, fmt.Errorf("crypto allowlist %s has no deps", path)
	}
	return &f, nil
}

// buildCryptoVex turns the allowlist into one OpenVEX not_affected statement per
// crypto CVE, plus the VEX-derived grype-ignore rules (one per distinct
// reported version). Pure, so it is fully unit-testable.
func buildCryptoVex(allowlist *CryptoAllowlistFile, product, pkgType string, now time.Time) (OpenVEXDocument, []grypeIgnoreRule, error) {
	trust := strings.ToLower(strings.TrimSpace(allowlist.Trust))
	if trust == "" {
		trust = fleet.CryptoTrustNixpkgs
	}
	ts := now.Format(time.RFC3339)

	doc := OpenVEXDocument{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         fmt.Sprintf("https://clearcutt.internal/vex/crypto/%d", now.Unix()),
		Author:     "ClearCutt Security Platform Gating Engine",
		Role:       "Document Creator",
		Timestamp:  ts,
		Version:    1,
		Statements: []OpenVEXStatement{},
	}
	rules := []grypeIgnoreRule{}

	// Stable order: deps as written (generator already sorts them).
	for _, dep := range allowlist.Deps {
		cve := strings.TrimSpace(dep.CVE)
		if cve == "" {
			continue
		}
		versions := distinctVersions(dep.KnownGood)
		identities := distinctStorePaths(dep.KnownGood)

		verify := ""
		if trust == fleet.CryptoTrustReproduce {
			verify = " The patched closure is also independently rebuilt and byte-compared (cryptoTrust=reproduce)."
		}
		impact := fmt.Sprintf(
			"%s ships the upstream fix for %s. The shipped %s carries the patch via its provenance-allowlisted store identity (%s), so the vulnerable code is not present even though the version string reads %s (patched-not-bumped).%s",
			dep.Provenance, cve, dep.Name, strings.Join(identities, ", "),
			strings.Join(versions, ", "), verify,
		)

		doc.Statements = append(doc.Statements, OpenVEXStatement{
			Vulnerability:   OpenVEXVulnerability{Name: cve},
			Products:        []OpenVEXProduct{{ID: product}},
			Status:          vexNotAffected,
			Justification:   "vulnerable_code_not_present",
			ImpactStatement: impact,
			Timestamp:       ts,
		})

		// Derive the grype suppression FROM the VEX: one rule per reported
		// version so the scanner clears the patched-but-mislabeled finding.
		for _, v := range versions {
			rules = append(rules, grypeIgnoreRule{
				Vulnerability: cve,
				Package:       &grypeIgnorePkg{Name: dep.Name, Version: v, Type: pkgType},
				Reason:        fmt.Sprintf("OpenVEX not_affected/vulnerable_code_not_present: %s ships the upstream fix for %s; provenance-allowlisted patched-not-bumped build", dep.Provenance, cve),
			})
		}
	}

	return doc, rules, nil
}

func distinctVersions(known []CryptoKnownGood) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, kg := range known {
		v := strings.TrimSpace(kg.Version)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func distinctStorePaths(known []CryptoKnownGood) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, kg := range known {
		s := strings.TrimSpace(kg.StorePath)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	// Cap the evidence list so the impact statement stays readable; the full
	// set lives in the allowlist file.
	if len(out) > 4 {
		out = append(out[:4], fmt.Sprintf("+%d more", len(out)-4))
	}
	return out
}
