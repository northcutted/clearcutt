package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/spf13/cobra"
)

type remediationIgnoreFlags struct {
	cve         string
	pkg         string
	versions    []string
	pkgType     string
	reason      string
	owner       string
	expires     string
	coreDir     string
	grypeConfig string
	evidenceDir string
}

var remediationIgnoreOpts remediationIgnoreFlags

var cveIDPattern = regexp.MustCompile(`^(?i)(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})$`)

// grypeIgnoreRule is one entry under `ignore:` in core/.grype.yaml. It is the
// suppression Grype's --fail-on gate respects (pipeline.sh runs grype from
// core/, which auto-loads .grype.yaml).
type grypeIgnoreRule struct {
	Vulnerability string          `json:"vulnerability"`
	Package       *grypeIgnorePkg `json:"package,omitempty"`
	Reason        string          `json:"reason,omitempty"`
}

type grypeIgnorePkg struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type,omitempty"`
}

type grypeConfig struct {
	Ignore []grypeIgnoreRule `json:"ignore"`
}

// ignoreEvidence documents a scanner suppression so it is never silent: who
// owns it, why, and when it expires. Pairs with the .grype.yaml rule, mirroring
// the overlays/cve evidence convention.
type ignoreEvidence struct {
	SchemaVersion string            `json:"schemaVersion"`
	Status        string            `json:"status"`
	CVE           string            `json:"cve"`
	Package       string            `json:"package"`
	Owner         string            `json:"owner"`
	Reason        string            `json:"reason"`
	Expires       string            `json:"expires,omitempty"`
	GeneratedBy   string            `json:"generatedBy"`
	Suppressions  []grypeIgnoreRule `json:"suppressions"`
}

// NewRemediationIgnoreCmd manages a tracked Grype suppression (and its evidence)
// from the CLI, so an operator never hand-edits core/.grype.yaml. Use it for a
// material finding whose fix is not yet available in the package set (e.g. an
// upstream point release that hasn't landed in nixpkgs) — the suppression is
// narrow, owned, and expiring.
func NewRemediationIgnoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ignore",
		Short: "Add a tracked Grype suppression (+ evidence) for a finding with no available fix yet",
		Long: `Adds a narrow, owned, expiring Grype ignore rule to core/.grype.yaml and writes
a paired evidence file, instead of requiring an operator to hand-edit the
scanner config. Intended for a material finding whose upstream fix is not yet in
the package set; the next scan re-flags it once a real remediation is possible.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemediationIgnore()
		},
	}
	f := cmd.Flags()
	f.StringVar(&remediationIgnoreOpts.cve, "cve", "", "Vulnerability ID to suppress, e.g. CVE-2026-9669 (required)")
	f.StringVar(&remediationIgnoreOpts.pkg, "package", "", "Affected package name as Grype reports it, e.g. python (required)")
	f.StringArrayVar(&remediationIgnoreOpts.versions, "version", nil, "Affected package version(s); repeatable (required)")
	f.StringVar(&remediationIgnoreOpts.pkgType, "type", "UnknownPackage", "Grype package type")
	f.StringVar(&remediationIgnoreOpts.reason, "reason", "", "Why this is suppressed (required) — recorded in the evidence and the rule")
	f.StringVar(&remediationIgnoreOpts.owner, "owner", "ClearCutt maintainers", "Owner accountable for the suppression")
	f.StringVar(&remediationIgnoreOpts.expires, "expires", "", "Expiry date YYYY-MM-DD (required) so a suppression cannot live forever")
	f.StringVar(&remediationIgnoreOpts.coreDir, "core-dir", "", "Core workspace directory (auto-detected when omitted)")
	f.StringVar(&remediationIgnoreOpts.grypeConfig, "grype-config", "", "Path to .grype.yaml (defaults to <core-dir>/.grype.yaml)")
	f.StringVar(&remediationIgnoreOpts.evidenceDir, "evidence-dir", "", "Directory for the evidence file (defaults to <core-dir>/overlays/cve)")
	return cmd
}

func runRemediationIgnore() error {
	o := remediationIgnoreOpts
	if !cveIDPattern.MatchString(strings.TrimSpace(o.cve)) {
		return fmt.Errorf("--cve %q is not a valid CVE/GHSA id", o.cve)
	}
	if strings.TrimSpace(o.pkg) == "" {
		return fmt.Errorf("--package is required")
	}
	if len(o.versions) == 0 {
		return fmt.Errorf("at least one --version is required")
	}
	if strings.TrimSpace(o.reason) == "" {
		return fmt.Errorf("--reason is required so the suppression is never silent")
	}
	if strings.TrimSpace(o.expires) == "" {
		return fmt.Errorf("--expires YYYY-MM-DD is required so a suppression cannot live forever")
	}
	if _, err := time.Parse("2006-01-02", o.expires); err != nil {
		return fmt.Errorf("--expires must be YYYY-MM-DD: %w", err)
	}

	coreDir := o.coreDir
	if coreDir == "" {
		resolved, err := resolveCoreDir("")
		if err != nil {
			return err
		}
		coreDir = resolved
	}
	grypePath := o.grypeConfig
	if grypePath == "" {
		grypePath = filepath.Join(coreDir, ".grype.yaml")
	}
	evidenceDir := o.evidenceDir
	if evidenceDir == "" {
		evidenceDir = filepath.Join(coreDir, "overlays", "cve")
	}

	rules := make([]grypeIgnoreRule, 0, len(o.versions))
	for _, v := range o.versions {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		rules = append(rules, grypeIgnoreRule{
			Vulnerability: o.cve,
			Package:       &grypeIgnorePkg{Name: o.pkg, Version: v, Type: o.pkgType},
			Reason:        fmt.Sprintf("%s (expires %s)", o.reason, o.expires),
		})
	}

	added, err := addGrypeIgnoreRules(grypePath, rules)
	if err != nil {
		return fmt.Errorf("update %s: %w", grypePath, err)
	}

	evidencePath := filepath.Join(evidenceDir, fmt.Sprintf("%s-%s.ignore.evidence.json", strings.ToLower(o.cve), grypeIgnoreSlug(o.pkg)))
	if err := writeIgnoreEvidence(evidencePath, o, rules); err != nil {
		return fmt.Errorf("write evidence %s: %w", evidencePath, err)
	}

	fmt.Fprintf(out, "[remediation-ignore] %d new suppression(s) for %s (%s) in %s\n", added, o.cve, o.pkg, grypePath)
	fmt.Fprintf(out, "[remediation-ignore] evidence -> %s (expires %s, owner %q)\n", evidencePath, o.expires, o.owner)
	return nil
}

// addGrypeIgnoreRules appends rules to .grype.yaml idempotently, preserving the
// file's leading comment header. Returns how many were newly added.
func addGrypeIgnoreRules(path string, rules []grypeIgnoreRule) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	header, body := splitGrypeHeader(raw)

	var cfg grypeConfig
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := yaml.Unmarshal(body, &cfg); err != nil {
			return 0, fmt.Errorf("parse existing ignore rules: %w", err)
		}
	}

	added := 0
	for _, r := range rules {
		if grypeRuleExists(cfg.Ignore, r) {
			continue
		}
		cfg.Ignore = append(cfg.Ignore, r)
		added++
	}

	encoded, err := yaml.Marshal(cfg)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, err
	}
	if err := os.WriteFile(path, append(header, encoded...), 0o644); err != nil {
		return 0, err
	}
	return added, nil
}

// splitGrypeHeader peels the leading comment/blank block (the file's header)
// off the YAML body so it survives a parse/re-marshal round trip.
func splitGrypeHeader(raw []byte) (header, body []byte) {
	lines := strings.SplitAfter(string(raw), "\n")
	i := 0
	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			i++
			continue
		}
		break
	}
	return []byte(strings.Join(lines[:i], "")), []byte(strings.Join(lines[i:], ""))
}

func grypeRuleExists(rules []grypeIgnoreRule, want grypeIgnoreRule) bool {
	for _, r := range rules {
		if r.Vulnerability != want.Vulnerability {
			continue
		}
		if (r.Package == nil) != (want.Package == nil) {
			continue
		}
		if r.Package == nil || (r.Package.Name == want.Package.Name && r.Package.Version == want.Package.Version && r.Package.Type == want.Package.Type) {
			return true
		}
	}
	return false
}

func writeIgnoreEvidence(path string, o remediationIgnoreFlags, rules []grypeIgnoreRule) error {
	ev := ignoreEvidence{
		SchemaVersion: "clearcutt.remediation.evidence/v1",
		Status:        "scanner_suppressed",
		CVE:           o.cve,
		Package:       o.pkg,
		Owner:         o.owner,
		Reason:        o.reason,
		Expires:       o.expires,
		GeneratedBy:   "clearcutt remediation ignore",
		Suppressions:  rules,
	}
	encoded, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o644)
}

func grypeIgnoreSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	return strings.Join(parts, "-")
}
