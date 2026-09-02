// Package acceptance implements time-boxed, owner-attributed acceptance of
// vulnerability findings the fleet cannot currently fix.
//
// It deliberately does NOT use VEX for this. A VEX `not_affected` statement is a
// claim that the vulnerability does not apply — it requires a justification from
// a fixed enum (vulnerable_code_not_present and friends), and it is the only
// status a scanner will suppress on. When openssl inside an image genuinely
// carries a CVE and the fix simply is not in the pinned nixpkgs yet, none of
// those justifications is true, and asserting one to get a green gate is the
// same dishonesty as an invisible scanner suppression wearing a better format.
//
// The claim here is different and checkable: the finding is real, it affects the
// image, no fix is reachable from the current pin, a named owner accepted it on
// a date, and the acceptance expires. An expired acceptance FAILS the gate — it
// cannot rot into a permanent silence the way an undated ignore rule does.
package acceptance

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// APIVersion and Kind identify the acceptance document.
const (
	APIVersion = "clearcutt.dev/v1"
	Kind       = "VulnerabilityAcceptances"
	dateLayout = "2006-01-02"
)

// Document is the parsed acceptance file.
type Document struct {
	APIVersion  string       `json:"apiVersion"`
	Kind        string       `json:"kind"`
	Acceptances []Acceptance `json:"acceptances"`
}

// Acceptance is one owner-attributed, expiring acceptance covering a set of
// vulnerabilities in a specific package at specific versions.
type Acceptance struct {
	ID              string   `json:"id"`
	Package         string   `json:"package"`
	Versions        []string `json:"versions,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities"`
	Reason          string   `json:"reason"`
	FixedIn         string   `json:"fixedIn,omitempty"`
	AcceptedBy      string   `json:"acceptedBy"`
	AcceptedAt      string   `json:"acceptedAt"`
	ExpiresAt       string   `json:"expiresAt"`
}

// Finding is the scanner output this package classifies, reduced to what the
// decision needs.
type Finding struct {
	ID       string
	Package  string
	Version  string
	Severity string
	FixedIn  string
}

// Verdict is the outcome for one finding.
type Verdict struct {
	Finding      Finding
	AcceptanceID string // empty when no acceptance covered the finding
	AcceptedBy   string // the owner who accepted it
	Reason       string
	ExpiresAt    string
	Expired      bool
}

// Result is the classification of a whole scan.
type Result struct {
	Accepted   []Verdict
	Expired    []Verdict
	Unaccepted []Finding
}

// Blocking reports whether the gate must fail. An expired acceptance blocks just
// as hard as an unaccepted finding: the point of the expiry is that letting it
// lapse is a decision someone has to make again, not a silence that persists.
func (r Result) Blocking() bool { return len(r.Expired) > 0 || len(r.Unaccepted) > 0 }

// Load reads and validates an acceptance document. A missing file is not an
// error — a fleet with nothing accepted is the normal case — and yields a
// document that accepts nothing.
func Load(path string) (Document, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Document{APIVersion: APIVersion, Kind: Kind}, nil
	}
	if err != nil {
		return Document{}, err
	}
	var doc Document
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return Document{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if doc.Kind != "" && doc.Kind != Kind {
		return Document{}, fmt.Errorf("%s: kind must be %q, got %q", path, Kind, doc.Kind)
	}
	seen := map[string]bool{}
	for i, a := range doc.Acceptances {
		where := fmt.Sprintf("%s: acceptances[%d]", path, i)
		switch {
		case strings.TrimSpace(a.ID) == "":
			return Document{}, fmt.Errorf("%s: id is required", where)
		case seen[a.ID]:
			return Document{}, fmt.Errorf("%s: duplicate id %q", where, a.ID)
		case strings.TrimSpace(a.Package) == "":
			return Document{}, fmt.Errorf("%s (%s): package is required", where, a.ID)
		case len(a.Vulnerabilities) == 0:
			return Document{}, fmt.Errorf("%s (%s): at least one vulnerability is required", where, a.ID)
		case strings.TrimSpace(a.Reason) == "":
			return Document{}, fmt.Errorf("%s (%s): reason is required — an acceptance without a stated reason is an ignore rule", where, a.ID)
		case strings.TrimSpace(a.AcceptedBy) == "":
			return Document{}, fmt.Errorf("%s (%s): acceptedBy is required — acceptances are attributed", where, a.ID)
		}
		seen[a.ID] = true
		if _, err := time.Parse(dateLayout, a.AcceptedAt); err != nil {
			return Document{}, fmt.Errorf("%s (%s): acceptedAt must be YYYY-MM-DD, got %q", where, a.ID, a.AcceptedAt)
		}
		expiry, err := time.Parse(dateLayout, a.ExpiresAt)
		if err != nil {
			return Document{}, fmt.Errorf("%s (%s): expiresAt must be YYYY-MM-DD, got %q — acceptances never expire only by mistake", where, a.ID, a.ExpiresAt)
		}
		accepted, _ := time.Parse(dateLayout, a.AcceptedAt)
		if !expiry.After(accepted) {
			return Document{}, fmt.Errorf("%s (%s): expiresAt %s must be after acceptedAt %s", where, a.ID, a.ExpiresAt, a.AcceptedAt)
		}
	}
	return doc, nil
}

// Classify sorts findings into accepted, expired-acceptance, and unaccepted.
//
// Matching is deliberately narrow: an acceptance covers a named package, an
// explicit vulnerability list, and optionally an explicit version list. A finding
// in a package version the acceptance did not name is NOT covered — a version
// bump that reintroduces or changes the exposure surfaces as a new decision
// rather than inheriting the old one.
func Classify(doc Document, findings []Finding, now time.Time) Result {
	var res Result
	for _, f := range findings {
		match, expired := lookup(doc, f, now)
		switch {
		case match == nil:
			res.Unaccepted = append(res.Unaccepted, f)
		case expired:
			res.Expired = append(res.Expired, Verdict{Finding: f, AcceptanceID: match.ID, AcceptedBy: match.AcceptedBy, Reason: match.Reason, ExpiresAt: match.ExpiresAt, Expired: true})
		default:
			res.Accepted = append(res.Accepted, Verdict{Finding: f, AcceptanceID: match.ID, AcceptedBy: match.AcceptedBy, Reason: match.Reason, ExpiresAt: match.ExpiresAt})
		}
	}
	sort.SliceStable(res.Accepted, func(i, j int) bool { return res.Accepted[i].Finding.ID < res.Accepted[j].Finding.ID })
	sort.SliceStable(res.Expired, func(i, j int) bool { return res.Expired[i].Finding.ID < res.Expired[j].Finding.ID })
	sort.SliceStable(res.Unaccepted, func(i, j int) bool { return res.Unaccepted[i].ID < res.Unaccepted[j].ID })
	return res
}

func lookup(doc Document, f Finding, now time.Time) (*Acceptance, bool) {
	for i := range doc.Acceptances {
		a := &doc.Acceptances[i]
		if !strings.EqualFold(a.Package, f.Package) {
			continue
		}
		if !containsFold(a.Vulnerabilities, f.ID) {
			continue
		}
		if len(a.Versions) > 0 && !containsFold(a.Versions, f.Version) {
			continue
		}
		expiry, err := time.Parse(dateLayout, a.ExpiresAt)
		if err != nil {
			return a, true
		}
		// Expiry is end-of-day: an acceptance dated today is still valid today.
		return a, now.After(expiry.AddDate(0, 0, 1))
	}
	return nil, false
}

func containsFold(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}
