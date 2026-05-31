// Package attest builds the ClearCutt rebase attestation: an in-toto statement that
// records exactly which base layers were swapped, proves the application layers were
// preserved, and carries the dual-control evidence (that the original developer
// signature over the source image was verified before the rebase was allowed).
package attest

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PredicateType is the custom in-toto predicate type for ClearCutt rebases.
const PredicateType = "https://clearcutt.dev/attestations/rebase/v1"

// StatementType is the in-toto Statement schema version.
const StatementType = "https://in-toto.io/Statement/v1"

// Decision values for Predicate.RebaseDecision.
const (
	DecisionAllowed = "allowed"
	DecisionBlocked = "blocked"
)

// Subject identifies the artifact an attestation is about.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Predicate is the body of the rebase attestation. It is what gets written to the
// file passed to `cosign attest --predicate`; cosign wraps it in the in-toto
// statement (subject = the rebased image) at attach time.
type Predicate struct {
	SourceImage         string   `json:"sourceImage"`
	SourceDigest        string   `json:"sourceDigest"`
	OldBaseDigest       string   `json:"oldBaseDigest"`
	NewBaseDigest       string   `json:"newBaseDigest"`
	PreservedAppLayers  []string `json:"preservedAppLayers"`
	RemovedBaseLayers   []string `json:"removedBaseLayers"`
	AddedBaseLayers     []string `json:"addedBaseLayers"`
	CompatibilityPolicy string   `json:"compatibilityPolicy"`
	RebaseDecision      string   `json:"rebaseDecision"`

	// Dual-control evidence: the developer identity whose keyless signature over
	// SourceDigest was verified before this rebase was permitted. An allowed rebase
	// MUST have DeveloperSignatureVerified=true with a pinned DeveloperIdentity, so a
	// downstream admission gate can enforce the developer leg of the trust chain by
	// asserting on these fields.
	DeveloperIdentity          string `json:"developerIdentity"`
	DeveloperIssuer            string `json:"developerIssuer"`
	DeveloperSignatureVerified bool   `json:"developerSignatureVerified"`
}

// Statement is the full in-toto statement (subject + predicate). It is used for
// local emission/inspection (`--attest-output`) and tests; the cosign attach path
// uses only the Predicate.
type Statement struct {
	Type          string    `json:"_type"`
	PredicateType string    `json:"predicateType"`
	Subject       []Subject `json:"subject"`
	Predicate     Predicate `json:"predicate"`
}

// NewStatement assembles a statement for the rebased subject (name + sha256:hex digest).
func NewStatement(subjectName, subjectDigest string, p Predicate) (Statement, error) {
	algo, hex, ok := splitDigest(subjectDigest)
	if !ok {
		return Statement{}, fmt.Errorf("invalid subject digest %q (want algo:hex)", subjectDigest)
	}
	return Statement{
		Type:          StatementType,
		PredicateType: PredicateType,
		Subject:       []Subject{{Name: subjectName, Digest: map[string]string{algo: hex}}},
		Predicate:     p,
	}, nil
}

// Validate enforces the structural and dual-control invariants. It is deliberately
// strict about the allowed case: an "allowed" decision with an unverified or
// anonymous developer signature is a contradiction and must never be emitted.
func (p Predicate) Validate() error {
	if p.SourceImage == "" {
		return fmt.Errorf("predicate missing sourceImage")
	}
	if !isDigest(p.SourceDigest) {
		return fmt.Errorf("predicate sourceDigest %q is not a valid digest", p.SourceDigest)
	}
	if !isDigest(p.NewBaseDigest) {
		return fmt.Errorf("predicate newBaseDigest %q is not a valid digest", p.NewBaseDigest)
	}
	if len(p.PreservedAppLayers) == 0 {
		return fmt.Errorf("predicate must record at least one preserved application layer")
	}
	switch p.RebaseDecision {
	case DecisionAllowed:
		if !p.DeveloperSignatureVerified {
			return fmt.Errorf("an allowed rebase requires developerSignatureVerified=true (dual-control)")
		}
		if strings.TrimSpace(p.DeveloperIdentity) == "" {
			return fmt.Errorf("an allowed rebase requires a pinned developerIdentity (dual-control)")
		}
	case DecisionBlocked:
		// A blocked decision is informational; no dual-control requirement.
	default:
		return fmt.Errorf("predicate rebaseDecision %q must be %q or %q", p.RebaseDecision, DecisionAllowed, DecisionBlocked)
	}
	return nil
}

// Marshal returns the indented JSON for the predicate body (the cosign --predicate file).
func (p Predicate) Marshal() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// Marshal returns the indented JSON for the full statement.
func (s Statement) Marshal() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

func splitDigest(d string) (algo, hex string, ok bool) {
	parts := strings.SplitN(d, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func isDigest(d string) bool {
	_, _, ok := splitDigest(d)
	return ok
}
