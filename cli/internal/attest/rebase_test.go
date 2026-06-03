package attest

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPredicateValidateRequiresDualControlForAllowedRebase(t *testing.T) {
	p := validPredicate()
	if err := p.Validate(); err != nil {
		t.Fatalf("valid predicate rejected: %v", err)
	}

	p.DeveloperSignatureVerified = false
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "developerSignatureVerified=true") {
		t.Fatalf("expected missing developer verification to fail, got %v", err)
	}

	p = validPredicate()
	p.DeveloperIdentity = ""
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "developerIdentity") {
		t.Fatalf("expected missing developer identity to fail, got %v", err)
	}
}

func TestNewStatementSplitsSubjectDigest(t *testing.T) {
	stmt, err := NewStatement("ghcr.io/acme/app", "sha256:abc123", validPredicate())
	if err != nil {
		t.Fatalf("NewStatement: %v", err)
	}
	if stmt.Type != StatementType || stmt.PredicateType != PredicateType {
		t.Fatalf("unexpected statement envelope: %+v", stmt)
	}
	if got := stmt.Subject[0].Digest["sha256"]; got != "abc123" {
		t.Fatalf("subject digest = %q", got)
	}
	data, err := stmt.Marshal()
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	var decoded Statement
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("statement JSON invalid: %v", err)
	}
}

func TestStatementAndPredicateErrorBranches(t *testing.T) {
	p := validPredicate()
	for name, mutate := range map[string]func(*Predicate){
		"source":       func(p *Predicate) { p.SourceImage = "" },
		"sourceDigest": func(p *Predicate) { p.SourceDigest = "" },
		"newDigest":    func(p *Predicate) { p.NewBaseDigest = "" },
		"preserved":    func(p *Predicate) { p.PreservedAppLayers = nil },
		"decision":     func(p *Predicate) { p.RebaseDecision = "maybe" },
	} {
		bad := p
		mutate(&bad)
		if err := bad.Validate(); err == nil {
			t.Fatalf("%s predicate unexpectedly validated", name)
		}
	}
	blocked := p
	blocked.RebaseDecision = DecisionBlocked
	blocked.DeveloperIdentity = ""
	blocked.DeveloperSignatureVerified = false
	if err := blocked.Validate(); err != nil {
		t.Fatalf("blocked predicate should not require dual-control fields: %v", err)
	}
	if _, err := NewStatement("ghcr.io/acme/app", "not-a-digest", validPredicate()); err == nil {
		t.Fatal("NewStatement should reject malformed subject digest")
	}
	if alg, _, ok := splitDigest("not-a-digest"); ok || alg != "" {
		t.Fatalf("malformed digest should not parse, alg=%q ok=%v", alg, ok)
	}
}

func validPredicate() Predicate {
	return Predicate{
		SourceImage:                "ghcr.io/acme/app:1.0.0",
		SourceDigest:               "sha256:1111",
		OldBaseDigest:              "sha256:2222",
		NewBaseDigest:              "sha256:3333",
		PreservedAppLayers:         []string{"sha256:aaaa"},
		RemovedBaseLayers:          []string{"sha256:bbbb"},
		AddedBaseLayers:            []string{"sha256:cccc"},
		CompatibilityPolicy:        "clearcutt-java21-distroless-v1",
		RebaseDecision:             DecisionAllowed,
		DeveloperIdentity:          "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main",
		DeveloperIssuer:            "https://token.actions.githubusercontent.com",
		DeveloperSignatureVerified: true,
	}
}
