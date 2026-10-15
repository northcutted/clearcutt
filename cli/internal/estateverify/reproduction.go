package estateverify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// reproductionPredicate is clearcutt-factory's reproduction attestation
// (PredicateReproduction), which `clearcutt-factory verify --image --attest`
// signs onto an image it rebuilt from its signed recipe, or whose signed
// rebase it repeated, to the same digest.
type reproductionPredicate struct {
	// Method is recipe-rebuild or rebase-repeat.
	Method string `json:"method"`
	// Image is the image that was reproduced (repository@digest), and Digest
	// what the reproduction gave.
	Image  string `json:"image"`
	Digest string `json:"digest"`
	// From is the recipe or rebase record it was reproduced from: its
	// predicate type and the digest of its in-toto statement.
	From struct {
		PredicateType string            `json:"predicateType"`
		Digest        map[string]string `json:"digest"`
	} `json:"from"`
	Factory struct {
		Version string `json:"version"`
	} `json:"factory"`
	BuildKit string `json:"buildkit"`
	Builder  struct {
		ID       string `json:"id"`
		Workflow string `json:"workflow"`
		Job      string `json:"job"`
		Runner   string `json:"runner"`
		OS       string `json:"os"`
		Arch     string `json:"arch"`
	} `json:"builder"`
	ReproducedAt string `json:"reproducedAt"`
}

// statementDigest is the sha256 of an in-toto statement (the signed DSSE
// payload), which is how a reproduction attestation names what it was made
// from.
func statementDigest(statement []byte) string {
	sum := sha256.Sum256(statement)
	return hex.EncodeToString(sum[:])
}

// attestedReproduction reads the reproduction attestations on repo@digest.
// One counts only when cosign verified it against the image signers, bound
// like the recipe (imageSource for signers that require the run to be in the
// image's source repository); when it is about this image alone (its
// subjects, and the digest it says the reproduction gave, are this digest);
// and when it was made from a recipe or rebase record verified on this image
// (from.digest is the sha256 of that statement, of the kind its method
// rebuilds from). The newest, by its signed reproducedAt, wins. Nothing is
// read from a copy cosign didn't verify. It returns nil, and why, when
// copies are attached but none counts.
func attestedReproduction(ctx context.Context, repo, digest, imageSource string, found []Found, opts Options, from map[string]string) (*report.Reproducibility, string) {
	item, verified := verifyEvidence(ctx, opts.Verifier, repo, digest, KindReproduction, imageSource, found)
	switch {
	case item.Status == "missing":
		return nil, ""
	case len(verified) == 0:
		return nil, fmt.Sprintf("A reproduction attestation is attached, but it is %s (%s), so it wasn't read.", item.Status, strings.TrimSuffix(firstNonEmpty(item.Detail, "not verified"), "."))
	}
	var best *report.Reproducibility
	var bestAt time.Time
	var why []string
	for _, c := range verified {
		p, at, err := boundReproduction(c, digest, from)
		if err != nil {
			why = appendUnique(why, err.Error())
			continue
		}
		if best != nil && !at.After(bestAt) {
			continue
		}
		signer := c.signer
		kind := "recipe"
		if p.Method == "rebase-repeat" {
			kind = "rebase record"
		}
		where := firstNonEmpty(p.Builder.ID, strings.Trim(p.Builder.OS+"/"+p.Builder.Arch, "/"), "an unnamed machine")
		best = &report.Reproducibility{
			Status: "reproduced", Method: p.Method, CheckedAt: p.ReproducedAt, Digest: p.Digest, Source: "attestation",
			Builder: &report.ReproductionBuilder{
				ID: p.Builder.ID, Workflow: p.Builder.Workflow, Job: p.Builder.Job, Runner: p.Builder.Runner,
				OS: p.Builder.OS, Arch: p.Builder.Arch, FactoryVersion: p.Factory.Version, BuildKit: p.BuildKit,
			},
			Signer: &signer, Ref: c.Ref,
			Detail: strings.TrimSpace(fmt.Sprintf("Reproduced from the %s verified on this image by clearcutt-factory %s on %s, as its verified reproduction attestation says; this run didn't rebuild it.",
				kind, firstNonEmpty(p.Factory.Version, "(version not given)"), where)),
		}
		bestAt = at
	}
	if best == nil {
		return nil, "A verified reproduction attestation is attached, but it wasn't counted: " + strings.Join(why, "; ") + "."
	}
	return best, ""
}

// boundReproduction reads a verified reproduction attestation and checks
// that it is about this image and was made from a recipe or rebase record
// verified on it.
func boundReproduction(c verifiedCopy, digest string, from map[string]string) (reproductionPredicate, time.Time, error) {
	var st struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate reproductionPredicate `json:"predicate"`
	}
	if err := json.Unmarshal(c.Statement, &st); err != nil {
		return reproductionPredicate{}, time.Time{}, fmt.Errorf("it can't be read: %v", err)
	}
	p := st.Predicate
	_, want, _ := strings.Cut(digest, ":")
	if len(st.Subject) == 0 {
		return p, time.Time{}, fmt.Errorf("it names no subject")
	}
	for _, s := range st.Subject {
		if s.Digest["sha256"] != want {
			return p, time.Time{}, fmt.Errorf("it is also about sha256:%s, not only this image", s.Digest["sha256"])
		}
	}
	if p.Digest != digest {
		return p, time.Time{}, fmt.Errorf("it says the reproduction gave %q, not this image's digest", p.Digest)
	}
	if _, d, ok := strings.Cut(p.Image, "@"); ok && d != digest {
		return p, time.Time{}, fmt.Errorf("it names %s, not this image", p.Image)
	}
	var wantKind string
	switch p.Method {
	case "recipe-rebuild":
		wantKind = KindRecipe
	case "rebase-repeat":
		wantKind = KindRebase
	default:
		return p, time.Time{}, fmt.Errorf("its method %q is neither recipe-rebuild nor rebase-repeat", p.Method)
	}
	madeFrom, ok := from[p.From.Digest["sha256"]]
	switch {
	case !ok:
		return p, time.Time{}, fmt.Errorf("it was made from a statement (sha256:%s) that isn't a recipe or rebase record verified on this image", p.From.Digest["sha256"])
	case KindOf(madeFrom) != wantKind || p.From.PredicateType != madeFrom:
		return p, time.Time{}, fmt.Errorf("its method %s doesn't match what it was made from (%s)", p.Method, madeFrom)
	}
	at, err := time.Parse(time.RFC3339, p.ReproducedAt)
	if err != nil {
		return p, time.Time{}, fmt.Errorf("its reproducedAt %q isn't a time", p.ReproducedAt)
	}
	return p, at, nil
}
