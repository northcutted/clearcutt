package estateverify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// Verifier checks evidence with cosign against trusted signers. cosign does
// the cryptography (certificate chain, transparency log, signature), as it
// does everywhere else in ClearCutt, so trust roots stay cosign's.
type Verifier struct {
	Signers []report.Signer
	// Cosign is the cosign binary (default "cosign").
	Cosign string
	// Run executes cosign and returns stdout; tests replace it.
	Run func(ctx context.Context, bin string, args ...string) ([]byte, error)
}

// ErrNoSigner means no trusted signer was configured, so evidence can only
// be present, never verified.
var ErrNoSigner = errors.New("no trusted signer configured")

// Subject is the evidence to verify and what is known about its image.
type Subject struct {
	// Ref is repository@digest.
	Ref string
	// Kind is the evidence kind, PredicateType its predicate (attestations).
	Kind, PredicateType string
	// ImageSource is the repository the image names as its source
	// (org.opencontainers.image.source), for signers with
	// sourceMatchesImage.
	ImageSource string
	// Signer is who signed the evidence found, as its certificate says
	// (not yet verified).
	Signer *report.Signer
}

// Verified is what cosign verified.
type Verified struct {
	// Trusted is the policy signer that accepted it.
	Trusted report.Signer
	// Signer is who signed it, as far as cosign checked: the certificate's
	// identity and issuer and, for GitHub Actions, the repository and ref of
	// the run that signed, each required exactly; or the trusted key.
	Signer report.Signer
	// Statements are the in-toto statements cosign verified (attestations),
	// each about the subject's digest and of the predicate type asked for.
	// They are the only content of the evidence that may be read.
	Statements [][]byte
}

// Verify checks evidence with cosign. Keyless evidence is verified as
// exactly the signer its certificate names (once a trusted signer accepts
// that signer), so whatever cosign returns was signed by that identity, in
// that repository, on that ref, and the report can say so. Evidence with no
// certificate is verified against the trusted keys.
func (v *Verifier) Verify(ctx context.Context, subj Subject) (Verified, error) {
	if len(v.Signers) == 0 {
		return Verified{}, ErrNoSigner
	}
	cert := subj.Signer
	keyless := cert != nil && cert.Key == "" && cert.Identity != "" && cert.Issuer != ""
	var errs []string
	var accepted []report.Signer
	for _, s := range v.Signers {
		if _, err := signerFlags(s); err != nil {
			return Verified{}, err
		}
		switch {
		case s.Key != "" && keyless:
			errs = append(errs, "signed with a certificate, not key "+s.Key)
		case s.Key != "":
			statements, err := v.verifyWith(ctx, subj, []string{"--key", s.Key})
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			return Verified{Trusted: s, Signer: report.Signer{Key: s.Key}, Statements: statements}, nil
		case !keyless:
			errs = append(errs, "no certificate names who signed it")
		default:
			if err := accepts(s, *cert, subj.ImageSource); err != nil {
				errs = append(errs, err.Error())
				continue
			}
			accepted = append(accepted, s)
		}
	}
	if len(accepted) > 0 {
		// Every signer that accepts the certificate's signer verifies it the
		// same way; prefer one that says which calling repositories count.
		trusted := accepted[0]
		for _, s := range accepted {
			if _, unchecked := callerUnchecked(s, *cert); !unchecked {
				trusted = s
				break
			}
		}
		flags, signer := exactFlags(*cert)
		statements, err := v.verifyWith(ctx, subj, flags)
		if err == nil {
			return Verified{Trusted: trusted, Signer: signer, Statements: statements}, nil
		}
		errs = append(errs, err.Error())
	}
	return Verified{}, fmt.Errorf("not signed by a trusted signer: %s", strings.Join(dedupe(errs), "; "))
}

// verifyWith runs cosign with flags and returns the statements it verified.
func (v *Verifier) verifyWith(ctx context.Context, subj Subject, flags []string) ([][]byte, error) {
	args := []string{"verify-attestation", "--type", subj.PredicateType}
	if subj.Kind == KindSignature {
		args = []string{"verify"}
	}
	args = append(append(append(args, "--output", "json"), flags...), subj.Ref)
	out, err := v.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	return verifiedOutput(out, subj)
}

// cosignImageSignature is the type cosign gives signatures it stored as
// simple signing payloads (cosign v2 .sig tags).
const cosignImageSignature = "cosign container image signature"

// verifiedOutput reads what cosign printed about the evidence it verified:
// for signatures, the signed payloads (a JSON array); for attestations, one
// DSSE envelope per line. Only what is about the subject's digest and of the
// kind asked for counts: cosign v3's verify accepts a bundle of any type as
// a signature, and nothing else may pass as verified.
func verifiedOutput(out []byte, subj Subject) ([][]byte, error) {
	_, digest, _ := strings.Cut(subj.Ref, "@")
	dec := json.NewDecoder(bytes.NewReader(out))
	if subj.Kind == KindSignature {
		var sigs []struct {
			Critical struct {
				Image struct {
					Digest string `json:"docker-manifest-digest"`
				} `json:"image"`
				Type string `json:"type"`
			} `json:"critical"`
		}
		if err := dec.Decode(&sigs); err != nil {
			return nil, fmt.Errorf("cosign's output couldn't be read: %w", err)
		}
		for _, s := range sigs {
			if s.Critical.Image.Digest == digest && (s.Critical.Type == cosignImageSignature || s.Critical.Type == PredicateCosignSign) {
				return nil, nil
			}
		}
		return nil, fmt.Errorf("cosign verified no signature over %s", digest)
	}
	var statements [][]byte
	for {
		var env struct {
			Payload []byte `json:"payload"`
		}
		err := dec.Decode(&env)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("cosign's output couldn't be read: %w", err)
		}
		if statementAbout(env.Payload, subj.PredicateType, digest) {
			statements = append(statements, env.Payload)
		}
	}
	if len(statements) == 0 {
		return nil, fmt.Errorf("cosign verified no %s attestation about %s", subj.PredicateType, digest)
	}
	return statements, nil
}

// statementAbout reports whether an in-toto statement has the predicate type
// and names the digest among its subjects.
func statementAbout(statement []byte, predicateType, digest string) bool {
	var s struct {
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if json.Unmarshal(statement, &s) != nil || s.PredicateType != predicateType {
		return false
	}
	alg, hex, _ := strings.Cut(digest, ":")
	for _, sub := range s.Subject {
		if hex != "" && sub.Digest[alg] == hex {
			return true
		}
	}
	return false
}

// accepts checks that trusted signer s accepts the signer a certificate
// names. cosign then verifies the certificate is genuine.
func accepts(s, cert report.Signer, imageSource string) error {
	if cert.Issuer != s.Issuer {
		return fmt.Errorf("issued by %s, not %s", cert.Issuer, s.Issuer)
	}
	switch {
	case s.IdentityRegexp != "":
		re, err := regexp.Compile(s.IdentityRegexp)
		if err != nil {
			return err
		}
		if !re.MatchString(cert.Identity) {
			return fmt.Errorf("signed by %s, which doesn't match %s", cert.Identity, s.IdentityRegexp)
		}
	case cert.Identity != s.Identity:
		return fmt.Errorf("signed by %s, not %s", cert.Identity, s.Identity)
	}
	repo, err := resolveRepository(s, Subject{ImageSource: imageSource, Signer: &cert})
	if err != nil {
		return err
	}
	if repo != "" && cert.SourceRepository != repo {
		return fmt.Errorf("signed in %s, not %s", firstNonEmpty(cert.SourceRepository, "an unnamed repository"), repo)
	}
	if s.SourceRef != "" && cert.SourceRef != s.SourceRef {
		return fmt.Errorf("signed on %s, not %s", firstNonEmpty(cert.SourceRef, "an unnamed ref"), s.SourceRef)
	}
	return nil
}

// exactFlags makes cosign require exactly the signer a certificate names:
// its identity and issuer and, for GitHub Actions, the repository and ref
// of the run that signed. It returns them as the signer cosign checked.
func exactFlags(cert report.Signer) ([]string, report.Signer) {
	flags := []string{"--certificate-identity", cert.Identity, "--certificate-oidc-issuer", cert.Issuer}
	signer := report.Signer{Identity: cert.Identity, Issuer: cert.Issuer}
	if cert.Issuer == githubIssuer {
		if repo, ok := strings.CutPrefix(cert.SourceRepository, "https://github.com/"); ok && strings.Count(repo, "/") == 1 {
			flags = append(flags, "--certificate-github-workflow-repository", repo)
			signer.SourceRepository = cert.SourceRepository
		}
		if cert.SourceRef != "" {
			flags = append(flags, "--certificate-github-workflow-ref", cert.SourceRef)
			signer.SourceRef = cert.SourceRef
		}
	}
	return flags, signer
}

// resolveRepository returns the one repository (https://github.com/OWNER/REPO)
// whose workflow runs the signer accepts for this evidence, or "" when the
// signer doesn't constrain the caller.
func resolveRepository(s report.Signer, subj Subject) (string, error) {
	repo := s.SourceRepository
	if s.SourceMatchesImage {
		src := strings.TrimSuffix(strings.TrimSuffix(subj.ImageSource, "/"), ".git")
		switch {
		case src == "":
			return "", errors.New("the image names no source repository (org.opencontainers.image.source), and the signer requires the run to be in it")
		case repo != "" && repo != src:
			return "", fmt.Errorf("the image names %s as its source, not %s", src, repo)
		}
		repo = src
	}
	if s.SourceRepositoryOwner != "" {
		if repo == "" && subj.Signer != nil {
			repo = subj.Signer.SourceRepository
		}
		if !strings.HasPrefix(repo, strings.TrimSuffix(s.SourceRepositoryOwner, "/")+"/") {
			return "", fmt.Errorf("signed in %q, not a repository of %s", repo, s.SourceRepositoryOwner)
		}
	}
	if repo != "" {
		name, ok := strings.CutPrefix(repo, "https://github.com/")
		if !ok || strings.Count(name, "/") != 1 {
			return "", fmt.Errorf("source repository %q is not https://github.com/OWNER/REPO", repo)
		}
	}
	return repo, nil
}

// constrainsCaller reports whether the signer says which runs may sign.
func constrainsCaller(s report.Signer) bool {
	return s.SourceRepository != "" || s.SourceRepositoryOwner != "" || s.SourceMatchesImage
}

// calledFromElsewhere reports whether the certificate's run was in another
// repository than the workflow that signed: a reusable workflow, which any
// repository can call. It returns that repository.
func calledFromElsewhere(cert *report.Signer) (string, bool) {
	if cert == nil || cert.SourceRepository == "" {
		return "", false
	}
	return cert.SourceRepository, !strings.HasPrefix(cert.Identity, cert.SourceRepository+"/")
}

// callerUnchecked says why evidence signed by signer, verified against
// trusted, can't count as verified. A GitHub Actions signer that doesn't say
// which calling repositories it accepts trusts a workflow only where it runs
// in its own repository: a reusable workflow signs with its own identity
// wherever it is called from, so trusting the identity alone would trust
// every caller. The certificate has to say which repository's run signed.
func callerUnchecked(trusted, signer report.Signer) (string, bool) {
	if constrainsCaller(trusted) || signer.Key != "" || signer.Issuer != githubIssuer {
		return "", false
	}
	const fix = "set sourceRepository, sourceRepositoryOwner, or sourceMatchesImage."
	if signer.SourceRepository == "" {
		return fmt.Sprintf("Signed by %s, but its certificate doesn't say which repository's run signed, and the trusted signer doesn't say which calling repositories it accepts: %s",
			signer.Identity, fix), true
	}
	if caller, ok := calledFromElsewhere(&signer); ok {
		return fmt.Sprintf("Signed by %s, called from %s. The trusted signer doesn't say which calling repositories it accepts, "+
			"so a run in any repository calling that workflow would verify too: %s", signer.Identity, caller, fix), true
	}
	return "", false
}

func (v *Verifier) run(ctx context.Context, args ...string) ([]byte, error) {
	bin := v.Cosign
	if bin == "" {
		bin = "cosign"
	}
	if v.Run != nil {
		return v.Run(ctx, bin, args...)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("cosign %s: %v: %s", args[0], err, lastLine(stderr.String()))
	}
	return out, nil
}

// signerFlags turns a trusted signer into cosign flags. Like the rest of
// ClearCutt, it refuses identities that would let anyone verify.
func signerFlags(s report.Signer) ([]string, error) {
	if s.Key != "" {
		return []string{"--key", s.Key}, nil
	}
	id := strings.TrimSpace(s.IdentityRegexp)
	if id == "" {
		id = strings.TrimSpace(s.Identity)
	}
	switch id {
	case "", ".*", ".+", "^.*$":
		return nil, fmt.Errorf("refusing a trusted signer with an empty or wildcard identity (%q): name the workflow or organization", id)
	}
	if s.IdentityRegexp != "" {
		if err := checkIdentityRegexp(s.IdentityRegexp); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(s.Issuer) == "" {
		return nil, fmt.Errorf("trusted signer %q has no OIDC issuer (e.g. https://token.actions.githubusercontent.com)", id)
	}
	if (constrainsCaller(s) || s.SourceRef != "") && s.Issuer != githubIssuer {
		return nil, fmt.Errorf("trusted signer %q: source constraints need the GitHub Actions issuer (%s)", id, githubIssuer)
	}
	if s.IdentityRegexp != "" {
		return []string{"--certificate-identity-regexp", s.IdentityRegexp, "--certificate-oidc-issuer", s.Issuer}, nil
	}
	return []string{"--certificate-identity", s.Identity, "--certificate-oidc-issuer", s.Issuer}, nil
}

// strangers are certificate identities no policy means to trust: workflows
// of made-up owners and repositories, another forge, and email addresses.
var strangers = []string{
	"https://github.com/clearcutt-probe-owner/probe-repo/.github/workflows/probe.yml@refs/heads/main",
	"https://github.com/clearcutt-probe-owner/probe-repo/.github/workflows/probe.yml@refs/tags/v1.0.0",
	"https://gitlab.com/clearcutt-probe-owner/probe-repo//.gitlab-ci.yml@refs/heads/main",
	"https://clearcutt-probe.example/probe-owner/probe-repo",
	"probe@clearcutt-probe.example",
}

// checkIdentityRegexp refuses identity regular expressions that trust
// strangers: ones that match the identities above, or that match an
// identity they accept with its GitHub owner swapped for another (any owner,
// or one whose name merely starts with the owner named:
// ^https://github\.com/acme matches acme-evil), and unanchored ones, which
// match inside any identity that contains them.
func checkIdentityRegexp(expr string) error {
	re, err := regexp.Compile(expr)
	if err != nil {
		return fmt.Errorf("trusted signer identityRegexp %q: %w", expr, err)
	}
	parsed, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return fmt.Errorf("trusted signer identityRegexp %q: %w", expr, err)
	}
	parsed = parsed.Simplify()
	probes := append([]string{}, strangers...)
	for _, id := range samples(parsed) {
		rest, ok := strings.CutPrefix(id, "https://github.com/")
		if !ok {
			continue
		}
		owner, path, _ := strings.Cut(rest, "/")
		if path != "" || strings.HasSuffix(rest, "/") {
			path = "/" + path
		}
		probes = append(probes, "https://github.com/clearcutt-probe-owner"+path, "https://github.com/"+owner+"-clearcutt-probe"+path)
	}
	for _, id := range probes {
		if re.MatchString(id) {
			return fmt.Errorf("refusing a trusted signer with a wildcard identity (%q also matches %s): name the workflow or organization, ending the owner with /", expr, id)
		}
	}
	if !anchored(parsed) {
		return fmt.Errorf("refusing an unanchored identityRegexp %q: start it with ^ so it can't match inside another identity", expr)
	}
	return nil
}

// anchored reports whether every match of re starts at the beginning of
// the text.
func anchored(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpBeginText:
		return true
	case syntax.OpConcat, syntax.OpCapture:
		return len(re.Sub) > 0 && anchored(re.Sub[0])
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !anchored(sub) {
				return false
			}
		}
		return len(re.Sub) > 0
	}
	return false
}

// maxSamples bounds how many example matches samples makes.
const maxSamples = 32

// samples makes example strings re matches: one per way through its
// alternations (up to maxSamples), with the fewest repetitions and the
// plainest character of each class.
func samples(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{string(re.Rune)}
	case syntax.OpCharClass:
		return []string{string(classRune(re.Rune))}
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return []string{"a"}
	case syntax.OpCapture:
		return samples(re.Sub[0])
	case syntax.OpPlus:
		return samples(re.Sub[0])
	case syntax.OpRepeat:
		out := []string{""}
		for range re.Min {
			out = product(out, samples(re.Sub[0]))
		}
		return out
	case syntax.OpConcat:
		out := []string{""}
		for _, sub := range re.Sub {
			out = product(out, samples(sub))
		}
		return out
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			out = append(out, samples(sub)...)
		}
		return out[:min(len(out), maxSamples)]
	}
	// Empty matches, anchors, x* and x?.
	return []string{""}
}

func product(a, b []string) []string {
	var out []string
	for _, x := range a {
		for _, y := range b {
			if len(out) == maxSamples {
				return out
			}
			out = append(out, x+y)
		}
	}
	return out
}

// classRune picks a character from a class (lo-hi pairs): a lower-case
// letter or digit when it has one, the way identities are spelled.
func classRune(ranges []rune) rune {
	for _, want := range "abcdefghijklmnopqrstuvwxyz0123456789-" {
		for i := 0; i+1 < len(ranges); i += 2 {
			if ranges[i] <= want && want <= ranges[i+1] {
				return want
			}
		}
	}
	if len(ranges) > 0 {
		return ranges[0]
	}
	return 'a'
}

// copiesOf lists the evidence of kind about digest, newest first.
func copiesOf(found []Found, kind, digest string) []Found {
	var out []Found
	for _, f := range found {
		if f.Kind == kind && (f.Subject == "" || f.Subject == digest) {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp > out[j].Timestamp })
	return out
}

// verifiedCopy is a copy of evidence whose content cosign verified, and who
// cosign verified signed it.
type verifiedCopy struct {
	Found
	signer, trusted report.Signer
}

// maxSigners bounds how many signers' copies of one kind of evidence are
// verified on one image: each is a cosign run, and anyone who can push can
// attach copies.
const maxSigners = 8

// verifyEvidence verifies every copy of one kind of evidence on
// repo@digest. It returns the evidence item, and the copies whose content
// cosign verified, best first: only those may be read. An unverified copy
// (unsigned, or signed by someone else, or newer) never stands in for a
// verified one; it is reported only when nothing verifies.
func verifyEvidence(ctx context.Context, v *Verifier, repo, digest, kind, imageSource string, found []Found) (report.EvidenceItem, []verifiedCopy) {
	copies := copiesOf(found, kind, digest)
	if len(copies) == 0 {
		return report.EvidenceItem{Status: "missing"}, nil
	}
	type outcome struct {
		res Verified
		err error
	}
	runs := map[string]outcome{}
	var verified []verifiedCopy
	var newest report.EvidenceItem
	for i, f := range copies {
		var status, detail string
		key := f.PredicateType + "\x00" + signerKey(f.Signer)
		o, ran := runs[key]
		switch {
		case f.Format == FormatRawReferrer:
			status, detail = "present", "An unsigned document; nothing to verify."
		case !ran && len(runs) >= maxSigners:
			status, detail = "present", fmt.Sprintf("Not checked: copies signed by more than %d signers are attached.", maxSigners)
		default:
			if !ran {
				o.res, o.err = v.Verify(ctx, Subject{Ref: repo + "@" + digest, Kind: kind, PredicateType: f.PredicateType, ImageSource: imageSource, Signer: f.Signer})
				runs[key] = o
			}
			reason, unchecked := callerUnchecked(o.res.Trusted, o.res.Signer)
			switch {
			case errors.Is(o.err, ErrNoSigner):
				status, detail = "present", "No trusted signer is configured, so it can't be verified."
			case o.err != nil:
				status, detail = "failed", o.err.Error()
			case unchecked:
				status, detail = "present", reason
			case kind != KindSignature && !containsBytes(o.res.Statements, f.Statement):
				// Its signer verifies, but not this content.
				status, detail = "failed", "Its signer's other attestations verify, but this one doesn't."
			default:
				status = "verified"
				verified = append(verified, verifiedCopy{Found: f, signer: o.res.Signer, trusted: o.res.Trusted})
			}
		}
		if i == 0 {
			newest = report.EvidenceItem{Status: status, Source: sourceName(f), PredicateType: f.PredicateType, Ref: f.Ref, Timestamp: f.Timestamp, Signer: f.Signer, Detail: detail}
		}
	}
	if len(verified) == 0 {
		return newest, nil
	}
	if kind == KindVulnerabilityScan {
		// The newest scan by its signed scan time, not by when (the registry
		// says) it was attached.
		sort.SliceStable(verified, func(i, j int) bool { return scanTime(verified[i].Found).After(scanTime(verified[j].Found)) })
	}
	best := verified[0]
	signer := best.signer
	item := report.EvidenceItem{Status: "verified", Source: sourceName(best.Found), PredicateType: best.PredicateType, Ref: best.Ref, Timestamp: best.Timestamp, Signer: &signer}
	if n := len(copies) - len(verified); n == 1 {
		item.Detail = "1 other attached copy isn't verified and wasn't read."
	} else if n > 1 {
		item.Detail = fmt.Sprintf("%d other attached copies aren't verified and weren't read.", n)
	}
	return item, verified
}

// signerKey identifies the signer a copy claims, for verifying each signer once.
func signerKey(s *report.Signer) string {
	if s == nil {
		return ""
	}
	return strings.Join([]string{s.Identity, s.Issuer, s.Key, s.SourceRepository, s.SourceRef}, "\x00")
}

// scanTime is when a vulnerability attestation says its scan ran.
func scanTime(f Found) time.Time {
	s, ok := readVulnPredicate(f.Predicate())
	if !ok {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s.ScannedAt)
	if err != nil {
		return time.Time{}
	}
	return t
}

func containsBytes(list [][]byte, b []byte) bool {
	for _, x := range list {
		if bytes.Equal(x, b) {
			return true
		}
	}
	return false
}

func dedupe(list []string) []string {
	var out []string
	for _, s := range list {
		out = appendUnique(out, s)
	}
	return out
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
