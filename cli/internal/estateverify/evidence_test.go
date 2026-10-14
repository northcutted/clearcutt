package estateverify

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// Later than bundleJSON's transparency log time: what an attacker attaching
// a copy afterwards would claim.
const later = 1791300000

func vulnPredicateAt(finished string, matches ...map[string]any) map[string]any {
	return map[string]any{
		"scanner":  map[string]any{"uri": "pkg:github/anchore/grype@0.118.0", "version": "0.118.0", "result": map[string]any{"matches": matches, "descriptor": map[string]string{"name": "grype", "version": "0.118.0"}}},
		"metadata": map[string]string{"scanFinishedOn": finished},
	}
}

func provenancePredicate(repo, commit string) map[string]any {
	return map[string]any{"buildDefinition": map[string]any{
		"externalParameters":   map[string]any{"workflow": map[string]string{"repository": repo}},
		"resolvedDependencies": []any{map[string]any{"uri": "git+" + repo + "@refs/heads/main", "digest": map[string]string{"gitCommit": commit}}},
	}}
}

func sbomPredicate(pkgs ...string) map[string]any {
	var components []any
	for _, p := range pkgs {
		components = append(components, map[string]string{"type": "library", "name": p, "version": "1", "purl": "pkg:apk/wolfi/" + p + "@1"})
	}
	return map[string]any{"bomFormat": "CycloneDX", "components": components}
}

// TestOnlyVerifiedEvidenceIsRead: anyone who can push to a repository can
// attach more evidence to its images. A copy cosign didn't verify (forged,
// signed by someone else, or simply newer) must never replace what a trusted
// signer attested, in what the report shows or what the policy decides.
func TestOnlyVerifiedEvidenceIsRead(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours, evil := fulcioCert(t, ourSigner, ghIssuer), fulcioCert(t, evilSigner, ghIssuer)
	// A certificate claiming another of acme's workflows that no certificate
	// authority issued; and one claiming ours.
	otherAcme := "https://github.com/acme/other/.github/workflows/x.yml@refs/heads/main"
	forgedOther, forgedOurs := fulcioCert(t, otherAcme, ghIssuer), fulcioCert(t, ourSigner, ghIssuer)
	critical := grypeMatchJSON("CVE-2026-1", "Critical", "openssl", "3.0", "3.1")

	var forged []string
	push := func(name string, scans bool) v1.ImageIndex {
		idx := pushIndex(t, host+"/"+name+":1", nil, built, nil)
		d := descriptorOf(t, idx)
		attach(t, host+"/"+name, d, bundleJSON(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, ours))
		attach(t, host+"/"+name, d, bundleJSON(t, "https://slsa.dev/provenance/v1", d.Digest.String(), provenancePredicate("https://github.com/acme/images", "abc123"), ours))
		im, _ := idx.IndexManifest()
		for _, p := range im.Manifests {
			attach(t, host+"/"+name, p, bundleJSON(t, "https://cyclonedx.org/bom", p.Digest.String(), sbomPredicate("openssl"), ours))
			if scans {
				attach(t, host+"/"+name, p, bundleJSON(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-01T00:00:00Z", critical), ours))
			}
		}
		return idx
	}

	// app carries a trusted scan with a critical finding, and newer copies
	// that say it is clean and fresh.
	app := push("app", true)
	appDesc := descriptorOf(t, app)
	forged = append(forged,
		attach(t, host+"/app", appDesc, bundleAt(t, PredicateCosignSign, appDesc.Digest.String(), map[string]any{}, forgedOther, later)),
		attach(t, host+"/app", appDesc, bundleAt(t, "https://slsa.dev/provenance/v1", appDesc.Digest.String(), provenancePredicate("https://github.com/mallory/evil", "bad"), forgedOurs, later)))
	im, _ := app.IndexManifest()
	for _, p := range im.Manifests {
		forged = append(forged,
			attach(t, host+"/app", p, bundleAt(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-09T00:00:00Z"), forgedOurs, later)),
			attach(t, host+"/app", p, bundleAt(t, "https://cyclonedx.org/bom", p.Digest.String(), sbomPredicate("nothing-to-see"), forgedOurs, later)))
		attach(t, host+"/app", p, bundleAt(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-09T00:00:00Z"), evil, later+1))
	}

	// clean's only scans say it is clean, but no trusted signer signed them.
	clean := push("clean", false)
	im, _ = clean.IndexManifest()
	for _, p := range im.Manifests {
		attach(t, host+"/clean", p, bundleJSON(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-09T00:00:00Z"), evil))
		forged = append(forged, attach(t, host+"/clean", p, bundleJSON(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-09T00:00:00Z"), forgedOurs)))
	}

	verifier := acmeVerifier(forged...)
	// The policy shape docs/verify-estate.md shows: the scan isn't required,
	// failOn is set.
	r, err := Build(context.Background(), observe(t, host, "app:1", "clean:1"), Options{
		Name: "attached", Version: "test", GeneratedAt: "2026-10-10T00:00:00Z", Verifier: verifier,
		Policy: report.Policy{Required: []string{"signature", "sbom", "provenance"}, TrustedSigners: verifier.Signers, FailOn: "critical", MaxScanAgeDays: 7},
	})
	if err != nil {
		t.Fatal(err)
	}
	validateReport(t, r)
	img := map[string]report.Image{}
	for _, i := range r.Images {
		img[i.ID] = i
	}

	a := img["app"]
	if s := a.Evidence.Signature; s.Status != "verified" || s.Signer == nil || s.Signer.Identity != ourSigner || s.Signer.SourceRepository != "https://github.com/acme/images" {
		t.Errorf("app signature names who cosign verified: %+v %+v", s, s.Signer)
	}
	if s := a.Evidence.VulnerabilityScan; s.Status != "verified" || !strings.Contains(s.Detail, "2 other attached copies") {
		t.Errorf("app scan: %+v", s)
	}
	if v := a.Vulnerabilities; v == nil || v.Counts.Critical != 1 || v.ScannedAt != "2026-10-01T00:00:00Z" {
		t.Errorf("app vulnerabilities come from the trusted scan: %+v", v)
	}
	if a.Source == nil || a.Source.URL != "https://github.com/acme/images" || a.Source.Revision != "abc123" {
		t.Errorf("app source from the trusted provenance: %+v", a.Source)
	}
	if a.Packages == nil || *a.Packages != 1 || a.PackagesSource == nil || a.PackagesSource.Status != "verified" {
		t.Errorf("app packages from the trusted SBOM: %v %+v", a.Packages, a.PackagesSource)
	}
	reasons := strings.Join(a.Verdict.Reasons, "; ")
	if a.Verdict.Status != "failed" || !strings.Contains(reasons, "1 vulnerabilities at critical") || !strings.Contains(reasons, "9 days old") {
		t.Errorf("app verdict: %+v", a.Verdict)
	}
	for _, p := range r.Packages {
		if p.Name == "nothing-to-see" {
			t.Errorf("a forged SBOM's package is in the index: %+v", p)
		}
	}

	c := img["clean"]
	if s := c.Evidence.VulnerabilityScan; s.Status == "verified" || c.Vulnerabilities != nil {
		t.Errorf("clean's unverified scans were read: %+v %+v", s, c.Vulnerabilities)
	}
	if c.Verdict.Status != "unverified" || !strings.Contains(strings.Join(c.Verdict.Reasons, "; "), "vulnerabilities are unknown") {
		t.Errorf("clean verdict: an unverified clean scan passed failOn: %+v", c.Verdict)
	}
}

// TestForgedCertificateDoesNotVerifyAReusableWorkflow: a reusable workflow
// signs with its own identity wherever it is called from, so evidence it
// signed in another repository's run is only present. A newer copy with a
// forged certificate saying the run was in the workflow's own repository (or
// saying nothing) must not make it verified.
func TestForgedCertificateDoesNotVerifyAReusableWorkflow(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	idx := pushIndex(t, host+"/checkout:1", nil, built, nil)
	d := descriptorOf(t, idx)
	attach(t, host+"/checkout", d, bundleJSON(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, fulcioCertFrom(t, reusable, ghIssuer, "https://github.com/mallory/evil")))
	forged := []string{
		attach(t, host+"/checkout", d, bundleAt(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, fulcioCertFrom(t, reusable, ghIssuer, "https://github.com/acme/factory"), later)),
		attach(t, host+"/checkout", d, bundleAt(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, fulcioCertFrom(t, reusable, ghIssuer, ""), later+1)),
	}
	v := acmeVerifier(forged...)
	v.Signers = []report.Signer{{IdentityRegexp: `^https://github\.com/acme/factory/\.github/workflows/images\.yml@`, Issuer: ghIssuer}}
	r, err := Build(context.Background(), observe(t, host, "checkout:1"), Options{
		Name: "reusable", Version: "test", GeneratedAt: "2026-10-06T00:00:00Z", Verifier: v,
		Policy: report.Policy{Required: []string{"signature"}, TrustedSigners: v.Signers},
	})
	if err != nil {
		t.Fatal(err)
	}
	if s := r.Images[0].Evidence.Signature; s.Status == "verified" || r.Images[0].Verdict.Status == "verified" {
		t.Errorf("a forged certificate verified a reusable workflow's signature: %+v, verdict %+v", s, r.Images[0].Verdict)
	}
}

// TestPolicyWithoutTrust: with no trusted signer nothing can be verified,
// so nothing evidence says is read and no image is verified; a policy that
// requires nothing verifies nothing either.
func TestPolicyWithoutTrust(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)
	idx := pushIndex(t, host+"/app:1", nil, built, nil)
	d := descriptorOf(t, idx)
	attach(t, host+"/app", d, bundleJSON(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, ours))
	attach(t, host+"/app", d, bundleJSON(t, "https://slsa.dev/provenance/v1", d.Digest.String(), provenancePredicate("https://github.com/acme/images", "abc123"), ours))
	im, _ := idx.IndexManifest()
	for _, p := range im.Manifests {
		attach(t, host+"/app", p, bundleJSON(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-05T00:00:00Z"), ours))
	}

	build := func(p report.Policy) report.Image {
		t.Helper()
		v := acmeVerifier()
		v.Signers = p.TrustedSigners
		r, err := Build(context.Background(), observe(t, host, "app:1"), Options{Name: "empty", Version: "test", GeneratedAt: "2026-10-06T00:00:00Z", Verifier: v, Policy: p})
		if err != nil {
			t.Fatal(err)
		}
		validateReport(t, r)
		return r.Images[0]
	}
	a := build(report.Policy{})
	if a.Evidence.Signature.Status != "present" || a.Evidence.Provenance.Status != "present" || a.Vulnerabilities != nil || (a.Source != nil && a.Source.Basis == "provenance") {
		t.Errorf("evidence nothing verified was read: %+v, vulnerabilities %+v, source %+v", a.Evidence, a.Vulnerabilities, a.Source)
	}
	if a.Verdict.Status != "unverified" || !strings.Contains(a.Verdict.Reasons[0], "no trusted signer") {
		t.Errorf("empty policy verdict: %+v", a.Verdict)
	}
	a = build(report.Policy{TrustedSigners: acmeVerifier().Signers})
	if a.Evidence.Signature.Status != "verified" || a.Verdict.Status != "unverified" || !strings.Contains(a.Verdict.Reasons[0], "requires nothing") {
		t.Errorf("policy requiring nothing: %+v, verdict %+v", a.Evidence.Signature, a.Verdict)
	}
}

// TestScanAgeIsTheOldestPlatforms: every platform's scan has to be fresh.
func TestScanAgeIsTheOldestPlatforms(t *testing.T) {
	scan := func(at string) vulnScan { return vulnScan{Scanner: "grype", ScannedAt: at} }
	v := mergeVulnerabilities(map[string]vulnScan{"linux/amd64": scan("2026-10-09T00:00:00Z"), "linux/arm64": scan("2026-10-01T00:00:00Z")})
	if v.ScannedAt != "2026-10-01T00:00:00Z" {
		t.Errorf("scannedAt %q, want the older platform's", v.ScannedAt)
	}
	p := report.Policy{MaxScanAgeDays: 7, TrustedSigners: acmeVerifier().Signers}
	if got := verdictAt(report.Image{Vulnerabilities: v}, p, time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)); got.Status != "unverified" || !strings.Contains(got.Reasons[0], "9 days old") {
		t.Errorf("verdict: %+v", got)
	}
	// One platform's scan time is unknown, so the image's is.
	if v := mergeVulnerabilities(map[string]vulnScan{"linux/amd64": scan("2026-10-09T00:00:00Z"), "linux/arm64": scan("")}); v.ScannedAt != "" {
		t.Errorf("scannedAt %q with an undated platform scan", v.ScannedAt)
	}
	// Times compare as times, not strings: 01:00+02:00 is 23:00Z the day before.
	if v := mergeVulnerabilities(map[string]vulnScan{"a": scan("2026-10-09T01:00:00+02:00"), "b": scan("2026-10-08T23:30:00Z")}); v.ScannedAt != "2026-10-09T01:00:00+02:00" {
		t.Errorf("scannedAt %q", v.ScannedAt)
	}
}

func TestVerdictFailOnNeedsAVerifiedScan(t *testing.T) {
	p := report.Policy{TrustedSigners: acmeVerifier().Signers, FailOn: "critical"}
	clean := &report.Vulnerabilities{ScannedAt: "2026-10-09T00:00:00Z"}
	for status, want := range map[string]string{"verified": "verified", "present": "unverified", "failed": "unverified", "unknown": "unverified", "missing": "unverified"} {
		img := report.Image{Evidence: report.Evidence{VulnerabilityScan: report.EvidenceItem{Status: status}}, Vulnerabilities: clean}
		if status == "missing" {
			img.Vulnerabilities = nil
		}
		if got := verdict(img, p); got.Status != want {
			t.Errorf("scan %s: %+v, want %s", status, got, want)
		}
	}
	// Findings from the platforms that verified still fail it.
	img := report.Image{Evidence: report.Evidence{VulnerabilityScan: report.EvidenceItem{Status: "failed"}},
		Vulnerabilities: &report.Vulnerabilities{Findings: []report.Finding{{ID: "CVE-1", Severity: "critical"}}}}
	if got := verdict(img, p); got.Status != "failed" {
		t.Errorf("partial findings: %+v", got)
	}
	// A verified scan that couldn't be read is unknown.
	img = report.Image{Evidence: report.Evidence{VulnerabilityScan: report.EvidenceItem{Status: "verified"}}}
	if got := verdict(img, p); got.Status != "unverified" || !strings.Contains(got.Reasons[0], "couldn't be read") {
		t.Errorf("unreadable scan: %+v", got)
	}
}

func TestVerdictStaleBaseOfUnknownAge(t *testing.T) {
	p := report.Policy{TrustedSigners: acmeVerifier().Signers, MaxDaysBehind: 30}
	img := report.Image{Base: &report.BaseLink{Drift: "stale", DaysBehindUnknown: true}}
	if got := verdict(img, p); got.Status != "unverified" || !strings.Contains(got.Reasons[0], "couldn't be measured") {
		t.Errorf("stale base of unknown age: %+v", got)
	}
	img.Base = &report.BaseLink{Drift: "stale", DaysBehind: 3}
	if got := verdict(img, p); got.Status != "verified" {
		t.Errorf("stale base within the limit: %+v", got)
	}
}

// TestBaseAgeAndRoots builds an estate of reproducible images (creation
// times zeroed), and an image whose annotations name a base it isn't built
// on, which another image is built on.
func TestBaseAgeAndRoots(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	epoch := time.Unix(1, 0)
	annotate := func(base v1.ImageIndex, name string) func(string) map[string]string {
		im, _ := base.IndexManifest()
		return func(arch string) map[string]string {
			for _, d := range im.Manifests {
				if d.Platform.Architecture == arch {
					return map[string]string{"org.opencontainers.image.base.name": name, "org.opencontainers.image.base.digest": d.Digest.String()}
				}
			}
			return nil
		}
	}

	// app is on nix:1; the graph sees nix:2 is newer, but not by how much.
	nix1 := pushIndex(t, host+"/nix:1", nil, epoch, nil)
	nix2 := pushIndex(t, host+"/nix:2", nil, epoch, nil)
	pushIndex(t, host+"/app:1", nix1, epoch, nil)
	// tools names dist:2 as its base at the version it was built on, dist:1,
	// which isn't observed: its claim is checked, and found behind.
	dist1 := pushIndex(t, host+"/dist:1", nil, epoch, nil)
	pushIndex(t, host+"/dist:2", nil, epoch, nil)
	pushIndex(t, host+"/tools:1", dist1, epoch, annotate(dist1, host+"/dist:2"))
	// liar names nix:2 as its base but isn't built on it; svc is built on
	// liar.
	liar := pushIndex(t, host+"/liar:1", nil, built, annotate(nix2, host+"/nix:2"))
	pushIndex(t, host+"/svc:1", liar, built, nil)

	v := acmeVerifier()
	r, err := Build(context.Background(), observe(t, host, "nix:1", "nix:2", "app:1", "tools:1", "liar:1", "svc:1"), Options{
		Name: "nix", Version: "test", GeneratedAt: "2026-10-06T00:00:00Z", Verifier: v, Platforms: []string{"linux/amd64"},
		Policy: report.Policy{TrustedSigners: v.Signers, MaxDaysBehind: 30},
	})
	if err != nil {
		t.Fatal(err)
	}
	validateReport(t, r)
	img := map[string]report.Image{}
	for _, i := range r.Images {
		img[i.ID] = i
	}
	for _, id := range []string{"app", "tools"} {
		b := img[id].Base
		if b == nil || b.Drift != "stale" || !b.DaysBehindUnknown || b.DaysBehind != 0 {
			t.Errorf("%s base: %+v (unresolved %v)", id, b, img[id].Unresolved)
		}
		if v := img[id].Verdict; v.Status != "unverified" || !strings.Contains(strings.Join(v.Reasons, ";"), "couldn't be measured") {
			t.Errorf("%s verdict: %+v", id, v)
		}
	}
	l := img["liar"]
	if l.Root != "" || l.Base != nil || !strings.Contains(strings.Join(l.Unresolved, ";"), "doesn't start with that image's layers") {
		t.Errorf("liar: root %q base %+v unresolved %v", l.Root, l.Base, l.Unresolved)
	}
	if l.Verdict.Status != "unverified" {
		t.Errorf("liar verdict: %+v", l.Verdict)
	}
	if s := img["svc"]; s.Base == nil || s.Base.ImageID != "liar" {
		t.Errorf("svc base: %+v", s.Base)
	}
	if n := img["nix"]; n.Root == "" {
		t.Errorf("nix is a root: %+v", n)
	}
}

// TestNewestVerifiedScanBySignedTime: among scans a trusted signer verified,
// the newest is the one whose signed scan time is latest, not the one the
// registry says was attached last: an old, clean scan of the same image,
// attached again, doesn't replace a newer one that found something.
func TestNewestVerifiedScanBySignedTime(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)
	idx := pushIndex(t, host+"/app:1", nil, built, nil)
	im, _ := idx.IndexManifest()
	for _, p := range im.Manifests {
		attach(t, host+"/app", p, bundleJSON(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-08T00:00:00Z", grypeMatchJSON("CVE-2026-2", "High", "zlib", "1.3", "1.3.1")), ours))
		attach(t, host+"/app", p, bundleAt(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-01T00:00:00Z"), ours, later))
	}
	v := acmeVerifier()
	r, err := Build(context.Background(), observe(t, host, "app:1"), Options{Name: "replay", Version: "test", GeneratedAt: "2026-10-10T00:00:00Z", Verifier: v,
		Policy: report.Policy{Required: []string{"vulnerabilityScan"}, TrustedSigners: v.Signers, FailOn: "high"}})
	if err != nil {
		t.Fatal(err)
	}
	a := r.Images[0]
	if a.Evidence.VulnerabilityScan.Status != "verified" || a.Vulnerabilities == nil || a.Vulnerabilities.Counts.High != 1 || a.Vulnerabilities.ScannedAt != "2026-10-08T00:00:00Z" {
		t.Errorf("scan: %+v, vulnerabilities %+v", a.Evidence.VulnerabilityScan, a.Vulnerabilities)
	}
	if a.Verdict.Status != "failed" {
		t.Errorf("verdict: %+v", a.Verdict)
	}
}
