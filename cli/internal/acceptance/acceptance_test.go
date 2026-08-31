package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "acceptances.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const validDoc = `apiVersion: clearcutt.dev/v1
kind: VulnerabilityAcceptances
acceptances:
  - id: openssl-pending-3.6.4
    package: openssl
    versions: ["3.6.3"]
    vulnerabilities: [CVE-2026-18798, CVE-2026-54876]
    reason: Fixed in openssl 3.6.4; the pinned nixpkgs ships 3.6.3.
    fixedIn: 3.6.4
    acceptedBy: platform-team
    acceptedAt: "2026-08-31"
    expiresAt: "2026-10-31"
`

func day(s string) time.Time {
	d, _ := time.Parse(dateLayout, s)
	return d
}

func TestLoadMissingFileAcceptsNothing(t *testing.T) {
	doc, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("a missing acceptance file is the normal case: %v", err)
	}
	if len(doc.Acceptances) != 0 {
		t.Fatalf("expected no acceptances, got %+v", doc.Acceptances)
	}
}

func TestLoadRejectsUnattributedOrUnexplainedAcceptances(t *testing.T) {
	base := `apiVersion: clearcutt.dev/v1
kind: VulnerabilityAcceptances
acceptances:
  - id: a
    package: openssl
    vulnerabilities: [CVE-1]
    reason: %s
    acceptedBy: %s
    acceptedAt: "2026-08-31"
    expiresAt: "2026-10-31"
`
	for name, body := range map[string]string{
		"no reason":     strings.Replace(base, "%s", `""`, 1),
		"no acceptedBy": base,
	} {
		t.Run(name, func(t *testing.T) {
			filled := strings.ReplaceAll(strings.ReplaceAll(body, "reason: %s", `reason: "because"`), "acceptedBy: %s", `acceptedBy: ""`)
			if name == "no reason" {
				filled = strings.ReplaceAll(strings.ReplaceAll(base, "reason: %s", `reason: ""`), "acceptedBy: %s", "acceptedBy: someone")
			}
			if _, err := Load(write(t, filled)); err == nil {
				t.Fatalf("%s should be rejected: an acceptance without it is an ignore rule", name)
			}
		})
	}
}

func TestLoadRequiresAWellFormedExpiry(t *testing.T) {
	for name, expiry := range map[string]string{
		"missing":      `""`,
		"not a date":   `"soon"`,
		"before start": `"2026-08-01"`,
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(validDoc, `expiresAt: "2026-10-31"`, "expiresAt: "+expiry, 1)
			if _, err := Load(write(t, body)); err == nil {
				t.Fatalf("expiry %s must be rejected", name)
			}
		})
	}
}

func TestLoadRejectsDuplicateIDs(t *testing.T) {
	body := validDoc + strings.SplitN(validDoc, "acceptances:\n", 2)[1]
	if _, err := Load(write(t, body)); err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Fatalf("expected a duplicate-id error, got %v", err)
	}
}

func TestClassifySplitsAcceptedExpiredAndUnaccepted(t *testing.T) {
	doc, err := Load(write(t, validDoc))
	if err != nil {
		t.Fatal(err)
	}
	findings := []Finding{
		{ID: "CVE-2026-18798", Package: "openssl", Version: "3.6.3", Severity: "High"},
		{ID: "CVE-2026-99999", Package: "openssl", Version: "3.6.3", Severity: "High"}, // not listed
		{ID: "CVE-2026-18798", Package: "python", Version: "3.14.7", Severity: "High"}, // wrong package
	}
	res := Classify(doc, findings, day("2026-09-15"))

	if len(res.Accepted) != 1 || res.Accepted[0].Finding.ID != "CVE-2026-18798" {
		t.Fatalf("Accepted = %+v", res.Accepted)
	}
	if res.Accepted[0].AcceptanceID != "openssl-pending-3.6.4" || res.Accepted[0].AcceptedBy != "platform-team" {
		t.Fatalf("acceptance attribution lost: %+v", res.Accepted[0])
	}
	if len(res.Unaccepted) != 2 {
		t.Fatalf("an unlisted CVE and a different package must both stay unaccepted: %+v", res.Unaccepted)
	}
	if !res.Blocking() {
		t.Fatal("unaccepted findings must block")
	}
}

func TestClassifyBlocksOnAnExpiredAcceptance(t *testing.T) {
	doc, err := Load(write(t, validDoc))
	if err != nil {
		t.Fatal(err)
	}
	f := []Finding{{ID: "CVE-2026-18798", Package: "openssl", Version: "3.6.3", Severity: "High"}}

	// Valid the day it expires...
	if res := Classify(doc, f, day("2026-10-31")); len(res.Accepted) != 1 || res.Blocking() {
		t.Fatalf("an acceptance is valid through its expiry date: %+v", res)
	}
	// ...and blocking after.
	res := Classify(doc, f, day("2026-11-02"))
	if len(res.Expired) != 1 || len(res.Accepted) != 0 {
		t.Fatalf("Expired = %+v Accepted = %+v", res.Expired, res.Accepted)
	}
	if !res.Blocking() {
		t.Fatal("an expired acceptance must block — that is the whole point of the expiry")
	}
}

func TestClassifyDoesNotCoverAnUnnamedPackageVersion(t *testing.T) {
	doc, err := Load(write(t, validDoc))
	if err != nil {
		t.Fatal(err)
	}
	// Same CVE, same package, a version the acceptance never named.
	res := Classify(doc, []Finding{{ID: "CVE-2026-18798", Package: "openssl", Version: "3.7.0", Severity: "High"}}, day("2026-09-15"))
	if len(res.Unaccepted) != 1 {
		t.Fatalf("a version bump must resurface the decision, got %+v", res)
	}
}

func TestReadGrypeFindingsMatchesTheRealGateSet(t *testing.T) {
	// The committed fixture is the actual scan of python3.14-slim that failed CI.
	findings, err := ReadGrypeFindings(filepath.Join("testdata", "openssl-3.6.3.grype.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 8 {
		t.Fatalf("expected the 8 blocking findings grype exits 2 on, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Package != "openssl" || f.Version != "3.6.3" {
			t.Fatalf("unexpected finding %+v", f)
		}
		if !strings.Contains(f.FixedIn, "3.6.4") {
			t.Fatalf("every one of these is fixed in 3.6.4: %+v", f)
		}
	}
}

func TestRealScanIsFullyCoveredByTheCommittedAcceptance(t *testing.T) {
	// End to end against the repo's own acceptance file and the real scan: the
	// gate should pass today, and every finding should be attributed.
	repoDoc := filepath.Join("..", "..", "..", "core", "vulnerability-acceptances.yaml")
	if _, err := os.Stat(repoDoc); err != nil {
		t.Skipf("no committed acceptance file: %v", err)
	}
	doc, err := Load(repoDoc)
	if err != nil {
		t.Fatalf("the committed acceptance file must be valid: %v", err)
	}
	findings, err := ReadGrypeFindings(filepath.Join("testdata", "openssl-3.6.3.grype.json"))
	if err != nil {
		t.Fatal(err)
	}
	res := Classify(doc, findings, time.Now())
	if len(res.Unaccepted) > 0 {
		t.Fatalf("findings with no acceptance: %+v", res.Unaccepted)
	}
	if len(res.Expired) > 0 {
		t.Fatalf("the committed acceptance has expired and must be renewed or dropped: %+v", res.Expired)
	}
	if len(res.Accepted) != len(findings) {
		t.Fatalf("every finding should be attributed, got %d of %d", len(res.Accepted), len(findings))
	}
}
