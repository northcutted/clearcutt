package commands

import (
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func evidenceTestRegistry(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(registry.New())
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Host
}

func seedEvidenceSubject(t *testing.T, ref string) v1.Image {
	t.Helper()
	img, err := random.Image(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	pushEvidenceSubject(t, ref, img)
	return img
}

func pushEvidenceSubject(t *testing.T, ref string, img v1.Image) {
	t.Helper()
	target, err := name.ParseReference(ref, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(target, img); err != nil {
		t.Fatal(err)
	}
}

func writeEvidenceFiles(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"sbom.json":       `{"spdxVersion":"SPDX-2.3","packages":[]}`,
		"provenance.json": `{"_type":"https://in-toto.io/Statement/v1"}`,
		"scan.json":       `{"matches":[]}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestEvidenceCommandRoundTrip drives the user-facing path end to end: attach,
// list, export, and restore into a different registry.
func TestEvidenceCommandRoundTrip(t *testing.T) {
	host := evidenceTestRegistry(t)
	ref := host + "/acme/app:v1.4.0"
	subject := seedEvidenceSubject(t, ref)
	dir := writeEvidenceFiles(t)

	stdout, err := runCLI(t, "evidence", "attach", ref, "--dir", dir,
		"--release", "v1.4.0", "--created", "2026-09-01T00:00:00Z", "--insecure")
	if err != nil {
		t.Fatalf("attach: %v\n%s", err, stdout)
	}
	// test-results.json is absent; the default set should tolerate that and say so.
	if !strings.Contains(stdout, "test-results.json not present") {
		t.Errorf("a missing default file should be reported, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "bundle sha256:") {
		t.Fatalf("attach should report the bundle digest:\n%s", stdout)
	}
	// The GC hedge must be advertised where an operator will see it.
	if !strings.Contains(stdout, "evidence export") {
		t.Errorf("attach should point at export as the retention hedge:\n%s", stdout)
	}

	listed, err := runCLI(t, "evidence", "list", ref, "--insecure")
	if err != nil {
		t.Fatalf("list: %v\n%s", err, listed)
	}
	for _, want := range []string{"v1.4.0", "2026-09-01T00:00:00Z", "sbom.json", "provenance.json", "scan.json"} {
		if !strings.Contains(listed, want) {
			t.Errorf("list output missing %q:\n%s", want, listed)
		}
	}

	exportDir := filepath.Join(t.TempDir(), "export")
	exported, err := runCLI(t, "evidence", "export", ref, "--output", exportDir, "--insecure")
	if err != nil {
		t.Fatalf("export: %v\n%s", err, exported)
	}
	for _, rel := range []string{"export.json", filepath.Join("oci", "index.json")} {
		if _, err := os.Stat(filepath.Join(exportDir, rel)); err != nil {
			t.Errorf("export should write %s: %v", rel, err)
		}
	}

	// Restore into a DIFFERENT registry: an export is only insurance if it can
	// be put back somewhere the original is not.
	//
	// The SAME image is pushed there first, deliberately. Evidence pins its
	// subject by digest, so it reconnects to the bytes it was made about and
	// nothing else — restoring it next to a different image would correctly
	// find nothing. That is the disaster-recovery shape: images come back at
	// their original digests, then evidence re-attaches to them.
	fresh := evidenceTestRegistry(t)
	freshRef := fresh + "/acme/app:v1.4.0"
	pushEvidenceSubject(t, freshRef, subject)
	restored, err := runCLI(t, "evidence", "import", exportDir, fresh+"/acme/app", "--insecure")
	if err != nil {
		t.Fatalf("import: %v\n%s", err, restored)
	}
	if !strings.Contains(restored, "signatures over this evidence still verify") {
		t.Errorf("import should state that digests are preserved:\n%s", restored)
	}
	relisted, err := runCLI(t, "evidence", "list", freshRef, "--insecure")
	if err != nil {
		t.Fatalf("list after restore: %v\n%s", err, relisted)
	}
	if !strings.Contains(relisted, "sbom.json") {
		t.Errorf("restored evidence should be listable in the new registry:\n%s", relisted)
	}
}

func TestEvidenceListReportsAbsenceRatherThanFailing(t *testing.T) {
	host := evidenceTestRegistry(t)
	ref := host + "/acme/bare:v1"
	seedEvidenceSubject(t, ref)
	stdout, err := runCLI(t, "evidence", "list", ref, "--insecure")
	if err != nil {
		t.Fatalf("listing an image with no evidence should succeed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "no evidence attached") {
		t.Errorf("absence should be reported explicitly:\n%s", stdout)
	}
}

func TestEvidenceAttachWithoutFilesExplainsItself(t *testing.T) {
	host := evidenceTestRegistry(t)
	ref := host + "/acme/app:v1"
	seedEvidenceSubject(t, ref)
	stdout, err := runCLI(t, "evidence", "attach", ref, "--dir", t.TempDir(), "--insecure")
	if err == nil {
		t.Fatalf("attaching an empty directory should fail:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "no evidence files found") {
		t.Fatalf("error should say what was looked for, got: %v", err)
	}
}

func TestEvidenceExportWithNothingToExportFails(t *testing.T) {
	host := evidenceTestRegistry(t)
	ref := host + "/acme/bare:v1"
	seedEvidenceSubject(t, ref)
	if _, err := runCLI(t, "evidence", "export", ref, "--output", t.TempDir(), "--insecure"); err == nil {
		t.Fatal("exporting an image with no evidence should fail rather than write an empty bundle")
	}
}
