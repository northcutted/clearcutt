package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/evidence"
)

// TestPublishAttachesEvidenceAndTheCatalogReadsItBack closes the registry-only
// loop: `fleet publish-target` writes evidence into the registry, and
// `--evidence-source=registry` finds it there. Until publish wrote that plane,
// reading from it found nothing — the two halves are only useful together.
func TestPublishAttachesEvidenceAndTheCatalogReadsItBack(t *testing.T) {
	host := evidenceTestRegistry(t)
	ref := host + "/acme/clearcutt-java:v1.4.0"
	subject := seedEvidenceSubject(t, ref)
	_ = subject

	// Stand in for what CertifyTarget leaves in the build output directory.
	outDir := t.TempDir()
	target := "java25-distroless"
	for suffix, body := range map[string]string{
		".sbom.json":         `{"spdxVersion":"SPDX-2.3","packages":[]}`,
		".grype.json":        `{"matches":[]}`,
		".test-results.json": `{"assertions":[]}`,
	} {
		if err := os.WriteFile(filepath.Join(outDir, target+suffix), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	restoreClient := evidenceClientForFleet
	evidenceClientForFleet = func() *evidence.Client { return evidence.NewInsecureClient() }
	t.Cleanup(func() { evidenceClientForFleet = restoreClient })

	restoreAttach, restoreTag := fleetOpts.attachEvidence, fleetOpts.versionTag
	fleetOpts.attachEvidence, fleetOpts.versionTag = true, "v1.4.0"
	t.Cleanup(func() { fleetOpts.attachEvidence, fleetOpts.versionTag = restoreAttach, restoreTag })

	if err := attachTargetEvidence(ref, target, outDir); err != nil {
		t.Fatalf("attach evidence: %v", err)
	}

	// Now read it back the way the catalog does — through the interface, with
	// no knowledge that a registry is involved.
	source := evidence.NewReleaseSource(evidence.NewInsecureClient(), host+"/acme/clearcutt-java")
	releases, err := source.ListReleases(10)
	if err != nil {
		t.Fatalf("list releases: %v", err)
	}
	if len(releases) != 1 {
		t.Fatalf("expected one release, got %+v", releases)
	}
	if releases[0].Tag != "v1.4.0" {
		t.Errorf("release tag = %q, want v1.4.0", releases[0].Tag)
	}
	names := []string{}
	for _, asset := range releases[0].Assets {
		names = append(names, asset.Name)
	}
	got := strings.Join(names, ",")
	if got != "sbom.json,scan.json,test-results.json" {
		t.Fatalf("evidence assets = %q, want the three stable names", got)
	}

	// The names are target-independent on purpose: a consumer reads sbom.json
	// whatever image produced it.
	for _, asset := range releases[0].Assets {
		if strings.Contains(asset.Name, target) {
			t.Errorf("bundle file %q leaks the target name; bundles use stable names", asset.Name)
		}
	}

	body, err := source.DownloadAsset(releases[0].Assets[0])
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !strings.Contains(string(body), "SPDX-2.3") {
		t.Errorf("sbom did not round-trip: %q", body)
	}
}

// TestPublishEvidenceAttachmentIsOffByDefault pins the default. Turning it on
// would make every existing publish newly depend on a registry write it did not
// need before — the same class of silent upgrade change as defaulting the read
// side to the registry, and caught the same way: an existing publish test
// started reaching for a registry that does not exist.
func TestPublishEvidenceAttachmentIsOffByDefault(t *testing.T) {
	fresh := fleetFlags{}
	if fresh.attachEvidence {
		t.Fatal("evidence attachment must default to off; switching planes is a migration, not an upgrade side effect")
	}

	restore := fleetOpts.attachEvidence
	fleetOpts.attachEvidence = false
	t.Cleanup(func() { fleetOpts.attachEvidence = restore })

	restoreClient := evidenceClientForFleet
	evidenceClientForFleet = func() *evidence.Client {
		t.Fatal("evidence must not be attached when the flag is off")
		return nil
	}
	t.Cleanup(func() { evidenceClientForFleet = restoreClient })

	if err := attachTargetEvidence("reg.test/acme/app:v1", "java25-distroless", t.TempDir()); err != nil {
		t.Fatalf("disabled attachment should be a no-op, got %v", err)
	}
}

// TestPublishWithNoEvidenceArtifactsSaysSo: a build that produced no evidence
// should report that rather than failing the publish or silently attaching an
// empty bundle.
func TestPublishWithNoEvidenceArtifactsSaysSo(t *testing.T) {
	restore := fleetOpts.attachEvidence
	fleetOpts.attachEvidence = true
	t.Cleanup(func() { fleetOpts.attachEvidence = restore })

	restoreClient := evidenceClientForFleet
	evidenceClientForFleet = func() *evidence.Client {
		t.Fatal("an empty bundle must not be attached")
		return nil
	}
	t.Cleanup(func() { evidenceClientForFleet = restoreClient })

	var buf strings.Builder
	oldOut := out
	out = &buf
	t.Cleanup(func() { out = oldOut })

	if err := attachTargetEvidence("reg.test/acme/app:v1", "java25-distroless", t.TempDir()); err != nil {
		t.Fatalf("no artifacts should not fail the publish, got %v", err)
	}
	if !strings.Contains(buf.String(), "nothing to attach") {
		t.Errorf("the absence should be reported, got: %q", buf.String())
	}
}
