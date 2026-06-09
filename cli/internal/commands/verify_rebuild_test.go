package commands

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyRebuildMatchesDigestAndEquivalentClosures(t *testing.T) {
	root := t.TempDir()
	runtimeClosure := filepath.Join(root, "runtime.txt")
	graftedClosure := filepath.Join(root, "grafted.txt")
	if err := os.WriteFile(runtimeClosure, []byte("/nix/store/b-runtime\n/nix/store/a-runtime\n/nix/store/a-runtime\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(graftedClosure, []byte("# normalized\n/nix/store/a-runtime\n/nix/store/b-runtime\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldCapture := captureExternalOutput
	captureExternalOutput = func(c externalCommand) (string, error) {
		if c.Name != "crane" || strings.Join(c.Args, " ") != "digest ghcr.io/acme/base:v1" {
			t.Fatalf("unexpected external command: %#v", c)
		}
		return "sha256:expected\n", nil
	}
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	stdout, err := runCLI(t,
		"verify", "rebuild",
		"--target", "java21-distroless",
		"--expected-ref", "ghcr.io/acme/base:v1",
		"--expected-digest", "sha256:expected",
		"--runtime-closure-file", runtimeClosure,
		"--grafted-closure-file", graftedClosure,
		"--require-digest-match",
		"--require-closure-equivalence",
		"--output-predicate",
	)
	if err != nil {
		t.Fatalf("verify rebuild failed: %v\n%s", err, stdout)
	}

	var predicate verifyRebuildPredicate
	if err := json.Unmarshal([]byte(stdout), &predicate); err != nil {
		t.Fatalf("predicate JSON did not parse: %v\n%s", err, stdout)
	}
	if predicate.Status != "pass" || predicate.Digest == nil || !predicate.Digest.Match || predicate.Closure == nil || !predicate.Closure.Equivalent {
		t.Fatalf("unexpected predicate: %#v", predicate)
	}
	if predicate.Closure.RuntimePaths != 2 || predicate.Closure.RuntimeHash != predicate.Closure.GraftedHash {
		t.Fatalf("closure normalization/hash mismatch: %#v", predicate.Closure)
	}
}

func TestVerifyRebuildFailsClosedOnMismatch(t *testing.T) {
	root := t.TempDir()
	runtimeClosure := filepath.Join(root, "runtime.txt")
	graftedClosure := filepath.Join(root, "grafted.txt")
	if err := os.WriteFile(runtimeClosure, []byte("/nix/store/a-runtime\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(graftedClosure, []byte("/nix/store/b-runtime\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldCapture := captureExternalOutput
	captureExternalOutput = func(c externalCommand) (string, error) {
		return "sha256:actual\n", nil
	}
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	stdout, err := runCLI(t,
		"verify", "rebuild",
		"--target", "java21-distroless",
		"--expected-ref", "ghcr.io/acme/base:v1",
		"--expected-digest", "sha256:expected",
		"--runtime-closure-file", runtimeClosure,
		"--grafted-closure-file", graftedClosure,
		"--require-digest-match",
		"--require-closure-equivalence",
	)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected ErrCheckFailed, got %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "digest mismatch") || !strings.Contains(stdout, "closure mismatch") {
		t.Fatalf("expected mismatch details, got:\n%s", stdout)
	}
}

func TestVerifyRebuildParsesProvenanceAndMatchesLayers(t *testing.T) {
	root := t.TempDir()
	provenance := filepath.Join(root, "provenance.json")
	if err := os.WriteFile(provenance, []byte(`{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "subject": [{"name": "ghcr.io/acme/clearcutt-java21:v1", "digest": {"sha256": "expected"}}],
  "predicate": {
    "materials": [{
      "uri": "git+https://github.com/northcutted/clearcutt@refs/heads/main",
      "digest": {"gitCommit": "abc123"}
    }]
  }
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	layer := overlayLayer(t, map[string]string{"nix/store/a-runtime/bin/java": "runtime"})
	rebuilt := overlayDockerArchive(t, layer, "rebuilt:latest")
	registry := overlayDockerArchive(t, layer, "registry:latest")

	oldCapture := captureExternalOutput
	captureExternalOutput = func(c externalCommand) (string, error) {
		if c.Name != "crane" || strings.Join(c.Args, " ") != "digest ghcr.io/acme/clearcutt-java21:v1" {
			t.Fatalf("unexpected external command: %#v", c)
		}
		return "sha256:expected\n", nil
	}
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	stdout, err := runCLI(t,
		"verify", "rebuild", "ghcr.io/acme/clearcutt-java21:v1",
		"--target", "java21-distroless",
		"--provenance-file", provenance,
		"--rebuilt-archive", rebuilt,
		"--registry-archive", registry,
		"--require-digest-match",
		"--require-layer-match",
		"--output-predicate",
	)
	if err != nil {
		t.Fatalf("verify rebuild failed: %v\n%s", err, stdout)
	}
	var predicate verifyRebuildPredicate
	if err := json.Unmarshal([]byte(stdout), &predicate); err != nil {
		t.Fatalf("predicate JSON did not parse: %v\n%s", err, stdout)
	}
	if predicate.Provenance == nil || predicate.Provenance.SourceRepo != "https://github.com/northcutted/clearcutt" || predicate.Provenance.SourceCommit != "abc123" {
		t.Fatalf("unexpected provenance: %#v", predicate.Provenance)
	}
	if len(predicate.Subject) != 1 || predicate.Subject[0].Digest["sha256"] != "expected" {
		t.Fatalf("unexpected subject: %#v", predicate.Subject)
	}
	if predicate.Layers == nil || !predicate.Layers.Match || len(predicate.Layers.RebuiltLayerDigests) != 1 {
		t.Fatalf("unexpected layer result: %#v", predicate.Layers)
	}
}

func TestVerifyRebuildCheckoutAndNixBuildFromPinnedProvenance(t *testing.T) {
	root := t.TempDir()
	provenance := filepath.Join(root, "provenance.json")
	if err := os.WriteFile(provenance, []byte(`{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "materials": [{
      "uri": "git+https://github.com/northcutted/clearcutt@refs/tags/v1",
      "digest": {"gitCommit": "def456"}
    }]
  }
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	checkout := filepath.Join(root, "checkout")
	outLink := filepath.Join(root, "rebuilt.tar")
	var calls []string
	oldCapture := captureExternalOutput
	captureExternalOutput = func(c externalCommand) (string, error) {
		calls = append(calls, c.Name+" "+strings.Join(c.Args, " ")+" @ "+c.Dir)
		return "", nil
	}
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	stdout, err := runCLI(t,
		"verify", "rebuild",
		"--target", "java21-distroless",
		"--provenance-file", provenance,
		"--rebuild",
		"--checkout-dir", checkout,
		"--out-link", outLink,
		"--output-predicate",
	)
	if err != nil {
		t.Fatalf("verify rebuild failed: %v\n%s", err, stdout)
	}
	flat := strings.Join(calls, "\n")
	for _, needle := range []string{
		"git clone https://github.com/northcutted/clearcutt " + checkout,
		"git fetch --depth 1 origin def456 @ " + checkout,
		"git checkout --detach def456 @ " + checkout,
		"nix --extra-experimental-features nix-command flakes build .#java21-distroless --out-link " + outLink + " @ " + filepath.Join(checkout, "core"),
	} {
		if !strings.Contains(flat, needle) {
			t.Fatalf("missing command %q in:\n%s", needle, flat)
		}
	}
}

func TestVerifyRebuildDownloadsProvenanceWhenDigestComesFromSubject(t *testing.T) {
	statement := `{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "subject": [{"name": "ghcr.io/acme/clearcutt-java21:v1", "digest": {"sha256": "expected"}}],
  "predicate": {
    "materials": [{
      "uri": "git+https://github.com/northcutted/clearcutt@refs/heads/main",
      "digest": {"gitCommit": "abc123"}
    }]
  }
}`
	envelope := `{"payload":"` + base64.StdEncoding.EncodeToString([]byte(statement)) + `"}`
	var calls []string
	oldCapture := captureExternalOutput
	captureExternalOutput = func(c externalCommand) (string, error) {
		calls = append(calls, c.Name+" "+strings.Join(c.Args, " "))
		switch c.Name {
		case "cosign":
			return envelope, nil
		case "crane":
			return "sha256:expected\n", nil
		default:
			t.Fatalf("unexpected external command: %#v", c)
			return "", nil
		}
	}
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	stdout, err := runCLI(t,
		"verify", "rebuild", "ghcr.io/acme/clearcutt-java21:v1",
		"--target", "java21-distroless",
		"--require-digest-match",
		"--output-predicate",
	)
	if err != nil {
		t.Fatalf("verify rebuild failed: %v\n%s", err, stdout)
	}
	flat := strings.Join(calls, "\n")
	if !strings.Contains(flat, "cosign download attestation --predicate-type https://slsa.dev/provenance/v1 ghcr.io/acme/clearcutt-java21:v1") {
		t.Fatalf("expected cosign provenance download, got:\n%s", flat)
	}
	var predicate verifyRebuildPredicate
	if err := json.Unmarshal([]byte(stdout), &predicate); err != nil {
		t.Fatalf("predicate JSON did not parse: %v\n%s", err, stdout)
	}
	if predicate.Provenance == nil || predicate.Provenance.SourceCommit != "abc123" || predicate.Digest == nil || !predicate.Digest.Match {
		t.Fatalf("unexpected downloaded provenance predicate: %#v", predicate)
	}
}
