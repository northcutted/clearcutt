package certify

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tarEntry struct {
	name     string
	mode     int64
	typeflag byte
	body     []byte
	linkname string
}

func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typeflag := e.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     e.mode,
			Typeflag: typeflag,
			Size:     int64(len(e.body)),
			Linkname: e.linkname,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", e.name, err)
		}
		if len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("write body %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// dockerArchive writes a legacy docker-save tarball with the given uncompressed
// layer tarballs and returns its path.
func dockerArchive(t *testing.T, layers ...[]byte) string {
	t.Helper()
	outer := []tarEntry{{name: "config.json", mode: 0o644, body: []byte(`{"config":{}}`)}}
	names := make([]string, 0, len(layers))
	for i, layer := range layers {
		name := fmt.Sprintf("layer%d.tar", i)
		names = append(names, fmt.Sprintf("%q", name))
		outer = append(outer, tarEntry{name: name, mode: 0o644, body: layer})
	}
	manifest := fmt.Sprintf(`[{"Config":"config.json","RepoTags":["test:latest"],"Layers":[%s]}]`, strings.Join(names, ","))
	outer = append(outer, tarEntry{name: "manifest.json", mode: 0o644, body: []byte(manifest)})

	dir := t.TempDir()
	p := filepath.Join(dir, "image.tar")
	if err := os.WriteFile(p, buildTar(t, outer), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	return p
}

func scanArchive(t *testing.T, archive string, allowlist []ClosureAllowlistEntry) ClosurePurityResult {
	t.Helper()
	res, err := ScanImageArchiveForClosurePurity(archive, allowlist)
	if err != nil {
		t.Fatalf("scan archive: %v", err)
	}
	return res
}

func violationMessages(res ClosurePurityResult) string {
	var b strings.Builder
	for _, v := range res.Violations {
		b.WriteString(v.Message)
		b.WriteString("\n")
	}
	return b.String()
}

func TestClosurePurityFlagsShellPkgManagerAndSetuid(t *testing.T) {
	layer := buildTar(t, []tarEntry{
		{name: "nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bash-5.2/bin/bash", mode: 0o755},
		{name: "nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-python3-3.14/bin/pip3.14", mode: 0o755},
		{name: "nix/store/cccccccccccccccccccccccccccccccc-foolib-1.0/bin/legit", mode: 0o755},
		{name: "nix/store/dddddddddddddddddddddddddddddddd-mountpkg-1.0/bin/mount", mode: 0o4755},
	})
	res := scanArchive(t, dockerArchive(t, layer), nil)

	if res.Clean() {
		t.Fatalf("expected violations, got clean")
	}
	if len(res.Violations) != 3 {
		t.Fatalf("expected 3 violations, got %d:\n%s", len(res.Violations), violationMessages(res))
	}
	msgs := violationMessages(res)
	for _, want := range []string{
		"provides interactive shell bin/bash",
		"provides package manager bin/pip3.14",
		"setuid regular file /nix/store/dddddddddddddddddddddddddddddddd-mountpkg-1.0/bin/mount (mode 4755)",
	} {
		if !strings.Contains(msgs, want) {
			t.Errorf("missing expected violation %q in:\n%s", want, msgs)
		}
	}
	if strings.Contains(msgs, "legit") {
		t.Errorf("non-flagged binary was reported:\n%s", msgs)
	}
}

func TestClosurePurityCleanImage(t *testing.T) {
	layer := buildTar(t, []tarEntry{
		{name: "nix/store/cccccccccccccccccccccccccccccccc-foolib-1.0/bin/legit", mode: 0o755},
		{name: "nix/store/cccccccccccccccccccccccccccccccc-foolib-1.0/lib/foo.so", mode: 0o644},
	})
	res := scanArchive(t, dockerArchive(t, layer), nil)
	if !res.Clean() {
		t.Fatalf("expected clean, got: %s", violationMessages(res))
	}
}

func TestClosurePurityWhiteoutDiscardsFinding(t *testing.T) {
	base := buildTar(t, []tarEntry{
		{name: "nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bash-5.2/bin/bash", mode: 0o755},
	})
	// A later layer whiteouts the exact bash entry; the finding must be dropped.
	whiteout := buildTar(t, []tarEntry{
		{name: "nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bash-5.2/bin/.wh.bash", mode: 0o644},
	})
	res := scanArchive(t, dockerArchive(t, base, whiteout), nil)
	if !res.Clean() {
		t.Fatalf("expected whiteout to discard the finding, got: %s", violationMessages(res))
	}
}

func TestClosurePurityAllowlistAccepts(t *testing.T) {
	layer := buildTar(t, []tarEntry{
		{name: "nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bash-5.2/bin/bash", mode: 0o755},
	})
	dir := t.TempDir()
	allowPath := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(allowPath, []byte("# explained exception\nbash-5.2* launcher needs a shell; tracked in #1\n"), 0o644); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}
	allowlist, err := LoadClosureAllowlist(allowPath)
	if err != nil {
		t.Fatalf("load allowlist: %v", err)
	}
	res := scanArchive(t, dockerArchive(t, layer), allowlist)
	if !res.Clean() {
		t.Fatalf("allowlisted finding should not be a violation, got: %s", violationMessages(res))
	}
	if len(res.Accepted) != 1 {
		t.Fatalf("expected 1 accepted note, got %d: %v", len(res.Accepted), res.Accepted)
	}
	if !strings.Contains(res.Accepted[0], "bash-5.2*") {
		t.Errorf("accepted note missing pattern: %q", res.Accepted[0])
	}
}

func TestLoadClosureAllowlistRejectsUnexplained(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(p, []byte("bash-5.2*\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadClosureAllowlist(p); err == nil {
		t.Fatalf("expected error for unexplained allowlist entry")
	}
}

func TestLoadClosureAllowlistMissingFileIsEmpty(t *testing.T) {
	entries, err := LoadClosureAllowlist(filepath.Join(t.TempDir(), "does-not-exist.txt"))
	if err != nil {
		t.Fatalf("missing file should be a no-op, got: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected empty allowlist, got %d entries", len(entries))
	}
}

func TestClosurePurityUnsupportedArchive(t *testing.T) {
	// A tar with neither manifest.json nor index.json is not an image.
	data := buildTar(t, []tarEntry{{name: "random.txt", mode: 0o644, body: []byte("x")}})
	p := filepath.Join(t.TempDir(), "bad.tar")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ScanImageArchiveForClosurePurity(p, nil); err == nil {
		t.Fatal("expected unsupported-archive error")
	}
}

func TestClosurePurityMissingArchive(t *testing.T) {
	if _, err := ScanImageArchiveForClosurePurity(filepath.Join(t.TempDir(), "nope.tar"), nil); err == nil {
		t.Fatal("expected error for a missing archive")
	}
}

func TestClosurePurityStorePathsMode(t *testing.T) {
	root := t.TempDir()
	storeDir := filepath.Join(root, "store", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-busybox-1.36")
	if err := os.MkdirAll(filepath.Join(storeDir, "bin"), 0o755); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	if err := os.WriteFile(filepath.Join(storeDir, "bin", "sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write sh: %v", err)
	}
	if err := os.WriteFile(filepath.Join(storeDir, "bin", "true"), []byte("x"), 0o755); err != nil {
		t.Fatalf("write true: %v", err)
	}
	pathsFile := filepath.Join(root, "store-paths")
	if err := os.WriteFile(pathsFile, []byte(storeDir+"\n"), 0o644); err != nil {
		t.Fatalf("write store-paths: %v", err)
	}

	res, err := ScanStorePathsForClosurePurity(pathsFile, nil)
	if err != nil {
		t.Fatalf("scan store paths: %v", err)
	}
	if res.Clean() {
		t.Fatalf("expected bin/sh to be flagged")
	}
	if !strings.Contains(violationMessages(res), "provides interactive shell bin/sh") {
		t.Errorf("missing bin/sh violation:\n%s", violationMessages(res))
	}
	if strings.Contains(violationMessages(res), "bin/true") {
		t.Errorf("non-flagged binary reported:\n%s", violationMessages(res))
	}
}

func TestFnmatchToRegexp(t *testing.T) {
	cases := []struct {
		pattern, candidate string
		want               bool
	}{
		{"bash-5.2*", "bash-5.2p37", true},
		{"bash-5.2*", "bash-5.1", false},
		{"*-dev", "icu4c-dev", true},
		{"*-dev", "icu4c", false},
		{"pip?", "pip3", true},
		{"pip?", "pip", false},
		// character classes (the fnmatch [...] branch)
		{"[abc]x", "ax", true},
		{"[abc]x", "dx", false},
		{"[!abc]x", "dx", true},
		{"[!abc]x", "ax", false},
		{"openssl-3.[0-9]", "openssl-3.6", true},
		{"openssl-3.[0-9]", "openssl-3.x", false},
		// an unterminated '[' is a literal bracket
		{"weird[", "weird[", true},
	}
	for _, c := range cases {
		re, err := fnmatchToRegexp(c.pattern)
		if err != nil {
			t.Fatalf("compile %q: %v", c.pattern, err)
		}
		if got := re.MatchString(c.candidate); got != c.want {
			t.Errorf("fnmatch(%q, %q) = %v, want %v", c.pattern, c.candidate, got, c.want)
		}
	}
}
