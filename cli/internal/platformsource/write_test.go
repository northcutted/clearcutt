package platformsource

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteArchiveRoundTripsMinimalRepo(t *testing.T) {
	root := t.TempDir()
	for rel, body := range map[string]string{
		"clearcutt.fleet.yaml": "registry:\n  host: ghcr.io\n",
		"go.work":              "go 1.22\n",
		"cli/go.mod":           "module example.com/clearcutt\n",
		"cli/.DS_Store":        "junk that the rules must skip\n",
	} {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dest, err := WriteArchive(root)
	if err != nil {
		t.Fatalf("WriteArchive: %v", err)
	}
	if dest != ArchivePath(root) {
		t.Fatalf("dest = %s, want %s", dest, ArchivePath(root))
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range reader.File {
		names[f.Name] = true
	}
	for _, want := range []string{
		"clearcutt-source/clearcutt.fleet.yaml",
		"clearcutt-source/cli/go.mod",
	} {
		if !names[want] {
			t.Fatalf("archive missing %s; got %v", want, names)
		}
	}
	if names["clearcutt-source/cli/.DS_Store"] {
		t.Fatal("archive must not include rule-skipped files")
	}
}

func TestWriteArchiveFailsOnUnwritableDest(t *testing.T) {
	root := t.TempDir()
	archiveDir := filepath.Dir(ArchivePath(root))
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(archiveDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(archiveDir, 0o755) })
	if _, err := WriteArchive(root); err == nil {
		t.Fatal("expected error writing into a read-only archive directory")
	}
}

func TestFindRepoRootNotFound(t *testing.T) {
	if root, ok := FindRepoRoot(t.TempDir()); ok {
		t.Fatalf("expected no repo root in an empty temp dir, got %s", root)
	}
}

func TestUnzipRejectsUnsafePaths(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("../escape.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("evil")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	err = unzip(reader, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "unsafe path") {
		t.Fatalf("expected unsafe-path error, got %v", err)
	}
}

func TestUnzipSkipsDirsAndIrregularFiles(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	dirHeader := &zip.FileHeader{Name: "clearcutt-source/dir/"}
	dirHeader.SetMode(0o755 | os.ModeDir)
	if _, err := zw.CreateHeader(dirHeader); err != nil {
		t.Fatal(err)
	}
	w, err := zw.Create("clearcutt-source/dir/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := unzip(reader, dir); err != nil {
		t.Fatalf("unzip: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "clearcutt-source", "dir", "file.txt")); err != nil {
		t.Fatalf("expected extracted file: %v", err)
	}
}
