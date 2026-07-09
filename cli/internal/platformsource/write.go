package platformsource

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/northcutted/clearcutt/internal/platformsource/rules"
)

// WriteArchive regenerates the reference source archive from the repo tree at
// root, writing it to ArchivePath(root) atomically. Callers that build
// distributable binaries (fleet build-cli-assets, make cli-build, CI) run this
// first so the embedded archive can never lag the tree it ships.
func WriteArchive(root string) (string, error) {
	dest := ArchivePath(root)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	tmp := dest + ".tmp"
	if err := writeArchiveFile(root, tmp); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return dest, nil
}

// CheckArchiveFresh verifies that the generated archive on disk matches the
// current source tree. It compares file payloads instead of zip bytes so file
// mtimes and zip header details do not create false positives.
func CheckArchiveFresh(root string) error {
	raw, err := os.ReadFile(ArchivePath(root))
	if err != nil {
		return fmt.Errorf("read embedded platform source archive: %w", err)
	}
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return fmt.Errorf("open embedded platform source archive: %w", err)
	}
	embedded := map[string][]byte{}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || !file.FileInfo().Mode().IsRegular() {
			continue
		}
		rel, err := filepath.Rel("clearcutt-source", filepath.FromSlash(file.Name))
		if err != nil || rel == "." || rel == ".." || rel == "" || rel[0] == '.' && len(rel) >= 2 && rel[:2] == ".." {
			return fmt.Errorf("embedded platform source archive contains unexpected path %q", file.Name)
		}
		src, err := file.Open()
		if err != nil {
			return fmt.Errorf("open embedded %s: %w", file.Name, err)
		}
		var buf bytes.Buffer
		_, readErr := buf.ReadFrom(src)
		closeErr := src.Close()
		if readErr != nil {
			return fmt.Errorf("read embedded %s: %w", file.Name, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close embedded %s: %w", file.Name, closeErr)
		}
		embedded[filepath.ToSlash(rel)] = buf.Bytes()
	}

	var stale []string
	live := map[string]bool{}
	if err := walkSourceTree(root, func(rel string, info os.FileInfo) error {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		live[rel] = true
		got, ok := embedded[rel]
		if !ok {
			stale = append(stale, "missing "+rel)
			return nil
		}
		if !bytes.Equal(got, raw) {
			stale = append(stale, "stale "+rel)
		}
		return nil
	}); err != nil {
		return err
	}
	for rel := range embedded {
		if !live[rel] {
			stale = append(stale, "extra "+rel)
		}
	}
	if len(stale) > 0 {
		return fmt.Errorf("embedded platform source is stale: %s", strings.Join(stale, ", "))
	}
	return nil
}

func writeArchiveFile(root, dest string) error {
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(out)
	err = walkSourceTree(root, func(rel string, info os.FileInfo) error {
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(filepath.Join("clearcutt-source", rel))
		writer, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return err
		}
		_, err = writer.Write(raw)
		return err
	})
	if closeErr := zw.Close(); err == nil {
		err = closeErr
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	return err
}

func walkSourceTree(root string, visit func(string, os.FileInfo) error) error {
	for _, entry := range rules.Entries {
		start := filepath.Join(root, entry)
		if _, err := os.Stat(start); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if err := filepath.WalkDir(start, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if rules.SkipPath(rel, info) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() || !info.Mode().IsRegular() {
				return nil
			}
			return visit(rel, info)
		}); err != nil {
			return err
		}
	}
	return nil
}
