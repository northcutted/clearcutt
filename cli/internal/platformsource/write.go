package platformsource

import (
	"archive/zip"
	"os"
	"path/filepath"

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
