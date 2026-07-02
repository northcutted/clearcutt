package oci

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"

	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// PushImageArchive loads a single-image docker-save archive from archivePath and
// pushes it to ref through the OCI distribution API. The ClearCutt Nix builder
// currently emits gzip-compressed docker archives, while some tests and tools
// produce plain tar archives, so the opener accepts either outer format.
func (c *Client) PushImageArchive(ref, archivePath string) (string, error) {
	img, err := tarball.Image(gzipAwareArchiveOpener(archivePath), nil)
	if err != nil {
		return "", fmt.Errorf("failed to load image archive %q: %w", archivePath, err)
	}
	return c.PushImage(ref, img)
}

func gzipAwareArchiveOpener(path string) tarball.Opener {
	return func() (io.ReadCloser, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		header := make([]byte, 2)
		n, readErr := io.ReadFull(f, header)
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			_ = f.Close()
			return nil, readErr
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			_ = f.Close()
			return nil, err
		}
		if n == 2 && header[0] == 0x1f && header[1] == 0x8b {
			gz, err := gzip.NewReader(f)
			if err != nil {
				_ = f.Close()
				return nil, err
			}
			return &gzipArchiveReadCloser{Reader: gz, gzip: gz, file: f}, nil
		}
		return f, nil
	}
}

type gzipArchiveReadCloser struct {
	io.Reader
	gzip *gzip.Reader
	file *os.File
}

func (r *gzipArchiveReadCloser) Close() error {
	gzipErr := r.gzip.Close()
	fileErr := r.file.Close()
	if gzipErr != nil {
		return gzipErr
	}
	return fileErr
}
