package certify

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
)

// walkImageLayers loads a docker-save or OCI-layout image archive and invokes
// fn for every member of every layer, in order. It is the shared layer walk
// backing the closure-purity and runtime-cve gates; an fn error aborts the walk.
func walkImageLayers(archivePath string, fn func(*tar.Header) error) error {
	tempDir, err := os.MkdirTemp("", "clearcutt-layers-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	img, err := LoadImageArchive(archivePath, tempDir)
	if err != nil {
		return err
	}
	if img.Format == "" {
		return fmt.Errorf("unsupported image archive: expected docker save or OCI layout tar")
	}
	for _, layerPath := range img.LayerPaths {
		if err := walkLayerTar(layerPath, fn); err != nil {
			return err
		}
	}
	return nil
}

// walkLayerTar iterates a single (optionally gzip-compressed) layer blob,
// invoking fn for each tar member header in order.
func walkLayerTar(layerPath string, fn func(*tar.Header) error) error {
	file, err := os.Open(layerPath)
	if err != nil {
		return err
	}
	defer file.Close()

	br := bufio.NewReader(file)
	var reader io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer gz.Close()
		reader = gz
	}

	tr := tar.NewReader(reader)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err := fn(hdr); err != nil {
			return err
		}
	}
	return nil
}
