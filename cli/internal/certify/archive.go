// Package certify provides offline readers for downstream application image
// archives — both legacy `docker save` tarballs and OCI-layout archives — plus
// the runtime-tool scan used to enforce the distroless contract. The `certify`
// command composes these with policy evaluation; the parsing and scanning logic
// lives here so it can be unit-tested without the cobra layer.
package certify

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// DockerManifest represents the legacy `docker save` manifest.json structure.
type DockerManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// Descriptor is the subset of an OCI content descriptor we need to walk an
// OCI-layout image archive (index.json -> manifest -> config/layers).
type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Index is an OCI image index (index.json, or a nested manifest list).
type Index struct {
	Manifests []Descriptor `json:"manifests"`
}

// Manifest is an OCI image manifest.
type Manifest struct {
	Config Descriptor   `json:"config"`
	Layers []Descriptor `json:"layers"`
}

// OCIImageConfig represents standard OCI runtime configuration metadata.
type OCIImageConfig struct {
	Config struct {
		User       string            `json:"User"`
		WorkingDir string            `json:"WorkingDir"`
		Env        []string          `json:"Env"`
		Entrypoint []string          `json:"Entrypoint"`
		Cmd        []string          `json:"Cmd"`
		Labels     map[string]string `json:"Labels"`
	} `json:"config"`
}

// Image holds the resolved pieces of an image tarball, abstracting over the
// legacy docker-save and OCI-layout on-disk formats.
type Image struct {
	Format     string   // "docker", "oci", or "" when unrecognized
	ConfigRaw  []byte   // OCI image config JSON
	RepoTags   []string // best-effort image references
	LayerPaths []string // temp-file paths of layer blobs (may be gzip-compressed)
}

// LoadImageArchive extracts every regular file from an image tarball into tempDir
// and resolves the image config and layer blobs for either a legacy docker-save
// archive (manifest.json) or an OCI-layout archive (index.json + blobs/). Files are
// stored under opaque names, so crafted entry paths cannot escape tempDir.
func LoadImageArchive(tarPath, tempDir string) (*Image, error) {
	file, err := os.Open(tarPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open image file: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file
	if strings.HasSuffix(tarPath, ".gz") || strings.HasSuffix(tarPath, ".tgz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize gzip reader: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	entries := map[string]string{} // cleaned tar entry name -> temp file path
	tr := tar.NewReader(reader)
	idx := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading tar archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		dest := filepath.Join(tempDir, fmt.Sprintf("e%06d", idx))
		idx++
		df, err := os.Create(dest)
		if err != nil {
			return nil, fmt.Errorf("failed to stage tar entry: %w", err)
		}
		if _, err := io.Copy(df, tr); err != nil {
			df.Close()
			return nil, fmt.Errorf("failed to stage tar entry %q: %w", name, err)
		}
		df.Close()
		entries[name] = dest
	}

	img := &Image{}

	// Legacy docker-save: manifest.json at the archive root.
	if p, ok := entries["manifest.json"]; ok {
		if data, err := os.ReadFile(p); err == nil {
			var manifests []DockerManifest
			if err := json.Unmarshal(data, &manifests); err == nil && len(manifests) > 0 {
				img.Format = "docker"
				img.RepoTags = manifests[0].RepoTags
				if cp, ok := entries[path.Clean(manifests[0].Config)]; ok {
					img.ConfigRaw, _ = os.ReadFile(cp)
				}
				for _, layer := range manifests[0].Layers {
					if lp, ok := entries[path.Clean(layer)]; ok {
						img.LayerPaths = append(img.LayerPaths, lp)
					}
				}
				return img, nil
			}
		}
	}

	// OCI-layout: index.json referencing blobs/sha256/<hex>.
	if p, ok := entries["index.json"]; ok {
		img.Format = "oci"
		resolveOCIImage(entries, p, img)
		return img, nil
	}

	return img, nil // Format == "" -> unrecognized
}

// resolveOCIImage walks index.json -> manifest -> {config, layers}, descending one
// level when the index points at a nested image index (multi-arch).
func resolveOCIImage(entries map[string]string, indexPath string, img *Image) {
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return
	}
	var index Index
	if err := json.Unmarshal(data, &index); err != nil || len(index.Manifests) == 0 {
		return
	}

	desc := index.Manifests[0]
	if ref, ok := desc.Annotations["org.opencontainers.image.ref.name"]; ok {
		img.RepoTags = append(img.RepoTags, ref)
	}

	manData := ReadBlob(entries, desc.Digest)
	if manData == nil {
		return
	}
	var man Manifest
	if err := json.Unmarshal(manData, &man); err != nil {
		return
	}
	// Nested index (manifest list) -> pick the first concrete manifest.
	if man.Config.Digest == "" && len(man.Layers) == 0 {
		var nested Index
		if err := json.Unmarshal(manData, &nested); err == nil && len(nested.Manifests) > 0 {
			if inner := ReadBlob(entries, nested.Manifests[0].Digest); inner != nil {
				_ = json.Unmarshal(inner, &man)
			}
		}
	}

	img.ConfigRaw = ReadBlob(entries, man.Config.Digest)
	for _, layer := range man.Layers {
		if lp := BlobPath(entries, layer.Digest); lp != "" {
			img.LayerPaths = append(img.LayerPaths, lp)
		}
	}
}

// BlobPath maps an OCI digest (sha256:hex) to the staged blob file path, or "" if
// the digest is malformed or absent from the archive.
func BlobPath(entries map[string]string, digest string) string {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	if p, ok := entries["blobs/"+parts[0]+"/"+parts[1]]; ok {
		return p
	}
	return ""
}

// ReadBlob reads the staged blob for an OCI digest, or returns nil when it is
// malformed, missing, or unreadable.
func ReadBlob(entries map[string]string, digest string) []byte {
	p := BlobPath(entries, digest)
	if p == "" {
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return data
}

// ScanLayerForRuntimeTools inspects a single layer blob (transparently handling
// gzip-compressed layers) for interactive shells and package managers.
func ScanLayerForRuntimeTools(layerPath string) (shells, pkgs []string, err error) {
	f, err := os.Open(layerPath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	br := bufio.NewReader(f)
	var reader io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, gerr := gzip.NewReader(br)
		if gerr != nil {
			return nil, nil, gerr
		}
		defer gz.Close()
		reader = gz
	}

	tr := tar.NewReader(reader)
	for {
		hdr, terr := tr.Next()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			return nil, nil, terr
		}
		name := strings.TrimPrefix(path.Clean(hdr.Name), "/")

		switch name {
		case "bin/sh", "bin/bash", "bin/ash", "bin/zsh",
			"usr/bin/sh", "usr/bin/bash", "usr/bin/ash", "usr/bin/zsh":
			shells = append(shells, name)
		case "sbin/apk", "usr/bin/apk", "usr/bin/apt", "usr/bin/apt-get",
			"usr/bin/dpkg", "usr/bin/dnf", "usr/bin/yum", "usr/bin/microdnf":
			pkgs = append(pkgs, name)
		}
	}
	return shells, pkgs, nil
}
