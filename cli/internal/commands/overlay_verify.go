package commands

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/northcutted/clearcutt/internal/certify"
)

type overlayStoreEntry struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Mode     int64  `json:"mode"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
	Size     int64  `json:"size,omitempty"`
	Linkname string `json:"linkname,omitempty"`
	Digest   string `json:"digest,omitempty"`
}

type overlayClosureDigest struct {
	Archive           string   `json:"archive"`
	Format            string   `json:"format"`
	Digest            string   `json:"digest"`
	Entries           int      `json:"entries"`
	Files             int      `json:"files"`
	Directories       int      `json:"directories"`
	Symlinks          int      `json:"symlinks"`
	StoreRoots        []string `json:"storeRoots"`
	IgnoredStoreRoots []string `json:"ignoredStoreRoots,omitempty"`
	FirstPath         string   `json:"firstPath,omitempty"`
	LastPath          string   `json:"lastPath,omitempty"`
	RecordDigest      string   `json:"recordDigest"`
}

type overlayClosureEquivalencePredicate struct {
	Status      string               `json:"status"`
	Target      string               `json:"target,omitempty"`
	RuntimeRef  string               `json:"runtimeRef,omitempty"`
	GraftedRef  string               `json:"graftedRef,omitempty"`
	GeneratedAt string               `json:"generatedAt"`
	Runtime     overlayClosureDigest `json:"runtime"`
	Grafted     overlayClosureDigest `json:"grafted"`
	Equivalent  bool                 `json:"equivalent"`
	Checks      []VerifyCheckResult  `json:"checks"`
}

type inTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type overlayClosureEquivalenceStatement struct {
	Type          string                             `json:"_type"`
	Subject       []inTotoSubject                    `json:"subject"`
	PredicateType string                             `json:"predicateType"`
	Predicate     overlayClosureEquivalencePredicate `json:"predicate"`
}

func runOverlayVerify() error {
	runtimeSubject, err := subjectFromDigestPinnedRef(overlayOpts.runtimeRefForVerify, "--runtime-ref")
	if err != nil {
		return err
	}
	graftedSubject, err := subjectFromDigestPinnedRef(overlayOpts.graftedRefForVerify, "--grafted-ref")
	if err != nil {
		return err
	}

	runtimeDigest, err := digestNixStoreClosure(overlayOpts.runtimeArchive, nil)
	if err != nil {
		return err
	}
	graftedDigest, err := digestNixStoreClosure(overlayOpts.graftedArchive, runtimeDigest.StoreRoots)
	if err != nil {
		return err
	}

	equivalent := runtimeDigest.Digest == graftedDigest.Digest
	status := "pass"
	checkStatus := "pass"
	message := fmt.Sprintf("runtime and grafted /nix/store closures match: %s", runtimeDigest.Digest)
	if !equivalent {
		status = "fail"
		checkStatus = "fail"
		message = fmt.Sprintf("runtime and grafted /nix/store closures differ: runtime=%s grafted=%s", runtimeDigest.Digest, graftedDigest.Digest)
	}

	statement := overlayClosureEquivalenceStatement{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: "https://clearcutt.dev/attestations/closure-equivalence/v1",
		Subject: []inTotoSubject{
			runtimeSubject,
			graftedSubject,
		},
		Predicate: overlayClosureEquivalencePredicate{
			Status:      status,
			Target:      overlayOpts.target,
			RuntimeRef:  overlayOpts.runtimeRefForVerify,
			GraftedRef:  overlayOpts.graftedRefForVerify,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Runtime:     *runtimeDigest,
			Grafted:     *graftedDigest,
			Equivalent:  equivalent,
			Checks: []VerifyCheckResult{{
				ID:      "closure.bytes.equivalent",
				Status:  checkStatus,
				Message: message,
			}},
		},
	}

	raw, err := json.MarshalIndent(statement, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if overlayOpts.attestationOutputPath != "" {
		if err := os.WriteFile(overlayOpts.attestationOutputPath, raw, 0o644); err != nil {
			return fmt.Errorf("write closure-equivalence predicate: %w", err)
		}
	}
	if overlayOpts.outputPredicate {
		if _, err := out.Write(raw); err != nil {
			return err
		}
	} else if equivalent {
		fmt.Fprintf(out, "[overlay] pass: %s\n", message)
	} else {
		fmt.Fprintf(errOut, "[overlay] fail: %s\n", message)
	}

	if !equivalent {
		return ErrCheckFailed
	}
	return nil
}

func subjectFromDigestPinnedRef(ref, flagName string) (inTotoSubject, error) {
	name, digest, ok := strings.Cut(strings.TrimSpace(ref), "@")
	if !ok || name == "" || digest == "" {
		return inTotoSubject{}, fmt.Errorf("%s must be a digest-pinned image ref in name@sha256:... form", flagName)
	}
	algorithm, value, ok := strings.Cut(digest, ":")
	if !ok || algorithm == "" || value == "" {
		return inTotoSubject{}, fmt.Errorf("%s must contain a digest in sha256:... form", flagName)
	}
	if algorithm != "sha256" {
		return inTotoSubject{}, fmt.Errorf("%s must use sha256 digest, got %s", flagName, algorithm)
	}
	return inTotoSubject{Name: name, Digest: map[string]string{algorithm: value}}, nil
}

func digestNixStoreClosure(archivePath string, includeRoots []string) (*overlayClosureDigest, error) {
	tmpDir, err := os.MkdirTemp("", "clearcutt-overlay-verify-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	image, err := certify.LoadImageArchive(archivePath, tmpDir)
	if err != nil {
		return nil, err
	}
	if image.Format == "" {
		return nil, fmt.Errorf("unrecognized image archive %s: expected docker-save or OCI-layout archive", archivePath)
	}

	entries := map[string]overlayStoreEntry{}
	for _, layerPath := range image.LayerPaths {
		if err := applyNixStoreLayer(layerPath, entries); err != nil {
			return nil, fmt.Errorf("scan layer %s: %w", filepath.Base(layerPath), err)
		}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("image archive %s contains no /nix/store closure entries", archivePath)
	}
	entries, ignoredRoots := filterStoreEntries(entries, includeRoots)
	if len(entries) == 0 {
		return nil, fmt.Errorf("image archive %s contains no /nix/store entries matching the source runtime closure", archivePath)
	}

	paths := make([]string, 0, len(entries))
	for p := range entries {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	recordHasher := sha256.New()
	roots := map[string]bool{}
	result := &overlayClosureDigest{
		Archive: archivePath,
		Format:  image.Format,
		Entries: len(paths),
	}
	for i, p := range paths {
		entry := entries[p]
		if i == 0 {
			result.FirstPath = p
		}
		result.LastPath = p
		switch entry.Type {
		case "file":
			result.Files++
		case "dir":
			result.Directories++
		case "symlink", "hardlink":
			result.Symlinks++
		}
		if root := storeRootForPath(p); root != "" {
			roots[root] = true
		}
		writeStoreRecord(recordHasher, entry)
	}

	rootList := make([]string, 0, len(roots))
	for root := range roots {
		rootList = append(rootList, root)
	}
	sort.Strings(rootList)
	result.StoreRoots = rootList
	result.IgnoredStoreRoots = ignoredRoots
	sum := recordHasher.Sum(nil)
	result.RecordDigest = hex.EncodeToString(sum)
	result.Digest = "sha256:" + result.RecordDigest
	return result, nil
}

func filterStoreEntries(entries map[string]overlayStoreEntry, includeRoots []string) (map[string]overlayStoreEntry, []string) {
	if len(includeRoots) == 0 {
		return entries, nil
	}
	rootSet := map[string]bool{}
	for _, root := range includeRoots {
		rootSet[root] = true
	}
	filtered := map[string]overlayStoreEntry{}
	ignored := map[string]bool{}
	for p, entry := range entries {
		root := storeRootForPath(p)
		if rootSet[root] {
			filtered[p] = entry
		} else if root != "" {
			ignored[root] = true
		}
	}
	ignoredList := make([]string, 0, len(ignored))
	for root := range ignored {
		ignoredList = append(ignoredList, root)
	}
	sort.Strings(ignoredList)
	return filtered, ignoredList
}

func applyNixStoreLayer(layerPath string, entries map[string]overlayStoreEntry) error {
	rc, err := openPossiblyGzipped(layerPath)
	if err != nil {
		return err
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := cleanLayerPath(hdr.Name)
		if name == "." || name == "" {
			continue
		}
		if applyWhiteout(name, entries) {
			continue
		}
		if !strings.HasPrefix(name, "nix/store/") {
			continue
		}

		entry := overlayStoreEntry{
			Path: name,
			Mode: hdr.Mode,
			UID:  hdr.Uid,
			GID:  hdr.Gid,
			Size: hdr.Size,
		}
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			entry.Type = "file"
			sum, err := hashReader(tr)
			if err != nil {
				return err
			}
			entry.Digest = sum
		case tar.TypeDir:
			entry.Type = "dir"
		case tar.TypeSymlink:
			entry.Type = "symlink"
			entry.Linkname = hdr.Linkname
		case tar.TypeLink:
			entry.Type = "hardlink"
			entry.Linkname = cleanLayerPath(hdr.Linkname)
		default:
			continue
		}
		entries[name] = entry
	}
	return nil
}

type layeredReadCloser struct {
	io.Reader
	closers []io.Closer
}

func (l *layeredReadCloser) Close() error {
	var firstErr error
	for i := len(l.closers) - 1; i >= 0; i-- {
		if err := l.closers[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func openPossiblyGzipped(layerPath string) (io.ReadCloser, error) {
	f, err := os.Open(layerPath)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReader(f)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &layeredReadCloser{Reader: gz, closers: []io.Closer{f, gz}}, nil
	}
	return &layeredReadCloser{Reader: br, closers: []io.Closer{f}}, nil
}

func hashReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func writeStoreRecord(h hash.Hash, entry overlayStoreEntry) {
	fmt.Fprintf(h, "%s\x00%s\x00%d\x00%d\x00%d\x00%d\x00%s\x00%s\n",
		entry.Path,
		entry.Type,
		entry.Mode,
		entry.UID,
		entry.GID,
		entry.Size,
		entry.Linkname,
		entry.Digest,
	)
}

func cleanLayerPath(name string) string {
	name = strings.TrimPrefix(name, "/")
	name = strings.TrimPrefix(name, "./")
	return path.Clean(name)
}

func applyWhiteout(name string, entries map[string]overlayStoreEntry) bool {
	base := path.Base(name)
	if !strings.HasPrefix(base, ".wh.") {
		return false
	}
	dir := path.Dir(name)
	if base == ".wh..wh..opq" {
		prefix := dir + "/"
		for p := range entries {
			if p == dir || strings.HasPrefix(p, prefix) {
				delete(entries, p)
			}
		}
		return true
	}
	target := path.Join(dir, strings.TrimPrefix(base, ".wh."))
	deletePathAndChildren(entries, target)
	return true
}

func deletePathAndChildren(entries map[string]overlayStoreEntry, target string) {
	prefix := target + "/"
	for p := range entries {
		if p == target || strings.HasPrefix(p, prefix) {
			delete(entries, p)
		}
	}
}

func storeRootForPath(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) < 3 || parts[0] != "nix" || parts[1] != "store" {
		return ""
	}
	return strings.Join(parts[:3], "/")
}
