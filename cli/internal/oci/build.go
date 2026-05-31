package oci

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// BuildOptions describes a `clearcutt app build`: lay a single prebuilt artifact on
// top of a ClearCutt base image as one deterministic layer, stamp the lifecycle
// labels, and push the result.
type BuildOptions struct {
	BaseRef      string   // registry reference of the ClearCutt base image
	BaseID       string   // catalog id (e.g. java25-distroless), stamped into a label
	BaseVersion  string   // base version (e.g. v0.6.2), stamped into a label
	ArtifactPath string   // local file embedded into the app layer
	DestPath     string   // absolute path the artifact lands at inside the image
	Entrypoint   []string // OCI entrypoint (JSON-exec form)
	Cmd          []string // optional OCI cmd
	WorkingDir   string   // optional working directory
	User         string   // optional non-root user override; empty preserves the base
	Executable   bool     // mark the embedded artifact executable (static binaries)
	TargetRef    string   // where to push the assembled image
}

// BuildResult reports what `app build` produced.
type BuildResult struct {
	Digest         string // assembled image manifest digest (sha256:...)
	BaseRef        string // digest-pinned reference of the base actually used
	BaseLastLayer  string // boundary digest stamped into LabelBaseLastLayer
	AppLayerDigest string // compressed digest of the single app layer
	AppLayerDiffID string // uncompressed (diff_id) of the app layer
}

// BuildApp assembles and pushes an application image. It is single-arch by design:
// a prebuilt artifact is platform-specific, so the app layer is laid onto the base's
// linux/amd64 image (or the base itself when it is single-arch).
func (c *Client) BuildApp(opts BuildOptions) (*BuildResult, error) {
	if opts.ArtifactPath == "" || opts.DestPath == "" || opts.TargetRef == "" {
		return nil, fmt.Errorf("BuildApp requires ArtifactPath, DestPath and TargetRef")
	}
	if len(opts.Entrypoint) == 0 {
		return nil, fmt.Errorf("BuildApp requires a non-empty entrypoint")
	}

	res, err := c.Pull(opts.BaseRef)
	if err != nil {
		return nil, err
	}
	base, err := c.resolveBaseImage(res)
	if err != nil {
		return nil, err
	}

	// Digest-pin the exact base artifact so a future rebase can fetch it precisely.
	// If --base resolved to an index, keep the index digest: that lets a multi-arch
	// rebase select the right child for each platform instead of pinning only amd64.
	baseDigest, err := res.ManifestDigest()
	if err != nil {
		return nil, err
	}
	baseRefPinned := res.Ref.Context().Name() + "@" + baseDigest

	boundary, err := lastLayerDigest(base)
	if err != nil {
		return nil, fmt.Errorf("base image is unusable: %w", err)
	}

	layerMediaType, err := appLayerMediaType(base)
	if err != nil {
		return nil, err
	}
	layer, err := artifactLayer(opts.ArtifactPath, opts.DestPath, opts.Executable, layerMediaType)
	if err != nil {
		return nil, err
	}

	appImg, err := mutate.AppendLayers(base, layer)
	if err != nil {
		return nil, fmt.Errorf("failed to append application layer: %w", err)
	}

	cfg, err := appImg.ConfigFile()
	if err != nil {
		return nil, err
	}
	cfg = cfg.DeepCopy()
	cfg.Config.Entrypoint = opts.Entrypoint
	if opts.Cmd != nil {
		cfg.Config.Cmd = opts.Cmd
	}
	if opts.WorkingDir != "" {
		cfg.Config.WorkingDir = opts.WorkingDir
	}
	if opts.User != "" {
		cfg.Config.User = opts.User
	}
	if cfg.Config.Labels == nil {
		cfg.Config.Labels = map[string]string{}
	}
	cfg.Config.Labels[LabelBaseID] = opts.BaseID
	cfg.Config.Labels[LabelBaseVersion] = opts.BaseVersion
	cfg.Config.Labels[LabelBaseRef] = baseRefPinned
	cfg.Config.Labels[LabelBaseLastLayer] = boundary
	cfg.Config.Labels[LabelRebasable] = "true"
	cfg.Created = v1.Time{Time: time.Now().UTC()}

	appImg, err = mutate.ConfigFile(appImg, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to apply application config: %w", err)
	}

	digest, err := c.PushImage(opts.TargetRef, appImg)
	if err != nil {
		return nil, err
	}

	appLayerDigest, err := layer.Digest()
	if err != nil {
		return nil, err
	}
	appLayerDiffID, err := layer.DiffID()
	if err != nil {
		return nil, err
	}

	return &BuildResult{
		Digest:         digest,
		BaseRef:        baseRefPinned,
		BaseLastLayer:  boundary,
		AppLayerDigest: appLayerDigest.String(),
		AppLayerDiffID: appLayerDiffID.String(),
	}, nil
}

// resolveBaseImage returns the concrete image to build on: the resolved image, or
// the linux/amd64 child of a multi-arch base index.
func (c *Client) resolveBaseImage(res *Resolved) (v1.Image, error) {
	if !res.IsIndex {
		return res.Image, nil
	}
	return childImage(res.Index, &v1.Platform{OS: "linux", Architecture: "amd64"})
}

// appLayerMediaType matches the new layer's media type to the base manifest so we
// don't mix OCI and Docker media types within one image.
func appLayerMediaType(base v1.Image) (types.MediaType, error) {
	mt, err := base.MediaType()
	if err != nil {
		return "", err
	}
	if mt == types.OCIManifestSchema1 {
		return types.OCILayer, nil
	}
	return types.DockerLayer, nil
}

// artifactLayer builds a single-file, reproducible tar layer placing artifactPath at
// destPath inside the image. The tar header is normalized (epoch mtime, uid/gid 0) so
// identical inputs always yield an identical layer digest.
func artifactLayer(artifactPath, destPath string, executable bool, mt types.MediaType) (v1.Layer, error) {
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read artifact %q: %w", artifactPath, err)
	}
	name := strings.TrimPrefix(filepath.ToSlash(destPath), "/")
	if name == "" {
		return nil, fmt.Errorf("invalid destination path %q", destPath)
	}
	mode := int64(0o644)
	if executable {
		mode = 0o755
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{
		Name:     name,
		Mode:     mode,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
		ModTime:  time.Unix(0, 0).UTC(),
		Uid:      0,
		Gid:      0,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := tw.Write(data); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	contents := buf.Bytes()

	return tarball.LayerFromOpener(
		func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(contents)), nil },
		tarball.WithMediaType(mt),
	)
}
