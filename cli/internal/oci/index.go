package oci

import (
	"fmt"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// IndexImage describes one already-published single-architecture image that
// should be included in a multi-arch image index.
type IndexImage struct {
	Ref          string
	OS           string
	Architecture string
	Variant      string
}

// PushImageIndex pulls the stage images in sources, builds a multi-arch OCI
// image index in-process, pushes it to targetRef, and returns the index digest.
func (c *Client) PushImageIndex(targetRef string, sources []IndexImage) (string, error) {
	if strings.TrimSpace(targetRef) == "" {
		return "", fmt.Errorf("target image reference is required")
	}
	if len(sources) == 0 {
		return "", fmt.Errorf("at least one source image is required")
	}

	adds := make([]mutate.IndexAddendum, 0, len(sources))
	for _, source := range sources {
		if strings.TrimSpace(source.Ref) == "" {
			return "", fmt.Errorf("source image reference is required")
		}
		img, err := c.PullImage(source.Ref)
		if err != nil {
			return "", fmt.Errorf("pull source image %q: %w", source.Ref, err)
		}
		platform, err := indexImagePlatform(source, img)
		if err != nil {
			return "", fmt.Errorf("resolve platform for %q: %w", source.Ref, err)
		}
		adds = append(adds, mutate.IndexAddendum{
			Add: img,
			Descriptor: v1.Descriptor{
				Platform: platform,
			},
		})
	}

	idx := mutate.AppendManifests(empty.Index, adds...)
	return c.PushIndex(targetRef, idx)
}

func indexImagePlatform(source IndexImage, img v1.Image) (*v1.Platform, error) {
	if strings.TrimSpace(source.OS) != "" || strings.TrimSpace(source.Architecture) != "" || strings.TrimSpace(source.Variant) != "" {
		if strings.TrimSpace(source.OS) == "" || strings.TrimSpace(source.Architecture) == "" {
			return nil, fmt.Errorf("both OS and architecture are required when overriding platform")
		}
		return &v1.Platform{
			OS:           source.OS,
			Architecture: source.Architecture,
			Variant:      source.Variant,
		}, nil
	}
	return imagePlatform(img)
}
