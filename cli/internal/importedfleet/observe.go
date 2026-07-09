package importedfleet

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"sigs.k8s.io/yaml"
)

type ImageObserver interface {
	Observe(ctx context.Context, ref string) (Observation, error)
}

type ObserveOptions struct {
	GeneratedAt string
	Strict      bool
}

func ObserveImages(ctx context.Context, inventory ImagesFile, observer ImageObserver, opts ObserveOptions) (Observations, error) {
	generatedAt := opts.GeneratedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	result := Observations{
		APIVersion:  APIVersion,
		Kind:        "ImportedFleetObservations",
		GeneratedAt: generatedAt,
		Images:      []Observation{},
	}
	specs := append([]ImageSpec(nil), inventory.Images...)
	sort.SliceStable(specs, func(i, j int) bool { return specs[i].ID < specs[j].ID })
	for _, spec := range specs {
		observation, err := observer.Observe(ctx, spec.Image)
		if err != nil {
			if opts.Strict {
				return Observations{}, fmt.Errorf("%s: observe %s: %w", spec.ID, spec.Image, err)
			}
			observation = baseObservation(spec.ID, spec.Image)
			observation.Warnings = append(observation.Warnings, fmt.Sprintf("observation failed: %v", err))
		}
		if observation.ID == "" {
			observation.ID = spec.ID
		}
		if observation.SourceRef == "" {
			observation.SourceRef = spec.Image
		}
		normalizeObservation(&observation)
		result.Images = append(result.Images, observation)
	}
	return result, nil
}

func ReadObservations(path string) (Observations, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Observations{}, err
	}
	var observations Observations
	if err := yaml.Unmarshal(raw, &observations); err != nil {
		return Observations{}, err
	}
	return observations, nil
}

func WriteObservations(path string, observations Observations) error {
	return writeJSON(path, observations)
}

type FixtureObserver struct {
	byID     map[string]Observation
	bySource map[string]Observation
}

func NewFixtureObserver(observations Observations) *FixtureObserver {
	observer := &FixtureObserver{byID: map[string]Observation{}, bySource: map[string]Observation{}}
	for _, obs := range observations.Images {
		normalizeObservation(&obs)
		if obs.ID != "" {
			observer.byID[obs.ID] = obs
		}
		if obs.SourceRef != "" {
			observer.bySource[obs.SourceRef] = obs
		}
	}
	return observer
}

func (f *FixtureObserver) Observe(_ context.Context, ref string) (Observation, error) {
	if obs, ok := f.bySource[ref]; ok {
		return obs, nil
	}
	return Observation{}, fmt.Errorf("no offline fixture for %s", ref)
}

type RegistryObserver struct{}

func (RegistryObserver) Observe(ctx context.Context, ref string) (Observation, error) {
	parsed, err := name.ParseReference(ref, name.WeakValidation)
	if err != nil {
		return Observation{}, err
	}
	desc, err := remote.Get(parsed, remote.WithContext(ctx))
	if err != nil {
		return Observation{}, err
	}
	obs := baseObservation("", ref)
	obs.ManifestDigest = desc.Digest.String()
	obs.DigestRef = parsed.Context().Name() + "@" + desc.Digest.String()
	obs.Annotations = desc.Annotations
	if desc.MediaType == types.OCIImageIndex || desc.MediaType == types.DockerManifestList {
		index, err := desc.ImageIndex()
		if err == nil {
			if manifest, err := index.IndexManifest(); err == nil {
				for _, item := range manifest.Manifests {
					if item.Platform == nil {
						continue
					}
					platform := item.Platform.OS + "/" + item.Platform.Architecture
					if item.Platform.Variant != "" {
						platform += "/" + item.Platform.Variant
					}
					obs.Platforms = append(obs.Platforms, platform)
				}
			}
		}
	}
	image, err := desc.Image()
	if err != nil {
		obs.Warnings = append(obs.Warnings, fmt.Sprintf("image config unavailable: %v", err))
		return obs, nil
	}
	fillImageObservation(&obs, image)
	return obs, nil
}

func fillImageObservation(obs *Observation, image v1.Image) {
	digest, err := image.Digest()
	if err == nil && obs.ManifestDigest == "" {
		obs.ManifestDigest = digest.String()
	}
	configDigest, err := image.ConfigName()
	if err == nil {
		obs.ConfigDigest = configDigest.String()
	}
	config, err := image.ConfigFile()
	if err == nil && config != nil {
		if config.Created.Time.Unix() > 0 {
			obs.Created = config.Created.Time.UTC().Format(time.RFC3339Nano)
		}
		obs.User = config.Config.User
		obs.Entrypoint = append([]string(nil), config.Config.Entrypoint...)
		obs.Cmd = append([]string(nil), config.Config.Cmd...)
		obs.Labels = cloneStringMap(config.Config.Labels)
		if len(obs.Platforms) == 0 && config.OS != "" && config.Architecture != "" {
			obs.Platforms = []string{config.OS + "/" + config.Architecture}
		}
		for _, hist := range config.History {
			obs.History = append(obs.History, HistoryObservation{CreatedBy: hist.CreatedBy, Comment: hist.Comment, EmptyLayer: hist.EmptyLayer})
		}
	}
	layers, err := image.Layers()
	if err == nil {
		for _, layer := range layers {
			item := LayerObservation{}
			if digest, err := layer.Digest(); err == nil {
				item.Digest = digest.String()
			}
			if size, err := layer.Size(); err == nil {
				item.Size = size
			}
			if mediaType, err := layer.MediaType(); err == nil {
				item.MediaType = string(mediaType)
			}
			obs.Layers = append(obs.Layers, item)
		}
	}
	normalizeObservation(obs)
}

func baseObservation(id, sourceRef string) Observation {
	return Observation{
		ID:          id,
		SourceRef:   sourceRef,
		Platforms:   []string{},
		Entrypoint:  []string{},
		Cmd:         []string{},
		Labels:      map[string]string{},
		Annotations: map[string]string{},
		Layers:      []LayerObservation{},
		History:     []HistoryObservation{},
		Evidence:    defaultEvidenceObservation(),
		Warnings:    []string{},
	}
}

func normalizeObservation(obs *Observation) {
	if obs.Platforms == nil {
		obs.Platforms = []string{}
	}
	sort.Strings(obs.Platforms)
	if obs.Entrypoint == nil {
		obs.Entrypoint = []string{}
	}
	if obs.Cmd == nil {
		obs.Cmd = []string{}
	}
	if obs.Labels == nil {
		obs.Labels = map[string]string{}
	}
	if obs.Annotations == nil {
		obs.Annotations = map[string]string{}
	}
	if obs.Layers == nil {
		obs.Layers = []LayerObservation{}
	}
	if obs.History == nil {
		obs.History = []HistoryObservation{}
	}
	if obs.Warnings == nil {
		obs.Warnings = []string{}
	}
	if obs.Evidence.Signature.Status == "" {
		obs.Evidence = mergeEvidenceDefaults(obs.Evidence)
	}
	if downgradeUnverifiedImportedClaims(&obs.Evidence) {
		obs.Warnings = append(obs.Warnings, "verified evidence claim downgraded to observed: imported observation does not run an evidence verifier")
	}
}

func downgradeUnverifiedImportedClaims(evidence *EvidenceObservation) bool {
	downgraded := false
	channels := []*EvidenceChannel{
		&evidence.Signature,
		&evidence.SBOM,
		&evidence.Provenance,
		&evidence.VulnerabilityScan,
		&evidence.Tests,
	}
	for _, channel := range channels {
		channel.Status = strings.ToLower(strings.TrimSpace(channel.Status))
		if channel.Status != "verified" {
			continue
		}
		channel.Status = "observed"
		if strings.TrimSpace(channel.Claim) == "" {
			channel.Claim = "Evidence was supplied to imported observation but was not verified by ClearCutt"
		}
		downgraded = true
	}
	return downgraded
}

func defaultEvidenceObservation() EvidenceObservation {
	return EvidenceObservation{
		Signature:         EvidenceChannel{Status: "missing", Source: "none", Claim: "No signature evidence inferred for imported image"},
		SBOM:              EvidenceChannel{Status: "missing", Source: "none", Claim: "Observed SBOM is not build provenance"},
		Provenance:        EvidenceChannel{Status: "missing", Source: "none", Claim: "No build provenance inferred for imported image"},
		VulnerabilityScan: EvidenceChannel{Status: "missing", Source: "none"},
		Tests:             EvidenceChannel{Status: "missing", Source: "none"},
	}
}

func mergeEvidenceDefaults(e EvidenceObservation) EvidenceObservation {
	defaults := defaultEvidenceObservation()
	if e.Signature.Status == "" {
		e.Signature = defaults.Signature
	}
	if e.SBOM.Status == "" {
		e.SBOM = defaults.SBOM
	}
	if e.Provenance.Status == "" {
		e.Provenance = defaults.Provenance
	}
	if e.VulnerabilityScan.Status == "" {
		e.VulnerabilityScan = defaults.VulnerabilityScan
	}
	if e.Tests.Status == "" {
		e.Tests = defaults.Tests
	}
	return e
}

func cloneStringMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
