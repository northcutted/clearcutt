package catalog

import (
	"fmt"
	"strings"
)

// knownLifecycleStatuses enumerates the lifecycle statuses the CLI gates on.
// A value outside this set almost always indicates a typo in source data that
// would otherwise silently bypass verify/list filtering.
var knownLifecycleStatuses = map[string]bool{
	"active":       true,
	"preview":      true,
	"deprecated":   true,
	"experimental": true,
	"eol":          true,
	"blocked":      true,
}

// knownTiers enumerates the supported image tiers.
var knownTiers = map[string]bool{
	"dev":        true,
	"slim":       true,
	"distroless": true,
}

// ValidLifecycleStatus reports whether s is a recognized lifecycle status.
func ValidLifecycleStatus(s string) bool {
	return knownLifecycleStatuses[strings.ToLower(s)]
}

// ValidTier reports whether s is a recognized tier id.
func ValidTier(s string) bool {
	return knownTiers[strings.ToLower(s)]
}

// ValidateCatalogIndex performs structural sanity checks plus enum validation on
// the fields downstream gating depends on.
func ValidateCatalogIndex(idx *CatalogIndex) error {
	if idx == nil {
		return fmt.Errorf("catalog index is nil")
	}
	if idx.GeneratedAt == "" {
		return fmt.Errorf("missing generatedAt")
	}
	if idx.Owner == "" {
		return fmt.Errorf("missing owner")
	}
	if idx.Repo == "" {
		return fmt.Errorf("missing repo")
	}
	if len(idx.Images) == 0 {
		return fmt.Errorf("catalog index contains no images")
	}
	for i, img := range idx.Images {
		if img.ID == "" {
			return fmt.Errorf("images[%d]: missing id", i)
		}
		if !ValidLifecycleStatus(img.Lifecycle.Status) {
			return fmt.Errorf("images[%d] (%s): unknown lifecycle status %q", i, img.ID, img.Lifecycle.Status)
		}
		if img.Tier != "" && !ValidTier(img.Tier) {
			return fmt.Errorf("images[%d] (%s): unknown tier %q", i, img.ID, img.Tier)
		}
	}
	return nil
}

// ValidateImageRecord performs structural validation plus enum validation on an
// image record and its releases.
func ValidateImageRecord(rec *ImageRecord) error {
	if rec == nil {
		return fmt.Errorf("image record is nil")
	}
	if rec.ID == "" {
		return fmt.Errorf("missing id")
	}
	if rec.Language.ID == "" {
		return fmt.Errorf("missing language id")
	}
	if rec.Tier.ID == "" {
		return fmt.Errorf("missing tier id")
	}
	if !ValidTier(rec.Tier.ID) {
		return fmt.Errorf("unknown tier %q", rec.Tier.ID)
	}
	for i := range rec.Releases {
		status := rec.Releases[i].Lifecycle.Status
		if status != "" && !ValidLifecycleStatus(status) {
			return fmt.Errorf("releases[%d] (%s): unknown lifecycle status %q", i, rec.Releases[i].Tag, status)
		}
	}
	return nil
}
