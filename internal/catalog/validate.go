package catalog

import (
	"errors"
)

// ValidateCatalogIndex performs basic structural sanity checks.
func ValidateCatalogIndex(idx *CatalogIndex) error {
	if idx == nil {
		return errors.New("catalog index is nil")
	}
	if idx.GeneratedAt == "" {
		return errors.New("missing generatedAt")
	}
	if idx.Owner == "" {
		return errors.New("missing owner")
	}
	if idx.Repo == "" {
		return errors.New("missing repo")
	}
	if len(idx.Images) == 0 {
		return errors.New("catalog index contains no images")
	}
	return nil
}

// ValidateImageRecord performs basic structural validation on an image record.
func ValidateImageRecord(rec *ImageRecord) error {
	if rec == nil {
		return errors.New("image record is nil")
	}
	if rec.ID == "" {
		return errors.New("missing id")
	}
	if rec.Language.ID == "" {
		return errors.New("missing language id")
	}
	if rec.Tier.ID == "" {
		return errors.New("missing tier id")
	}
	return nil
}
