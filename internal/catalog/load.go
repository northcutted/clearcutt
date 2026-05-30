package catalog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// LoadCatalogIndex reads index.json from the specified catalog directory.
func LoadCatalogIndex(catalogPath string) (*CatalogIndex, error) {
	indexPath := filepath.Join(catalogPath, "index.json")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read catalog index at %s: %w", indexPath, err)
	}

	var index CatalogIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("failed to unmarshal catalog index: %w", err)
	}

	return &index, nil
}

// LoadImageRecord reads an image record file images/<imageID>.json from the catalog directory.
func LoadImageRecord(catalogPath, imageID string) (*ImageRecord, error) {
	recordPath := filepath.Join(catalogPath, "images", fmt.Sprintf("%s.json", imageID))
	data, err := os.ReadFile(recordPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read image record for %q at %s: %w", imageID, recordPath, err)
	}

	var record ImageRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal image record: %w", err)
	}

	return &record, nil
}
