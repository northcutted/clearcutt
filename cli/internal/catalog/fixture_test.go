package catalog_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt/internal/catalog"
)

func TestCatalogLoadAndValidation(t *testing.T) {
	catalogPath := filepath.Join("..", "testdata", "catalog")

	// 1. Test loading catalog index
	idx, err := catalog.LoadCatalogIndex(catalogPath)
	if err != nil {
		t.Fatalf("Failed to load catalog index: %v", err)
	}

	if err := catalog.ValidateCatalogIndex(idx); err != nil {
		t.Fatalf("Catalog index validation failed: %v", err)
	}

	if idx.Owner != "test-owner" || idx.Repo != "test-repo" {
		t.Errorf("Expected owner 'test-owner' and repo 'test-repo', got '%s/%s'", idx.Owner, idx.Repo)
	}

	if len(idx.Images) != 1 || idx.Images[0].ID != "java21-distroless" {
		t.Errorf("Unexpected images length or ID")
	}

	// 2. Test loading image record
	rec, err := catalog.LoadImageRecord(catalogPath, "java21-distroless")
	if err != nil {
		t.Fatalf("Failed to load image record: %v", err)
	}

	if err := catalog.ValidateImageRecord(rec); err != nil {
		t.Fatalf("Image record validation failed: %v", err)
	}

	if rec.ID != "java21-distroless" || rec.Language.ID != "java" {
		t.Errorf("Unexpected image record fields")
	}

	// 3. Test missing catalog path
	_, err = catalog.LoadCatalogIndex("non-existent-path")
	if err == nil {
		t.Error("Expected error when loading from missing catalog path, got nil")
	}

	// 4. Test missing image id
	_, err = catalog.LoadImageRecord(catalogPath, "missing-image")
	if err == nil {
		t.Error("Expected error when loading missing image ID, got nil")
	}

	// 5. Test latest release selection
	if len(rec.Releases) == 0 {
		t.Fatalf("Image record has no releases")
	}
	latestRelease := rec.Releases[0]
	if !latestRelease.IsLatest {
		t.Errorf("Expected first release to be latest")
	}
	if latestRelease.Tag != "v1.0.0" {
		t.Errorf("Expected release tag v1.0.0, got %s", latestRelease.Tag)
	}
}

func TestListFiltersAndJSON(t *testing.T) {
	catalogPath := filepath.Join("..", "testdata", "catalog")

	idx, err := catalog.LoadCatalogIndex(catalogPath)
	if err != nil {
		t.Fatalf("Failed to load catalog index: %v", err)
	}

	// Test filters logic
	filteredCount := 0
	for _, img := range idx.Images {
		if img.Language == "java" && img.Tier == "distroless" && img.Lifecycle.ProductionAllowed {
			filteredCount++
		}
	}
	if filteredCount != 1 {
		t.Errorf("Expected 1 filtered image, got %d", filteredCount)
	}

	// Test JSON output logic (just marshal and check if it has valid fields)
	data, err := json.Marshal(idx)
	if err != nil {
		t.Fatalf("Failed to marshal catalog index to JSON: %v", err)
	}
	if !strings.Contains(string(data), "java21-distroless") {
		t.Errorf("JSON output does not contain image ID")
	}
	if !strings.Contains(string(data), "productionAllowed") {
		t.Errorf("JSON output does not contain lifecycle productionAllowed key")
	}
}
