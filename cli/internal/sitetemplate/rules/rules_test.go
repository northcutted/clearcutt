package rules

import "testing"

func TestIsExcluded(t *testing.T) {
	for _, path := range []string{"node_modules/pkg", `src\data\catalog`, "public/catalog/index.json", "src/pages/.astro/cache"} {
		if !IsExcluded(path) {
			t.Errorf("IsExcluded(%q) = false", path)
		}
	}
	for _, path := range []string{"", ".", "./src/pages/index.astro", "/src/components/Card.astro/"} {
		if IsExcluded(path) {
			t.Errorf("IsExcluded(%q) = true", path)
		}
	}
}
