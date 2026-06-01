package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeGrypeMatchesFixtureOutput(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "scan", "grype-python3.13-slim.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result grypeResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}

	dbBuiltAt := "2026-05-28T00:00:00Z"
	report := normalizeGrype(
		result,
		"2026-05-31T00:00:00.000Z",
		"grype-0.0.0-test",
		&dbBuiltAt,
		targetMetadata("python3.13-slim"),
	)
	got, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	expected, err := os.ReadFile(filepath.Join("testdata", "scan", "expected-python3.13-slim.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(string(expected)) {
		t.Fatalf("normalized scan output drifted.\n got:\n%s\nwant:\n%s", got, expected)
	}
}

func TestSelectScanTagsUsesDepthWindowAndExplicitPrecedence(t *testing.T) {
	old := scanOpts
	t.Cleanup(func() { scanOpts = old })

	scanOpts = scanFlags{depth: "2"}
	selected, err := selectScanTags([]string{"v1.0.0", "v1.0.1", "v1.0.2", "v1.0.3"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(selected, ",") != "v1.0.3,v1.0.2" {
		t.Fatalf("unexpected depth selection: %v", selected)
	}

	scanOpts = scanFlags{depth: "1", all: true, tags: "v1.0.0,v1.0.3"}
	selected, err = selectScanTags([]string{"v1.0.0", "v1.0.1", "v1.0.2", "v1.0.3"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(selected, ",") != "v1.0.0,v1.0.3" {
		t.Fatalf("explicit tags should override all/depth, got: %v", selected)
	}
}
