package commands

import (
	"os"
	"testing"
)

func TestRunConformanceSuite(t *testing.T) {
	osExit = func(code int) {}
	defer func() { osExit = os.Exit }()

	testImages := []string{
		"java25-distroless",
		"node22-slim",
		"go1.26-dev",
		"dotnet8-distroless",
		"rust1.95-slim",
		"cc15-distroless",
		"coreLTS-distroless",
	}

	for _, img := range testImages {
		t.Run(img, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "clearcutt-conformance-*.json")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())
			tmpFile.Close()

			conformanceOpts = conformanceFlags{
				image:  img,
				output: tmpFile.Name(),
			}

			err = runConformanceSuite()
			if err != nil {
				t.Fatalf("runConformanceSuite failed for image %s: %v", img, err)
			}

			// Verify report is written
			data, err := os.ReadFile(tmpFile.Name())
			if err != nil {
				t.Fatalf("failed to read conformance report: %v", err)
			}

			if len(data) == 0 {
				t.Errorf("conformance report is empty for image %s", img)
			}
		})
	}
}
