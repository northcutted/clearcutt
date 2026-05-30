package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/northcutted/clearcutt/internal/catalog"
	"github.com/northcutted/clearcutt/internal/output"
)

type inspectFlags struct {
	tag string
}

var inspectOpts inspectFlags

// NewInspectCmd creates the Cobra inspect command.
func NewInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect <image-id>",
		Short: "Inspect a specific ClearCutt image record",
		Long:  `Inspect all supply chain evidence, lifecycle states, vulnerabilities, and assets for a single base image.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInspect(args[0])
		},
	}

	cmd.Flags().StringVar(&inspectOpts.tag, "tag", "", "Inspect details for a specific versioned release tag")

	return cmd
}

func runInspect(imageID string) error {
	record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, imageID)
	if err != nil {
		return err
	}

	if err := catalog.ValidateImageRecord(record); err != nil {
		return fmt.Errorf("image record validation failed: %w", err)
	}

	// Find the targeted release
	var targetRelease *catalog.ReleaseEntry
	if inspectOpts.tag != "" {
		for i := range record.Releases {
			if record.Releases[i].Tag == inspectOpts.tag {
				targetRelease = &record.Releases[i]
				break
			}
		}
		if targetRelease == nil {
			return fmt.Errorf("release tag %q not found for image %q", inspectOpts.tag, imageID)
		}
	} else {
		// Default to latest release
		for i := range record.Releases {
			if record.Releases[i].IsLatest {
				targetRelease = &record.Releases[i]
				break
			}
		}
		if targetRelease == nil && len(record.Releases) > 0 {
			targetRelease = &record.Releases[0]
		}
	}

	if targetRelease == nil {
		return fmt.Errorf("no releases found for image %q", imageID)
	}

	// Format output
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(os.Stdout, struct {
			ImageRecord   *catalog.ImageRecord  `json:"imageRecord"`
			ActiveRelease *catalog.ReleaseEntry `json:"activeRelease"`
		}{
			ImageRecord:   record,
			ActiveRelease: targetRelease,
		})
	case "yaml", "yml":
		return output.PrintYAML(os.Stdout, struct {
			ImageRecord   *catalog.ImageRecord  `json:"imageRecord"`
			ActiveRelease *catalog.ReleaseEntry `json:"activeRelease"`
		}{
			ImageRecord:   record,
			ActiveRelease: targetRelease,
		})
	default:
		// Human readable formatted terminal output
		fmt.Printf("Image ID:           %s\n", record.ID)
		fmt.Printf("Language/Runtime:   %s (%s)\n", record.Language.DisplayName, record.Language.Version)
		fmt.Printf("Tier:               %s\n", record.Tier.Name)
		fmt.Printf("Full Image Name:    %s\n", record.FullName)
		fmt.Printf("Tag Reference:      %s:%s\n", record.FullName, targetRelease.Tag)

		// Digest-pinned reference
		if targetRelease.ManifestDigest != nil && *targetRelease.ManifestDigest != "" {
			fmt.Printf("Digest Reference:   %s@%s\n", record.FullName, *targetRelease.ManifestDigest)
		} else {
			fmt.Println("Digest Reference:   [Evidence Incomplete - Manifest Digest Missing]")
		}

		fmt.Println("\n--- Lifecycle Policy ---")
		fmt.Printf("Status:             %s\n", targetRelease.Lifecycle.Status)
		fmt.Printf("Support Tier:       %s\n", targetRelease.Lifecycle.Support)
		prodAllowed := "no"
		if targetRelease.Lifecycle.ProductionAllowed {
			prodAllowed = "yes"
		}
		fmt.Printf("Prod Allowed:       %s\n", prodAllowed)
		if targetRelease.Lifecycle.Reason != nil && *targetRelease.Lifecycle.Reason != "" {
			fmt.Printf("Reason:             %s\n", *targetRelease.Lifecycle.Reason)
		}

		fmt.Println("\n--- Runtime Contract ---")
		if targetRelease.RuntimeContract.User != nil {
			fmt.Printf("User:               %s\n", *targetRelease.RuntimeContract.User)
		} else {
			fmt.Println("User:               unknown")
		}
		if targetRelease.RuntimeContract.WorkingDir != nil {
			fmt.Printf("Working Dir:        %s\n", *targetRelease.RuntimeContract.WorkingDir)
		} else {
			fmt.Println("Working Dir:        unknown")
		}

		shellVal := "unknown"
		if targetRelease.RuntimeContract.ShellPresent != nil {
			if *targetRelease.RuntimeContract.ShellPresent {
				shellVal = "present"
			} else {
				shellVal = "absent"
			}
		}
		fmt.Printf("Shell:              %s\n", shellVal)

		pkgManagerVal := "unknown"
		if targetRelease.RuntimeContract.PackageManagerPresent != nil {
			if *targetRelease.RuntimeContract.PackageManagerPresent {
				pkgManagerVal = "present"
			} else {
				pkgManagerVal = "absent"
			}
		}
		fmt.Printf("Package Manager:    %s\n", pkgManagerVal)

		caCertVal := "unknown"
		if targetRelease.RuntimeContract.CACertificatesPresent != nil {
			if *targetRelease.RuntimeContract.CACertificatesPresent {
				caCertVal = "present"
			} else {
				caCertVal = "absent"
			}
		}
		fmt.Printf("CA Certificates:    %s\n", caCertVal)

		timezoneVal := "unknown"
		if targetRelease.RuntimeContract.TimezoneDataPresent != nil {
			if *targetRelease.RuntimeContract.TimezoneDataPresent {
				timezoneVal = "present"
			} else {
				timezoneVal = "absent"
			}
		}
		fmt.Printf("Timezone Data:      %s\n", timezoneVal)

		if targetRelease.RuntimeContract.DefaultEntrypoint != nil {
			fmt.Printf("Default Entrypoint:  %s\n", *targetRelease.RuntimeContract.DefaultEntrypoint)
		} else {
			fmt.Println("Default Entrypoint:  none")
		}

		fmt.Println("\n--- Architectures & Payloads ---")
		for _, arch := range targetRelease.Architectures {
			fmt.Printf("Platform:           linux/%s\n", arch.Arch)
			if arch.ImageDigest != nil {
				fmt.Printf("  Digest:           %s\n", *arch.ImageDigest)
			}
			if arch.ImageSize != nil {
				fmt.Printf("  Size:             %.2f MB\n", float64(*arch.ImageSize)/(1024*1024))
			}
			if arch.LayerCount != nil {
				fmt.Printf("  Layers:           %d\n", *arch.LayerCount)
			}
			fmt.Printf("  SBOM Packages:    %d\n", arch.SBOM.PackageCount)

			// Test status
			testStatus := "missing"
			if arch.TestResults != nil {
				testStatus = strings.ToLower(arch.TestResults.Status)
			}
			fmt.Printf("  Smoke Tests:      %s\n", testStatus)

			// Vulnerability counts
			if arch.Vulnerabilities != nil {
				counts := arch.Vulnerabilities.CountsBySeverity
				fmt.Printf("  Vulnerabilities:  critical=%d, high=%d, medium=%d, low=%d (Scanned At: %s)\n",
					counts.Critical, counts.High, counts.Medium, counts.Low, arch.Vulnerabilities.ScannedAt)
			} else {
				fmt.Println("  Vulnerabilities:  no scan results on record")
			}
		}

		// Supply chain evidence flags
		fmt.Println("\n--- Supply Chain Evidence ---")
		sigVal := "absent"
		if targetRelease.Evidence != nil && targetRelease.Evidence.Signature {
			sigVal = "present"
		}
		fmt.Printf("Cosign Signature:   %s\n", sigVal)

		sbomVal := "absent"
		if targetRelease.Evidence != nil && targetRelease.Evidence.SBOM {
			sbomVal = "present (all architectures)"
		} else if targetRelease.Evidence != nil && targetRelease.Evidence.SBOMArchCount > 0 {
			sbomVal = fmt.Sprintf("incomplete (%d/%d architectures)", targetRelease.Evidence.SBOMArchCount, targetRelease.Evidence.ArchCount)
		}
		fmt.Printf("SPDX SBOMs:         %s\n", sbomVal)

		provVal := "absent"
		if targetRelease.Evidence != nil && targetRelease.Evidence.Provenance {
			provVal = "present"
		}
		fmt.Printf("SLSA Provenance:    %s\n", provVal)

		testEvVal := "absent"
		if targetRelease.Evidence != nil && targetRelease.Evidence.Tests {
			testEvVal = "passed (all architectures)"
		} else if targetRelease.Evidence != nil && targetRelease.Evidence.TestArchCount > 0 {
			testEvVal = fmt.Sprintf("failed or incomplete (%d/%d architectures passed)", targetRelease.Evidence.PassedTestArchCount, targetRelease.Evidence.ArchCount)
		}
		fmt.Printf("Conformance Tests:  %s\n", testEvVal)

		// Exceptions Summary
		fmt.Println("\n--- Vulnerability Governance ---")
		fmt.Printf("Total Exceptions:   %d (active=%d, expired=%d)\n",
			targetRelease.Exceptions.Total, targetRelease.Exceptions.Active, targetRelease.Exceptions.Expired)
		fmt.Printf("Remediation State:  acceptedRisk=%d, noFixAvailable=%d, falsePositive=%d, inheritedFromBase=%d\n",
			targetRelease.Exceptions.AcceptedRisk, targetRelease.Exceptions.NoFixAvailable,
			targetRelease.Exceptions.FalsePositive, targetRelease.Exceptions.InheritedFromBase)

		// Release Assets
		fmt.Println("\n--- Release Assets ---")
		if targetRelease.AssetURLs.Provenance != nil && *targetRelease.AssetURLs.Provenance != "" {
			fmt.Printf("SLSA Provenance:    %s\n", *targetRelease.AssetURLs.Provenance)
		}
		if len(targetRelease.AssetURLs.SBOM) > 0 {
			fmt.Println("SBOM Archives:")
			for arch, url := range targetRelease.AssetURLs.SBOM {
				fmt.Printf("  %-6s            %s\n", arch, url)
			}
		}
		if len(targetRelease.AssetURLs.TestResults) > 0 {
			fmt.Println("Test Results:")
			for arch, url := range targetRelease.AssetURLs.TestResults {
				fmt.Printf("  %-6s            %s\n", arch, url)
			}
		}
		if targetRelease.AssetURLs.Digest != nil && *targetRelease.AssetURLs.Digest != "" {
			fmt.Printf("Manifest Digest:    %s\n", *targetRelease.AssetURLs.Digest)
		}
	}
	return nil
}
