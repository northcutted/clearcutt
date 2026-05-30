package commands

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/northcutted/clearcutt/internal/catalog"
	"github.com/northcutted/clearcutt/internal/output"
)

type verifyFlags struct {
	tag                     string
	requireProduction       bool
	allowPreview            bool
	allowDeprecated         bool
	requireSignature        bool
	requireSBOM             bool
	requireProvenance       bool
	requireTests            bool
	requireVulnScan         bool
	maxCritical             int
	maxHigh                 int
	exceptionsFile          string
	allowExceptions         bool
	failOnExpiredExceptions bool
}

var verifyOpts verifyFlags

// VerifyCheckResult represents a single assertion check result.
type VerifyCheckResult struct {
	ID      string `json:"id"`
	Status  string `json:"status"` // pass or fail
	Message string `json:"message"`
}

// VerifyResponse represents the complete JSON response payload.
type VerifyResponse struct {
	Status string              `json:"status"` // pass or fail
	Image  string              `json:"image"`
	Tag    string              `json:"tag"`
	Checks []VerifyCheckResult `json:"checks"`
}

// NewVerifyCmd creates the Cobra verify command.
func NewVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <image-id>",
		Short: "Verify a specific ClearCutt image against policy contract gates",
		Long:  `Enforces signatures, SBOMs, SLSA provenance, smoke tests, vulnerability limits, and lifecycle constraints.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(args[0])
		},
	}

	cmd.Flags().StringVar(&verifyOpts.tag, "tag", "", "Enforce policies against a specific versioned tag (defaults to latest)")
	cmd.Flags().BoolVar(&verifyOpts.requireProduction, "require-production", false, "Require that the image is approved for production deployment")
	cmd.Flags().BoolVar(&verifyOpts.allowPreview, "allow-preview", false, "Allow images currently marked in the 'preview' lifecycle status")
	cmd.Flags().BoolVar(&verifyOpts.allowDeprecated, "allow-deprecated", false, "Allow images currently marked in the 'deprecated' lifecycle status")
	cmd.Flags().BoolVar(&verifyOpts.requireSignature, "require-signature", false, "Enforce presence of a valid Cosign cryptographic signature")
	cmd.Flags().BoolVar(&verifyOpts.requireSBOM, "require-sbom", false, "Enforce presence of SPDX SBOM assets for all architectures")
	cmd.Flags().BoolVar(&verifyOpts.requireProvenance, "require-provenance", false, "Enforce presence of SLSA level-3 build provenance attestations")
	cmd.Flags().BoolVar(&verifyOpts.requireTests, "require-tests", false, "Enforce that smoke and conformance tests exist and have passed")
	cmd.Flags().BoolVar(&verifyOpts.requireVulnScan, "require-vuln-scan", false, "Enforce presence of complete vulnerability scan results")
	cmd.Flags().IntVar(&verifyOpts.maxCritical, "max-critical", -1, "Maximum tolerated critical severity vulnerabilities (-1 to disable threshold)")
	cmd.Flags().IntVar(&verifyOpts.maxHigh, "max-high", -1, "Maximum tolerated high severity vulnerabilities (-1 to disable threshold)")
	cmd.Flags().StringVar(&verifyOpts.exceptionsFile, "exceptions", "", "Path to local exceptions YAML triage governance file")
	cmd.Flags().BoolVar(&verifyOpts.allowExceptions, "allow-exceptions", false, "Honour active vulnerability exceptions during gating")
	cmd.Flags().BoolVar(&verifyOpts.failOnExpiredExceptions, "fail-on-expired-exceptions", true, "Fail verification if any matched exception is expired")

	return cmd
}

func runVerify(imageID string) error {
	record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, imageID)
	if err != nil {
		return err
	}

	if err := catalog.ValidateImageRecord(record); err != nil {
		return fmt.Errorf("image record validation failed: %w", err)
	}

	// Resolve the target release
	var release *catalog.ReleaseEntry
	if verifyOpts.tag != "" {
		for i := range record.Releases {
			if record.Releases[i].Tag == verifyOpts.tag {
				release = &record.Releases[i]
				break
			}
		}
		if release == nil {
			return fmt.Errorf("release tag %q not found for image %q", verifyOpts.tag, imageID)
		}
	} else {
		for i := range record.Releases {
			if record.Releases[i].IsLatest {
				release = &record.Releases[i]
				break
			}
		}
		if release == nil && len(record.Releases) > 0 {
			release = &record.Releases[0]
		}
	}

	if release == nil {
		return fmt.Errorf("no releases found for image %q", imageID)
	}

	// Parse exceptions if allowed
	var exceptionsDoc *ExceptionsDoc
	if verifyOpts.allowExceptions && verifyOpts.exceptionsFile != "" {
		doc, err := LoadExceptionsFile(verifyOpts.exceptionsFile)
		if err != nil {
			return fmt.Errorf("failed to load exceptions file: %w", err)
		}
		exceptionsDoc = doc
	}

	checks := []VerifyCheckResult{}
	hasFailures := false

	addCheck := func(id, status, message string) {
		checks = append(checks, VerifyCheckResult{
			ID:      id,
			Status:  status,
			Message: message,
		})
		if status == "fail" {
			hasFailures = true
		}
	}

	// 1. Check Digest & Architectures
	if release.ManifestDigest != nil && *release.ManifestDigest != "" {
		addCheck("digest.present", "pass", fmt.Sprintf("manifest digest present: %s", *release.ManifestDigest))
	} else {
		addCheck("digest.present", "fail", "manifest digest is missing from release")
	}

	if len(release.Architectures) > 0 {
		var archList []string
		for _, arch := range release.Architectures {
			archList = append(archList, arch.Arch)
		}
		addCheck("architectures.present", "pass", fmt.Sprintf("architectures present: %s", strings.Join(archList, ", ")))
	} else {
		addCheck("architectures.present", "fail", "no architecture payloads found in release record")
	}

	// 2. Check Signature
	hasSig := release.Evidence != nil && release.Evidence.Signature
	if !hasSig && release.Signature != nil {
		hasSig = release.Signature.CosignBundlePresent
	}
	if verifyOpts.requireSignature {
		if hasSig {
			addCheck("signature.present", "pass", "Sigstore signature verified in release record")
		} else {
			addCheck("signature.present", "fail", "Sigstore cryptographic signature is missing")
		}
	} else if hasSig {
		addCheck("signature.present", "pass", "Sigstore signature present (not explicitly required)")
	}

	// 3. Check SBOM
	hasSBOM := release.Evidence != nil && release.Evidence.SBOM
	if verifyOpts.requireSBOM {
		if hasSBOM {
			addCheck("sbom.present", "pass", "SPDX SBOM evidence verified for all platforms")
		} else {
			missingCount := 0
			if release.Evidence != nil {
				missingCount = release.Evidence.ArchCount - release.Evidence.SBOMArchCount
			}
			addCheck("sbom.present", "fail", fmt.Sprintf("SPDX SBOM is missing or incomplete (%d platforms missing)", missingCount))
		}
	} else if hasSBOM {
		addCheck("sbom.present", "pass", "SPDX SBOM present for all platforms (not explicitly required)")
	}

	// 4. Check SLSA Provenance
	hasProv := release.Evidence != nil && release.Evidence.Provenance
	if !hasProv && release.Provenance != nil {
		hasProv = true
	}
	if verifyOpts.requireProvenance {
		if hasProv {
			addCheck("provenance.present", "pass", "SLSA Level-3 build provenance attestation present")
		} else {
			addCheck("provenance.present", "fail", "SLSA build provenance attestation is missing")
		}
	} else if hasProv {
		addCheck("provenance.present", "pass", "SLSA build provenance present (not explicitly required)")
	}

	// 5. Check Conformance Tests
	hasTests := release.Evidence != nil && release.Evidence.Tests
	if verifyOpts.requireTests {
		if hasTests {
			addCheck("tests.passed", "pass", "conformance and smoke tests passed on all platforms")
		} else {
			failedCount := 0
			if release.Evidence != nil {
				failedCount = release.Evidence.ArchCount - release.Evidence.PassedTestArchCount
			}
			addCheck("tests.passed", "fail", fmt.Sprintf("smoke tests failed or missing (%d platforms failed/incomplete)", failedCount))
		}
	} else if hasTests {
		addCheck("tests.passed", "pass", "conformance tests passed on all platforms (not explicitly required)")
	}

	// 6. Check Vulnerability Scanning
	hasScan := release.Evidence != nil && release.Evidence.Vulnerabilities
	if verifyOpts.requireVulnScan {
		if hasScan {
			addCheck("vulnerabilities.scanned", "pass", "vulnerability scan results present for all platforms")
		} else {
			missingCount := 0
			if release.Evidence != nil {
				missingCount = release.Evidence.ArchCount - release.Evidence.VulnerabilityArchCount
			}
			addCheck("vulnerabilities.scanned", "fail", fmt.Sprintf("vulnerability scan coverage incomplete (%d platforms missing)", missingCount))
		}
	} else if hasScan {
		addCheck("vulnerabilities.scanned", "pass", "vulnerability scans present (not explicitly required)")
	}

	// 7. Check Production Gating
	if verifyOpts.requireProduction {
		if release.Lifecycle.ProductionAllowed {
			addCheck("lifecycle.productionAllowed", "pass", "image is approved for production deployment")
		} else {
			addCheck("lifecycle.productionAllowed", "fail", "production allowed check failed: this image is not approved for production use")
		}
	}

	// 8. Check Lifecycle Status
	lifecycleStatus := strings.ToLower(release.Lifecycle.Status)
	if lifecycleStatus == "preview" && !verifyOpts.allowPreview {
		addCheck("lifecycle.status", "fail", "lifecycle check failed: image is in 'preview' status (use --allow-preview to override)")
	} else if lifecycleStatus == "deprecated" && !verifyOpts.allowDeprecated {
		addCheck("lifecycle.status", "fail", "lifecycle check failed: image is in 'deprecated' status (use --allow-deprecated to override)")
	} else if lifecycleStatus == "eol" {
		addCheck("lifecycle.status", "fail", "lifecycle check failed: image is marked End-of-Life ('eol')")
	} else if lifecycleStatus == "blocked" {
		addCheck("lifecycle.status", "fail", "lifecycle check failed: image is 'blocked' due to security or platform concerns")
	} else {
		addCheck("lifecycle.status", "pass", fmt.Sprintf("lifecycle status verified: %s", lifecycleStatus))
	}

	// 9. Gating Vulnerability Thresholds
	if verifyOpts.maxCritical >= 0 || verifyOpts.maxHigh >= 0 {
		critExceeded := false
		highExceeded := false
		maxCritFound := 0
		maxHighFound := 0

		now := time.Now().UTC()

		for _, arch := range release.Architectures {
			if arch.Vulnerabilities != nil {
				criticalCount := 0
				highCount := 0

				for _, finding := range arch.Vulnerabilities.Findings {
					isExempted := false
					if exceptionsDoc != nil {
						for _, exc := range exceptionsDoc.Spec.Exceptions {
							if exc.ID == finding.ID &&
								(exc.Package == "*" || exc.Package == finding.PackageName) &&
								(exc.Image == "*" || exc.Image == imageID) &&
								(exc.Release == "*" || exc.Release == release.Tag) {

								expiry, err := time.Parse("2006-01-02", exc.ExpiresAt)
								if err == nil {
									if expiry.Before(now) {
										if verifyOpts.failOnExpiredExceptions {
											continue
										}
									}
									isExempted = true
									break
								}
							}
						}
					}

					if isExempted {
						continue
					}

					sev := strings.ToLower(finding.Severity)
					if sev == "critical" {
						criticalCount++
					} else if sev == "high" {
						highCount++
					}
				}

				// If we don't have findings but have pre-aggregated counts, use them as fallback
				if len(arch.Vulnerabilities.Findings) == 0 {
					criticalCount = arch.Vulnerabilities.CountsBySeverity.Critical
					highCount = arch.Vulnerabilities.CountsBySeverity.High
				}

				if criticalCount > maxCritFound {
					maxCritFound = criticalCount
				}
				if highCount > maxHighFound {
					maxHighFound = highCount
				}

				if verifyOpts.maxCritical >= 0 && criticalCount > verifyOpts.maxCritical {
					critExceeded = true
				}
				if verifyOpts.maxHigh >= 0 && highCount > verifyOpts.maxHigh {
					highExceeded = true
				}
			}
		}

		if verifyOpts.maxCritical >= 0 {
			if critExceeded {
				addCheck("vulnerabilities.threshold.critical", "fail", fmt.Sprintf("critical vulnerability count %d exceeds maximum allowed %d", maxCritFound, verifyOpts.maxCritical))
			} else {
				addCheck("vulnerabilities.threshold.critical", "pass", fmt.Sprintf("critical vulnerabilities verified within limits (%d found, max allowed %d)", maxCritFound, verifyOpts.maxCritical))
			}
		}

		if verifyOpts.maxHigh >= 0 {
			if highExceeded {
				addCheck("vulnerabilities.threshold.high", "fail", fmt.Sprintf("high vulnerability count %d exceeds maximum allowed %d", maxHighFound, verifyOpts.maxHigh))
			} else {
				addCheck("vulnerabilities.threshold.high", "pass", fmt.Sprintf("high vulnerabilities verified within limits (%d found, max allowed %d)", maxHighFound, verifyOpts.maxHigh))
			}
		}
	}

	overallStatus := "pass"
	if hasFailures {
		overallStatus = "fail"
	}

	response := VerifyResponse{
		Status: overallStatus,
		Image:  imageID,
		Tag:    release.Tag,
		Checks: checks,
	}

	// Format output
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		if err := output.PrintJSON(os.Stdout, response); err != nil {
			return err
		}
	case "yaml", "yml":
		if err := output.PrintYAML(os.Stdout, response); err != nil {
			return err
		}
	default:
		// Print human readable
		fmt.Printf("Policy Gating Report for %s:%s\n", imageID, release.Tag)
		fmt.Println("-----------------------------------------------------------------")
		for _, check := range checks {
			statusSymbol := "✔ PASS"
			if check.Status == "fail" {
				statusSymbol = "✘ FAIL"
			}
			fmt.Printf("[%-6s] %-32s : %s\n", statusSymbol, check.ID, check.Message)
		}
		fmt.Println("-----------------------------------------------------------------")
		if hasFailures {
			fmt.Println("Verification Result: FAIL")
		} else {
			fmt.Println("Verification Result: PASS")
		}
	}

	if hasFailures {
		// Exit process with non-zero failure code
		osExit(1)
	}

	return nil
}
