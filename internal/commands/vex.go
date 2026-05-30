package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/northcutted/clearcutt/internal/catalog"
	"github.com/northcutted/clearcutt/internal/output"
)

type vexFlags struct {
	tag            string
	output         string
	exceptionsFile string
}

var vexOpts vexFlags

type OpenVEXDocument struct {
	Context    string             `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Role       string             `json:"role"`
	Timestamp  string             `json:"timestamp"`
	Version    int                `json:"version"`
	Statements []OpenVEXStatement `json:"statements"`
}

type OpenVEXStatement struct {
	Vulnerability   OpenVEXVulnerability `json:"vulnerability"`
	Products        []OpenVEXProduct     `json:"products"`
	Status          string               `json:"status"` // affected, not_affected, under_investigation, fixed
	Justification   string               `json:"justification,omitempty"`
	ImpactStatement string               `json:"impact_statement,omitempty"`
}

type OpenVEXVulnerability struct {
	Name string `json:"name"`
}

type OpenVEXProduct struct {
	ID string `json:"@id"`
}

func NewVexCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vex <image-id>",
		Short: "Generate standard compliant OpenVEX documents dynamically",
		Long:  `Resolves base image vulnerability findings and exception statements, generating standard OpenVEX JSON documents dynamically.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVex(args[0])
		},
	}

	cmd.Flags().StringVar(&vexOpts.tag, "tag", "", "Target release tag version (defaults to latest)")
	cmd.Flags().StringVar(&vexOpts.output, "output", "", "Output JSON file path destination")
	cmd.Flags().StringVar(&vexOpts.exceptionsFile, "exceptions", "", "Path to local exceptions YAML triage governance file")

	return cmd
}

func runVex(imageID string) error {
	record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, imageID)
	if err != nil {
		return err
	}

	if err := catalog.ValidateImageRecord(record); err != nil {
		return fmt.Errorf("image record validation failed: %w", err)
	}

	// Resolve the target release
	var release *catalog.ReleaseEntry
	if vexOpts.tag != "" {
		for i := range record.Releases {
			if record.Releases[i].Tag == vexOpts.tag {
				release = &record.Releases[i]
				break
			}
		}
		if release == nil {
			return fmt.Errorf("release tag %q not found for image %q", vexOpts.tag, imageID)
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

	// Load exceptions if provided
	var exceptionsDoc *ExceptionsDoc
	if vexOpts.exceptionsFile != "" {
		doc, err := LoadExceptionsFile(vexOpts.exceptionsFile)
		if err != nil {
			return fmt.Errorf("failed to load exceptions file: %w", err)
		}
		exceptionsDoc = doc
	}

	// Create OpenVEX Document
	doc := OpenVEXDocument{
		Context:   "https://openvex.dev/ns/v0.2.0",
		ID:        fmt.Sprintf("https://clearcutt.internal/vex/%s/%s", imageID, release.Tag),
		Author:    "ClearCutt Security Platform Gating Engine",
		Role:      "Document Creator",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   1,
		Statements: []OpenVEXStatement{},
	}

	// Iterate architectures and parse findings to extract VEX statements
	productID := fmt.Sprintf("pkg:nix/%s@%s", imageID, release.Tag)
	product := OpenVEXProduct{ID: productID}

	seenVulnerabilities := make(map[string]bool)
	now := time.Now().UTC()

	for _, arch := range release.Architectures {
		if arch.Vulnerabilities == nil {
			continue
		}

		for _, finding := range arch.Vulnerabilities.Findings {
			if seenVulnerabilities[finding.ID] {
				continue
			}
			seenVulnerabilities[finding.ID] = true

			// Create VEX statement
			vuln := OpenVEXVulnerability{Name: finding.ID}
			stmt := OpenVEXStatement{
				Vulnerability: vuln,
				Products:      []OpenVEXProduct{product},
			}

			// Check if we have an active exception for this finding
			var matchedException *ExceptionEntry
			if exceptionsDoc != nil {
				for i := range exceptionsDoc.Spec.Exceptions {
					exc := &exceptionsDoc.Spec.Exceptions[i]
					if exc.ID == finding.ID &&
						(exc.Package == "*" || exc.Package == finding.PackageName) &&
						(exc.Image == "*" || exc.Image == imageID) &&
						(exc.Release == "*" || exc.Release == release.Tag) {

						expiry, err := time.Parse("2006-01-02", exc.ExpiresAt)
						if err == nil && expiry.After(now) {
							matchedException = exc
							break
						}
					}
				}
			}

			// Map remediation/justification dynamically
			if matchedException != nil {
				stmt.Status = strings.ToLower(matchedException.Status)
				stmt.ImpactStatement = matchedException.Notes
				reason := strings.ToLower(matchedException.Reason)
				switch reason {
				case "vulnerable_code_not_present":
					stmt.Justification = "component_not_present"
				case "vulnerable_code_not_executed":
					stmt.Justification = "vulnerable_code_not_in_execute_path"
				case "inherited_from_base":
					stmt.Justification = "vulnerable_code_not_in_execute_path"
				default:
					stmt.Justification = "vulnerable_code_cannot_be_controlled_by_adversary"
				}
			} else if finding.Remediation != nil {
				reason := strings.ToLower(finding.Remediation.Reason)
				status := strings.ToLower(finding.Remediation.Status)

				stmt.ImpactStatement = finding.Remediation.Summary

				if status == "deferred" {
					if reason == "base_layer" {
						stmt.Status = "not_affected"
						stmt.Justification = "vulnerable_code_not_in_execute_path"
					} else if reason == "below_priority_threshold" {
						stmt.Status = "not_affected"
						stmt.Justification = "vulnerable_code_not_in_execute_path"
					} else if reason == "no_fixed_version" {
						stmt.Status = "under_investigation"
					} else if reason == "accepted_risk" {
						stmt.Status = "not_affected"
						stmt.Justification = "vulnerable_code_cannot_be_controlled_by_adversary"
					} else {
						stmt.Status = "under_investigation"
					}
				} else if status == "eligible" {
					stmt.Status = "affected"
					stmt.ImpactStatement = "Image layer is affected; update is eligible for compilation."
				} else {
					stmt.Status = "not_affected"
					stmt.Justification = "vulnerable_code_not_present"
				}
			} else {
				// Defaults if no explicit remediation exists
				stmt.Status = "under_investigation"
				stmt.ImpactStatement = "Finding is active and under platform triage."
			}

			doc.Statements = append(doc.Statements, stmt)
		}
	}

	// Serialize
	outputData, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize OpenVEX document: %w", err)
	}

	if vexOpts.output != "" {
		if err := os.WriteFile(vexOpts.output, outputData, 0644); err != nil {
			return fmt.Errorf("failed to write OpenVEX file: %w", err)
		}
		if !GlobalOpts.Quiet {
			fmt.Printf("Successfully generated OpenVEX compliance document: %s\n", vexOpts.output)
		}
	} else {
		// Output format checks
		switch strings.ToLower(GlobalOpts.Format) {
		case "yaml", "yml":
			if err := output.PrintYAML(os.Stdout, doc); err != nil {
				return err
			}
		default:
			os.Stdout.Write(outputData)
			fmt.Println()
		}
	}

	return nil
}
