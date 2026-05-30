package commands

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

type exceptionsFlags struct {
	failOnExpired bool
}

var exceptionsOpts exceptionsFlags

type ExceptionsDoc struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Exceptions []ExceptionEntry `json:"exceptions"`
	} `json:"spec"`
}

type ExceptionEntry struct {
	ID         string   `json:"id"`
	Package    string   `json:"package"`
	Image      string   `json:"image"`
	Release    string   `json:"release"`
	Status     string   `json:"status"`
	Reason     string   `json:"reason"`
	Owner      string   `json:"owner"`
	CreatedAt  string   `json:"createdAt"`
	ExpiresAt  string   `json:"expiresAt"`
	References []string `json:"references,omitempty"`
	Notes      string   `json:"notes,omitempty"`
}

var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func NewExceptionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exceptions",
		Short: "Govern vulnerability exceptions and triages",
	}

	validateCmd := &cobra.Command{
		Use:   "validate <exceptions-yaml>",
		Short: "Validate an exceptions YAML configuration against schema policies",
		Long:  `Validates vulnerability exceptions YAML files for schema correctness, owner verification, references validation, and expiration dates completely offline.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExceptionsValidate(args[0])
		},
	}

	validateCmd.Flags().BoolVar(&exceptionsOpts.failOnExpired, "fail-on-expired-exceptions", true, "Fail validation if any exception is currently expired")
	cmd.AddCommand(validateCmd)

	return cmd
}

func runExceptionsValidate(yamlPath string) error {
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return fmt.Errorf("failed to read exceptions file: %w", err)
	}

	var doc ExceptionsDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse exceptions YAML: %w", err)
	}

	// Schema assertions
	if doc.APIVersion != "clearcutt.dev/v1" {
		return fmt.Errorf("invalid apiVersion: %q (expected clearcutt.dev/v1)", doc.APIVersion)
	}
	if doc.Kind != "VulnerabilityExceptions" {
		return fmt.Errorf("invalid kind: %q (expected VulnerabilityExceptions)", doc.Kind)
	}
	if doc.Metadata.Name == "" {
		return fmt.Errorf("metadata.name must not be empty")
	}

	errors := []string{}
	now := time.Now().UTC()

	for i, exc := range doc.Spec.Exceptions {
		prefix := fmt.Sprintf("spec.exceptions[%d] (%s)", i, exc.ID)

		if !cveRegex.MatchString(exc.ID) {
			errors = append(errors, fmt.Sprintf("%s: invalid CVE ID format", prefix))
		}
		if exc.Package == "" {
			errors = append(errors, fmt.Sprintf("%s: package is required", prefix))
		}
		if exc.Image == "" {
			errors = append(errors, fmt.Sprintf("%s: image is required", prefix))
		}
		if exc.Release == "" {
			errors = append(errors, fmt.Sprintf("%s: release is required", prefix))
		}
		if exc.Owner == "" {
			errors = append(errors, fmt.Sprintf("%s: owner is required", prefix))
		}

		// Status verification
		status := strings.ToLower(exc.Status)
		if status != "affected" && status != "not_affected" && status != "fixed" && status != "under_investigation" && status != "false_positive" && status != "accepted_risk" {
			errors = append(errors, fmt.Sprintf("%s: invalid status %q", prefix, exc.Status))
		}

		// Reason verification
		reason := strings.ToLower(exc.Reason)
		if reason != "inherited_from_base" && reason != "no_fix_available" && reason != "vulnerable_code_not_present" && reason != "vulnerable_code_not_executed" && reason != "scanner_false_positive" && reason != "temporary_business_exception" && reason != "requires_upstream_fix" {
			errors = append(errors, fmt.Sprintf("%s: invalid reason %q", prefix, exc.Reason))
		}

		// Owner and references assertions
		if status == "accepted_risk" && len(exc.References) == 0 {
			errors = append(errors, fmt.Sprintf("%s: references are required for accepted_risk status", prefix))
		}

		// Dates verification
		if _, err := time.Parse("2006-01-02", exc.CreatedAt); err != nil {
			errors = append(errors, fmt.Sprintf("%s: invalid createdAt format %q (expected YYYY-MM-DD)", prefix, exc.CreatedAt))
		}

		expiry, err := time.Parse("2006-01-02", exc.ExpiresAt)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: invalid expiresAt format %q (expected YYYY-MM-DD)", prefix, exc.ExpiresAt))
		} else {
			if exceptionsOpts.failOnExpired && expiry.Before(now) {
				errors = append(errors, fmt.Sprintf("%s: exception has expired (expired on %s)", prefix, exc.ExpiresAt))
			}
		}
	}

	if len(errors) > 0 {
		fmt.Fprintf(os.Stderr, "Exception validation failed with %d errors:\n", len(errors))
		for _, err := range errors {
			fmt.Fprintf(os.Stderr, "  - %s\n", err)
		}
		osExit(1)
		return fmt.Errorf("exceptions validation failed")
	}

	if !GlobalOpts.Quiet {
		fmt.Printf("Vulnerability exceptions document %q is fully valid and active!\n", doc.Metadata.Name)
	}

	return nil
}

// LoadExceptionsFile reads and parses an exceptions YAML file.
func LoadExceptionsFile(path string) (*ExceptionsDoc, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc ExceptionsDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}
