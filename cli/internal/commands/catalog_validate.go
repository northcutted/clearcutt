package commands

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt/internal/catalog"
	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
)

type catalogValidateFlags struct {
	warningsAsErrors bool
	schemaVersion    string
}

var catalogValidateOpts catalogValidateFlags

type catalogValidationReport struct {
	CatalogPath  string   `json:"catalogPath"`
	ImageCount   int      `json:"imageCount"`
	ErrorCount   int      `json:"errorCount"`
	WarningCount int      `json:"warningCount"`
	Errors       []string `json:"errors"`
	Warnings     []string `json:"warnings"`
}

func newCatalogValidateCmd() *cobra.Command {
	catalogValidateOpts = catalogValidateFlags{}
	cmd := &cobra.Command{
		Use:   "validate [catalog-dir]",
		Short: "Validate a generated catalog directory",
		Long: `Validate index.json plus every images/*.json record for directory shape,
referential integrity, required release fields, required package/CVE fields, and
evidence-summary consistency. Missing optional evidence is reported as warnings
unless --strict or --warnings-as-errors is set.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := GlobalOpts.CatalogPath
			if len(args) == 1 {
				path = args[0]
			}
			return runCatalogValidate(path)
		},
	}
	cmd.Flags().BoolVar(&catalogValidateOpts.warningsAsErrors, "warnings-as-errors", false, "Fail validation when warnings are present")
	cmd.Flags().StringVar(&catalogValidateOpts.schemaVersion, "schema-version", "", "Require a specific catalog schema version")
	return cmd
}

func runCatalogValidate(catalogPath string) error {
	report := validateCatalogDirectory(catalogPath)
	failed := report.ErrorCount > 0 || ((catalogValidateOpts.warningsAsErrors || catalog.Strict) && report.WarningCount > 0)

	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		if err := output.PrintJSON(out, report); err != nil {
			return err
		}
	case "yaml", "yml":
		if err := output.PrintYAML(out, report); err != nil {
			return err
		}
	default:
		if report.ErrorCount == 0 && report.WarningCount == 0 {
			fmt.Fprintf(out, "[catalog-validate] ok: %d image record(s) validated in %s\n", report.ImageCount, catalogPath)
		} else {
			fmt.Fprintf(out, "[catalog-validate] %d error(s), %d warning(s) in %s\n", report.ErrorCount, report.WarningCount, catalogPath)
			for _, msg := range report.Errors {
				fmt.Fprintf(out, "- error: %s\n", msg)
			}
			for _, msg := range report.Warnings {
				fmt.Fprintf(out, "- warning: %s\n", msg)
			}
		}
	}

	if failed {
		return ErrCheckFailed
	}
	return nil
}

func validateCatalogDirectory(catalogPath string) catalogValidationReport {
	report := catalogValidationReport{CatalogPath: catalogPath}
	addError := func(format string, args ...any) {
		report.Errors = append(report.Errors, fmt.Sprintf(format, args...))
	}
	addWarning := func(format string, args ...any) {
		report.Warnings = append(report.Warnings, fmt.Sprintf(format, args...))
	}

	index, err := catalog.LoadCatalogIndex(catalogPath)
	if err != nil {
		addError("%s", err.Error())
		report.finish()
		return report
	}
	if err := catalog.ValidateCatalogIndex(index); err != nil {
		addError("index.json: %v", err)
	}

	validateIndexSchemaVersion(index, catalogValidateOpts.schemaVersion, addError)

	seen := map[string]bool{}
	for i, summary := range index.Images {
		if summary.ID == "" {
			addError("index images[%d]: missing id", i)
			continue
		}
		if seen[summary.ID] {
			addError("index images[%d] %q: duplicate image id", i, summary.ID)
			continue
		}
		seen[summary.ID] = true

		record, err := catalog.LoadImageRecord(catalogPath, summary.ID)
		if err != nil {
			addError("index image %q: %v", summary.ID, err)
			continue
		}
		report.ImageCount++
		validateImageSchemaVersion(record, catalogValidateOpts.schemaVersion, addError)
		validateCatalogRecord(catalogPath, index, summary, record, addError, addWarning)
	}

	report.finish()
	return report
}

func validateIndexSchemaVersion(index *catalog.CatalogIndex, requested string, addError func(string, ...any)) {
	if index.SchemaVersion != "" && index.SchemaVersion != catalog.CatalogIndexSchemaVersion {
		addError("index.json: unsupported schemaVersion %q", index.SchemaVersion)
	}
	if requested == "" {
		return
	}
	switch requested {
	case catalog.CatalogIndexSchemaVersion:
		if index.SchemaVersion != requested {
			addError("index.json: schemaVersion %s does not match requested %q", schemaVersionLabel(index.SchemaVersion), requested)
		}
	case catalog.ImageRecordSchemaVersion:
		// Checked against each image record as records are loaded.
	default:
		addError("unsupported schema version %q (known: %q, %q)", requested, catalog.CatalogIndexSchemaVersion, catalog.ImageRecordSchemaVersion)
	}
}

func validateImageSchemaVersion(record *catalog.ImageRecord, requested string, addError func(string, ...any)) {
	if record.SchemaVersion != "" && record.SchemaVersion != catalog.ImageRecordSchemaVersion {
		addError("%s: unsupported schemaVersion %q", record.ID, record.SchemaVersion)
	}
	if requested != catalog.ImageRecordSchemaVersion {
		return
	}
	if record.SchemaVersion != requested {
		addError("%s: schemaVersion %s does not match requested %q", record.ID, schemaVersionLabel(record.SchemaVersion), requested)
	}
}

func schemaVersionLabel(value string) string {
	if value == "" {
		return "<missing>"
	}
	return fmt.Sprintf("%q", value)
}

func validateCatalogRecord(catalogPath string, index *catalog.CatalogIndex, summary catalog.CatalogImageSummary, record *catalog.ImageRecord, addError, addWarning func(string, ...any)) {
	if record.ID != summary.ID {
		addError("%s: record id %q does not match index id %q", imageRecordLabel(catalogPath, summary.ID), record.ID, summary.ID)
	}
	if err := catalog.ValidateImageRecord(record); err != nil {
		addError("%s: %v", imageRecordLabel(catalogPath, summary.ID), err)
	}
	if len(record.Releases) == 0 {
		addError("%s: no releases", imageRecordLabel(catalogPath, summary.ID))
		return
	}

	var latest *catalog.ReleaseEntry
	for i := range record.Releases {
		rel := &record.Releases[i]
		validateCatalogRelease(record.ID, rel, addError, addWarning)
		if rel.Tag == summary.LatestTag || rel.Tag == index.LatestTag || rel.IsLatest {
			if latest == nil {
				latest = rel
			}
		}
	}
	if latest == nil {
		addError("%s: latest release %q is missing from image record", record.ID, summary.LatestTag)
		return
	}
	validateIndexEvidence(summary, latest, addError, addWarning)
	warnMissingOptionalEvidence(summary.ID, latest, addWarning)
}

func validateCatalogRelease(imageID string, rel *catalog.ReleaseEntry, addError, addWarning func(string, ...any)) {
	if rel.Tag == "" {
		addError("%s: release is missing tag", imageID)
	}
	if len(rel.Architectures) == 0 {
		addWarning("%s:%s: no architectures", imageID, rel.Tag)
	}
	for i := range rel.Architectures {
		arch := &rel.Architectures[i]
		label := fmt.Sprintf("%s:%s architectures[%d]", imageID, rel.Tag, i)
		if arch.Arch == "" {
			addError("%s: missing arch", label)
		}
		if arch.OS == "" {
			addError("%s: missing os", label)
		}
		validateCatalogPackages(label, arch.SBOM.Packages, addError)
		validateCatalogFindings(label, arch.Vulnerabilities, addError)
		warnLayerMapping(label, arch, addWarning)
	}
}

func validateCatalogPackages(label string, packages []catalog.PackageEntry, addError func(string, ...any)) {
	for i, pkg := range packages {
		prefix := fmt.Sprintf("%s sbom.packages[%d]", label, i)
		if pkg.Name == "" {
			addError("%s: missing name", prefix)
		}
		if pkg.Version == "" {
			addError("%s: missing version", prefix)
		}
		if pkg.SpdxID == "" {
			addError("%s: missing spdxId", prefix)
		}
	}
}

func validateCatalogFindings(label string, vuln *catalog.VulnerabilitiesInfo, addError func(string, ...any)) {
	if vuln == nil {
		return
	}
	for i, finding := range vuln.Findings {
		prefix := fmt.Sprintf("%s vulnerabilities.findings[%d]", label, i)
		if finding.ID == "" {
			addError("%s: missing id", prefix)
		}
		if finding.Severity == "" {
			addError("%s: missing severity", prefix)
		}
		if finding.PackageName == "" {
			addError("%s: missing packageName", prefix)
		}
		if finding.PackageVersion == "" {
			addError("%s: missing packageVersion", prefix)
		}
	}
}

func validateIndexEvidence(summary catalog.CatalogImageSummary, rel *catalog.ReleaseEntry, addError, addWarning func(string, ...any)) {
	evidence := releaseEvidenceSummary(rel)
	for _, pair := range []struct {
		key      string
		summaryV bool
		relV     bool
	}{
		{"signed", summary.Signed, evidence.Signature},
		{"provenance", summary.Provenance, evidence.Provenance},
	} {
		if pair.summaryV != pair.relV {
			addError("%s: index %s=%t but latest release evidence=%t", summary.ID, pair.key, pair.summaryV, pair.relV)
		}
	}
	if summary.Evidence == nil {
		addWarning("%s: index summary is missing evidence object", summary.ID)
		return
	}
	for _, pair := range []struct {
		key      string
		summaryV bool
		relV     bool
	}{
		{"signature", summary.Evidence.Signature, evidence.Signature},
		{"provenance", summary.Evidence.Provenance, evidence.Provenance},
		{"sbom", summary.Evidence.SBOM, evidence.SBOM},
		{"tests", summary.Evidence.Tests, evidence.Tests},
		{"vulnerabilities", summary.Evidence.Vulnerabilities, evidence.Vulnerabilities},
	} {
		if pair.summaryV != pair.relV {
			addError("%s: index evidence.%s=%t but latest release evidence=%t", summary.ID, pair.key, pair.summaryV, pair.relV)
		}
	}
}

func warnMissingOptionalEvidence(imageID string, rel *catalog.ReleaseEntry, addWarning func(string, ...any)) {
	evidence := releaseEvidenceSummary(rel)
	if !evidence.Signature {
		addWarning("%s:%s: missing signature evidence", imageID, rel.Tag)
	}
	if !evidence.Provenance {
		addWarning("%s:%s: missing provenance evidence", imageID, rel.Tag)
	}
	if !evidence.SBOM {
		addWarning("%s:%s: missing or incomplete SBOM evidence (%d/%d architectures)", imageID, rel.Tag, evidence.SBOMArchCount, evidence.ArchCount)
	}
	if !evidence.Vulnerabilities {
		addWarning("%s:%s: missing or incomplete vulnerability scans (%d/%d architectures)", imageID, rel.Tag, evidence.VulnerabilityArchCount, evidence.ArchCount)
	}
}

func warnLayerMapping(label string, arch *catalog.ArchPayload, addWarning func(string, ...any)) {
	if len(arch.Layers) == 0 || len(arch.SBOM.Packages) == 0 {
		return
	}
	for _, pkg := range arch.SBOM.Packages {
		if pkg.LayerDigest != nil && *pkg.LayerDigest != "" {
			return
		}
	}
	addWarning("%s: layers and packages are present but package layerDigest mapping is unavailable", label)
}

func imageRecordLabel(catalogPath, imageID string) string {
	return filepath.Join(catalogPath, "images", imageID+".json")
}

func (r *catalogValidationReport) finish() {
	sort.Strings(r.Errors)
	sort.Strings(r.Warnings)
	r.ErrorCount = len(r.Errors)
	r.WarningCount = len(r.Warnings)
}
