package commands

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/northcutted/clearcutt/internal/catalog"
	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

type certifyFlags struct {
	base             string
	requireSignature bool
	requireSbom      bool
	requireProv      bool
	policyFile       string
}

var certifyOpts certifyFlags

type CertificationPolicyDoc struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Base struct {
			AllowedImages       []string `json:"allowedImages"`
			RequireDigestPinned bool     `json:"requireDigestPinned"`
			RequireKnownBase    bool     `json:"requireKnownBase"`
		} `json:"base"`
		SupplyChain struct {
			RequireSignature  bool `json:"requireSignature"`
			RequireProvenance bool `json:"requireProvenance"`
			RequireSbom       bool `json:"requireSbom"`
			MinimumSlsaLevel  int  `json:"minimumSlsaLevel"`
		} `json:"supplyChain"`
		Runtime struct {
			RequireNonRoot        bool `json:"requireNonRoot"`
			ForbidShell           bool `json:"forbidShell"`
			ForbidPackageManagers bool `json:"forbidPackageManagers"`
			ForbidDevTier         bool `json:"forbidDevTier"`
		} `json:"runtime"`
		Lifecycle struct {
			AllowPreview      bool `json:"allowPreview"`
			AllowDeprecated   bool `json:"allowDeprecated"`
			AllowExperimental bool `json:"allowExperimental"`
		} `json:"lifecycle"`
		Vulnerabilities struct {
			MaxCritical     int    `json:"maxCritical"`
			MaxHigh         int    `json:"maxHigh"`
			AllowExceptions bool   `json:"allowExceptions"`
			ExceptionFile   string `json:"exceptionFile"`
		} `json:"vulnerabilities"`
	} `json:"spec"`
}

type CertifyCheckResult struct {
	ID      string `json:"id"`
	Status  string `json:"status"` // pass, fail, or skip
	Message string `json:"message"`
}

type CertifyResponse struct {
	Status string               `json:"status"` // pass or fail
	Image  string               `json:"image"`
	Checks []CertifyCheckResult `json:"checks"`
}

// DockerManifest represents the legacy `docker save` manifest.json structure.
type DockerManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// ociDescriptor is the subset of an OCI content descriptor we need to walk an
// OCI-layout image archive (index.json -> manifest -> config/layers).
type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type ociIndex struct {
	Manifests []ociDescriptor `json:"manifests"`
}

type ociManifest struct {
	Config ociDescriptor   `json:"config"`
	Layers []ociDescriptor `json:"layers"`
}

// OCIImageConfig represents standard OCI runtime configuration metadata.
type OCIImageConfig struct {
	Config struct {
		User       string            `json:"User"`
		WorkingDir string            `json:"WorkingDir"`
		Env        []string          `json:"Env"`
		Entrypoint []string          `json:"Entrypoint"`
		Cmd        []string          `json:"Cmd"`
		Labels     map[string]string `json:"Labels"`
	} `json:"config"`
}

// tarImage holds the resolved pieces of an image tarball, abstracting over the
// legacy docker-save and OCI-layout on-disk formats.
type tarImage struct {
	format     string   // "docker", "oci", or "" when unrecognized
	configRaw  []byte   // OCI image config JSON
	repoTags   []string // best-effort image references
	layerPaths []string // temp-file paths of layer blobs (may be gzip-compressed)
}

func NewCertifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certify <tarball-path>",
		Short: "Certify a downstream application image against platform security contracts",
		Long: `Unpacks and parses local OCI/Docker image tarballs completely offline to verify
non-root users, shell-free distroless tiers, and required OCI labels. Supports both
legacy 'docker save' archives and OCI-layout archives. Supply-chain attestations
(signature, SBOM, provenance) live as registry referrers and cannot be verified
from an offline tarball; those checks are reported as skipped with guidance.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCertify(args[0])
		},
	}

	cmd.Flags().StringVar(&certifyOpts.base, "base", "", "Optional ClearCutt base image ID the app claims to derive from (e.g. java21-distroless)")
	cmd.Flags().BoolVar(&certifyOpts.requireSignature, "require-signature", false, "Require signed attestations to exist for downstream image layers")
	cmd.Flags().BoolVar(&certifyOpts.requireSbom, "require-sbom", false, "Require SPDX SBOM attachments to exist for downstream image layers")
	cmd.Flags().BoolVar(&certifyOpts.requireProv, "require-provenance", false, "Require SLSA Level-3 build provenance attestations")
	cmd.Flags().StringVar(&certifyOpts.policyFile, "policy", "", "Path to local declarative certification-policy.yaml file")

	return cmd
}

func runCertify(tarPath string) error {
	checks := []CertifyCheckResult{}
	hasFailures := false
	skipped := 0

	addCheck := func(id, status, message string) {
		checks = append(checks, CertifyCheckResult{ID: id, Status: status, Message: message})
		switch status {
		case "fail":
			hasFailures = true
		case "skip":
			skipped++
		}
	}

	var policy *CertificationPolicyDoc
	reqSig := certifyOpts.requireSignature
	reqSbom := certifyOpts.requireSbom
	reqProv := certifyOpts.requireProv
	baseID := certifyOpts.base

	if certifyOpts.policyFile != "" {
		data, err := os.ReadFile(certifyOpts.policyFile)
		if err != nil {
			return fmt.Errorf("failed to read policy file: %w", err)
		}
		var p CertificationPolicyDoc
		if err := yaml.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("failed to parse policy YAML: %w", err)
		}
		if p.APIVersion != "clearcutt.dev/v1" {
			return fmt.Errorf("invalid certification policy apiVersion: %q (expected clearcutt.dev/v1)", p.APIVersion)
		}
		if p.Kind != "CertificationPolicy" {
			return fmt.Errorf("invalid certification policy kind: %q (expected CertificationPolicy)", p.Kind)
		}
		policy = &p
		reqSig = policy.Spec.SupplyChain.RequireSignature
		reqSbom = policy.Spec.SupplyChain.RequireSbom
		reqProv = policy.Spec.SupplyChain.RequireProvenance
	}

	tempDir, err := os.MkdirTemp("", "clearcutt-certify-*")
	if err != nil {
		return fmt.Errorf("failed to create temp workspace: %w", err)
	}
	defer os.RemoveAll(tempDir)

	img, err := loadImageTarball(tarPath, tempDir)
	if err != nil {
		return err
	}

	switch img.format {
	case "docker":
		addCheck("manifest.parsed", "pass", "Parsed legacy docker-save image manifest")
	case "oci":
		addCheck("manifest.parsed", "pass", "Parsed OCI-layout image index and manifest")
	default:
		addCheck("manifest.parsed", "fail", "Unrecognized image archive: expected a docker-save manifest.json or an OCI-layout index.json")
	}

	if len(img.configRaw) > 0 {
		var config OCIImageConfig
		if err := json.Unmarshal(img.configRaw, &config); err != nil {
			addCheck("config.parsed", "fail", fmt.Sprintf("Failed to parse OCI config JSON structure: %v", err))
		} else {
			addCheck("config.parsed", "pass", "Successfully parsed OCI image configuration specs")

			// Check 1: Rootless execution (Config.User)
			user := strings.TrimSpace(config.Config.User)
			switch {
			case user == "":
				addCheck("config.user.nonroot", "fail", "Security Violation: Config.User is not specified (defaults to root/UID 0)")
			case user == "0" || user == "root" || strings.HasPrefix(user, "0:") || strings.HasPrefix(user, "root:"):
				addCheck("config.user.nonroot", "fail", fmt.Sprintf("Security Violation: Config.User executes under root privilege -> %s", user))
			default:
				addCheck("config.user.nonroot", "pass", fmt.Sprintf("Unprivileged non-root operator boundaries verified: User %s", user))
			}

			// Check 2: OCI standard labels
			hasCompliantLabel := false
			for k := range config.Config.Labels {
				if strings.HasPrefix(k, "org.opencontainers.image.") || strings.HasPrefix(k, "org.clearcutt.") {
					hasCompliantLabel = true
					break
				}
			}
			if hasCompliantLabel {
				addCheck("config.labels.compliance", "pass", "Corporate engineering compliance metadata labels are present")
			} else {
				addCheck("config.labels.compliance", "fail", "Compliance Notice: Image lacks required org.opencontainers.image compliance labels")
			}
		}
	} else if img.format != "" {
		addCheck("config.parsed", "fail", "OCI image configuration blob was not found in the tarball archive")
	}

	// Check 3: Shell & package-manager audits, only when the claimed base is distroless.
	isDistroless := false
	if baseID != "" {
		if strings.Contains(baseID, "distroless") {
			isDistroless = true
		} else if record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, baseID); err == nil && record.Tier.ID == "distroless" {
			isDistroless = true
		}
	}

	if isDistroless {
		shellsFound := []string{}
		packageManagersFound := []string{}
		scanErrors := 0

		for _, layerPath := range img.layerPaths {
			shells, pkgs, err := scanLayerForRuntimeTools(layerPath)
			if err != nil {
				scanErrors++
				continue
			}
			shellsFound = append(shellsFound, shells...)
			packageManagersFound = append(packageManagersFound, pkgs...)
		}

		// If we couldn't read any layer, don't claim a clean result we didn't verify.
		if scanErrors > 0 && scanErrors == len(img.layerPaths) {
			addCheck("contract.shell.absence", "skip", "Could not read any image layers (unsupported layer encoding); shell audit not performed")
			addCheck("contract.package_manager.absence", "skip", "Could not read any image layers (unsupported layer encoding); package-manager audit not performed")
		} else {
			if len(shellsFound) > 0 {
				addCheck("contract.shell.absence", "fail", fmt.Sprintf("Security Violation: Distroless contract broken. Shell binaries found: %s", strings.Join(shellsFound, ", ")))
			} else {
				addCheck("contract.shell.absence", "pass", "Verified absence of interactive shell tools inside distroless closure")
			}
			if len(packageManagersFound) > 0 {
				addCheck("contract.package_manager.absence", "fail", fmt.Sprintf("Security Violation: Package manager tools found: %s", strings.Join(packageManagersFound, ", ")))
			} else {
				addCheck("contract.package_manager.absence", "pass", "Verified absence of package manager tools inside runtime boundary")
			}
		}
	} else if baseID != "" {
		addCheck("contract.shell.absence", "skip", "Base image tier is not distroless; shell audit not applicable")
		addCheck("contract.package_manager.absence", "skip", "Base image tier is not distroless; package-manager audit not applicable")
	}

	// Supply-chain attestations are OCI referrers in a registry, not contents of an
	// offline tarball. We cannot verify them here, so when required we mark them
	// skipped with guidance rather than asserting a result we did not check.
	const attestationGuidance = "verify against the registry with `cosign verify` / `cosign verify-attestation`"
	if reqSig {
		addCheck("evidence.signature.verified", "skip", "Signature is a registry referrer and cannot be verified from an offline tarball; "+attestationGuidance)
	}
	if reqSbom {
		addCheck("evidence.sbom.present", "skip", "SBOM attestation is a registry referrer and cannot be verified from an offline tarball; "+attestationGuidance)
	}
	if reqProv {
		addCheck("evidence.provenance.present", "skip", "SLSA provenance is a registry referrer and cannot be verified from an offline tarball; "+attestationGuidance)
	}

	// Declarative certification policy enforcement.
	if policy != nil {
		// 1. Allowed base images.
		if len(policy.Spec.Base.AllowedImages) > 0 {
			allowed := false
			for _, candidate := range policy.Spec.Base.AllowedImages {
				if candidate == baseID {
					allowed = true
					break
				}
			}
			if allowed {
				addCheck("policy.base.allowed", "pass", fmt.Sprintf("Base image %q is in approved allowedImages list", baseID))
			} else {
				addCheck("policy.base.allowed", "fail", fmt.Sprintf("Security Violation: Base image %q is not allowed by this policy", baseID))
			}
		}

		// 2. Digest pinning, evaluated against the image's own references.
		if policy.Spec.Base.RequireDigestPinned {
			isDigestPinned := strings.Contains(baseID, "@sha256:")
			for _, ref := range img.repoTags {
				if strings.Contains(ref, "@sha256:") {
					isDigestPinned = true
					break
				}
			}
			if isDigestPinned {
				addCheck("policy.base.digestPinned", "pass", "Container image reference is digest-pinned")
			} else {
				addCheck("policy.base.digestPinned", "fail", "Security Violation: Image reference must be digest-pinned for production deployment")
			}
		}

		// 3. Minimum SLSA level cannot be determined from an offline tarball.
		if policy.Spec.SupplyChain.MinimumSlsaLevel > 0 {
			addCheck("policy.supplychain.slsaLevel", "skip", fmt.Sprintf("SLSA level requires the provenance attestation from the registry; cannot confirm >= %d offline", policy.Spec.SupplyChain.MinimumSlsaLevel))
		}

		// 4. Vulnerability gating against the declared base image's catalog record.
		if policy.Spec.Vulnerabilities.MaxCritical >= 0 || policy.Spec.Vulnerabilities.MaxHigh >= 0 {
			certifyVulnGate(policy, baseID, addCheck)
		}
	}

	overallStatus := "pass"
	if hasFailures {
		overallStatus = "fail"
	}

	response := CertifyResponse{
		Status: overallStatus,
		Image:  filepath.Base(tarPath),
		Checks: checks,
	}

	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		if err := output.PrintJSON(out, response); err != nil {
			return err
		}
	case "yaml", "yml":
		if err := output.PrintYAML(out, response); err != nil {
			return err
		}
	default:
		fmt.Fprintf(out, "Downstream Security Certification Report for %s\n", filepath.Base(tarPath))
		fmt.Fprintln(out, "-----------------------------------------------------------------")
		for _, check := range checks {
			statusSymbol := "✔ PASS"
			switch check.Status {
			case "fail":
				statusSymbol = "✘ FAIL"
			case "skip":
				statusSymbol = "↷ SKIP"
			}
			fmt.Fprintf(out, "[%-6s] %-32s : %s\n", statusSymbol, check.ID, check.Message)
		}
		fmt.Fprintln(out, "-----------------------------------------------------------------")
		switch {
		case hasFailures:
			fmt.Fprintln(out, "Certification Result: FAIL")
		case skipped > 0:
			fmt.Fprintf(out, "Certification Result: PASS (%d check(s) skipped — see guidance above)\n", skipped)
		default:
			fmt.Fprintln(out, "Certification Result: PASS")
		}
	}

	if hasFailures {
		return ErrCheckFailed
	}

	return nil
}

// certifyVulnGate enforces the policy's critical/high thresholds against the
// declared base image's catalog record, honoring active vulnerability exceptions.
func certifyVulnGate(policy *CertificationPolicyDoc, baseID string, addCheck func(id, status, message string)) {
	record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, baseID)
	if err != nil {
		return
	}
	release, err := latestOrTaggedRelease(record.Releases, "")
	if err != nil {
		return
	}

	var exceptionsDoc *ExceptionsDoc
	if policy.Spec.Vulnerabilities.AllowExceptions && policy.Spec.Vulnerabilities.ExceptionFile != "" {
		if doc, err := LoadExceptionsFile(policy.Spec.Vulnerabilities.ExceptionFile); err == nil {
			exceptionsDoc = doc
		}
	}

	now := time.Now().UTC()
	maxCritFound, maxHighFound := 0, 0
	critExceeded, highExceeded := false, false

	for _, arch := range release.Architectures {
		if arch.Vulnerabilities == nil {
			continue
		}
		criticalCount, highCount := 0, 0
		for _, finding := range arch.Vulnerabilities.Findings {
			if entry, expired := exceptionsDoc.Match(finding.ID, finding.PackageName, baseID, release.Tag, now); entry != nil && !expired {
				continue
			}
			switch strings.ToLower(finding.Severity) {
			case "critical":
				criticalCount++
			case "high":
				highCount++
			}
		}
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
		if policy.Spec.Vulnerabilities.MaxCritical >= 0 && criticalCount > policy.Spec.Vulnerabilities.MaxCritical {
			critExceeded = true
		}
		if policy.Spec.Vulnerabilities.MaxHigh >= 0 && highCount > policy.Spec.Vulnerabilities.MaxHigh {
			highExceeded = true
		}
	}

	if policy.Spec.Vulnerabilities.MaxCritical >= 0 {
		if critExceeded {
			addCheck("policy.vulnerabilities.critical", "fail", fmt.Sprintf("Critical vulnerabilities count %d exceeds policy limit %d", maxCritFound, policy.Spec.Vulnerabilities.MaxCritical))
		} else {
			addCheck("policy.vulnerabilities.critical", "pass", fmt.Sprintf("Critical vulnerabilities count %d is within policy limit %d", maxCritFound, policy.Spec.Vulnerabilities.MaxCritical))
		}
	}
	if policy.Spec.Vulnerabilities.MaxHigh >= 0 {
		if highExceeded {
			addCheck("policy.vulnerabilities.high", "fail", fmt.Sprintf("High vulnerabilities count %d exceeds policy limit %d", maxHighFound, policy.Spec.Vulnerabilities.MaxHigh))
		} else {
			addCheck("policy.vulnerabilities.high", "pass", fmt.Sprintf("High vulnerabilities count %d is within policy limit %d", maxHighFound, policy.Spec.Vulnerabilities.MaxHigh))
		}
	}
}

// loadImageTarball extracts every regular file from an image tarball into tempDir
// and resolves the image config and layer blobs for either a legacy docker-save
// archive (manifest.json) or an OCI-layout archive (index.json + blobs/). Files are
// stored under opaque names, so crafted entry paths cannot escape tempDir.
func loadImageTarball(tarPath, tempDir string) (*tarImage, error) {
	file, err := os.Open(tarPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open image file: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file
	if strings.HasSuffix(tarPath, ".gz") || strings.HasSuffix(tarPath, ".tgz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize gzip reader: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	entries := map[string]string{} // cleaned tar entry name -> temp file path
	tr := tar.NewReader(reader)
	idx := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading tar archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		dest := filepath.Join(tempDir, fmt.Sprintf("e%06d", idx))
		idx++
		df, err := os.Create(dest)
		if err != nil {
			return nil, fmt.Errorf("failed to stage tar entry: %w", err)
		}
		if _, err := io.Copy(df, tr); err != nil {
			df.Close()
			return nil, fmt.Errorf("failed to stage tar entry %q: %w", name, err)
		}
		df.Close()
		entries[name] = dest
	}

	img := &tarImage{}

	// Legacy docker-save: manifest.json at the archive root.
	if p, ok := entries["manifest.json"]; ok {
		if data, err := os.ReadFile(p); err == nil {
			var manifests []DockerManifest
			if err := json.Unmarshal(data, &manifests); err == nil && len(manifests) > 0 {
				img.format = "docker"
				img.repoTags = manifests[0].RepoTags
				if cp, ok := entries[path.Clean(manifests[0].Config)]; ok {
					img.configRaw, _ = os.ReadFile(cp)
				}
				for _, layer := range manifests[0].Layers {
					if lp, ok := entries[path.Clean(layer)]; ok {
						img.layerPaths = append(img.layerPaths, lp)
					}
				}
				return img, nil
			}
		}
	}

	// OCI-layout: index.json referencing blobs/sha256/<hex>.
	if p, ok := entries["index.json"]; ok {
		img.format = "oci"
		resolveOCIImage(entries, p, img)
		return img, nil
	}

	return img, nil // format == "" -> unrecognized
}

// resolveOCIImage walks index.json -> manifest -> {config, layers}, descending one
// level when the index points at a nested image index (multi-arch).
func resolveOCIImage(entries map[string]string, indexPath string, img *tarImage) {
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return
	}
	var index ociIndex
	if err := json.Unmarshal(data, &index); err != nil || len(index.Manifests) == 0 {
		return
	}

	desc := index.Manifests[0]
	if ref, ok := desc.Annotations["org.opencontainers.image.ref.name"]; ok {
		img.repoTags = append(img.repoTags, ref)
	}

	manData := readBlob(entries, desc.Digest)
	if manData == nil {
		return
	}
	var man ociManifest
	if err := json.Unmarshal(manData, &man); err != nil {
		return
	}
	// Nested index (manifest list) -> pick the first concrete manifest.
	if man.Config.Digest == "" && len(man.Layers) == 0 {
		var nested ociIndex
		if err := json.Unmarshal(manData, &nested); err == nil && len(nested.Manifests) > 0 {
			if inner := readBlob(entries, nested.Manifests[0].Digest); inner != nil {
				_ = json.Unmarshal(inner, &man)
			}
		}
	}

	img.configRaw = readBlob(entries, man.Config.Digest)
	for _, layer := range man.Layers {
		if lp := blobPath(entries, layer.Digest); lp != "" {
			img.layerPaths = append(img.layerPaths, lp)
		}
	}
}

// blobPath maps an OCI digest (sha256:hex) to the staged blob file path.
func blobPath(entries map[string]string, digest string) string {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	if p, ok := entries["blobs/"+parts[0]+"/"+parts[1]]; ok {
		return p
	}
	return ""
}

func readBlob(entries map[string]string, digest string) []byte {
	p := blobPath(entries, digest)
	if p == "" {
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return data
}

// scanLayerForRuntimeTools inspects a single layer blob (transparently handling
// gzip-compressed layers) for interactive shells and package managers.
func scanLayerForRuntimeTools(layerPath string) (shells, pkgs []string, err error) {
	f, err := os.Open(layerPath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	br := bufio.NewReader(f)
	var reader io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, gerr := gzip.NewReader(br)
		if gerr != nil {
			return nil, nil, gerr
		}
		defer gz.Close()
		reader = gz
	}

	tr := tar.NewReader(reader)
	for {
		hdr, terr := tr.Next()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			return nil, nil, terr
		}
		name := strings.TrimPrefix(path.Clean(hdr.Name), "/")

		switch name {
		case "bin/sh", "bin/bash", "bin/ash", "bin/zsh",
			"usr/bin/sh", "usr/bin/bash", "usr/bin/ash", "usr/bin/zsh":
			shells = append(shells, name)
		case "sbin/apk", "usr/bin/apk", "usr/bin/apt", "usr/bin/apt-get",
			"usr/bin/dpkg", "usr/bin/dnf", "usr/bin/yum", "usr/bin/microdnf":
			pkgs = append(pkgs, name)
		}
	}
	return shells, pkgs, nil
}
