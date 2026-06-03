package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt/internal/catalog"
)

// catalog.go ports the catalog producer transforms from
// core/scripts/gather-catalog.mjs into Go (Phase 5). The producer structs below
// emit explicit null fields in the .mjs key order so the generated catalog JSON
// keeps its exact shape; they are intentionally distinct from the
// omitempty-tolerant *consumer* types in internal/catalog. The file carries the
// producer transforms shared by `clearcutt catalog gather` and
// `clearcutt catalog enrich`; command wiring lives in catalog_cmd.go.

// gatherLifecycle mirrors the lifecycle object the Node producer emits.
type gatherLifecycle struct {
	Status            string  `json:"status"`
	Support           string  `json:"support"`
	ProductionAllowed bool    `json:"productionAllowed"`
	DeprecatedAt      *string `json:"deprecatedAt"`
	EOLAt             *string `json:"eolAt"`
	Reason            *string `json:"reason"`
}

// gatherRuntimeContract mirrors the runtimeContract object the Node producer emits.
type gatherRuntimeContract struct {
	User                  string  `json:"user"`
	WorkingDir            string  `json:"workingDir"`
	ShellPresent          bool    `json:"shellPresent"`
	PackageManagerPresent bool    `json:"packageManagerPresent"`
	CACertificatesPresent bool    `json:"caCertificatesPresent"`
	TimezoneDataPresent   bool    `json:"timezoneDataPresent"`
	DefaultEntrypoint     *string `json:"defaultEntrypoint"`
	ProductionTier        bool    `json:"productionTier"`
}

func gatherStr(s string) *string { return &s }

// gatherLangKey strips the trailing tier segment from a target id, matching the
// `target.lastIndexOf('-')` split in gather-catalog.mjs.
func gatherLangKey(target string) string {
	if idx := strings.LastIndex(target, "-"); idx != -1 {
		return target[:idx]
	}
	return target
}

func determineLifecycle(target, tier string) gatherLifecycle {
	langKey := gatherLangKey(target)

	status, support, productionAllowed := "preview", "preview", false
	switch langKey {
	case "coreLTS", "java21", "node22", "dotnet8":
		status, support = "active", "lts"
		if tier != "dev" {
			productionAllowed = true
		}
	case "python3.13":
		status, support = "active", "current"
		if tier != "dev" {
			productionAllowed = true
		}
	case "java25", "node24", "python3.14", "dotnet10":
		status, support, productionAllowed = "preview", "preview", false
	case "go1.25", "go1.26", "rust1.95", "cc15":
		status, support, productionAllowed = "experimental", "unsupported", false
	}

	return gatherLifecycle{
		Status:            status,
		Support:           support,
		ProductionAllowed: productionAllowed,
	}
}

func determineRuntimeContract(target, tier string) gatherRuntimeContract {
	langKey := gatherLangKey(target)

	var entrypoint *string
	switch {
	case strings.HasPrefix(langKey, "java"):
		entrypoint = gatherStr("/usr/local/bin/java")
	case strings.HasPrefix(langKey, "node"):
		entrypoint = gatherStr("/usr/bin/node")
	case strings.HasPrefix(langKey, "python"):
		entrypoint = gatherStr("/usr/bin/python")
	case strings.HasPrefix(langKey, "go"):
		entrypoint = gatherStr("/usr/bin/go")
	case strings.HasPrefix(langKey, "dotnet"):
		entrypoint = gatherStr("/usr/bin/dotnet")
	case langKey == "coreLTS":
		entrypoint = gatherStr("/bin/sh")
	}

	shellPresent, packageManagerPresent, productionTier := true, true, false
	switch tier {
	case "slim":
		shellPresent, packageManagerPresent, productionTier = true, false, true
	case "distroless":
		shellPresent, packageManagerPresent, productionTier = false, false, true
	default:
		shellPresent, packageManagerPresent, productionTier = true, true, false
	}

	return gatherRuntimeContract{
		User:                  "10001",
		WorkingDir:            "/app",
		ShellPresent:          shellPresent,
		PackageManagerPresent: packageManagerPresent,
		CACertificatesPresent: true,
		TimezoneDataPresent:   true,
		DefaultEntrypoint:     entrypoint,
		ProductionTier:        productionTier,
	}
}

func defaultGatherExceptions() catalog.ExceptionSummary {
	return catalog.ExceptionSummary{}
}

// -- SPDX SBOM transforms ----------------------------------------------------

// SPDX input model (only the fields gather-catalog.mjs reads).
type spdxDoc struct {
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPkg          `json:"packages"`
	Files             []spdxFile         `json:"files"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Creators []string `json:"creators"`
	Created  string   `json:"created"`
}

type spdxPkg struct {
	SPDXID                string            `json:"SPDXID"`
	Name                  string            `json:"name"`
	VersionInfo           string            `json:"versionInfo"`
	Supplier              string            `json:"supplier"`
	LicenseDeclared       string            `json:"licenseDeclared"`
	LicenseConcluded      string            `json:"licenseConcluded"`
	SourceInfo            string            `json:"sourceInfo"`
	PrimaryPackagePurpose string            `json:"primaryPackagePurpose"`
	ExternalRefs          []spdxExternalRef `json:"externalRefs"`
	Checksums             []spdxChecksum    `json:"checksums"`
}

type spdxExternalRef struct {
	ReferenceType    string `json:"referenceType"`
	ReferenceLocator string `json:"referenceLocator"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxFile struct {
	SPDXID  string `json:"SPDXID"`
	Comment string `json:"comment"`
}

type spdxRelationship struct {
	RelationshipType   string `json:"relationshipType"`
	SpdxElementID      string `json:"spdxElementId"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
}

// spdxPackageOut mirrors the compacted package the Node producer emits (explicit
// nulls, fixed key order, empty cpes array rather than null).
type spdxPackageOut struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Purl         *string  `json:"purl"`
	Cpes         []string `json:"cpes"`
	License      string   `json:"license"`
	Supplier     string   `json:"supplier"`
	NixStorePath *string  `json:"nixStorePath"`
	SpdxID       string   `json:"spdxId"`
	LayerDigest  *string  `json:"layerDigest"`
}

var nixStorePathRe = regexp.MustCompile(`(/nix/store/[^\s]+)`)

func extractNixStorePath(sourceInfo string) *string {
	if sourceInfo == "" {
		return nil
	}
	if m := nixStorePathRe.FindString(sourceInfo); m != "" {
		return &m
	}
	return nil
}

func pickLicense(pkg spdxPkg) string {
	for _, c := range []string{pkg.LicenseDeclared, pkg.LicenseConcluded} {
		if c != "" && c != "NOASSERTION" {
			return c
		}
	}
	return "NOASSERTION"
}

func mapPackageIDToLayerDigest(spdx spdxDoc) map[string]string {
	fileToLayer := map[string]string{}
	for _, f := range spdx.Files {
		if strings.HasPrefix(f.Comment, "layerID: ") {
			fileToLayer[f.SPDXID] = strings.TrimSpace(strings.TrimPrefix(f.Comment, "layerID: "))
		}
	}
	packageToLayer := map[string]string{}
	for _, r := range spdx.Relationships {
		if r.RelationshipType == "OTHER" && r.SpdxElementID != "" && r.RelatedSpdxElement != "" {
			if digest, ok := fileToLayer[r.RelatedSpdxElement]; ok {
				packageToLayer[r.SpdxElementID] = digest
			}
		}
	}
	return packageToLayer
}

func compactPackages(spdx spdxDoc) []spdxPackageOut {
	packageToLayer := mapPackageIDToLayerDigest(spdx)
	items := []spdxPackageOut{}
	for _, p := range spdx.Packages {
		if p.PrimaryPackagePurpose == "CONTAINER" {
			continue
		}
		cpes := []string{}
		var purl *string
		for _, ref := range p.ExternalRefs {
			switch ref.ReferenceType {
			case "cpe23Type":
				cpes = append(cpes, ref.ReferenceLocator)
			case "purl":
				if purl == nil {
					loc := ref.ReferenceLocator
					purl = &loc
				}
			}
		}
		supplier := p.Supplier
		if supplier == "" {
			supplier = "NOASSERTION"
		}
		var layerDigest *string
		if d, ok := packageToLayer[p.SPDXID]; ok {
			layerDigest = &d
		}
		items = append(items, spdxPackageOut{
			Name:         p.Name,
			Version:      p.VersionInfo,
			Purl:         purl,
			Cpes:         cpes,
			License:      pickLicense(p),
			Supplier:     supplier,
			NixStorePath: extractNixStorePath(p.SourceInfo),
			SpdxID:       p.SPDXID,
			LayerDigest:  layerDigest,
		})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}

func rootDigest(spdx spdxDoc) *string {
	for _, p := range spdx.Packages {
		if p.PrimaryPackagePurpose != "CONTAINER" {
			continue
		}
		for _, c := range p.Checksums {
			if c.Algorithm == "SHA256" {
				d := "sha256:" + c.ChecksumValue
				return &d
			}
		}
		if strings.HasPrefix(p.VersionInfo, "sha256:") {
			v := p.VersionInfo
			return &v
		}
		return nil
	}
	return nil
}

// -- in-toto / SLSA provenance summarization ---------------------------------

type provenanceOut struct {
	PredicateType  string     `json:"predicateType"`
	Builder        builderOut `json:"builder"`
	BuildType      *string    `json:"buildType"`
	SourceURI      *string    `json:"sourceUri"`
	SourceRevision *string    `json:"sourceRevision"`
	SlsaLevel      int        `json:"slsaLevel"`
}

type builderOut struct {
	ID string `json:"id"`
}

type intotoLine struct {
	DsseEnvelope *struct {
		Payload string `json:"payload"`
	} `json:"dsseEnvelope"`
	Payload       string          `json:"payload"`
	PredicateType string          `json:"predicateType"`
	Raw           json.RawMessage `json:"-"`
}

type intotoStatement struct {
	PredicateType string          `json:"predicateType"`
	Predicate     intotoPredicate `json:"predicate"`
}

type intotoPredicate struct {
	Builder         *intotoBuilder         `json:"builder"`
	RunDetails      *intotoRunDetails      `json:"runDetails"`
	BuildType       string                 `json:"buildType"`
	BuildDefinition *intotoBuildDefinition `json:"buildDefinition"`
	Invocation      *intotoInvocation      `json:"invocation"`
	Materials       []intotoDependency     `json:"materials"`
}

type intotoBuilder struct {
	ID string `json:"id"`
}

type intotoRunDetails struct {
	Builder *intotoBuilder `json:"builder"`
}

type intotoBuildDefinition struct {
	BuildType            string                `json:"buildType"`
	ExternalParameters   *intotoExternalParams `json:"externalParameters"`
	ResolvedDependencies []intotoDependency    `json:"resolvedDependencies"`
}

type intotoExternalParams struct {
	Workflow  *intotoWorkflow `json:"workflow"`
	Source    *intotoSource   `json:"source"`
	SourceURI string          `json:"sourceUri"`
}

type intotoWorkflow struct {
	Repository string `json:"repository"`
}

type intotoSource struct {
	URI    string        `json:"uri"`
	Digest *intotoDigest `json:"digest"`
}

type intotoInvocation struct {
	ConfigSource *intotoSource `json:"configSource"`
}

type intotoDependency struct {
	URI    string        `json:"uri"`
	Digest *intotoDigest `json:"digest"`
}

type intotoDigest struct {
	Sha1      string `json:"sha1"`
	GitCommit string `json:"gitCommit"`
}

func decodeIntotoPayload(line []byte) *intotoStatement {
	var env intotoLine
	if err := json.Unmarshal(line, &env); err != nil {
		return nil
	}
	payloadB64 := env.Payload
	if env.DsseEnvelope != nil {
		payloadB64 = env.DsseEnvelope.Payload
	}
	if payloadB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(payloadB64)
		if err != nil {
			return nil
		}
		var stmt intotoStatement
		if err := json.Unmarshal(decoded, &stmt); err != nil {
			return nil
		}
		return &stmt
	}
	if env.PredicateType != "" {
		var stmt intotoStatement
		if err := json.Unmarshal(line, &stmt); err != nil {
			return nil
		}
		return &stmt
	}
	return nil
}

func firstGitDependency(pred intotoPredicate) *intotoDependency {
	deps := pred.Materials
	if pred.BuildDefinition != nil && len(pred.BuildDefinition.ResolvedDependencies) > 0 {
		deps = pred.BuildDefinition.ResolvedDependencies
	}
	for i := range deps {
		if strings.Contains(deps[i].URI, "github.com") {
			return &deps[i]
		}
	}
	return nil
}

func summarizeIntotoStatement(stmt intotoStatement) provenanceOut {
	predicateType := stmt.PredicateType
	if predicateType == "" {
		predicateType = "unknown"
	}
	out := provenanceOut{PredicateType: predicateType, Builder: builderOut{ID: "unknown"}, SlsaLevel: 3}
	pred := stmt.Predicate

	var buildDef intotoBuildDefinition
	if pred.BuildDefinition != nil {
		buildDef = *pred.BuildDefinition
	}
	var workflow intotoWorkflow
	if buildDef.ExternalParameters != nil && buildDef.ExternalParameters.Workflow != nil {
		workflow = *buildDef.ExternalParameters.Workflow
	}
	var configSource *intotoSource
	if pred.Invocation != nil && pred.Invocation.ConfigSource != nil {
		configSource = pred.Invocation.ConfigSource
	} else if buildDef.ExternalParameters != nil {
		configSource = buildDef.ExternalParameters.Source
	}
	gitDep := firstGitDependency(pred)

	// builder.id: pred.builder.id || pred.runDetails.builder.id || unknown
	if pred.Builder != nil && pred.Builder.ID != "" {
		out.Builder.ID = pred.Builder.ID
	} else if pred.RunDetails != nil && pred.RunDetails.Builder != nil && pred.RunDetails.Builder.ID != "" {
		out.Builder.ID = pred.RunDetails.Builder.ID
	}

	out.BuildType = firstNonEmptyPtr(pred.BuildType, buildDef.BuildType)

	sourceURI := ""
	if configSource != nil {
		sourceURI = configSource.URI
	}
	sourceURI = firstNonEmptyStr(sourceURI, workflow.Repository)
	if buildDef.ExternalParameters != nil {
		sourceURI = firstNonEmptyStr(sourceURI, buildDef.ExternalParameters.SourceURI)
	}
	if gitDep != nil {
		sourceURI = firstNonEmptyStr(sourceURI, gitDep.URI)
	}
	out.SourceURI = ptrIfNotEmpty(sourceURI)

	sourceRev := ""
	if configSource != nil && configSource.Digest != nil {
		sourceRev = firstNonEmptyStr(configSource.Digest.Sha1, configSource.Digest.GitCommit)
	}
	if buildDef.ExternalParameters != nil && buildDef.ExternalParameters.Source != nil && buildDef.ExternalParameters.Source.Digest != nil {
		d := buildDef.ExternalParameters.Source.Digest
		sourceRev = firstNonEmptyStr(sourceRev, d.Sha1, d.GitCommit)
	}
	if gitDep != nil && gitDep.Digest != nil {
		sourceRev = firstNonEmptyStr(sourceRev, gitDep.Digest.GitCommit, gitDep.Digest.Sha1)
	}
	out.SourceRevision = ptrIfNotEmpty(sourceRev)

	return out
}

func isUsefulProvenanceSummary(p provenanceOut) bool {
	return p.PredicateType != "unknown" || p.Builder.ID != "unknown" ||
		p.BuildType != nil || p.SourceURI != nil || p.SourceRevision != nil
}

func summarizeProvenance(intotoJSONL string) provenanceOut {
	fallback := provenanceOut{PredicateType: "unknown", Builder: builderOut{ID: "unknown"}, SlsaLevel: 3}
	var best *provenanceOut
	for _, line := range strings.Split(intotoJSONL, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		stmt := decodeIntotoPayload([]byte(line))
		if stmt == nil {
			continue
		}
		summary := summarizeIntotoStatement(*stmt)
		if strings.Contains(summary.PredicateType, "slsa.dev/provenance") {
			return summary
		}
		if best == nil && isUsefulProvenanceSummary(summary) {
			s := summary
			best = &s
		}
	}
	if best != nil {
		return *best
	}
	return fallback
}

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func ptrIfNotEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func firstNonEmptyPtr(values ...string) *string {
	return ptrIfNotEmpty(firstNonEmptyStr(values...))
}

// -- catalog image/index assembly --------------------------------------------

type gatherLanguageDef struct {
	ID      string
	Display string
	Version string
}

type gatherTierDef struct {
	Name  string
	Blurb string
}

var gatherLanguageOrder = []string{
	"coreLTS",
	"java21",
	"java25",
	"node22",
	"node24",
	"python3.13",
	"python3.14",
	"go1.25",
	"go1.26",
	"dotnet8",
	"dotnet10",
	"rust1.95",
	"cc15",
}

var gatherLanguages = map[string]gatherLanguageDef{
	"coreLTS":    {ID: "core", Display: "Core", Version: "LTS"},
	"java21":     {ID: "java", Display: "Java", Version: "21"},
	"java25":     {ID: "java", Display: "Java", Version: "25"},
	"node22":     {ID: "node", Display: "Node.js", Version: "22"},
	"node24":     {ID: "node", Display: "Node.js", Version: "24"},
	"python3.13": {ID: "python", Display: "Python", Version: "3.13"},
	"python3.14": {ID: "python", Display: "Python", Version: "3.14"},
	"go1.25":     {ID: "go", Display: "Go", Version: "1.25"},
	"go1.26":     {ID: "go", Display: "Go", Version: "1.26"},
	"dotnet8":    {ID: "dotnet", Display: ".NET", Version: "8"},
	"dotnet10":   {ID: "dotnet", Display: ".NET", Version: "10"},
	"rust1.95":   {ID: "rust", Display: "Rust", Version: "1.95"},
	"cc15":       {ID: "cc", Display: "C/C++", Version: "15"},
}

var gatherTierOrder = []string{"dev", "slim", "distroless"}

var gatherTiers = map[string]gatherTierDef{
	"dev":        {Name: "Dev", Blurb: "Builder tier — full toolchain, shells, debug utilities, credential helper."},
	"slim":       {Name: "Slim", Blurb: "Runtime tier — language runtime plus minimal troubleshooting binaries."},
	"distroless": {Name: "Distroless", Blurb: "Hardened tier — no shells, no coreutils, runtime only."},
}

type gatherLanguageOut struct {
	ID          string  `json:"id"`
	DisplayName string  `json:"displayName"`
	Version     string  `json:"version"`
	Icon        *string `json:"icon"`
}

type gatherTierOut struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Blurb string `json:"blurb"`
}

type gatherImageRecord struct {
	ID              string                `json:"id"`
	Language        gatherLanguageOut     `json:"language"`
	Tier            gatherTierOut         `json:"tier"`
	Registry        string                `json:"registry"`
	ImageName       string                `json:"imageName"`
	FullName        string                `json:"fullName"`
	Releases        []gatherReleaseEntry  `json:"releases"`
	Lifecycle       gatherLifecycle       `json:"lifecycle"`
	RuntimeContract gatherRuntimeContract `json:"runtimeContract"`
}

type gatherReleaseEntry struct {
	Tag             string                   `json:"tag"`
	PublishedAt     string                   `json:"publishedAt"`
	LastRebuiltAt   string                   `json:"lastRebuiltAt"`
	IsLatest        bool                     `json:"isLatest"`
	ManifestDigest  *string                  `json:"manifestDigest"`
	TotalSize       *int64                   `json:"totalSize"`
	Architectures   []gatherArchPayload      `json:"architectures"`
	Signature       *gatherSignature         `json:"signature"`
	Provenance      *provenanceOut           `json:"provenance"`
	Attestations    []gatherAttestation      `json:"attestations"`
	AssetURLs       gatherAssetURLs          `json:"assetUrls"`
	Lifecycle       gatherLifecycle          `json:"lifecycle"`
	RuntimeContract gatherRuntimeContract    `json:"runtimeContract"`
	Exceptions      catalog.ExceptionSummary `json:"exceptions"`
	Evidence        catalog.EvidenceSummary  `json:"evidence"`
}

type gatherArchPayload struct {
	Arch            string                       `json:"arch"`
	OS              string                       `json:"os"`
	ImageDigest     *string                      `json:"imageDigest"`
	ImageSize       *int64                       `json:"imageSize"`
	LayerCount      *int                         `json:"layerCount"`
	Layers          []json.RawMessage            `json:"layers"`
	Labels          json.RawMessage              `json:"labels"`
	SBOM            gatherSBOMInfo               `json:"sbom"`
	TestResults     *gatherTestResults           `json:"testResults"`
	Vulnerabilities *json.RawMessage             `json:"vulnerabilities,omitempty"`
	vulnInfo        *catalog.VulnerabilitiesInfo `json:"-"`
}

type gatherSBOMInfo struct {
	Tool         string           `json:"tool"`
	CreatedAt    string           `json:"createdAt"`
	RootDigest   *string          `json:"rootDigest"`
	PackageCount int              `json:"packageCount"`
	Packages     []spdxPackageOut `json:"packages"`
}

type gatherTestResults struct {
	Status     string            `json:"status"`
	Timestamp  *string           `json:"timestamp"`
	Assertions []gatherAssertion `json:"assertions"`
}

type gatherAssertion struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type gatherSignature struct {
	CosignBundlePresent bool               `json:"cosignBundlePresent"`
	RekorLogIndex       *int64             `json:"rekorLogIndex"`
	Certificate         *gatherCertificate `json:"certificate"`
}

type gatherCertificate struct {
	Subject       *string `json:"subject"`
	Issuer        *string `json:"issuer"`
	RunInvocation *string `json:"runInvocation"`
}

type gatherAttestation struct {
	Kind                 string   `json:"kind"`
	PredicateType        string   `json:"predicateType"`
	SubjectName          *string  `json:"subjectName"`
	SubjectDigest        *string  `json:"subjectDigest"`
	SignerIdentity       *string  `json:"signerIdentity"`
	Issuer               *string  `json:"issuer"`
	RunURL               *string  `json:"runUrl"`
	WorkflowURL          *string  `json:"workflowUrl"`
	GithubAPIURL         *string  `json:"githubApiUrl"`
	TransparencyLogIndex *int64   `json:"transparencyLogIndex"`
	TransparencyURL      *string  `json:"transparencyUrl"`
	Sources              []string `json:"sources"`
	ReleaseAssetURL      *string  `json:"releaseAssetUrl"`
}

type gatherEnrichmentAttestation struct {
	Kind                 string   `json:"kind"`
	PredicateType        string   `json:"predicateType"`
	SubjectName          *string  `json:"subjectName"`
	SubjectDigest        *string  `json:"subjectDigest"`
	SignerIdentity       *string  `json:"signerIdentity"`
	Issuer               *string  `json:"issuer"`
	RunURL               *string  `json:"runUrl"`
	WorkflowURL          *string  `json:"workflowUrl"`
	GithubAPIURL         *string  `json:"githubApiUrl"`
	TransparencyLogIndex *int64   `json:"transparencyLogIndex"`
	TransparencyURL      *string  `json:"transparencyUrl"`
	Sources              []string `json:"sources"`
}

type gatherAssetURLs struct {
	SBOM        map[string]string `json:"sbom"`
	Provenance  *string           `json:"provenance"`
	TestResults map[string]string `json:"testResults"`
	Digest      *string           `json:"digest"`
}

type gatherCatalogImageSummary struct {
	ID                   string                  `json:"id"`
	Language             string                  `json:"language"`
	LanguageDisplay      string                  `json:"languageDisplay"`
	LanguageVersion      string                  `json:"languageVersion"`
	Tier                 string                  `json:"tier"`
	LatestTag            string                  `json:"latestTag"`
	LatestManifestDigest *string                 `json:"latestManifestDigest"`
	LatestPackageCount   int                     `json:"latestPackageCount"`
	Architectures        []string                `json:"architectures"`
	Signed               bool                    `json:"signed"`
	Provenance           bool                    `json:"provenance"`
	Evidence             catalog.EvidenceSummary `json:"evidence"`
	Passed               bool                    `json:"passed"`
	VulnSummary          *gatherVulnSummary      `json:"vulnSummary"`
	Lifecycle            gatherLifecycle         `json:"lifecycle"`
	RuntimeContract      gatherRuntimeContract   `json:"runtimeContract"`
}

type gatherVulnSummary struct {
	Critical    int                       `json:"critical"`
	High        int                       `json:"high"`
	Medium      int                       `json:"medium"`
	Low         int                       `json:"low"`
	ScannedAt   *string                   `json:"scannedAt"`
	Remediation catalog.RemediationCounts `json:"remediation"`
}

type gatherCatalogIndex struct {
	GeneratedAt  string                      `json:"generatedAt"`
	Owner        string                      `json:"owner"`
	Repo         string                      `json:"repo"`
	RepoURL      string                      `json:"repoUrl"`
	RegistryBase string                      `json:"registryBase"`
	LatestTag    string                      `json:"latestTag"`
	Releases     []catalog.ReleaseSummary    `json:"releases"`
	Languages    []gatherLanguageOut         `json:"languages"`
	Tiers        []gatherTierOut             `json:"tiers"`
	Images       []gatherCatalogImageSummary `json:"images"`
}

type catalogRelease struct {
	Tag         string
	Name        string
	PublishedAt string
	Prerelease  bool
	Assets      []catalogAsset
}

type catalogAsset struct {
	Name   string
	URL    string
	Size   int64
	Digest *string
}

type ReleaseSource interface {
	ListReleases(limit int) ([]catalogRelease, error)
	DownloadAsset(asset catalogAsset) ([]byte, error)
}

type gatherBuildOptions struct {
	RegistryBase  string
	SBOMCacheDir  string
	EnrichmentDir string
	VulnDir       string
	Source        ReleaseSource
}

type parsedCatalogAssetName struct {
	Target   string
	Kind     string
	Ext      string
	Filename string
}

var catalogAssetNameRe = regexp.MustCompile(`^(.+?)\.(sbom|test-results|intoto|digest|sigstore)\.(json|jsonl)$`)

func parseCatalogTargetName(filename string) *parsedCatalogAssetName {
	m := catalogAssetNameRe.FindStringSubmatch(filename)
	if m == nil {
		return nil
	}
	return &parsedCatalogAssetName{Target: m[1], Kind: m[2], Ext: m[3], Filename: filename}
}

type gatherTargetInfo struct {
	LangKey string
	Tier    string
}

func gatherTargetMeta(target string) *gatherTargetInfo {
	idx := strings.LastIndex(target, "-")
	if idx == -1 {
		return nil
	}
	langKey := target[:idx]
	tier := target[idx+1:]
	if _, ok := gatherLanguages[langKey]; !ok {
		return nil
	}
	if _, ok := gatherTiers[tier]; !ok {
		return nil
	}
	return &gatherTargetInfo{LangKey: langKey, Tier: tier}
}

func displayAssertionName(name string) string {
	switch name {
	case "Grype Vulnerability Gating":
		return "Vulnerability gate"
	case "Syft SBOM Generation":
		return "SBOM generation"
	default:
		return name
	}
}

func normalizeAssertions(assertions []gatherAssertion) []gatherAssertion {
	out := make([]gatherAssertion, 0, len(assertions))
	for _, assertion := range assertions {
		assertion.Name = displayAssertionName(assertion.Name)
		out = append(out, assertion)
	}
	return out
}

func remediationReason(finding catalog.FindingInfo) string {
	if finding.Remediation != nil && finding.Remediation.Reason != "" {
		return finding.Remediation.Reason
	}
	severity := strings.ToLower(firstNonEmptyStr(finding.Severity, "Unknown"))
	layer := firstNonEmptyStr(finding.Layer, "base")
	switch {
	case layer != "runtime":
		return "base_layer"
	case severity != "critical" && severity != "high":
		return "below_priority_threshold"
	case finding.FixedIn == nil || *finding.FixedIn == "":
		return "no_fixed_version"
	default:
		return "fix_available"
	}
}

func remediationBucket(reason string) string {
	switch reason {
	case "fix_available":
		return "eligible"
	case "base_layer":
		return "baseLayer"
	case "no_fixed_version":
		return "noFixedVersion"
	case "below_priority_threshold":
		return "belowPriorityThreshold"
	default:
		return "otherDeferred"
	}
}

func archForSystem(system string) string {
	if strings.Contains(system, "aarch64") || strings.Contains(system, "arm64") {
		return "arm64"
	}
	return "amd64"
}

func guessArchFromAsset(filename string, spdx *spdxDoc) string {
	if strings.Contains(filename, "arm64") || strings.Contains(filename, "aarch64") {
		return "arm64"
	}
	if strings.Contains(filename, "amd64") || strings.Contains(filename, "x86_64") {
		return "amd64"
	}
	if spdx != nil {
		ns := spdx.DocumentNamespace
		if strings.Contains(ns, "aarch64") || strings.Contains(ns, "arm64") {
			return "arm64"
		}
	}
	return "amd64"
}

func defaultArchPayload(arch, when string) gatherArchPayload {
	return gatherArchPayload{
		Arch:        arch,
		OS:          "linux",
		Layers:      []json.RawMessage{},
		Labels:      json.RawMessage(`{}`),
		SBOM:        gatherSBOMInfo{Tool: "unknown", CreatedAt: when, Packages: []spdxPackageOut{}},
		TestResults: nil,
	}
}

func releaseEvidenceFromGather(rel *gatherReleaseEntry) catalog.EvidenceSummary {
	archCount := len(rel.Architectures)
	var sbomArch, testArch, passedTestArch, vulnArch int
	for _, arch := range rel.Architectures {
		if arch.SBOM.PackageCount > 0 {
			sbomArch++
		}
		if arch.TestResults != nil {
			testArch++
			if arch.TestResults.Status == "passed" {
				passedTestArch++
			}
		}
		if arch.Vulnerabilities != nil {
			vulnArch++
		}
	}
	return catalog.EvidenceSummary{
		Signature:              rel.Signature != nil && rel.Signature.CosignBundlePresent,
		Provenance:             rel.Provenance != nil,
		SBOM:                   archCount > 0 && sbomArch == archCount,
		Tests:                  archCount > 0 && testArch == archCount && passedTestArch == archCount,
		Vulnerabilities:        archCount > 0 && vulnArch == archCount,
		ArchCount:              archCount,
		SBOMArchCount:          sbomArch,
		TestArchCount:          testArch,
		PassedTestArchCount:    passedTestArch,
		VulnerabilityArchCount: vulnArch,
	}
}

func summarizeImageForIndex(img gatherImageRecord) gatherCatalogImageSummary {
	latestRel := img.Releases[0]
	arches := make([]string, 0, len(latestRel.Architectures))
	totalPackages := 0
	passed := len(latestRel.Architectures) > 0
	withVulns := []gatherArchPayload{}
	for _, arch := range latestRel.Architectures {
		arches = append(arches, arch.Arch)
		totalPackages += arch.SBOM.PackageCount
		if arch.TestResults == nil || arch.TestResults.Status != "passed" {
			passed = false
		}
		if arch.vulnInfo != nil {
			withVulns = append(withVulns, arch)
		}
	}
	avgPkgs := 0
	if len(latestRel.Architectures) > 0 {
		avgPkgs = int(math.Round(float64(totalPackages) / float64(len(latestRel.Architectures))))
	}

	var vulnSummary *gatherVulnSummary
	if len(withVulns) > 0 {
		distinct := map[string]catalog.FindingInfo{}
		var scannedAt *string
		for _, arch := range withVulns {
			for _, finding := range arch.vulnInfo.Findings {
				key := finding.ID + "::" + finding.PackageName + "::" + finding.PackageVersion
				if _, ok := distinct[key]; !ok {
					distinct[key] = finding
				}
			}
			if arch.vulnInfo.ScannedAt != "" && (scannedAt == nil || arch.vulnInfo.ScannedAt > *scannedAt) {
				s := arch.vulnInfo.ScannedAt
				scannedAt = &s
			}
		}
		remediation := catalog.RemediationCounts{}
		vulnSummary = &gatherVulnSummary{ScannedAt: scannedAt, Remediation: remediation}
		for _, finding := range distinct {
			severity := strings.ToLower(finding.Severity)
			switch severity {
			case "critical":
				vulnSummary.Critical++
			case "high":
				vulnSummary.High++
			case "medium":
				vulnSummary.Medium++
			case "low":
				vulnSummary.Low++
			}
			if severity == "critical" || severity == "high" {
				switch remediationBucket(remediationReason(finding)) {
				case "eligible":
					vulnSummary.Remediation.Eligible++
				case "baseLayer":
					vulnSummary.Remediation.BaseLayer++
				case "noFixedVersion":
					vulnSummary.Remediation.NoFixedVersion++
				case "belowPriorityThreshold":
					vulnSummary.Remediation.BelowPriorityThreshold++
				default:
					vulnSummary.Remediation.OtherDeferred++
				}
			}
		}
	}

	return gatherCatalogImageSummary{
		ID:                   img.ID,
		Language:             img.Language.ID,
		LanguageDisplay:      img.Language.DisplayName,
		LanguageVersion:      img.Language.Version,
		Tier:                 img.Tier.ID,
		LatestTag:            latestRel.Tag,
		LatestManifestDigest: latestRel.ManifestDigest,
		LatestPackageCount:   avgPkgs,
		Architectures:        arches,
		Signed:               latestRel.Signature != nil && latestRel.Signature.CosignBundlePresent,
		Provenance:           latestRel.Provenance != nil,
		Evidence:             latestRel.Evidence,
		Passed:               passed,
		VulnSummary:          vulnSummary,
		Lifecycle:            img.Lifecycle,
		RuntimeContract:      img.RuntimeContract,
	}
}

func attachReleaseAssetLinks(attestations []gatherEnrichmentAttestation, provenanceURL *string) []gatherAttestation {
	out := make([]gatherAttestation, 0, len(attestations))
	for _, attestation := range attestations {
		releaseAttestation := gatherAttestation{
			Kind:                 attestation.Kind,
			PredicateType:        attestation.PredicateType,
			SubjectName:          attestation.SubjectName,
			SubjectDigest:        attestation.SubjectDigest,
			SignerIdentity:       attestation.SignerIdentity,
			Issuer:               attestation.Issuer,
			RunURL:               attestation.RunURL,
			WorkflowURL:          attestation.WorkflowURL,
			GithubAPIURL:         attestation.GithubAPIURL,
			TransparencyLogIndex: attestation.TransparencyLogIndex,
			TransparencyURL:      attestation.TransparencyURL,
			Sources:              attestation.Sources,
		}
		if releaseAttestation.Kind == "slsa-provenance" && stringSliceContains(releaseAttestation.Sources, "oci") {
			releaseAttestation.ReleaseAssetURL = provenanceURL
		}
		out = append(out, releaseAttestation)
	}
	return out
}

func stringSliceContains(values []string, needle string) bool {
	for _, v := range values {
		if v == needle {
			return true
		}
	}
	return false
}

type gatherEnrichment struct {
	ManifestDigest *string                       `json:"manifestDigest"`
	Architectures  []gatherEnrichmentArch        `json:"architectures"`
	Signature      *gatherSignature              `json:"signature"`
	Provenance     *provenanceOut                `json:"provenance"`
	TestResults    *gatherTestResults            `json:"testResults"`
	Attestations   []gatherEnrichmentAttestation `json:"attestations"`
}

type gatherEnrichmentArch struct {
	Arch   string            `json:"arch"`
	Digest *string           `json:"digest"`
	Size   *int64            `json:"size"`
	Layers []json.RawMessage `json:"layers"`
	Labels json.RawMessage   `json:"labels"`
}

func loadEnrichment(tag, target, enrichmentDir string) *gatherEnrichment {
	if enrichmentDir == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(enrichmentDir, tag, target+".json"))
	if err != nil {
		return nil
	}
	var out gatherEnrichment
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return &out
}

func loadVulnerabilities(tag, target, arch, vulnDir string) (*json.RawMessage, *catalog.VulnerabilitiesInfo) {
	if vulnDir == "" {
		return nil, nil
	}
	data, err := os.ReadFile(filepath.Join(vulnDir, tag, target+"-"+arch+".json"))
	if err != nil {
		return nil, nil
	}
	raw := json.RawMessage(data)
	var info catalog.VulnerabilitiesInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return &raw, nil
	}
	return &raw, &info
}

func buildImageRecord(target string, releases []catalogRelease, refreshSet map[string]bool, opts gatherBuildOptions) (*gatherImageRecord, error) {
	meta := gatherTargetMeta(target)
	if meta == nil {
		return nil, nil
	}
	langInfo := gatherLanguages[meta.LangKey]
	tierInfo := gatherTiers[meta.Tier]
	imageName := "clearcutt-" + strings.ToLower(meta.LangKey)
	fullName := strings.TrimRight(opts.RegistryBase, "/") + "/" + imageName
	releaseEntries := []gatherReleaseEntry{}
	isLatestSet := false

	for _, rel := range releases {
		mustRefresh := refreshSet[rel.Tag]
		sbomAssets := catalogArchAssets(rel.Assets, target, ".sbom.json")
		if len(sbomAssets) == 0 {
			sbomAssets = catalogAssetsNamed(rel.Assets, target+".sbom.json")
		}
		if len(sbomAssets) == 0 {
			continue
		}
		provAsset := catalogAssetNamed(rel.Assets, target+".intoto.jsonl")
		digestAsset := catalogAssetNamed(rel.Assets, target+".digest.json")
		testAssets := catalogArchAssets(rel.Assets, target, ".test-results.json")
		if len(testAssets) == 0 {
			testAssets = catalogAssetsNamed(rel.Assets, target+".test-results.json")
		}

		archMap := map[string]*gatherArchPayload{}
		for _, asset := range sbomAssets {
			arch := guessArchFromAsset(asset.Name, nil)
			cachePath := filepath.Join(opts.SBOMCacheDir, rel.Tag, target+"-"+arch+".sbom.json")
			buf, ok := readCachedSBOM(cachePath, mustRefresh)
			if !ok {
				if opts.Source == nil {
					continue
				}
				var err error
				buf, err = opts.Source.DownloadAsset(asset)
				if err != nil {
					continue
				}
			}
			var spdx spdxDoc
			if err := json.Unmarshal(buf, &spdx); err != nil {
				continue
			}
			if mustRefresh || !fileExists(cachePath) {
				_ = os.MkdirAll(filepath.Dir(cachePath), 0o755)
				_ = os.WriteFile(cachePath, buf, 0o644)
			}
			compact := compactPackages(spdx)
			archEntry := defaultArchPayload(arch, rel.PublishedAt)
			archEntry.SBOM = gatherSBOMInfo{
				Tool:         spdxTool(spdx),
				CreatedAt:    firstNonEmptyStr(spdx.CreationInfo.Created, rel.PublishedAt),
				RootDigest:   rootDigest(spdx),
				PackageCount: len(compact),
				Packages:     compact,
			}
			archMap[arch] = &archEntry
		}

		perArchTest := map[string]gatherTestResults{}
		var legacyTest *gatherTestResults
		for _, asset := range testAssets {
			if opts.Source == nil {
				continue
			}
			buf, err := opts.Source.DownloadAsset(asset)
			if err != nil {
				continue
			}
			var parsed gatherTestResults
			if err := json.Unmarshal(buf, &parsed); err != nil {
				continue
			}
			arch := guessArchFromAsset(asset.Name, nil)
			if strings.HasPrefix(asset.Name, target+"-") {
				perArchTest[arch] = parsed
			} else {
				legacyTest = &parsed
			}
		}
		for arch, entry := range archMap {
			tr, ok := perArchTest[arch]
			if !ok && legacyTest != nil {
				tr = *legacyTest
				ok = true
			}
			if !ok {
				continue
			}
			tr.Assertions = normalizeAssertions(tr.Assertions)
			entry.TestResults = &tr
		}

		var provenance *provenanceOut
		if provAsset != nil {
			if opts.Source == nil {
				return nil, fmt.Errorf("download %s: release source is nil", provAsset.Name)
			}
			buf, err := opts.Source.DownloadAsset(*provAsset)
			if err != nil {
				return nil, err
			}
			p := summarizeProvenance(string(buf))
			provenance = &p
		}

		var manifestDigest *string
		if digestAsset != nil {
			if opts.Source == nil {
				return nil, fmt.Errorf("download %s: release source is nil", digestAsset.Name)
			}
			buf, err := opts.Source.DownloadAsset(*digestAsset)
			if err != nil {
				return nil, err
			}
			var parsed struct {
				Digest string `json:"digest"`
			}
			if err := json.Unmarshal(buf, &parsed); err == nil && parsed.Digest != "" {
				manifestDigest = &parsed.Digest
			}
		}

		enrich := loadEnrichment(rel.Tag, target, opts.EnrichmentDir)
		var signature *gatherSignature
		attestations := []gatherAttestation{}
		if enrich != nil {
			if enrich.ManifestDigest != nil {
				manifestDigest = enrich.ManifestDigest
			}
			for _, archEnr := range enrich.Architectures {
				arch := archEnr.Arch
				if arch == "" {
					continue
				}
				entry, ok := archMap[arch]
				if !ok {
					payload := defaultArchPayload(arch, rel.PublishedAt)
					archMap[arch] = &payload
					entry = &payload
				}
				if archEnr.Digest != nil {
					entry.ImageDigest = archEnr.Digest
				}
				if archEnr.Size != nil {
					entry.ImageSize = archEnr.Size
				}
				if archEnr.Layers != nil {
					layerCount := len(archEnr.Layers)
					entry.LayerCount = &layerCount
					entry.Layers = archEnr.Layers
				}
				if archEnr.Labels != nil {
					entry.Labels = archEnr.Labels
				}
			}
			if (provenance == nil || !isUsefulProvenanceSummary(*provenance)) && enrich.Provenance != nil {
				p := *enrich.Provenance
				provenance = &p
			}
			if enrich.TestResults != nil {
				for _, entry := range archMap {
					if entry.TestResults != nil {
						continue
					}
					tr := *enrich.TestResults
					tr.Status = firstNonEmptyStr(tr.Status, "unknown")
					tr.Assertions = normalizeAssertions(tr.Assertions)
					entry.TestResults = &tr
				}
			}
			signature = enrich.Signature
			attestations = attachReleaseAssetLinks(enrich.Attestations, assetURL(provAsset))
		}

		lastRebuiltAt := rel.PublishedAt
		for arch, entry := range archMap {
			raw, info := loadVulnerabilities(rel.Tag, target, arch, opts.VulnDir)
			if raw != nil {
				entry.Vulnerabilities = raw
				entry.vulnInfo = info
				if info != nil && info.ScannedAt != "" && info.ScannedAt > lastRebuiltAt {
					lastRebuiltAt = info.ScannedAt
				}
			}
		}

		architectures := make([]gatherArchPayload, 0, len(archMap))
		for _, entry := range archMap {
			architectures = append(architectures, *entry)
		}
		sort.Slice(architectures, func(i, j int) bool { return architectures[i].Arch < architectures[j].Arch })
		if len(architectures) == 0 {
			continue
		}

		isLatest := !isLatestSet && !rel.Prerelease
		if isLatest {
			isLatestSet = true
		}
		releaseEntry := gatherReleaseEntry{
			Tag:             rel.Tag,
			PublishedAt:     rel.PublishedAt,
			LastRebuiltAt:   lastRebuiltAt,
			IsLatest:        isLatest,
			ManifestDigest:  manifestDigest,
			TotalSize:       totalImageSize(architectures),
			Architectures:   architectures,
			Signature:       signature,
			Provenance:      provenance,
			Attestations:    attestations,
			AssetURLs:       assetURLsFromAssets(sbomAssets, testAssets, provAsset, digestAsset),
			Lifecycle:       determineLifecycle(target, meta.Tier),
			RuntimeContract: determineRuntimeContract(target, meta.Tier),
			Exceptions:      defaultGatherExceptions(),
		}
		releaseEntry.Evidence = releaseEvidenceFromGather(&releaseEntry)
		releaseEntries = append(releaseEntries, releaseEntry)
	}

	if len(releaseEntries) == 0 {
		return nil, nil
	}
	return &gatherImageRecord{
		ID:              target,
		Language:        gatherLanguageOut{ID: langInfo.ID, DisplayName: langInfo.Display, Version: langInfo.Version},
		Tier:            gatherTierOut{ID: meta.Tier, Name: tierInfo.Name, Blurb: tierInfo.Blurb},
		Registry:        opts.RegistryBase,
		ImageName:       imageName,
		FullName:        fullName,
		Releases:        releaseEntries,
		Lifecycle:       determineLifecycle(target, meta.Tier),
		RuntimeContract: determineRuntimeContract(target, meta.Tier),
	}, nil
}

func spdxTool(spdx spdxDoc) string {
	for _, creator := range spdx.CreationInfo.Creators {
		if strings.HasPrefix(creator, "Tool:") {
			tool := strings.TrimSpace(strings.TrimPrefix(creator, "Tool:"))
			if tool != "" {
				return tool
			}
		}
	}
	return "syft"
}

func readCachedSBOM(cachePath string, mustRefresh bool) ([]byte, bool) {
	if mustRefresh || cachePath == "" {
		return nil, false
	}
	buf, err := os.ReadFile(cachePath)
	return buf, err == nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func catalogArchAssets(assets []catalogAsset, target, suffix string) []catalogAsset {
	out := []catalogAsset{}
	for _, asset := range assets {
		if (strings.HasPrefix(asset.Name, target+"-amd64.") || strings.HasPrefix(asset.Name, target+"-arm64.")) && strings.HasSuffix(asset.Name, suffix) {
			out = append(out, asset)
		}
	}
	return out
}

func catalogAssetsNamed(assets []catalogAsset, name string) []catalogAsset {
	out := []catalogAsset{}
	for _, asset := range assets {
		if asset.Name == name {
			out = append(out, asset)
		}
	}
	return out
}

func catalogAssetNamed(assets []catalogAsset, name string) *catalogAsset {
	for i := range assets {
		if assets[i].Name == name {
			return &assets[i]
		}
	}
	return nil
}

func assetURL(asset *catalogAsset) *string {
	if asset == nil || asset.URL == "" {
		return nil
	}
	url := asset.URL
	return &url
}

func assetURLsFromAssets(sbomAssets, testAssets []catalogAsset, provAsset, digestAsset *catalogAsset) gatherAssetURLs {
	sbomURLs := map[string]string{}
	for _, asset := range sbomAssets {
		sbomURLs[guessArchFromAsset(asset.Name, nil)] = asset.URL
	}
	testURLs := map[string]string{}
	for _, asset := range testAssets {
		testURLs[guessArchFromAsset(asset.Name, nil)] = asset.URL
	}
	return gatherAssetURLs{
		SBOM:        sbomURLs,
		Provenance:  assetURL(provAsset),
		TestResults: testURLs,
		Digest:      assetURL(digestAsset),
	}
}

func totalImageSize(architectures []gatherArchPayload) *int64 {
	var total int64
	for _, arch := range architectures {
		if arch.ImageSize != nil {
			total += *arch.ImageSize
		}
	}
	if total == 0 {
		return nil
	}
	return &total
}

func refreshTagSet(releases []catalogRelease, forceAll bool, forceTags string) map[string]bool {
	out := map[string]bool{}
	if forceAll {
		for _, rel := range releases {
			out[rel.Tag] = true
		}
		return out
	}
	if forceTags != "" {
		for _, tag := range strings.Split(forceTags, ",") {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				out[tag] = true
			}
		}
		return out
	}
	for _, rel := range releases {
		if !rel.Prerelease {
			out[rel.Tag] = true
			return out
		}
	}
	if len(releases) > 0 {
		out[releases[0].Tag] = true
	}
	return out
}
