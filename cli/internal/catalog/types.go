package catalog

import (
	"encoding/json"
)

const (
	// CatalogIndexSchemaVersion identifies the top-level v1 runtime catalog shape.
	CatalogIndexSchemaVersion = "clearcutt.catalog.index/v1"
	// CatalogIndexSchemaVersionV2 identifies the top-level mixed-kind catalog shape.
	CatalogIndexSchemaVersionV2 = "clearcutt.catalog.index/v2"
	// ImageRecordSchemaVersion identifies individual v1 runtime images/*.json records.
	ImageRecordSchemaVersion = "clearcutt.catalog.image/v1"
	// ImageRecordSchemaVersionV2 identifies individual mixed-kind images/*.json records.
	ImageRecordSchemaVersionV2 = "clearcutt.catalog.image/v2"
	// EvidenceManifestSchemaVersion identifies the generated per-release evidence manifest.
	EvidenceManifestSchemaVersion = "clearcutt.catalog.evidence-manifest/v1"
)

// CatalogIndex represents the top-level index.json structure.
type CatalogIndex struct {
	SchemaVersion string                `json:"schemaVersion,omitempty"`
	GeneratedAt   string                `json:"generatedAt"`
	Generator     *CatalogGenerator     `json:"generator,omitempty"`
	Source        *CatalogSource        `json:"source,omitempty"`
	Summary       *CatalogSummary       `json:"summary,omitempty"`
	Owner         string                `json:"owner"`
	Repo          string                `json:"repo"`
	RepoURL       string                `json:"repoUrl"`
	RegistryBase  string                `json:"registryBase"`
	LatestTag     string                `json:"latestTag"`
	Releases      []ReleaseSummary      `json:"releases"`
	Languages     []LanguageInfo        `json:"languages"`
	Tiers         []TierInfo            `json:"tiers"`
	Images        []CatalogImageSummary `json:"images"`
}

// CatalogGenerator describes the tool that produced a versioned catalog.
type CatalogGenerator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// CatalogSource describes the source repository and registry namespace.
type CatalogSource struct {
	Owner        string `json:"owner"`
	Repo         string `json:"repo"`
	RepoURL      string `json:"repoUrl"`
	RegistryBase string `json:"registryBase"`
}

// CatalogSummary provides lightweight top-level evidence coverage counts.
type CatalogSummary struct {
	ImageCount      int `json:"imageCount"`
	ReleaseCount    int `json:"releaseCount"`
	SignedCount     int `json:"signedCount"`
	ProvenanceCount int `json:"provenanceCount"`
	SBOMCount       int `json:"sbomCount"`
	ScanCount       int `json:"scanCount"`
	PassingCount    int `json:"passingCount"`
}

// ReleaseSummary represents a release entry inside the index.
type ReleaseSummary struct {
	Tag         string `json:"tag"`
	PublishedAt string `json:"publishedAt"`
	IsLatest    bool   `json:"isLatest"`
}

// LanguageInfo represents language details.
type LanguageInfo struct {
	ID          string  `json:"id"`
	DisplayName string  `json:"displayName"`
	Version     string  `json:"version"`
	Icon        *string `json:"icon,omitempty"`
}

// TierInfo represents tier details.
type TierInfo struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Blurb string `json:"blurb"`
}

// CatalogImageSummary represents a summary image record inside index.json.
type CatalogImageSummary struct {
	ID              string `json:"id"`
	Kind            string `json:"kind,omitempty"`
	Language        string `json:"language"`
	LanguageDisplay string `json:"languageDisplay"`
	LanguageVersion string `json:"languageVersion"`
	Tier            string `json:"tier"`
	LatestTag       string `json:"latestTag"`
	// LatestManifestDigest denormalizes the latest release's manifest digest into
	// the index summary so commands like `list` can render it without reading
	// every individual image record.
	LatestManifestDigest *string          `json:"latestManifestDigest,omitempty"`
	LatestPackageCount   int              `json:"latestPackageCount"`
	Architectures        []string         `json:"architectures"`
	Signed               bool             `json:"signed"`
	Provenance           bool             `json:"provenance"`
	Evidence             *EvidenceSummary `json:"evidence,omitempty"`
	Passed               bool             `json:"passed"`
	VulnSummary          *VulnSummary     `json:"vulnSummary,omitempty"`
	Lifecycle            Lifecycle        `json:"lifecycle"`
	RuntimeContract      RuntimeContract  `json:"runtimeContract"`
	Service              *ServiceInfo     `json:"service,omitempty"`
}

// EvidenceSummary tracks the presence of various supply-chain evidence pieces.
type EvidenceSummary struct {
	Signature              bool `json:"signature"`
	Provenance             bool `json:"provenance"`
	SBOM                   bool `json:"sbom"`
	Tests                  bool `json:"tests"`
	Vulnerabilities        bool `json:"vulnerabilities"`
	ArchCount              int  `json:"archCount"`
	SBOMArchCount          int  `json:"sbomArchCount"`
	TestArchCount          int  `json:"testArchCount"`
	PassedTestArchCount    int  `json:"passedTestArchCount"`
	VulnerabilityArchCount int  `json:"vulnerabilityArchCount"`
}

// VulnSummary aggregates vulnerability counts and scanning timestamps.
type VulnSummary struct {
	Critical    int                `json:"critical"`
	High        int                `json:"high"`
	Medium      int                `json:"medium"`
	Low         int                `json:"low"`
	ScannedAt   *string            `json:"scannedAt,omitempty"`
	Remediation *RemediationCounts `json:"remediation,omitempty"`
}

// RemediationCounts categorises fixable/unfixable/base CVE remediation states.
type RemediationCounts struct {
	Eligible               int `json:"eligible"`
	BaseLayer              int `json:"baseLayer"`
	NoFixedVersion         int `json:"noFixedVersion"`
	BelowPriorityThreshold int `json:"belowPriorityThreshold"`
	OtherDeferred          int `json:"otherDeferred"`
}

// Lifecycle maps base image support, status, and production gating.
type Lifecycle struct {
	Status            string  `json:"status"`
	Support           string  `json:"support"`
	ProductionAllowed bool    `json:"productionAllowed"`
	DeprecatedAt      *string `json:"deprecatedAt,omitempty"`
	EOLAt             *string `json:"eolAt,omitempty"`
	Reason            *string `json:"reason,omitempty"`
}

// RuntimeContract represents expectations and runtime platform guarantees.
type RuntimeContract struct {
	User                  *string `json:"user,omitempty"`
	WorkingDir            *string `json:"workingDir,omitempty"`
	ShellPresent          *bool   `json:"shellPresent,omitempty"`
	PackageManagerPresent *bool   `json:"packageManagerPresent,omitempty"`
	CACertificatesPresent *bool   `json:"caCertificatesPresent,omitempty"`
	TimezoneDataPresent   *bool   `json:"timezoneDataPresent,omitempty"`
	DefaultEntrypoint     *string `json:"defaultEntrypoint,omitempty"`
	ProductionTier        bool    `json:"productionTier"`
}

// ServiceInfo describes first-class platform service images such as Postgres,
// Valkey, and oauth2-proxy.
type ServiceInfo struct {
	Template    string            `json:"template"`
	Version     string            `json:"version"`
	Ports       []ServicePortInfo `json:"ports,omitempty"`
	Stateful    bool              `json:"stateful"`
	DataDirs    []string          `json:"dataDirs,omitempty"`
	Smoke       []string          `json:"smoke,omitempty"`
	SmokeStatus string            `json:"smokeStatus,omitempty"`
}

type ServicePortInfo struct {
	Name     string `json:"name,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
}

// ImageRecord represents individual image records under images/*.json.
type ImageRecord struct {
	SchemaVersion   string          `json:"schemaVersion,omitempty"`
	ID              string          `json:"id"`
	Kind            string          `json:"kind,omitempty"`
	Language        LanguageInfo    `json:"language"`
	Tier            TierInfo        `json:"tier"`
	Registry        string          `json:"registry"`
	ImageName       string          `json:"imageName"`
	FullName        string          `json:"fullName"`
	Lifecycle       Lifecycle       `json:"lifecycle"`
	RuntimeContract RuntimeContract `json:"runtimeContract"`
	Service         *ServiceInfo    `json:"service,omitempty"`
	Releases        []ReleaseEntry  `json:"releases"`
}

// ReleaseEntry represents a detailed release record inside ImageRecord.
type ReleaseEntry struct {
	Tag             string             `json:"tag"`
	PublishedAt     string             `json:"publishedAt"`
	LastRebuiltAt   *string            `json:"lastRebuiltAt,omitempty"`
	IsLatest        bool               `json:"isLatest"`
	ManifestDigest  *string            `json:"manifestDigest,omitempty"`
	TotalSize       *int64             `json:"totalSize,omitempty"`
	Architectures   []ArchPayload      `json:"architectures"`
	Signature       *SignatureInfo     `json:"signature,omitempty"`
	Provenance      *ProvenanceInfo    `json:"provenance,omitempty"`
	Attestations    []AttestationEntry `json:"attestations"`
	AssetURLs       AssetURLs          `json:"assetUrls"`
	Evidence        *EvidenceSummary   `json:"evidence,omitempty"`
	Lifecycle       Lifecycle          `json:"lifecycle"`
	RuntimeContract RuntimeContract    `json:"runtimeContract"`
	Exceptions      ExceptionSummary   `json:"exceptions"`
}

// ArchPayload represents detailed architecture metadata.
type ArchPayload struct {
	Arch            string               `json:"arch"`
	OS              string               `json:"os"`
	ImageDigest     *string              `json:"imageDigest,omitempty"`
	ImageSize       *int64               `json:"imageSize,omitempty"`
	LayerCount      *int                 `json:"layerCount,omitempty"`
	Layers          []LayerInfo          `json:"layers"`
	Labels          map[string]string    `json:"labels"`
	SBOM            SBOMInfo             `json:"sbom"`
	TestResults     *TestResultsInfo     `json:"testResults,omitempty"`
	Vulnerabilities *VulnerabilitiesInfo `json:"vulnerabilities,omitempty"`
}

// LayerInfo tracks layer digests and size.
type LayerInfo struct {
	Digest string  `json:"digest"`
	Size   int64   `json:"size"`
	DiffID *string `json:"diffID,omitempty"`
}

// SBOMInfo maps syft SBOM metadata.
type SBOMInfo struct {
	Tool         string         `json:"tool"`
	CreatedAt    string         `json:"createdAt"`
	RootDigest   *string        `json:"rootDigest,omitempty"`
	PackageCount int            `json:"packageCount"`
	Packages     []PackageEntry `json:"packages"`
}

// PackageEntry represents a package entry inside an SBOM.
type PackageEntry struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Purl         *string  `json:"purl,omitempty"`
	Cpes         []string `json:"cpes"`
	License      string   `json:"license"`
	Supplier     string   `json:"supplier"`
	NixStorePath *string  `json:"nixStorePath,omitempty"`
	SpdxID       string   `json:"spdxId"`
	LayerDigest  *string  `json:"layerDigest,omitempty"`
}

// TestResultsInfo tracks structured smoke/conformance tests.
type TestResultsInfo struct {
	Status     string          `json:"status"`
	Timestamp  *string         `json:"timestamp,omitempty"`
	Assertions []AssertionInfo `json:"assertions"`
}

// AssertionInfo tracks a single test case assertion.
type AssertionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// VulnerabilitiesInfo maps scanner vulnerability details.
type VulnerabilitiesInfo struct {
	ScannedAt         string         `json:"scannedAt"`
	Scanner           string         `json:"scanner"`
	DBBuiltAt         *string        `json:"dbBuiltAt,omitempty"`
	KEVStatus         string         `json:"kevStatus,omitempty"`
	KEVCatalogVersion *string        `json:"kevCatalogVersion,omitempty"`
	CountsBySeverity  SeverityCounts `json:"countsBySeverity"`
	Findings          []FindingInfo  `json:"findings"`
}

// SeverityCounts categorises vulnerabilities.
type SeverityCounts struct {
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible"`
	Unknown    int `json:"unknown"`
}

// FindingInfo represents a single vulnerability finding.
type FindingInfo struct {
	ID             string           `json:"id"`
	Severity       string           `json:"severity"`
	PackageName    string           `json:"packageName"`
	PackageVersion string           `json:"packageVersion"`
	Purl           *string          `json:"purl,omitempty"`
	Layer          string           `json:"layer"`
	FixedIn        *string          `json:"fixedIn,omitempty"`
	FixState       string           `json:"fixState"`
	Remediation    *RemediationInfo `json:"remediation,omitempty"`
	Inclusion      *InclusionInfo   `json:"inclusion,omitempty"`
	DataSource     *string          `json:"dataSource,omitempty"`
	Namespace      *string          `json:"namespace,omitempty"`
	Description    *string          `json:"description,omitempty"`
	CvssScore      *float64         `json:"cvssScore,omitempty"`
	CvssVersion    *string          `json:"cvssVersion,omitempty"`
	CvssVector     *string          `json:"cvssVector,omitempty"`
	EpssScore      *float64         `json:"epssScore,omitempty"`
	EpssPercentile *float64         `json:"epssPercentile,omitempty"`
	RiskScore      *float64         `json:"riskScore,omitempty"`
	KEV            *KEVInfo         `json:"kev,omitempty"`
}

type KEVInfo struct {
	KnownExploited             bool    `json:"knownExploited"`
	CatalogVersion             *string `json:"catalogVersion,omitempty"`
	DateReleased               *string `json:"dateReleased,omitempty"`
	DateAdded                  *string `json:"dateAdded,omitempty"`
	DueDate                    *string `json:"dueDate,omitempty"`
	VendorProject              *string `json:"vendorProject,omitempty"`
	Product                    *string `json:"product,omitempty"`
	VulnerabilityName          *string `json:"vulnerabilityName,omitempty"`
	RequiredAction             *string `json:"requiredAction,omitempty"`
	KnownRansomwareCampaignUse *string `json:"knownRansomwareCampaignUse,omitempty"`
}

// RemediationInfo defines policy remediation actions.
type RemediationInfo struct {
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Summary string `json:"summary"`
}

// InclusionInfo provides category notes for standard packages.
type InclusionInfo struct {
	Category string `json:"category"`
	Summary  string `json:"summary"`
}

// SignatureInfo maps OCI cosign bundle signatures.
type SignatureInfo struct {
	CosignBundlePresent bool             `json:"cosignBundlePresent"`
	RekorLogIndex       *int64           `json:"rekorLogIndex,omitempty"`
	Certificate         *CertificateInfo `json:"certificate,omitempty"`
}

// CertificateInfo tracks the OIDC subject, issuer, and context.
type CertificateInfo struct {
	Subject       *string `json:"subject,omitempty"`
	Issuer        *string `json:"issuer,omitempty"`
	RunInvocation *string `json:"runInvocation,omitempty"`
}

// ProvenanceInfo maps SLSA provenance.
type ProvenanceInfo struct {
	PredicateType  string           `json:"predicateType"`
	Builder        BuilderInfo      `json:"builder"`
	BuildType      *string          `json:"buildType,omitempty"`
	SourceURI      *string          `json:"sourceUri,omitempty"`
	SourceRevision *string          `json:"sourceRevision,omitempty"`
	SlsaLevel      int              `json:"slsaLevel"`
	Raw            *json.RawMessage `json:"raw,omitempty"`
}

// BuilderInfo represents builder ID.
type BuilderInfo struct {
	ID string `json:"id"`
}

// AttestationEntry maps sigstore in-toto DSSE envelopes.
type AttestationEntry struct {
	Kind                 string   `json:"kind"`
	PredicateType        string   `json:"predicateType"`
	SubjectName          *string  `json:"subjectName,omitempty"`
	SubjectDigest        *string  `json:"subjectDigest,omitempty"`
	SignerIdentity       *string  `json:"signerIdentity,omitempty"`
	Issuer               *string  `json:"issuer,omitempty"`
	RunURL               *string  `json:"runUrl,omitempty"`
	WorkflowURL          *string  `json:"workflowUrl,omitempty"`
	GithubAPIURL         *string  `json:"githubApiUrl,omitempty"`
	ReleaseAssetURL      *string  `json:"releaseAssetUrl,omitempty"`
	TransparencyLogIndex *int64   `json:"transparencyLogIndex,omitempty"`
	TransparencyURL      *string  `json:"transparencyUrl,omitempty"`
	Sources              []string `json:"sources"`
}

// AssetURLs contains release download locations.
type AssetURLs struct {
	SBOM        map[string]string `json:"sbom"`
	Provenance  *string           `json:"provenance,omitempty"`
	TestResults map[string]string `json:"testResults"`
	Digest      *string           `json:"digest,omitempty"`
}

// ExceptionSummary tracks Phase 3 vulnerability exception statistics.
type ExceptionSummary struct {
	Total             int `json:"total"`
	Expired           int `json:"expired"`
	Active            int `json:"active"`
	AcceptedRisk      int `json:"acceptedRisk"`
	NoFixAvailable    int `json:"noFixAvailable"`
	FalsePositive     int `json:"falsePositive"`
	InheritedFromBase int `json:"inheritedFromBase"`
}
