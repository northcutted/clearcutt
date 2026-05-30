package catalog

// CatalogIndex represents the top-level index.json structure.
type CatalogIndex struct {
	GeneratedAt  string                `json:"generatedAt"`
	Owner        string                `json:"owner"`
	Repo         string                `json:"repo"`
	RepoURL      string                `json:"repoUrl"`
	RegistryBase string                `json:"registryBase"`
	LatestTag    string                `json:"latestTag"`
	Releases     []ReleaseSummary      `json:"releases"`
	Languages    []LanguageInfo        `json:"languages"`
	Tiers        []TierInfo            `json:"tiers"`
	Images       []CatalogImageSummary `json:"images"`
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
	Icon        *string `json:"icon"`
}

// TierInfo represents tier details.
type TierInfo struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Blurb string `json:"blurb"`
}

// CatalogImageSummary represents a summary image record inside index.json.
type CatalogImageSummary struct {
	ID                 string           `json:"id"`
	Language           string           `json:"language"`
	LanguageDisplay    string           `json:"languageDisplay"`
	LanguageVersion    string           `json:"languageVersion"`
	Tier               string           `json:"tier"`
	LatestTag          string           `json:"latestTag"`
	LatestPackageCount int              `json:"latestPackageCount"`
	Architectures      []string         `json:"architectures"`
	Signed             bool             `json:"signed"`
	Provenance         bool             `json:"provenance"`
	Evidence           *EvidenceSummary `json:"evidence,omitempty"`
	Passed             bool             `json:"passed"`
	VulnSummary        *VulnSummary     `json:"vulnSummary,omitempty"`
	Lifecycle          Lifecycle        `json:"lifecycle"`
	RuntimeContract    RuntimeContract  `json:"runtimeContract"`
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
	Critical    int               `json:"critical"`
	High        int               `json:"high"`
	Medium      int               `json:"medium"`
	Low         int               `json:"low"`
	ScannedAt   *string           `json:"scannedAt"`
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
	DeprecatedAt      *string `json:"deprecatedAt"`
	EOLAt             *string `json:"eolAt"`
	Reason            *string `json:"reason"`
}

// RuntimeContract represents expectations and runtime platform guarantees.
type RuntimeContract struct {
	User                  *string `json:"user"`
	WorkingDir            *string `json:"workingDir"`
	ShellPresent          *bool   `json:"shellPresent"`
	PackageManagerPresent *bool   `json:"packageManagerPresent"`
	CACertificatesPresent *bool   `json:"caCertificatesPresent"`
	TimezoneDataPresent   *bool   `json:"timezoneDataPresent"`
	DefaultEntrypoint     *string `json:"defaultEntrypoint"`
	ProductionTier        bool    `json:"productionTier"`
}

// ImageRecord represents individual image records under images/*.json.
type ImageRecord struct {
	ID              string          `json:"id"`
	Language        LanguageInfo    `json:"language"`
	Tier            TierInfo        `json:"tier"`
	Registry        string          `json:"registry"`
	ImageName       string          `json:"imageName"`
	FullName        string          `json:"fullName"`
	Lifecycle       Lifecycle       `json:"lifecycle"`
	RuntimeContract RuntimeContract `json:"runtimeContract"`
	Releases        []ReleaseEntry  `json:"releases"`
}

// ReleaseEntry represents a detailed release record inside ImageRecord.
type ReleaseEntry struct {
	Tag            string             `json:"tag"`
	PublishedAt    string             `json:"publishedAt"`
	LastRebuiltAt  *string            `json:"lastRebuiltAt,omitempty"`
	IsLatest       bool               `json:"isLatest"`
	ManifestDigest *string            `json:"manifestDigest"`
	TotalSize      *int64             `json:"totalSize"`
	Architectures  []ArchPayload      `json:"architectures"`
	Signature      *SignatureInfo     `json:"signature"`
	Provenance     *ProvenanceInfo    `json:"provenance"`
	Attestations   []AttestationEntry `json:"attestations"`
	AssetURLs      AssetURLs          `json:"assetUrls"`
	Evidence       *EvidenceSummary   `json:"evidence,omitempty"`
	Lifecycle      Lifecycle          `json:"lifecycle"`
	RuntimeContract RuntimeContract    `json:"runtimeContract"`
	Exceptions     ExceptionSummary   `json:"exceptions"`
}

// ArchPayload represents detailed architecture metadata.
type ArchPayload struct {
	Arch            string               `json:"arch"`
	OS              string               `json:"os"`
	ImageDigest     *string              `json:"imageDigest"`
	ImageSize       *int64               `json:"imageSize"`
	LayerCount      *int                 `json:"layerCount"`
	Layers          []LayerInfo          `json:"layers"`
	Labels          map[string]string    `json:"labels"`
	SBOM            SBOMInfo             `json:"sbom"`
	TestResults     *TestResultsInfo     `json:"testResults"`
	Vulnerabilities *VulnerabilitiesInfo `json:"vulnerabilities"`
}

// LayerInfo tracks layer digests and size.
type LayerInfo struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	DiffID *string `json:"diffID,omitempty"`
}

// SBOMInfo maps syft SBOM metadata.
type SBOMInfo struct {
	Tool         string         `json:"tool"`
	CreatedAt    string         `json:"createdAt"`
	RootDigest   *string        `json:"rootDigest"`
	PackageCount int            `json:"packageCount"`
	Packages     []PackageEntry `json:"packages"`
}

// PackageEntry represents a package entry inside an SBOM.
type PackageEntry struct {
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

// TestResultsInfo tracks structured smoke/conformance tests.
type TestResultsInfo struct {
	Status     string          `json:"status"`
	Timestamp  *string         `json:"timestamp"`
	Assertions []AssertionInfo `json:"assertions"`
}

// AssertionInfo tracks a single test case assertion.
type AssertionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// VulnerabilitiesInfo maps scanner vulnerability details.
type VulnerabilitiesInfo struct {
	ScannedAt        string         `json:"scannedAt"`
	Scanner          string         `json:"scanner"`
	DBBuiltAt        *string        `json:"dbBuiltAt"`
	CountsBySeverity SeverityCounts `json:"countsBySeverity"`
	Findings         []FindingInfo  `json:"findings"`
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
	Purl           *string          `json:"purl"`
	Layer          string           `json:"layer"`
	FixedIn        *string          `json:"fixedIn"`
	FixState       string           `json:"fixState"`
	Remediation    *RemediationInfo `json:"remediation,omitempty"`
	Inclusion      *InclusionInfo   `json:"inclusion,omitempty"`
	DataSource     *string          `json:"dataSource"`
	Namespace      *string          `json:"namespace"`
	Description    *string          `json:"description"`
	CvssScore      *float64         `json:"cvssScore,omitempty"`
	CvssVersion    *string          `json:"cvssVersion,omitempty"`
	CvssVector     *string          `json:"cvssVector,omitempty"`
	EpssScore      *float64         `json:"epssScore,omitempty"`
	EpssPercentile *float64         `json:"epssPercentile,omitempty"`
	RiskScore      *float64         `json:"riskScore,omitempty"`
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
	PredicateType  string      `json:"predicateType"`
	Builder        BuilderInfo `json:"builder"`
	BuildType      *string     `json:"buildType"`
	SourceURI      *string     `json:"sourceUri"`
	SourceRevision *string     `json:"sourceRevision"`
	SlsaLevel      int         `json:"slsaLevel"`
}

// BuilderInfo represents builder ID.
type BuilderInfo struct {
	ID string `json:"id"`
}

// AttestationEntry maps sigstore in-toto DSSE envelopes.
type AttestationEntry struct {
	Kind                 string   `json:"kind"`
	PredicateType        string   `json:"predicateType"`
	SubjectName          *string  `json:"subjectName"`
	SubjectDigest        *string  `json:"subjectDigest"`
	SignerIdentity       *string  `json:"signerIdentity"`
	Issuer               *string  `json:"issuer"`
	RunURL               *string  `json:"runUrl"`
	WorkflowURL          *string  `json:"workflowUrl"`
	GithubAPIURL         *string  `json:"githubApiUrl"`
	ReleaseAssetURL      *string  `json:"releaseAssetUrl,omitempty"`
	TransparencyLogIndex *int64   `json:"transparencyLogIndex"`
	TransparencyURL      *string  `json:"transparencyUrl"`
	Sources              []string `json:"sources"`
}

// AssetURLs contains release download locations.
type AssetURLs struct {
	SBOM        map[string]string `json:"sbom"`
	Provenance  *string           `json:"provenance"`
	TestResults map[string]string `json:"testResults"`
	Digest      *string           `json:"digest"`
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
