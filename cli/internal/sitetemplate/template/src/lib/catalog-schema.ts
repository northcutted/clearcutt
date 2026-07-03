import { z } from 'zod';

const NullableString = z.string().nullable().optional().default(null);
const NullableNumber = z.number().nullable().optional().default(null);
const NullableBoolean = z.boolean().nullable().optional().default(null);

export const PackageEntry = z.object({
  name: z.string(),
  version: z.string(),
  purl: NullableString,
  cpes: z.array(z.string()).optional().default([]),
  license: z.string(),
  supplier: z.string(),
  nixStorePath: NullableString,
  spdxId: z.string(),
  layerDigest: NullableString,
});
export type PackageEntry = z.infer<typeof PackageEntry>;

export const ArchPayload = z.object({
  arch: z.enum(['amd64', 'arm64']),
  os: z.string().default('linux'),
  imageDigest: NullableString,
  // Compressed layer sum in bytes (approximate registry pull size).
  imageSize: NullableNumber,
  // Byte size of the OCI manifest descriptor itself, not the image contents.
  manifestDescriptorSize: NullableNumber,
  layerCount: NullableNumber,
  layers: z
    .array(
      z.object({
        digest: z.string(),
        size: z.number(),
        diffID: z.string().nullable().optional(),
      })
    )
    .default([]),
  labels: z.record(z.string()).default({}),
  sbom: z.object({
    tool: z.string(),
    createdAt: z.string(),
    rootDigest: NullableString,
    packageCount: z.number(),
    packages: z.array(PackageEntry),
  }),
  testResults: z
    .object({
      status: z.string(),
      timestamp: NullableString,
      assertions: z.array(z.object({ name: z.string(), status: z.string() })),
    })
    .nullable()
    .optional(),
  vulnerabilities: z
    .object({
      scannedAt: z.string(),
      scanner: z.string(),
      dbBuiltAt: NullableString,
      kevStatus: z.string().optional(),
      kevCatalogVersion: NullableString.optional(),
      countsBySeverity: z.object({
        critical: z.number(),
        high: z.number(),
        medium: z.number(),
        low: z.number(),
        negligible: z.number(),
        unknown: z.number(),
      }),
      findings: z.array(
        z.object({
          id: z.string(),
          severity: z.string(),
          packageName: z.string(),
          packageVersion: z.string(),
          purl: NullableString,
          layer: z.string().default('base'),
          fixedIn: NullableString,
          fixState: z.string(),
          remediation: z
            .object({
              status: z.enum(['eligible', 'deferred']),
              reason: z.string(),
              summary: z.string(),
            })
            .optional(),
          inclusion: z
            .object({
              category: z.string(),
              summary: z.string(),
            })
            .optional(),
          dataSource: NullableString,
          namespace: NullableString,
          description: NullableString,
          // Quantitative risk fields — all optional because older scans
          // didn't capture them and grype doesn't always have them per CVE.
          cvssScore: z.number().nullable().optional(),
          cvssVersion: z.string().nullable().optional(),
          cvssVector: z.string().nullable().optional(),
          epssScore: z.number().nullable().optional(),
          epssPercentile: z.number().nullable().optional(),
          riskScore: z.number().nullable().optional(),
          kev: z
            .object({
              knownExploited: z.boolean(),
              catalogVersion: z.string().nullable().optional(),
              dateReleased: z.string().nullable().optional(),
              dateAdded: z.string().nullable().optional(),
              dueDate: z.string().nullable().optional(),
              vendorProject: z.string().nullable().optional(),
              product: z.string().nullable().optional(),
              vulnerabilityName: z.string().nullable().optional(),
              requiredAction: z.string().nullable().optional(),
              knownRansomwareCampaignUse: z.string().nullable().optional(),
            })
            .nullable()
            .optional(),
        }),
      ),
    })
    .nullable()
    .optional(),
});
export type ArchPayload = z.infer<typeof ArchPayload>;

export const AttestationEntry = z.object({
  kind: z.enum(['slsa-provenance', 'sbom', 'test-results', 'custom']),
  predicateType: z.string(),
  subjectName: NullableString,
  subjectDigest: NullableString,
  signerIdentity: NullableString,
  issuer: NullableString,
  runUrl: NullableString,
  workflowUrl: NullableString,
  githubApiUrl: NullableString,
  releaseAssetUrl: NullableString,
  transparencyLogIndex: NullableNumber,
  transparencyUrl: NullableString,
  sources: z.array(z.enum(['oci', 'github'])).optional().default([]),
});
export type AttestationEntry = z.infer<typeof AttestationEntry>;

export const Lifecycle = z.object({
  status: z.enum(['active', 'preview', 'deprecated', 'eol', 'experimental', 'blocked']),
  // Free-form support label (e.g. "lts", "current", or a fork's own taxonomy):
  // the published JSON Schemas type it as a plain string, so the site must not
  // reject catalogs that use values outside the original enum.
  support: z.string(),
  productionAllowed: z.boolean(),
  deprecatedAt: NullableString,
  eolAt: NullableString,
  reason: NullableString,
});
export type Lifecycle = z.infer<typeof Lifecycle>;

export const RuntimeContract = z.object({
  user: NullableString,
  workingDir: NullableString,
  shellPresent: NullableBoolean,
  packageManagerPresent: NullableBoolean,
  caCertificatesPresent: NullableBoolean,
  timezoneDataPresent: NullableBoolean,
  defaultEntrypoint: NullableString,
  productionTier: z.boolean(),
});
export type RuntimeContract = z.infer<typeof RuntimeContract>;

export const ServiceInfo = z.object({
  template: z.string(),
  version: z.string(),
  ports: z
    .array(
      z.object({
        name: z.string().optional(),
        port: z.number(),
        protocol: z.enum(['tcp', 'udp']).optional().default('tcp'),
      }),
    )
    .optional()
    .default([]),
  stateful: z.boolean(),
  dataDirs: z.array(z.string()).optional().default([]),
  smoke: z.array(z.string()).optional().default([]),
  smokeStatus: z.string().optional(),
});
export type ServiceInfo = z.infer<typeof ServiceInfo>;

export const ExceptionSummary = z.object({
  total: z.number(),
  expired: z.number(),
  active: z.number(),
  acceptedRisk: z.number(),
  noFixAvailable: z.number(),
  falsePositive: z.number(),
  inheritedFromBase: z.number(),
});
export type ExceptionSummary = z.infer<typeof ExceptionSummary>;

export const ReleaseEntry = z.object({
  tag: z.string(),
  publishedAt: z.string(),
  lastRebuiltAt: z.string().nullable().optional(), // Add lastRebuiltAt rebuild timestamp field
  isLatest: z.boolean(),
  manifestDigest: NullableString,
  totalSize: NullableNumber,
  architectures: z.array(ArchPayload),
  signature: z
    .object({
      cosignBundlePresent: z.boolean(),
      rekorLogIndex: z.number().nullable().optional(),
      certificate: z
        .object({
          subject: z.string().nullable().optional(),
          issuer: z.string().nullable().optional(),
          runInvocation: z.string().nullable().optional(),
        })
        .nullable()
        .optional(),
    })
    .nullable()
    .optional(),
  provenance: z
    .object({
      predicateType: z.string(),
      builder: z.object({ id: z.string() }),
      buildType: NullableString,
      sourceUri: NullableString,
      sourceRevision: NullableString,
      slsaLevel: z.number(),
      raw: z.unknown().optional(),
    })
    .nullable()
    .optional(),
  attestations: z.array(AttestationEntry).default([]),
  assetUrls: z.object({
    sbom: z.record(z.string()).default({}),
    provenance: NullableString,
    testResults: z.record(z.string()).default({}),
    digest: NullableString,
  }),
  evidence: z
    .object({
      signature: z.boolean(),
      provenance: z.boolean(),
      sbom: z.boolean(),
      tests: z.boolean(),
      vulnerabilities: z.boolean(),
      archCount: z.number(),
      sbomArchCount: z.number(),
      testArchCount: z.number(),
      passedTestArchCount: z.number(),
      vulnerabilityArchCount: z.number(),
    })
    .optional(),
  lifecycle: Lifecycle,
  runtimeContract: RuntimeContract,
  exceptions: ExceptionSummary,
});
export type ReleaseEntry = z.infer<typeof ReleaseEntry>;

export const ImageRecord = z.object({
  schemaVersion: z.union([z.literal('clearcutt.catalog.image/v1'), z.literal('clearcutt.catalog.image/v2')]).optional(),
  id: z.string(),
  kind: z.enum(['runtime', 'service', 'application']).optional().default('runtime'),
  language: z.object({
    id: z.string(),
    displayName: z.string(),
    version: z.string(),
    icon: NullableString,
  }),
  tier: z.object({
    id: z.enum(['dev', 'slim', 'distroless', 'service']),
    name: z.string(),
    blurb: z.string(),
  }),
  registry: z.string(),
  imageName: z.string(),
  fullName: z.string(),
  releases: z.array(ReleaseEntry),
  lifecycle: Lifecycle,
  runtimeContract: RuntimeContract,
  service: ServiceInfo.optional(),
});
export type ImageRecord = z.infer<typeof ImageRecord>;

export const CatalogIndex = z.object({
  schemaVersion: z.union([z.literal('clearcutt.catalog.index/v1'), z.literal('clearcutt.catalog.index/v2')]).optional(),
  generatedAt: z.string(),
  generator: z
    .object({
      name: z.string(),
      version: z.string(),
      commit: z.string(),
    })
    .optional(),
  source: z
    .object({
      owner: z.string(),
      repo: z.string(),
      repoUrl: z.string(),
      registryBase: z.string(),
    })
    .optional(),
  summary: z
    .object({
      imageCount: z.number(),
      releaseCount: z.number(),
      signedCount: z.number(),
      provenanceCount: z.number(),
      sbomCount: z.number(),
      scanCount: z.number(),
      passingCount: z.number(),
    })
    .optional(),
  owner: z.string(),
  repo: z.string(),
  repoUrl: z.string(),
  registryBase: z.string(),
  latestTag: z.string(),
  releases: z.array(
    z.object({
      tag: z.string(),
      publishedAt: z.string(),
      isLatest: z.boolean(),
    }),
  ),
  languages: z.array(
    z.object({
      id: z.string(),
      displayName: z.string(),
      version: z.string(),
      icon: NullableString,
    }),
  ),
  tiers: z.array(
    z.object({
      id: z.enum(['dev', 'slim', 'distroless', 'service']),
      name: z.string(),
      blurb: z.string(),
    }),
  ),
  images: z.array(
    z.object({
      id: z.string(),
      kind: z.enum(['runtime', 'service', 'application']).optional().default('runtime'),
      language: z.string(),
      languageDisplay: z.string(),
      languageVersion: z.string(),
      tier: z.enum(['dev', 'slim', 'distroless', 'service']),
      latestTag: z.string(),
      latestManifestDigest: NullableString,
      latestPackageCount: z.number(),
      architectures: z.array(z.string()),
      signed: z.boolean(),
      provenance: z.boolean(),
      evidence: z
        .object({
          signature: z.boolean(),
          provenance: z.boolean(),
          sbom: z.boolean(),
          tests: z.boolean(),
          vulnerabilities: z.boolean(),
          archCount: z.number(),
          sbomArchCount: z.number(),
          testArchCount: z.number(),
          passedTestArchCount: z.number(),
          vulnerabilityArchCount: z.number(),
        })
        .optional(),
      passed: z.boolean(),
      vulnSummary: z
        .object({
          critical: z.number(),
          high: z.number(),
          medium: z.number(),
          low: z.number(),
          scannedAt: NullableString,
          remediation: z
            .object({
              eligible: z.number(),
              baseLayer: z.number(),
              noFixedVersion: z.number(),
              belowPriorityThreshold: z.number(),
              otherDeferred: z.number(),
            })
            .optional(),
        })
        .nullable()
        .optional(),
      lifecycle: Lifecycle,
      runtimeContract: RuntimeContract,
      service: ServiceInfo.optional(),
    }),
  ),
});
export type CatalogIndex = z.infer<typeof CatalogIndex>;
