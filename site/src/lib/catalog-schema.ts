import { z } from 'zod';

export const PackageEntry = z.object({
  name: z.string(),
  version: z.string(),
  purl: z.string().nullable(),
  cpes: z.array(z.string()),
  license: z.string(),
  supplier: z.string(),
  nixStorePath: z.string().nullable(),
  spdxId: z.string(),
});
export type PackageEntry = z.infer<typeof PackageEntry>;

export const ArchPayload = z.object({
  arch: z.enum(['amd64', 'arm64']),
  os: z.string().default('linux'),
  imageDigest: z.string().nullable(),
  imageSize: z.number().nullable(),
  layerCount: z.number().nullable(),
  layers: z
    .array(z.object({ digest: z.string(), size: z.number() }))
    .default([]),
  labels: z.record(z.string()).default({}),
  sbom: z.object({
    tool: z.string(),
    createdAt: z.string(),
    rootDigest: z.string().nullable(),
    packageCount: z.number(),
    packages: z.array(PackageEntry),
  }),
  testResults: z
    .object({
      status: z.string(),
      timestamp: z.string().nullable(),
      assertions: z.array(z.object({ name: z.string(), status: z.string() })),
    })
    .nullable(),
  vulnerabilities: z
    .object({
      scannedAt: z.string(),
      scanner: z.string(),
      dbBuiltAt: z.string().nullable(),
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
          purl: z.string().nullable(),
          layer: z.enum(['runtime', 'base']).default('base'), // Add the layer classification field
          fixedIn: z.string().nullable(),
          fixState: z.string(),
          dataSource: z.string().nullable(),
          namespace: z.string().nullable(),
          description: z.string().nullable(),
          // Quantitative risk fields — all optional because older scans
          // didn't capture them and grype doesn't always have them per CVE.
          cvssScore: z.number().nullable().optional(),
          cvssVersion: z.string().nullable().optional(),
          cvssVector: z.string().nullable().optional(),
          epssScore: z.number().nullable().optional(),
          epssPercentile: z.number().nullable().optional(),
          riskScore: z.number().nullable().optional(),
        }),
      ),
    })
    .nullable()
    .optional(),
});
export type ArchPayload = z.infer<typeof ArchPayload>;

export const ReleaseEntry = z.object({
  tag: z.string(),
  publishedAt: z.string(),
  lastRebuiltAt: z.string().nullable().optional(), // Add lastRebuiltAt rebuild timestamp field
  isLatest: z.boolean(),
  manifestDigest: z.string().nullable(),
  totalSize: z.number().nullable(),
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
    .nullable(),
  provenance: z
    .object({
      predicateType: z.string(),
      builder: z.object({ id: z.string() }),
      buildType: z.string().nullable(),
      sourceUri: z.string().nullable(),
      sourceRevision: z.string().nullable(),
      slsaLevel: z.number(),
      raw: z.unknown().optional(),
    })
    .nullable(),
  assetUrls: z.object({
    sbom: z.record(z.string()).default({}),
    provenance: z.string().nullable(),
    testResults: z.record(z.string()).default({}),
    digest: z.string().nullable(),
  }),
});
export type ReleaseEntry = z.infer<typeof ReleaseEntry>;

export const ImageRecord = z.object({
  id: z.string(),
  language: z.object({
    id: z.string(),
    displayName: z.string(),
    version: z.string(),
    icon: z.string().nullable(),
  }),
  tier: z.object({
    id: z.enum(['dev', 'slim', 'distroless']),
    name: z.string(),
    blurb: z.string(),
  }),
  registry: z.string(),
  imageName: z.string(),
  fullName: z.string(),
  releases: z.array(ReleaseEntry),
});
export type ImageRecord = z.infer<typeof ImageRecord>;

export const CatalogIndex = z.object({
  generatedAt: z.string(),
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
      icon: z.string().nullable(),
    }),
  ),
  tiers: z.array(
    z.object({
      id: z.enum(['dev', 'slim', 'distroless']),
      name: z.string(),
      blurb: z.string(),
    }),
  ),
  images: z.array(
    z.object({
      id: z.string(),
      language: z.string(),
      languageDisplay: z.string(),
      languageVersion: z.string(),
      tier: z.enum(['dev', 'slim', 'distroless']),
      latestTag: z.string(),
      latestPackageCount: z.number(),
      architectures: z.array(z.string()),
      signed: z.boolean(),
      provenance: z.boolean(),
      passed: z.boolean(),
      vulnSummary: z
        .object({
          critical: z.number(),
          high: z.number(),
          medium: z.number(),
          low: z.number(),
          scannedAt: z.string().nullable(),
        })
        .nullable()
        .optional(),
    }),
  ),
});
export type CatalogIndex = z.infer<typeof CatalogIndex>;
