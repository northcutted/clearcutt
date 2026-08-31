import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';

// Estate artifacts are produced by `clearcutt graph build` and
// `clearcutt graph layers`. They are staged under public/estate by
// `catalog site build --graph/--layers`, mirroring how catalog data lands in
// public/catalog. Both are OPTIONAL: a site with no estate scan is the common
// case, so every loader here returns null rather than throwing.
const DATA_ROOTS = [
  path.resolve(process.cwd(), 'public/estate'),
  path.resolve(process.cwd(), 'src/data/estate'),
];

const GraphSignal = z.object({
  type: z.string(),
  result: z.string(),
  weight: z.string(),
  detail: z.string().optional(),
});

const GraphEdge = z.object({
  consumerId: z.string().optional(),
  consumerRef: z.string(),
  consumerDigest: z.string().optional(),
  baseRepository: z.string(),
  baseRef: z.string(),
  baseDigest: z.string().optional(),
  baseCreated: z.string().optional(),
  currentBaseRef: z.string().optional(),
  currentBaseDigest: z.string().optional(),
  method: z.string(),
  confidence: z.string(),
  drift: z.string(),
  versionsBehind: z.number(),
  daysBehind: z.number(),
  signals: z.array(GraphSignal).default([]),
  notes: z.array(z.string()).default([]),
});

const BaseImageGraph = z.object({
  apiVersion: z.string(),
  kind: z.literal('BaseImageGraph'),
  generatedAt: z.string(),
  summary: z.object({
    observedImages: z.number(),
    baseFamilies: z.number(),
    consumers: z.number(),
    rootImages: z.number().default(0),
    resolvedConsumers: z.number(),
    unresolvedConsumers: z.number(),
    staleConsumers: z.number(),
    currentConsumers: z.number(),
    edgesByMethod: z.record(z.string(), z.number()).default({}),
    edgesByConfidence: z.record(z.string(), z.number()).default({}),
    distinctLayers: z.number().default(0),
    sharedLayers: z.number().default(0),
    widestLayerReach: z.number().default(0),
  }),
  bases: z.array(z.object({
    repository: z.string(),
    versions: z.number(),
    currentRef: z.string(),
    currentDigest: z.string().optional(),
    currentCreated: z.string().optional(),
    consumers: z.number(),
    staleConsumers: z.number(),
    warnings: z.array(z.string()).optional(),
  })).default([]),
  edges: z.array(GraphEdge).default([]),
  roots: z.array(z.object({
    imageId: z.string().optional(),
    imageRef: z.string(),
    repository: z.string(),
    reason: z.string(),
    consumers: z.number(),
  })).default([]),
  sharedLayers: z.array(z.object({
    digest: z.string(),
    size: z.number().optional(),
    imageCount: z.number(),
    images: z.array(z.string()),
  })).default([]),
  unresolved: z.array(z.object({
    consumerId: z.string().optional(),
    consumerRef: z.string(),
    reasons: z.array(z.string()),
  })).default([]),
  warnings: z.array(z.string()).default([]),
});

const LayerCommonalityGraph = z.object({
  apiVersion: z.string(),
  kind: z.literal('LayerCommonalityGraph'),
  generatedAt: z.string(),
  summary: z.object({
    images: z.number(),
    distinctLayers: z.number(),
    sharedLayers: z.number(),
    uniqueLayers: z.number(),
    coreLayers: z.number(),
    commonLayers: z.number(),
    coverageThreshold: z.number(),
    storedBytes: z.number(),
    naiveBytes: z.number(),
    sharingRatio: z.number(),
    identicalGroups: z.number(),
    clusters: z.number(),
    pairsCompared: z.number().default(0),
    pairsReported: z.number().default(0),
  }),
  images: z.array(z.object({
    ref: z.string(),
    layers: z.number(),
    sharedLayers: z.number(),
    uniqueLayers: z.number(),
    totalBytes: z.number(),
    sharedBytes: z.number(),
    uniqueBytes: z.number(),
    uniqueShare: z.number(),
  })).default([]),
  common: z.array(z.object({
    digest: z.string(),
    size: z.number().optional(),
    imageCount: z.number(),
    coverage: z.number(),
    images: z.array(z.string()),
  })).default([]),
  identical: z.array(z.object({
    layerCount: z.number(),
    bytes: z.number(),
    images: z.array(z.string()),
  })).default([]),
  clusters: z.array(z.object({
    id: z.number(),
    images: z.array(z.string()),
    sharedLayers: z.number(),
    sharedBytes: z.number(),
  })).default([]),
  similar: z.array(z.object({
    a: z.string(),
    b: z.string(),
    sharedLayers: z.number(),
    sharedBytes: z.number(),
    jaccard: z.number(),
    containment: z.number(),
  })).default([]),
  warnings: z.array(z.string()).default([]),
});

export type BaseImageGraphT = z.infer<typeof BaseImageGraph>;
export type LayerCommonalityGraphT = z.infer<typeof LayerCommonalityGraph>;
export type GraphEdgeT = z.infer<typeof GraphEdge>;

function loadArtifact<T>(fileName: string, schema: z.ZodType<T>): T | null {
  for (const root of DATA_ROOTS) {
    const file = path.join(root, fileName);
    if (!fs.existsSync(file)) continue;
    const parsed = schema.safeParse(JSON.parse(fs.readFileSync(file, 'utf8')));
    if (!parsed.success) {
      // A malformed artifact is worth surfacing: it means the CLI and the site
      // disagree about the contract, which silent-nulling would hide.
      throw new Error(`${file} does not match the expected schema: ${parsed.error.message}`);
    }
    return parsed.data;
  }
  return null;
}

export function loadGraph(): BaseImageGraphT | null {
  return loadArtifact('graph.json', BaseImageGraph);
}

export function loadLayerGraph(): LayerCommonalityGraphT | null {
  return loadArtifact('layers.json', LayerCommonalityGraph);
}

/** hasEstate reports whether either artifact is present, for nav gating. */
export function hasEstate(): boolean {
  return DATA_ROOTS.some(
    (root) => fs.existsSync(path.join(root, 'graph.json')) || fs.existsSync(path.join(root, 'layers.json')),
  );
}

/**
 * Only layer-digest matching is proof; every other method reports a claim the
 * image's own author made. The site must never present the two as one number.
 */
export const PROOF_METHOD = 'layer-prefix';

export const METHOD_LABELS: Record<string, { label: string; strength: string; meaning: string }> = {
  'layer-prefix': {
    label: 'Layer digests',
    strength: 'proof',
    meaning: "The consumer's leading layer digests are the base's layers.",
  },
  'oci-base-digest': {
    label: 'OCI base digest',
    strength: 'declared',
    meaning: 'org.opencontainers.image.base.digest names this base. Exact, but self-reported.',
  },
  'buildpacks-metadata': {
    label: 'Buildpacks metadata',
    strength: 'declared',
    meaning: 'CNB lifecycle metadata names this run image. Exact, but self-reported.',
  },
  'oci-base-name': {
    label: 'OCI base name',
    strength: 'assisted',
    meaning: 'org.opencontainers.image.base.name names the repository but not a version.',
  },
  history: {
    label: 'Build history',
    strength: 'weak',
    meaning: "The base repository appears in the consumer's build history.",
  },
};

/** provenBreakdown splits resolved edges into proven and self-reported. */
export function provenBreakdown(graph: BaseImageGraphT): { proven: number; claimed: number } {
  const proven = graph.summary.edgesByMethod[PROOF_METHOD] ?? 0;
  return { proven, claimed: Math.max(0, graph.summary.resolvedConsumers - proven) };
}

/** shortRef trims a reference to its last path segment for table display. */
export function shortRef(ref: string): string {
  const slash = ref.lastIndexOf('/');
  return slash >= 0 ? ref.slice(slash + 1) : ref;
}

/** humanBytes formats a compressed layer size. */
export function humanBytes(size: number): string {
  if (!size || size <= 0) return '—';
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${Math.round(size / 1024)} KB`;
  if (size < 1024 * 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  return `${(size / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
