import fs from 'node:fs';
import path from 'node:path';
import {
  CatalogIndex,
  ImageRecord,
  type ArchPayload,
  type CatalogIndex as CatalogIndexT,
  type ImageRecord as ImageRecordT,
} from './catalog-schema';

// Astro runs build steps with cwd set to the project root. The source repo keeps
// generated data under src/data/catalog, while scaffolded sites copy portable
// catalog artifacts under public/catalog so they are also deployed as static
// assets.
const DATA_ROOTS = [
  path.resolve(process.cwd(), 'public/catalog'),
  path.resolve(process.cwd(), 'src/data/catalog'),
];

let cachedIndex: CatalogIndexT | null = null;

function publicBlurb(blurb: string): string {
  return blurb.replace('credential broker', 'credential helper');
}

function displayAssertionName(name: string): string {
  switch (name) {
    case 'Grype Vulnerability Gating':
      return 'Vulnerability check';
    case 'Syft SBOM Generation':
      return 'SBOM generation';
    default:
      return name;
  }
}

function publicArchPayload(arch: ArchPayload): ArchPayload {
  return {
    ...arch,
    testResults: arch.testResults
      ? {
          ...arch.testResults,
          assertions: arch.testResults.assertions.map((assertion) => ({
            ...assertion,
            name: displayAssertionName(assertion.name),
          })),
        }
      : arch.testResults,
    vulnerabilities: arch.vulnerabilities
      ? {
          ...arch.vulnerabilities,
          scanner: arch.vulnerabilities.scanner.toLowerCase().startsWith('grype')
            ? 'vulnerability-check'
            : arch.vulnerabilities.scanner,
        }
      : arch.vulnerabilities,
  };
}

function publicImageRecord(image: ImageRecordT): ImageRecordT {
  return {
    ...image,
    tier: {
      ...image.tier,
      blurb: publicBlurb(image.tier.blurb),
    },
    releases: image.releases.map((release) => ({
      ...release,
      architectures: release.architectures.map(publicArchPayload),
    })),
  };
}

function publicCatalogIndex(index: CatalogIndexT): CatalogIndexT {
  return {
    ...index,
    tiers: index.tiers.map((tier) => ({
      ...tier,
      blurb: publicBlurb(tier.blurb),
    })),
  };
}

export function loadIndex(): CatalogIndexT {
  if (cachedIndex) return cachedIndex;
  const dataRoot = resolveDataRoot();
  const file = path.join(dataRoot, 'index.json');
  if (!fs.existsSync(file)) {
    throw new Error(
      `Catalog index not found at ${file}. Run clearcutt catalog generate first.`,
    );
  }
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  cachedIndex = publicCatalogIndex(CatalogIndex.parse(raw));
  return cachedIndex;
}

export function loadImage(id: string): ImageRecordT {
  const dataRoot = resolveDataRoot();
  const file = path.join(dataRoot, 'images', `${id}.json`);
  if (!fs.existsSync(file)) {
    throw new Error(`Image record not found: ${id}`);
  }
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  return publicImageRecord(ImageRecord.parse(raw));
}

export function loadCatalogArtifact(relativePath: string): string {
  const dataRoot = resolveDataRoot();
  const file = path.join(dataRoot, relativePath);
  if (!fs.existsSync(file)) {
    throw new Error(`Catalog artifact not found: ${relativePath}`);
  }
  return fs.readFileSync(file, 'utf8');
}

export function listImageIds(): string[] {
  return loadIndex().images.map((image) => image.id);
}

function resolveDataRoot(): string {
  for (const root of DATA_ROOTS) {
    if (fs.existsSync(path.join(root, 'index.json'))) {
      return root;
    }
  }
  return DATA_ROOTS[0];
}

export function tierDescription(id: 'dev' | 'slim' | 'distroless'): string {
  switch (id) {
    case 'dev':
      return 'Builder tier — full toolchain, shells, debug utilities, credential helper.';
    case 'slim':
      return 'Runtime tier — language runtime plus minimal troubleshooting binaries.';
    case 'distroless':
      return 'Hardened tier — no shells, no coreutils, runtime only.';
  }
}

export function languageDisplayName(id: string): string {
  switch (id) {
    case 'core':
      return 'Core';
    case 'java':
      return 'Java';
    case 'node':
      return 'Node.js';
    case 'python':
      return 'Python';
    case 'go':
      return 'Go';
    case 'dotnet':
      return '.NET';
    default:
      return id;
  }
}
