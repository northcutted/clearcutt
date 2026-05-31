import fs from 'node:fs';
import path from 'node:path';
import {
  CatalogIndex,
  ImageRecord,
  type ArchPayload,
  type CatalogIndex as CatalogIndexT,
  type ImageRecord as ImageRecordT,
} from './catalog-schema';

// Astro runs build steps with cwd set to the project root (site/). Data is
// generated there by core/scripts/gather-catalog.mjs before the build runs.
const DATA_ROOT = path.resolve(process.cwd(), 'src/data/catalog');

let cachedIndex: CatalogIndexT | null = null;

function publicBlurb(blurb: string): string {
  return blurb.replace('credential broker', 'credential helper');
}

function displayAssertionName(name: string): string {
  switch (name) {
    case 'Grype Vulnerability Gating':
      return 'Vulnerability gate';
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
  const file = path.join(DATA_ROOT, 'index.json');
  if (!fs.existsSync(file)) {
    throw new Error(
      `Catalog index not found at ${file}. Run core/scripts/gather-catalog.mjs first.`,
    );
  }
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  cachedIndex = publicCatalogIndex(CatalogIndex.parse(raw));
  return cachedIndex;
}

export function loadImage(id: string): ImageRecordT {
  const file = path.join(DATA_ROOT, 'images', `${id}.json`);
  if (!fs.existsSync(file)) {
    throw new Error(`Image record not found: ${id}`);
  }
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  return publicImageRecord(ImageRecord.parse(raw));
}

export function listImageIds(): string[] {
  const dir = path.join(DATA_ROOT, 'images');
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.replace(/\.json$/, ''));
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
