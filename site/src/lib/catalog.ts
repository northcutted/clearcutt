import fs from 'node:fs';
import path from 'node:path';
import {
  CatalogIndex,
  ImageRecord,
  type CatalogIndex as CatalogIndexT,
  type ImageRecord as ImageRecordT,
} from './catalog-schema';

// Astro runs build steps with cwd set to the project root (site/). Data is
// generated there by scripts/gather-catalog.mjs before the build runs.
const DATA_ROOT = path.resolve(process.cwd(), 'src/data/catalog');

let cachedIndex: CatalogIndexT | null = null;

export function loadIndex(): CatalogIndexT {
  if (cachedIndex) return cachedIndex;
  const file = path.join(DATA_ROOT, 'index.json');
  if (!fs.existsSync(file)) {
    throw new Error(
      `Catalog index not found at ${file}. Run scripts/gather-catalog.mjs first.`,
    );
  }
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  cachedIndex = CatalogIndex.parse(raw);
  return cachedIndex;
}

export function loadImage(id: string): ImageRecordT {
  const file = path.join(DATA_ROOT, 'images', `${id}.json`);
  if (!fs.existsSync(file)) {
    throw new Error(`Image record not found: ${id}`);
  }
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  return ImageRecord.parse(raw);
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
      return 'Builder tier — full toolchain, shells, debug utilities, credential broker.';
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
