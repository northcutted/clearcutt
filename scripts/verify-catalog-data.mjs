#!/usr/bin/env node
// Fail the catalog build when the latest release would publish incomplete or
// contradictory trust data.

import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CATALOG_DIR = process.env.CATALOG_DIR || path.join(ROOT, 'site', 'src', 'data', 'catalog');
const strictEvidence = process.env.CATALOG_STRICT_EVIDENCE !== '0';

function readJson(file) {
  return JSON.parse(readFileSync(file, 'utf8'));
}

function releaseEvidence(entry) {
  const architectures = entry.architectures || [];
  const archCount = architectures.length;
  const sbomArchCount = architectures.filter((a) => (a.sbom?.packageCount || 0) > 0).length;
  const testArchCount = architectures.filter((a) => !!a.testResults).length;
  const passedTestArchCount = architectures.filter((a) => a.testResults?.status === 'passed').length;
  const vulnerabilityArchCount = architectures.filter((a) => !!a.vulnerabilities).length;

  return {
    signature: !!entry.signature?.cosignBundlePresent,
    provenance: !!entry.provenance,
    sbom: archCount > 0 && sbomArchCount === archCount,
    tests: archCount > 0 && testArchCount === archCount && passedTestArchCount === archCount,
    vulnerabilities: archCount > 0 && vulnerabilityArchCount === archCount,
    archCount,
    sbomArchCount,
    testArchCount,
    passedTestArchCount,
    vulnerabilityArchCount,
  };
}

function failFor(id, message) {
  return `${id}: ${message}`;
}

const indexPath = path.join(CATALOG_DIR, 'index.json');
if (!existsSync(indexPath)) {
  console.error(`[catalog-verify] missing ${indexPath}`);
  process.exit(1);
}

const index = readJson(indexPath);
const failures = [];
let checked = 0;

for (const summary of index.images || []) {
  if (summary.latestTag !== index.latestTag) continue;
  checked += 1;
  const imagePath = path.join(CATALOG_DIR, 'images', `${summary.id}.json`);
  if (!existsSync(imagePath)) {
    failures.push(failFor(summary.id, 'image record is missing'));
    continue;
  }

  const image = readJson(imagePath);
  const release = (image.releases || []).find((r) => r.tag === index.latestTag);
  if (!release) {
    failures.push(failFor(summary.id, `latest release ${index.latestTag} is missing from image record`));
    continue;
  }

  const evidence = release.evidence || releaseEvidence(release);
  const summaryEvidence = summary.evidence || {};

  if (summary.signed !== evidence.signature) {
    failures.push(failFor(summary.id, `index signed=${summary.signed} but signature evidence=${evidence.signature}`));
  }
  if (summary.provenance !== evidence.provenance) {
    failures.push(failFor(summary.id, `index provenance=${summary.provenance} but provenance evidence=${evidence.provenance}`));
  }
  for (const key of ['signature', 'provenance', 'sbom', 'tests', 'vulnerabilities']) {
    if (typeof summaryEvidence[key] === 'boolean' && summaryEvidence[key] !== evidence[key]) {
      failures.push(failFor(summary.id, `index evidence.${key}=${summaryEvidence[key]} but image evidence.${key}=${evidence[key]}`));
    }
  }

  if (!evidence.sbom) {
    failures.push(failFor(summary.id, `SBOM coverage incomplete (${evidence.sbomArchCount}/${evidence.archCount} archs)`));
  }
  if (!evidence.vulnerabilities) {
    failures.push(failFor(summary.id, `vulnerability scan coverage incomplete (${evidence.vulnerabilityArchCount}/${evidence.archCount} archs)`));
  }
  if (strictEvidence) {
    if (!evidence.signature) failures.push(failFor(summary.id, 'Sigstore signature is missing'));
    if (!evidence.provenance) failures.push(failFor(summary.id, 'SLSA provenance is missing'));
    if (!evidence.tests) {
      failures.push(failFor(summary.id, `test evidence incomplete (${evidence.passedTestArchCount}/${evidence.archCount} archs passed)`));
    }
  }
}

if (checked === 0) {
  failures.push(`no images are published for latest tag ${index.latestTag}`);
}

if (failures.length > 0) {
  console.error(`[catalog-verify] ${failures.length} catalog data issue(s):`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

const scope = strictEvidence
  ? 'complete signature, provenance, SBOM, test, and scan evidence'
  : 'complete SBOM/scan coverage and internally consistent evidence summaries';
console.log(`[catalog-verify] ok: ${checked} latest images have ${scope}.`);
