#!/usr/bin/env node
// Build the catalog JSON files consumed by the Astro site at build time.
//
// Inputs (in priority order):
//   1) Environment vars: GH_OWNER, GH_REPO (default: parse `git remote get-url origin`)
//      GITHUB_TOKEN (optional, for higher rate limits / private repos)
//      ENRICHMENT_DIR (optional, output of enrich-registry.mjs merged in)
//   2) --limit N to restrict to N most recent releases (default: 10)
//
// Outputs:
//   ../../site/src/data/catalog/index.json
//   ../../site/src/data/catalog/images/<lang><ver>-<tier>.json

import fs from 'node:fs/promises';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const CORE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = path.resolve(CORE_ROOT, '..');
const OUT_DIR = path.join(REPO_ROOT, 'site', 'src', 'data', 'catalog');
const IMG_DIR = path.join(OUT_DIR, 'images');
const ENRICHMENT_DIR =
  process.env.ENRICHMENT_DIR || path.join(REPO_ROOT, 'site', 'src', 'data', 'enrichment');
// Downloaded SBOMs are persisted here so scan-vulnerabilities.mjs can run
// grype against local files without re-fetching from GitHub.
const SBOM_CACHE_DIR =
  process.env.SBOM_CACHE_DIR || path.join(REPO_ROOT, 'site', 'src', 'data', 'sboms');
const VULN_DIR =
  process.env.VULN_DIR || path.join(REPO_ROOT, 'site', 'src', 'data', 'vulnerabilities');

const LANGUAGES = {
  coreLTS: { id: 'core', display: 'Core', version: 'LTS' },
  java21: { id: 'java', display: 'Java', version: '21' },
  java25: { id: 'java', display: 'Java', version: '25' },
  node22: { id: 'node', display: 'Node.js', version: '22' },
  node24: { id: 'node', display: 'Node.js', version: '24' },
  'python3.13': { id: 'python', display: 'Python', version: '3.13' },
  'python3.14': { id: 'python', display: 'Python', version: '3.14' },
  'go1.25': { id: 'go', display: 'Go', version: '1.25' },
  'go1.26': { id: 'go', display: 'Go', version: '1.26' },
  dotnet8: { id: 'dotnet', display: '.NET', version: '8' },
  dotnet10: { id: 'dotnet', display: '.NET', version: '10' },
  'rust1.95': { id: 'rust', display: 'Rust', version: '1.95' },
  'cc15': { id: 'cc', display: 'C/C++', version: '15' },
};

const TIERS = {
  dev: { name: 'Dev', blurb: 'Builder tier — full toolchain, shells, debug utilities, credential helper.' },
  slim: { name: 'Slim', blurb: 'Runtime tier — language runtime plus minimal troubleshooting binaries.' },
  distroless: { name: 'Distroless', blurb: 'Hardened tier — no shells, no coreutils, runtime only.' },
};

function determineLifecycle(target, tier) {
  const idx = target.lastIndexOf('-');
  const langKey = idx !== -1 ? target.slice(0, idx) : target;

  let status = 'preview';
  let support = 'preview';
  let productionAllowed = false;

  if (tier === 'dev') {
    productionAllowed = false;
  }

  if (langKey === 'coreLTS') {
    status = 'active';
    support = 'lts';
    if (tier !== 'dev') productionAllowed = true;
  } else if (langKey === 'java21') {
    status = 'active';
    support = 'lts';
    if (tier !== 'dev') productionAllowed = true;
  } else if (langKey === 'java25') {
    status = 'preview';
    support = 'preview';
    productionAllowed = false;
  } else if (langKey === 'node22') {
    status = 'active';
    support = 'lts';
    if (tier !== 'dev') productionAllowed = true;
  } else if (langKey === 'node24') {
    status = 'preview';
    support = 'preview';
    productionAllowed = false;
  } else if (langKey === 'python3.13') {
    status = 'active';
    support = 'current';
    if (tier !== 'dev') productionAllowed = true;
  } else if (langKey === 'python3.14') {
    status = 'preview';
    support = 'preview';
    productionAllowed = false;
  } else if (langKey === 'dotnet8') {
    status = 'active';
    support = 'lts';
    if (tier !== 'dev') productionAllowed = true;
  } else if (langKey === 'dotnet10') {
    status = 'preview';
    support = 'preview';
    productionAllowed = false;
  } else if (['go1.25', 'go1.26', 'rust1.95', 'cc15'].includes(langKey)) {
    status = 'experimental';
    support = 'unsupported';
    productionAllowed = false;
  }

  return {
    status,
    support,
    productionAllowed,
    deprecatedAt: null,
    eolAt: null,
    reason: null,
  };
}

function determineRuntimeContract(target, tier) {
  const idx = target.lastIndexOf('-');
  const langKey = idx !== -1 ? target.slice(0, idx) : target;

  let defaultEntrypoint = null;
  if (langKey.startsWith('java')) {
    defaultEntrypoint = '/usr/local/bin/java';
  } else if (langKey.startsWith('node')) {
    defaultEntrypoint = '/usr/bin/node';
  } else if (langKey.startsWith('python')) {
    defaultEntrypoint = '/usr/bin/python';
  } else if (langKey.startsWith('go')) {
    defaultEntrypoint = '/usr/bin/go';
  } else if (langKey.startsWith('dotnet')) {
    defaultEntrypoint = '/usr/bin/dotnet';
  } else if (langKey === 'coreLTS') {
    defaultEntrypoint = '/bin/sh';
  }

  let shellPresent = true;
  let packageManagerPresent = true;
  let productionTier = false;

  if (tier === 'slim') {
    shellPresent = true;
    packageManagerPresent = false;
    productionTier = true;
  } else if (tier === 'distroless') {
    shellPresent = false;
    packageManagerPresent = false;
    productionTier = true;
  } else {
    shellPresent = true;
    packageManagerPresent = true;
    productionTier = false;
  }

  return {
    user: '10001',
    workingDir: '/app',
    shellPresent,
    packageManagerPresent,
    caCertificatesPresent: true,
    timezoneDataPresent: true,
    defaultEntrypoint,
    productionTier,
  };
}

function defaultExceptions() {
  return {
    total: 0,
    expired: 0,
    active: 0,
    acceptedRisk: 0,
    noFixAvailable: 0,
    falsePositive: 0,
    inheritedFromBase: 0,
  };
}

const args = parseArgs(process.argv.slice(2));
const LIMIT = Number(args.limit ?? process.env.RELEASE_LIMIT ?? 10);
const TARGET_FILTER = new Set(
  (process.env.CATALOG_TARGETS || '')
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean),
);

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true';
      out[k] = v;
    }
  }
  return out;
}

function targetAllowed(target) {
  return TARGET_FILTER.size === 0 || TARGET_FILTER.has(target);
}

function sh(cmd) {
  return execSync(cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function remediationReason(finding) {
  if (finding.remediation?.reason) return finding.remediation.reason;
  const sev = String(finding.severity || 'Unknown').toLowerCase();
  if ((finding.layer || 'base') !== 'runtime') return 'base_layer';
  if (sev !== 'critical' && sev !== 'high') return 'below_priority_threshold';
  if (!finding.fixedIn) return 'no_fixed_version';
  return 'fix_available';
}

function remediationBucket(reason) {
  switch (reason) {
    case 'fix_available':
      return 'eligible';
    case 'base_layer':
      return 'baseLayer';
    case 'no_fixed_version':
      return 'noFixedVersion';
    case 'below_priority_threshold':
      return 'belowPriorityThreshold';
    default:
      return 'otherDeferred';
  }
}

function displayAssertionName(name) {
  switch (name) {
    case 'Grype Vulnerability Gating':
      return 'Vulnerability gate';
    case 'Syft SBOM Generation':
      return 'SBOM generation';
    default:
      return name;
  }
}

function normalizeAssertions(assertions) {
  return (assertions || []).map((assertion) => ({
    ...assertion,
    name: displayAssertionName(assertion.name || ''),
  }));
}

function releaseEvidence(entry) {
  const architectures = entry.architectures || [];
  const archCount = architectures.length;
  const sbomArchCount = architectures.filter((a) => (a.sbom?.packageCount || 0) > 0).length;
  const testArchCount = architectures.filter((a) => !!a.testResults).length;
  const passedTestArchCount = architectures.filter(
    (a) => a.testResults?.status === 'passed',
  ).length;
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

function summarizeImageForIndex(img) {
  const latestRel = img.releases[0];
  const arches = latestRel.architectures.map((a) => a.arch);
  const totalPkgs =
    latestRel.architectures.reduce((s, a) => s + a.sbom.packageCount, 0) /
      Math.max(1, latestRel.architectures.length) || 0;
  const passed =
    latestRel.architectures.length > 0 &&
    latestRel.architectures.every((a) => a.testResults?.status === 'passed');
  let vulnSummary = null;
  const archsWithVulns = latestRel.architectures.filter((a) => a.vulnerabilities);
  if (archsWithVulns.length > 0) {
    // amd64 and arm64 share an identical Nix closure, so the same CVE is
    // reported once per arch. Union findings by identity (CVE id + package +
    // version) before counting so the catalog badge reflects DISTINCT findings
    // — summing per-arch countsBySeverity would ~double every number and
    // disagree with the per-image table (which shows a single arch at a time).
    const distinct = new Map();
    let scannedAt = null;
    for (const a of archsWithVulns) {
      for (const finding of a.vulnerabilities.findings || []) {
        const key = `${finding.id}::${finding.packageName}::${finding.packageVersion}`;
        if (!distinct.has(key)) distinct.set(key, finding);
      }
      if (!scannedAt || a.vulnerabilities.scannedAt > scannedAt) {
        scannedAt = a.vulnerabilities.scannedAt;
      }
    }

    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    const remediation = {
      eligible: 0,
      baseLayer: 0,
      noFixedVersion: 0,
      belowPriorityThreshold: 0,
      otherDeferred: 0,
    };
    for (const finding of distinct.values()) {
      const sev = String(finding.severity || '').toLowerCase();
      if (sev in counts) counts[sev] += 1;
      if (sev === 'critical' || sev === 'high') {
        remediation[remediationBucket(remediationReason(finding))] += 1;
      }
    }
    vulnSummary = { ...counts, scannedAt, remediation };
  }

  return {
    id: img.id,
    language: img.language.id,
    languageDisplay: img.language.displayName,
    languageVersion: img.language.version,
    tier: img.tier.id,
    latestTag: latestRel.tag,
    latestManifestDigest: latestRel.manifestDigest ?? null,
    latestPackageCount: Math.round(totalPkgs),
    architectures: arches,
    signed: !!latestRel.signature?.cosignBundlePresent,
    provenance: !!latestRel.provenance,
    evidence: latestRel.evidence ?? releaseEvidence(latestRel),
    passed,
    vulnSummary,
    lifecycle: img.lifecycle,
    runtimeContract: img.runtimeContract,
  };
}

function detectRepo() {
  if (process.env.GH_OWNER && process.env.GH_REPO) {
    return { owner: process.env.GH_OWNER, repo: process.env.GH_REPO };
  }
  if (process.env.GITHUB_REPOSITORY) {
    const [owner, repo] = process.env.GITHUB_REPOSITORY.split('/');
    return { owner, repo };
  }
  try {
    const url = sh('git remote get-url origin').trim();
    const m =
      url.match(/github\.com[:/]+([^/]+)\/([^/.]+)/) ||
      url.match(/^([^/]+)\/([^/.]+)$/);
    if (m) return { owner: m[1], repo: m[2] };
  } catch {}
  throw new Error('Unable to detect GH repo. Set GH_OWNER and GH_REPO.');
}

const { owner, repo } = detectRepo();
const REPO_LC = `${owner.toLowerCase()}/${repo.toLowerCase()}`;
const REGISTRY_BASE = `ghcr.io/${REPO_LC}`;

console.log(`[gather] repo=${owner}/${repo}  out=${OUT_DIR}`);

async function ghJson(pathname) {
  const url = `https://api.github.com${pathname}`;
  const headers = { Accept: 'application/vnd.github+json' };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  const res = await fetch(url, { headers });
  if (!res.ok) {
    throw new Error(`GitHub API ${res.status} ${res.statusText} for ${url}`);
  }
  return res.json();
}

async function listReleases() {
  const raw = await ghJson(`/repos/${owner}/${repo}/releases?per_page=${LIMIT * 2}`);
  return raw
    .filter((r) => !r.draft)
    .slice(0, LIMIT)
    .map((r) => ({
      tag: r.tag_name,
      name: r.name,
      publishedAt: r.published_at || r.created_at,
      prerelease: r.prerelease,
      assets: (r.assets || []).map((a) => ({
        name: a.name,
        url: a.browser_download_url,
        size: a.size,
        digest: a.digest,
      })),
    }));
}

async function downloadAsset(asset) {
  const headers = { Accept: 'application/octet-stream' };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  const res = await fetch(asset.url, { headers, redirect: 'follow' });
  if (!res.ok) {
    throw new Error(`Asset download ${res.status} for ${asset.name}`);
  }
  return Buffer.from(await res.arrayBuffer());
}

function parseTargetName(filename) {
  // e.g. java25-distroless.sbom.json -> { target: 'java25-distroless', kind: 'sbom' }
  const m = filename.match(/^(.+?)\.(sbom|test-results|intoto|digest|sigstore)\.(json|jsonl)$/);
  if (!m) return null;
  return { target: m[1], kind: m[2], ext: m[3], filename };
}

function targetMeta(target) {
  // target = "<langKey>-<tier>" but langKey may contain dots (python3.13, go1.25) and dashes? No, just dots.
  const idx = target.lastIndexOf('-');
  if (idx === -1) return null;
  const langKey = target.slice(0, idx);
  const tier = target.slice(idx + 1);
  if (!LANGUAGES[langKey] || !TIERS[tier]) return null;
  return { langKey, tier };
}

function extractNixStorePath(sourceInfo) {
  if (!sourceInfo) return null;
  const m = sourceInfo.match(/(\/nix\/store\/[^\s]+)/);
  return m ? m[1] : null;
}

function pickLicense(pkg) {
  const candidates = [pkg.licenseDeclared, pkg.licenseConcluded];
  for (const c of candidates) {
    if (c && c !== 'NOASSERTION') return c;
  }
  return 'NOASSERTION';
}

function mapPackageIdToLayerDigest(spdx) {
  const fileToLayer = new Map();
  for (const f of spdx.files || []) {
    if (f.comment && f.comment.startsWith('layerID: ')) {
      const digest = f.comment.replace('layerID: ', '').trim();
      fileToLayer.set(f.SPDXID, digest);
    }
  }

  const packageToLayer = new Map();
  for (const r of spdx.relationships || []) {
    if (r.relationshipType === 'OTHER' && r.spdxElementId && r.relatedSpdxElement) {
      const layerDigest = fileToLayer.get(r.relatedSpdxElement);
      if (layerDigest) {
        packageToLayer.set(r.spdxElementId, layerDigest);
      }
    }
  }
  return packageToLayer;
}

function compactPackages(spdx) {
  const packageToLayer = mapPackageIdToLayerDigest(spdx);
  const items = [];
  for (const p of spdx.packages || []) {
    // Skip the image-root pseudo-package
    if (p.primaryPackagePurpose === 'CONTAINER') continue;
    const cpes = [];
    let purl = null;
    for (const ref of p.externalRefs || []) {
      if (ref.referenceType === 'cpe23Type') cpes.push(ref.referenceLocator);
      else if (ref.referenceType === 'purl' && !purl) purl = ref.referenceLocator;
    }
    items.push({
      name: p.name,
      version: p.versionInfo || '',
      purl,
      cpes,
      license: pickLicense(p),
      supplier: p.supplier || 'NOASSERTION',
      nixStorePath: extractNixStorePath(p.sourceInfo),
      spdxId: p.SPDXID,
      layerDigest: packageToLayer.get(p.SPDXID) || null,
    });
  }
  items.sort((a, b) => a.name.localeCompare(b.name));
  return items;
}

function rootDigest(spdx) {
  const container = (spdx.packages || []).find((p) => p.primaryPackagePurpose === 'CONTAINER');
  if (!container) return null;
  const sha = (container.checksums || []).find((c) => c.algorithm === 'SHA256');
  if (sha) return `sha256:${sha.checksumValue}`;
  if (container.versionInfo?.startsWith('sha256:')) return container.versionInfo;
  return null;
}

function isUsefulProvenanceSummary(provenance) {
  if (!provenance) return false;
  return (
    provenance.predicateType !== 'unknown' ||
    provenance.builder?.id !== 'unknown' ||
    !!provenance.buildType ||
    !!provenance.sourceUri ||
    !!provenance.sourceRevision
  );
}

function decodeIntotoPayload(env) {
  const dsse = env.dsseEnvelope || env;
  if (dsse.payload) {
    try {
      const decoded = Buffer.from(dsse.payload, 'base64').toString('utf8');
      return JSON.parse(decoded);
    } catch {
      return null;
    }
  }
  if (env.predicateType) {
    return env;
  }
  return null;
}

function firstGitDependency(pred) {
  return (
    pred.buildDefinition?.resolvedDependencies || pred.materials || []
  ).find((dep) => typeof dep?.uri === 'string' && dep.uri.includes('github.com'));
}

function summarizeIntotoStatement(payloadJson) {
  const out = {
    predicateType: payloadJson.predicateType || 'unknown',
    builder: { id: 'unknown' },
    buildType: null,
    sourceUri: null,
    sourceRevision: null,
    slsaLevel: 3,
    raw: payloadJson,
  };
  const pred = payloadJson.predicate || {};
  const buildDefinition = pred.buildDefinition || {};
  const workflow = buildDefinition.externalParameters?.workflow || {};
  const configSource = pred.invocation?.configSource || buildDefinition.externalParameters?.source;
  const gitDependency = firstGitDependency(pred);

  out.builder.id = pred.builder?.id || pred.runDetails?.builder?.id || 'unknown';
  out.buildType = pred.buildType || buildDefinition.buildType || null;
  out.sourceUri =
    configSource?.uri ||
    workflow.repository ||
    buildDefinition.externalParameters?.sourceUri ||
    gitDependency?.uri ||
    null;
  out.sourceRevision =
    configSource?.digest?.sha1 ||
    configSource?.digest?.gitCommit ||
    buildDefinition.externalParameters?.source?.digest?.sha1 ||
    buildDefinition.externalParameters?.source?.digest?.gitCommit ||
    gitDependency?.digest?.gitCommit ||
    gitDependency?.digest?.sha1 ||
    null;

  return out;
}

function summarizeProvenance(intotoJsonl) {
  // jsonl: each line is either a DSSE envelope { payload (base64), payloadType, signatures }
  // or a raw in-toto Statement JSON object.
  const fallback = {
    predicateType: 'unknown',
    builder: { id: 'unknown' },
    buildType: null,
    sourceUri: null,
    sourceRevision: null,
    slsaLevel: 3,
    raw: null,
  };
  let best = null;
  const lines = intotoJsonl.split('\n').filter(Boolean);
  for (const line of lines) {
    let env;
    try { env = JSON.parse(line); } catch { continue; }
    const payloadJson = decodeIntotoPayload(env);
    if (!payloadJson) continue;

    const summary = summarizeIntotoStatement(payloadJson);
    if (summary.predicateType?.includes('slsa.dev/provenance')) return summary;
    if (!best && isUsefulProvenanceSummary(summary)) best = summary;
  }
  return best || fallback;
}

function attachReleaseAssetLinks(attestations, { provenanceUrl }) {
  return (attestations || []).map((attestation) => ({
    ...attestation,
    releaseAssetUrl:
      attestation.releaseAssetUrl ||
      (attestation.kind === 'slsa-provenance' && attestation.sources?.includes('oci')
        ? provenanceUrl || null
        : null),
  }));
}

function loadEnrichment(tag, target) {
  const p = path.join(ENRICHMENT_DIR, tag, `${target}.json`);
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

function loadVulnerabilities(tag, target, arch) {
  const p = path.join(VULN_DIR, tag, `${target}-${arch}.json`);
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

function archForSystem(system) {
  if (system.includes('aarch64') || system.includes('arm64')) return 'arm64';
  return 'amd64';
}

async function buildImageRecord(target, releases, refreshSet) {
  const meta = targetMeta(target);
  if (!meta) return null;
  const { langKey, tier } = meta;
  const langInfo = LANGUAGES[langKey];
  const imageName = `clearcutt-${langKey.toLowerCase()}`;
  const fullName = `${REGISTRY_BASE}/${imageName}`;

  const releaseEntries = [];
  let isLatestSet = false;

  for (const rel of releases) {
    const mustRefresh = refreshSet.has(rel.tag);
    // Prefer arch-suffixed assets (clean, post-fix); fall back to unsuffixed
    // for old releases where same-name SBOMs raced and corrupted each other.
    const archSuffixed = rel.assets.filter(
      (a) =>
        (a.name.startsWith(`${target}-amd64.`) ||
          a.name.startsWith(`${target}-arm64.`)) &&
        a.name.endsWith('.sbom.json'),
    );
    const legacyUnsuffixed = rel.assets.filter(
      (a) => a.name === `${target}.sbom.json`,
    );
    const sbomAssets = archSuffixed.length > 0 ? archSuffixed : legacyUnsuffixed;
    if (sbomAssets.length === 0) continue; // image not in this release

    const provAsset = rel.assets.find((a) => a.name === `${target}.intoto.jsonl`);
    const digestAsset = rel.assets.find((a) => a.name === `${target}.digest.json`);
    const testAssetsArch = rel.assets.filter(
      (a) =>
        (a.name.startsWith(`${target}-amd64.`) ||
          a.name.startsWith(`${target}-arm64.`)) &&
        a.name.endsWith('.test-results.json'),
    );
    const testAssetsLegacy = rel.assets.filter(
      (a) => a.name === `${target}.test-results.json`,
    );
    const testAssets = testAssetsArch.length > 0 ? testAssetsArch : testAssetsLegacy;

    // Collect per-arch payloads
    const archMap = new Map();
    for (const a of sbomAssets) {
      // Cache hit path: if this release is not in the refresh set AND a
      // cached SBOM exists on disk, skip the GH download entirely. Old
      // release assets are immutable, so disk is canonical for them.
      const arch = guessArchFromAsset(a.name);
      const cachePath = path.join(SBOM_CACHE_DIR, rel.tag, `${target}-${arch}.sbom.json`);
      let buf;
      if (!mustRefresh && existsSync(cachePath)) {
        try { buf = readFileSync(cachePath); } catch { buf = null; }
      }
      if (!buf) {
        try {
          buf = await downloadAsset(a);
        } catch (err) {
          console.warn(`[gather]   skip ${a.name}: download failed: ${err.message}`);
          continue;
        }
      }
      let spdx;
      try {
        spdx = JSON.parse(buf.toString('utf8'));
      } catch (err) {
        console.warn(`[gather]   skip ${a.name}: parse failed (${err.message})`);
        continue;
      }
      // Persist the SBOM to disk so the vulnerability scanner can read it
      // (only on miss; cached path already has the file).
      if (mustRefresh || !existsSync(cachePath)) {
        try {
          mkdirSync(path.join(SBOM_CACHE_DIR, rel.tag), { recursive: true });
          await fs.writeFile(cachePath, buf);
        } catch (err) {
          console.warn(`[gather]   warn: could not persist SBOM for ${target} ${arch}: ${err.message}`);
        }
      }
      archMap.set(arch, {
        arch,
        os: 'linux',
        imageDigest: null,
        imageSize: null,
        layerCount: null,
        layers: [],
        labels: {},
        sbom: {
          tool: (spdx.creationInfo?.creators || []).find((c) => c.startsWith('Tool:'))?.replace('Tool:', '').trim() || 'syft',
          createdAt: spdx.creationInfo?.created || rel.publishedAt,
          rootDigest: rootDigest(spdx),
          packageCount: 0,
          packages: [],
        },
        testResults: null,
      });
      const compact = compactPackages(spdx);
      const entry = archMap.get(arch);
      entry.sbom.packageCount = compact.length;
      entry.sbom.packages = compact;
    }

    // Test results — prefer per-arch suffixed assets; legacy unsuffixed treated as
    // applying to all archs.
    const perArchTest = new Map();
    let legacyTest = null;
    for (const t of testAssets) {
      let buf;
      try { buf = await downloadAsset(t); } catch { continue; }
      let parsed;
      try { parsed = JSON.parse(buf.toString('utf8')); } catch { continue; }
      const arch = guessArchFromAsset(t.name);
      if (t.name.startsWith(`${target}-`)) perArchTest.set(arch, parsed);
      else legacyTest = parsed;
    }
    for (const [arch, v] of archMap.entries()) {
      const tr = perArchTest.get(arch) ?? legacyTest;
      if (!tr) continue;
      v.testResults = {
        status: tr.status,
        timestamp: tr.timestamp || null,
        assertions: normalizeAssertions(tr.assertions),
      };
    }

    let provenance = null;
    if (provAsset) {
      const buf = await downloadAsset(provAsset);
      provenance = summarizeProvenance(buf.toString('utf8'));
    }

    let manifestDigest = null;
    if (digestAsset) {
      const buf = await downloadAsset(digestAsset);
      try { manifestDigest = JSON.parse(buf.toString('utf8')).digest || null; } catch {}
    }

    // Merge in enrichment (manifest, layers, labels, signatures, attestations)
    // if available. Enrichment is the canonical source for provenance/signature
    // since those live on the GHCR manifest, not the release-asset upload.
    const enrich = loadEnrichment(rel.tag, target);
    if (enrich) {
      manifestDigest = enrich.manifestDigest || manifestDigest;
      for (const archEnr of enrich.architectures || []) {
        const arch = archEnr.arch;
        if (!archMap.has(arch)) {
          archMap.set(arch, defaultArchPayload(arch, rel.publishedAt));
        }
        const v = archMap.get(arch);
        v.imageDigest = archEnr.digest ?? v.imageDigest;
        v.imageSize = archEnr.size ?? v.imageSize;
        v.layerCount = archEnr.layers?.length ?? v.layerCount;
        v.layers = archEnr.layers ?? v.layers;
        v.labels = archEnr.labels ?? v.labels;
      }
      // Fall back to enrichment provenance if the release-asset intoto copy is
      // absent or too old to parse. Attestations on the GHCR manifest are the
      // authoritative source — release assets are a duplicate copy that can
      // fail to upload or change envelope shape across tooling versions.
      if ((!provenance || !isUsefulProvenanceSummary(provenance)) && enrich.provenance) {
        provenance = {
          predicateType: enrich.provenance.predicateType,
          builder: enrich.provenance.builder,
          buildType: enrich.provenance.buildType,
          sourceUri: enrich.provenance.sourceUri,
          sourceRevision: enrich.provenance.sourceRevision,
          slsaLevel: enrich.provenance.slsaLevel ?? 3,
          raw: null,
        };
      }
      // Same fallback for test results when the cosign --type custom envelope
      // is present on the image even if the release-asset was racy/missing.
      if (enrich.testResults) {
        for (const v of archMap.values()) {
          if (v.testResults) continue;
          v.testResults = {
            status: enrich.testResults.status ?? 'unknown',
            timestamp: enrich.testResults.timestamp ?? null,
            assertions: normalizeAssertions(enrich.testResults.assertions),
          };
        }
      }
    }

    // Fold in vulnerability scan output if available (second-pass run).
    let lastRebuiltAt = rel.publishedAt;
    for (const [arch, v] of archMap.entries()) {
      const vuln = loadVulnerabilities(rel.tag, target, arch);
      if (vuln) {
        v.vulnerabilities = vuln;
        if (vuln.scannedAt) lastRebuiltAt = vuln.scannedAt;
      }
    }

    const architectures = Array.from(archMap.values()).sort((a, b) =>
      a.arch.localeCompare(b.arch),
    );

    // If we couldn't get any usable SBOM for this release, skip the release entirely
    // (rather than emit an empty/broken record).
    if (architectures.length === 0) continue;

    const isLatest = !isLatestSet && !rel.prerelease;
    if (isLatest) isLatestSet = true;

    const releaseEntry = {
      tag: rel.tag,
      publishedAt: rel.publishedAt,
      lastRebuiltAt,
      isLatest,
      manifestDigest,
      totalSize: architectures.reduce((s, a) => s + (a.imageSize || 0), 0) || null,
      architectures,
      signature: enrich?.signature || null,
      provenance,
      attestations: attachReleaseAssetLinks(enrich?.attestations, {
        provenanceUrl: provAsset?.url ?? null,
      }),
      assetUrls: {
        sbom: Object.fromEntries(sbomAssets.map((a) => [guessArchFromAsset(a.name), a.url])),
        provenance: provAsset?.url ?? null,
        testResults: Object.fromEntries(testAssets.map((a) => [guessArchFromAsset(a.name), a.url])),
        digest: digestAsset?.url ?? null,
      },
      lifecycle: determineLifecycle(target, tier),
      runtimeContract: determineRuntimeContract(target, tier),
      exceptions: defaultExceptions(),
    };
    releaseEntry.evidence = releaseEvidence(releaseEntry);
    releaseEntries.push(releaseEntry);
  }

  if (releaseEntries.length === 0) return null;

  return {
    id: target,
    language: {
      id: langInfo.id,
      displayName: langInfo.display,
      version: langInfo.version,
      icon: null,
    },
    tier: { id: tier, name: TIERS[tier].name, blurb: TIERS[tier].blurb },
    registry: REGISTRY_BASE,
    imageName,
    fullName,
    releases: releaseEntries,
    lifecycle: determineLifecycle(target, tier),
    runtimeContract: determineRuntimeContract(target, tier),
  };
}

function defaultArchPayload(arch, when) {
  return {
    arch,
    os: 'linux',
    imageDigest: null,
    imageSize: null,
    layerCount: null,
    layers: [],
    labels: {},
    sbom: { tool: 'unknown', createdAt: when, rootDigest: null, packageCount: 0, packages: [] },
    testResults: null,
  };
}

function guessArchFromAsset(filename, spdx) {
  // GH artifact names from this repo collapse arch into a single SBOM per target
  // (the workflow attaches one of the two arch SBOMs). When a hint is embedded,
  // honor it; otherwise default to amd64. Enrichment fills in arm64.
  if (filename.includes('arm64') || filename.includes('aarch64')) return 'arm64';
  if (filename.includes('amd64') || filename.includes('x86_64')) return 'amd64';
  // Look inside the SPDX documentNamespace for arch hint
  if (spdx?.documentNamespace?.match(/aarch64|arm64/)) return 'arm64';
  return 'amd64';
}

// Same cache-bypass semantics as enrich-registry.mjs: we always refresh the
// most recent release (its assets could still be edited), and read older
// releases from the on-disk SBOM cache. Override with FORCE_REFRESH_TAGS=
// or FORCE_REFRESH_ALL=1.
function refreshTagSet(releases) {
  if (process.env.FORCE_REFRESH_ALL === '1') return new Set(releases.map((r) => r.tag));
  if (process.env.FORCE_REFRESH_TAGS) {
    return new Set(process.env.FORCE_REFRESH_TAGS.split(',').map((t) => t.trim()).filter(Boolean));
  }
  const latest = releases.find((r) => !r.prerelease) || releases[0];
  return new Set(latest ? [latest.tag] : []);
}

async function main() {
  mkdirSync(IMG_DIR, { recursive: true });

  const releases = await listReleases();
  if (releases.length === 0) {
    console.warn('[gather] No releases found; rebuilding from existing image records if available.');
    if (await rebuildIndexFromExistingImages()) return;
    console.warn('[gather] No existing image records found; writing empty catalog.');
  }
  const refreshSet = refreshTagSet(releases);
  console.log(`[gather] Found ${releases.length} releases. Refresh: ${[...refreshSet].join(', ') || '(none)'}`);
  console.log(`[gather] Cached tags reused from disk: ${releases.filter((r) => !refreshSet.has(r.tag)).map((r) => r.tag).join(', ') || '(none)'}`);

  // The full target enumeration
  const targets = [];
  for (const langKey of Object.keys(LANGUAGES)) {
    for (const tier of Object.keys(TIERS)) {
      const target = `${langKey}-${tier}`;
      if (targetAllowed(target)) targets.push(target);
    }
  }

  const images = [];
  const concurrency = 6;
  for (let i = 0; i < targets.length; i += concurrency) {
    const slice = targets.slice(i, i + concurrency);
    const results = await Promise.all(
      slice.map(async (t) => {
        try {
          const rec = await buildImageRecord(t, releases, refreshSet);
          if (rec) {
            await fs.writeFile(
              path.join(IMG_DIR, `${t}.json`),
              JSON.stringify(rec, null, 2),
            );
            console.log(`[gather] wrote ${t} (${rec.releases.length} releases)`);
            return { rec };
          }
          return null;
        } catch (err) {
          console.warn(`[gather] ${t}: ${err.message}`);
          return null;
        }
      }),
    );
    for (const r of results) if (r?.rec) images.push(r.rec);
  }

  // Build the slim index
  const latest = releases.find((r) => !r.prerelease) || releases[0];
  const index = {
    generatedAt: new Date().toISOString(),
    owner,
    repo,
    repoUrl: `https://github.com/${owner}/${repo}`,
    registryBase: REGISTRY_BASE,
    latestTag: latest?.tag ?? '',
    releases: releases.map((r, i) => ({
      tag: r.tag,
      publishedAt: r.publishedAt,
      isLatest: r === latest,
    })),
    languages: dedupeBy(
      Object.values(LANGUAGES).map((l) => ({
        id: l.id,
        displayName: l.display,
        version: l.version,
        icon: null,
      })),
      (l) => `${l.id}-${l.version}`,
    ),
    tiers: Object.entries(TIERS).map(([id, t]) => ({ id, ...t })),
    images: images.map(summarizeImageForIndex),
  };

  await fs.writeFile(path.join(OUT_DIR, 'index.json'), JSON.stringify(index, null, 2));
  console.log(`[gather] wrote index.json with ${index.images.length} images.`);
}

function dedupeBy(arr, keyFn) {
  const seen = new Map();
  for (const item of arr) seen.set(keyFn(item), item);
  return Array.from(seen.values());
}

async function rebuildIndexFromExistingImages() {
  if (!existsSync(IMG_DIR)) return false;
  const files = readdirSync(IMG_DIR).filter((f) => f.endsWith('.json')).sort();
  if (files.length === 0) return false;

  const images = [];
  for (const file of files) {
    const imagePath = path.join(IMG_DIR, file);
    const img = JSON.parse(readFileSync(imagePath, 'utf8'));
    img.releases = (img.releases || []).map((release) => {
      let lastRebuiltAt = release.lastRebuiltAt || release.publishedAt;
      const architectures = (release.architectures || []).map((arch) => {
        const vuln = loadVulnerabilities(release.tag, img.id, arch.arch);
        if (!vuln) return arch;
        if (vuln.scannedAt) lastRebuiltAt = vuln.scannedAt;
        return { ...arch, vulnerabilities: vuln };
      });
      const updated = { ...release, lastRebuiltAt, architectures };
      updated.evidence = releaseEvidence(updated);
      return updated;
    });
    writeFileSync(imagePath, JSON.stringify(img, null, 2));
    if (img.releases.length > 0) images.push(img);
  }
  if (images.length === 0) return false;

  const releasesByTag = new Map();
  for (const img of images) {
    for (const rel of img.releases) {
      if (!releasesByTag.has(rel.tag)) {
        releasesByTag.set(rel.tag, {
          tag: rel.tag,
          publishedAt: rel.publishedAt,
          isLatest: false,
        });
      }
    }
  }
  const releases = Array.from(releasesByTag.values()).sort(
    (a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime(),
  );
  const latestTag = images[0].releases[0]?.tag ?? releases[0]?.tag ?? '';
  for (const release of releases) release.isLatest = release.tag === latestTag;

  const index = {
    generatedAt: new Date().toISOString(),
    owner,
    repo,
    repoUrl: `https://github.com/${owner}/${repo}`,
    registryBase: REGISTRY_BASE,
    latestTag,
    releases,
    languages: dedupeBy(
      Object.values(LANGUAGES).map((l) => ({
        id: l.id,
        displayName: l.display,
        version: l.version,
        icon: null,
      })),
      (l) => `${l.id}-${l.version}`,
    ),
    tiers: Object.entries(TIERS).map(([id, t]) => ({ id, ...t })),
    images: images.map(summarizeImageForIndex),
  };

  await fs.writeFile(path.join(OUT_DIR, 'index.json'), JSON.stringify(index, null, 2));
  console.log(`[gather] rebuilt index.json from ${images.length} existing image records.`);
  return true;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
