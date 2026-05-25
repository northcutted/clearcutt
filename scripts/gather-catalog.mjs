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
//   site/src/data/catalog/index.json
//   site/src/data/catalog/images/<lang><ver>-<tier>.json

import fs from 'node:fs/promises';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT_DIR = path.join(ROOT, 'site', 'src', 'data', 'catalog');
const IMG_DIR = path.join(OUT_DIR, 'images');
const ENRICHMENT_DIR =
  process.env.ENRICHMENT_DIR || path.join(ROOT, 'site', 'src', 'data', 'enrichment');

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
};

const TIERS = {
  dev: { name: 'Dev', blurb: 'Builder tier — full toolchain, shells, debug utilities, credential broker.' },
  slim: { name: 'Slim', blurb: 'Runtime tier — language runtime plus minimal troubleshooting binaries.' },
  distroless: { name: 'Distroless', blurb: 'Hardened tier — no shells, no coreutils, runtime only.' },
};

const args = parseArgs(process.argv.slice(2));
const LIMIT = Number(args.limit ?? process.env.RELEASE_LIMIT ?? 10);

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

function sh(cmd) {
  return execSync(cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
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

function compactPackages(spdx) {
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

function summarizeProvenance(intotoJsonl) {
  // jsonl: each line is a DSSE envelope { payload (base64), payloadType, signatures }
  const out = {
    predicateType: 'unknown',
    builder: { id: 'unknown' },
    buildType: null,
    sourceUri: null,
    sourceRevision: null,
    slsaLevel: 3,
    raw: null,
  };
  const lines = intotoJsonl.split('\n').filter(Boolean);
  for (const line of lines) {
    let env;
    try { env = JSON.parse(line); } catch { continue; }
    if (!env.payload) continue;
    let payloadJson;
    try {
      const decoded = Buffer.from(env.payload, 'base64').toString('utf8');
      payloadJson = JSON.parse(decoded);
    } catch { continue; }
    out.predicateType = payloadJson.predicateType || out.predicateType;
    const pred = payloadJson.predicate || {};
    if (pred.builder?.id) out.builder.id = pred.builder.id;
    if (pred.buildType) out.buildType = pred.buildType;
    if (pred.buildDefinition?.buildType) out.buildType = pred.buildDefinition.buildType;
    const cs = pred.invocation?.configSource || pred.buildDefinition?.externalParameters?.source;
    if (cs?.uri) out.sourceUri = cs.uri;
    if (cs?.digest?.sha1) out.sourceRevision = cs.digest.sha1;
    if (cs?.digest?.gitCommit) out.sourceRevision = cs.digest.gitCommit;
    out.raw = payloadJson;
    break; // first envelope is enough
  }
  return out;
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

function archForSystem(system) {
  if (system.includes('aarch64') || system.includes('arm64')) return 'arm64';
  return 'amd64';
}

async function buildImageRecord(target, releases) {
  const meta = targetMeta(target);
  if (!meta) return null;
  const { langKey, tier } = meta;
  const langInfo = LANGUAGES[langKey];
  const imageName = `clearcutt-${langKey.toLowerCase()}`;
  const fullName = `${REGISTRY_BASE}/${imageName}`;

  const releaseEntries = [];
  let isLatestSet = false;

  for (const rel of releases) {
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
      let buf;
      try {
        buf = await downloadAsset(a);
      } catch (err) {
        console.warn(`[gather]   skip ${a.name}: download failed: ${err.message}`);
        continue;
      }
      let spdx;
      try {
        spdx = JSON.parse(buf.toString('utf8'));
      } catch (err) {
        console.warn(`[gather]   skip ${a.name}: parse failed (${err.message})`);
        continue;
      }
      const arch = guessArchFromAsset(a.name, spdx);
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
        assertions: tr.assertions || [],
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

    // Merge in enrichment (manifest, layers, labels, signatures) if available
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
    }

    const architectures = Array.from(archMap.values()).sort((a, b) =>
      a.arch.localeCompare(b.arch),
    );

    // If we couldn't get any usable SBOM for this release, skip the release entirely
    // (rather than emit an empty/broken record).
    if (architectures.length === 0) continue;

    const isLatest = !isLatestSet && !rel.prerelease;
    if (isLatest) isLatestSet = true;

    releaseEntries.push({
      tag: rel.tag,
      publishedAt: rel.publishedAt,
      isLatest,
      manifestDigest,
      totalSize: architectures.reduce((s, a) => s + (a.imageSize || 0), 0) || null,
      architectures,
      signature: enrich?.signature || null,
      provenance,
      assetUrls: {
        sbom: Object.fromEntries(sbomAssets.map((a) => [guessArchFromAsset(a.name), a.url])),
        provenance: provAsset?.url ?? null,
        testResults: Object.fromEntries(testAssets.map((a) => [guessArchFromAsset(a.name), a.url])),
        digest: digestAsset?.url ?? null,
      },
    });
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

async function main() {
  mkdirSync(IMG_DIR, { recursive: true });

  const releases = await listReleases();
  if (releases.length === 0) {
    console.warn('[gather] No releases found; writing empty catalog.');
  }
  console.log(`[gather] Found ${releases.length} releases. Building image records...`);

  // The full target enumeration
  const targets = [];
  for (const langKey of Object.keys(LANGUAGES)) {
    for (const tier of Object.keys(TIERS)) {
      targets.push(`${langKey}-${tier}`);
    }
  }

  const images = [];
  const concurrency = 6;
  for (let i = 0; i < targets.length; i += concurrency) {
    const slice = targets.slice(i, i + concurrency);
    const results = await Promise.all(
      slice.map(async (t) => {
        try {
          const rec = await buildImageRecord(t, releases);
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
    images: images.map((img) => {
      const latestRel = img.releases[0];
      const arches = latestRel.architectures.map((a) => a.arch);
      const totalPkgs =
        latestRel.architectures.reduce((s, a) => s + a.sbom.packageCount, 0) /
          Math.max(1, latestRel.architectures.length) || 0;
      const passed =
        latestRel.architectures.every((a) => !a.testResults || a.testResults.status === 'passed');
      return {
        id: img.id,
        language: img.language.id,
        languageDisplay: img.language.displayName,
        languageVersion: img.language.version,
        tier: img.tier.id,
        latestTag: latestRel.tag,
        latestPackageCount: Math.round(totalPkgs),
        architectures: arches,
        signed: latestRel.signature?.cosignBundlePresent ?? !!latestRel.provenance,
        provenance: !!latestRel.provenance,
        passed,
      };
    }),
  };

  await fs.writeFile(path.join(OUT_DIR, 'index.json'), JSON.stringify(index, null, 2));
  console.log(`[gather] wrote index.json with ${index.images.length} images.`);
}

function dedupeBy(arr, keyFn) {
  const seen = new Map();
  for (const item of arr) seen.set(keyFn(item), item);
  return Array.from(seen.values());
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
