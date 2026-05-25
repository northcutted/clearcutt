#!/usr/bin/env node
// Enrich each (release, target) pair with GHCR manifest, config labels,
// per-arch digests/sizes/layers, and cosign certificate metadata.
//
// Requires: crane, cosign on PATH. If absent, exits 0 silently (the gather
// step will fall back to GH-release-only data).
//
// Outputs: <ENRICHMENT_DIR>/<tag>/<target>.json (one per image per release).

import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = process.env.ENRICHMENT_DIR || path.join(ROOT, 'site', 'src', 'data', 'enrichment');

const LANG_KEYS = [
  'coreLTS', 'java21', 'java25', 'node22', 'node24',
  'python3.13', 'python3.14', 'go1.25', 'go1.26', 'dotnet8', 'dotnet10',
];
const TIERS = ['dev', 'slim', 'distroless'];

function have(cmd) {
  try { execSync(`command -v ${cmd}`, { stdio: 'ignore' }); return true; } catch { return false; }
}
function sh(cmd) {
  return execSync(cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}
function tryJson(cmd) {
  try { return JSON.parse(sh(cmd)); } catch { return null; }
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
    const m = url.match(/github\.com[:/]+([^/]+)\/([^/.]+)/);
    if (m) return { owner: m[1], repo: m[2] };
  } catch {}
  throw new Error('Set GH_OWNER and GH_REPO.');
}

if (!have('crane')) {
  console.warn('[enrich] crane not on PATH — skipping enrichment.');
  process.exit(0);
}
const COSIGN_AVAILABLE = have('cosign');

const { owner, repo } = detectRepo();
const REGISTRY_BASE = `ghcr.io/${owner.toLowerCase()}/${repo.toLowerCase()}`;

async function listReleaseTags() {
  if (process.env.GATHER_TAGS) {
    return process.env.GATHER_TAGS.split(',').map((t) => t.trim()).filter(Boolean);
  }
  const headers = { Accept: 'application/vnd.github+json' };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/releases?per_page=10`,
    { headers },
  );
  if (!res.ok) throw new Error(`gh releases: ${res.status}`);
  const data = await res.json();
  return data.filter((r) => !r.draft).map((r) => r.tag_name);
}

function manifestList(ref) {
  return tryJson(`crane manifest ${ref} 2>/dev/null`);
}
function imageConfig(ref) {
  return tryJson(`crane config ${ref} 2>/dev/null`);
}

function cosignCertSubject(ref) {
  if (!COSIGN_AVAILABLE) return null;
  // cosign verify will produce json; without --certificate-identity we still
  // can at least try cosign tree to detect signature presence.
  try {
    const tree = sh(`cosign tree ${ref} 2>/dev/null`);
    return { cosignBundlePresent: /Signatures/.test(tree), tree };
  } catch {
    return null;
  }
}

function enrichOne(tag, target) {
  // Two roots get probed: bootstrap (where attestations live) and final published image.
  const langKey = target.slice(0, target.lastIndexOf('-'));
  const tier = target.slice(target.lastIndexOf('-') + 1);
  const baseImage = `${REGISTRY_BASE}/clearcutt-${langKey.toLowerCase()}`;
  const rollingRef = `${baseImage}:${tier}`;
  const versionedRef = `${baseImage}:${tag}-${tier}`;

  const ml = manifestList(versionedRef) || manifestList(rollingRef);
  if (!ml) {
    return null;
  }

  const result = {
    manifestDigest: null,
    architectures: [],
    signature: null,
  };

  // Compute the multi-arch manifest digest from versioned ref via crane digest
  try {
    result.manifestDigest = sh(`crane digest ${versionedRef} 2>/dev/null`).trim();
  } catch {
    try {
      result.manifestDigest = sh(`crane digest ${rollingRef} 2>/dev/null`).trim();
    } catch {}
  }

  const manifests = Array.isArray(ml.manifests) ? ml.manifests : [];
  for (const m of manifests) {
    const arch = m.platform?.architecture === 'arm64' ? 'arm64' : 'amd64';
    const archRef = `${baseImage}@${m.digest}`;
    const cfg = imageConfig(archRef);
    const mf = manifestList(archRef);
    const layers = (mf?.layers || []).map((l) => ({ digest: l.digest, size: l.size }));
    result.architectures.push({
      arch,
      digest: m.digest,
      size: m.size || layers.reduce((s, l) => s + l.size, 0),
      layers,
      labels: cfg?.config?.Labels || {},
    });
  }

  const sig = cosignCertSubject(versionedRef);
  if (sig) {
    result.signature = {
      cosignBundlePresent: sig.cosignBundlePresent,
      rekorLogIndex: null,
      certificate: null,
    };
  }

  return result;
}

async function main() {
  const tags = await listReleaseTags();
  mkdirSync(OUT, { recursive: true });
  for (const tag of tags) {
    const dir = path.join(OUT, tag);
    mkdirSync(dir, { recursive: true });
    for (const langKey of LANG_KEYS) {
      for (const tier of TIERS) {
        const target = `${langKey}-${tier}`;
        const data = enrichOne(tag, target);
        if (data) {
          writeFileSync(path.join(dir, `${target}.json`), JSON.stringify(data, null, 2));
          console.log(`[enrich] ${tag} ${target}`);
        }
      }
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(0); // never fail the pipeline on enrichment
});
