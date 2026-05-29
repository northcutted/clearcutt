#!/usr/bin/env node
// Enrich each (release, target) pair with what's pinned to the GHCR manifest:
// per-arch digests/sizes/layers, OCI config labels, and parsed cosign
// attestations (signature cert, SLSA provenance if attached, custom test
// results). This is the canonical source of truth for the catalog — GHCR
// attestations live with the image regardless of whether the release-asset
// upload step succeeded.
//
// Requires: crane (mandatory), cosign (mandatory for attestation parsing).
// If either is missing, exits 0 silently; the gather step falls back to
// release assets.
//
// Outputs: <ENRICHMENT_DIR>/<tag>/<target>.json (one per image per release).

import { execSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { X509Certificate } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = process.env.ENRICHMENT_DIR || path.join(ROOT, 'site', 'src', 'data', 'enrichment');

const LANG_KEYS = [
  'coreLTS', 'java21', 'java25', 'node22', 'node24',
  'python3.13', 'python3.14', 'go1.25', 'go1.26', 'dotnet8', 'dotnet10',
  'rust1.95', 'cc15',
];
const TIERS = ['dev', 'slim', 'distroless'];
const TARGET_FILTER = new Set(
  (process.env.CATALOG_TARGETS || '')
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean),
);

function have(cmd) {
  try { execSync(`command -v ${cmd}`, { stdio: 'ignore' }); return true; } catch { return false; }
}
function targetAllowed(target) {
  return TARGET_FILTER.size === 0 || TARGET_FILTER.has(target);
}
function sh(cmd) {
  return execSync(cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 });
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
if (!COSIGN_AVAILABLE) {
  console.warn('[enrich] cosign not on PATH — attestation extraction disabled, manifest only.');
}

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

// Pull attestations as a stream of sigstore bundles (cosign v2+ default).
// Returns array of { predicateType, payload, cert } where cert is X509Certificate.
function downloadAttestations(ref) {
  if (!COSIGN_AVAILABLE) return [];
  const res = spawnSync('cosign', ['download', 'attestation', ref], {
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (res.status !== 0 || !res.stdout) return [];
  const out = [];
  for (const line of res.stdout.split('\n')) {
    if (!line.trim()) continue;
    let env;
    try { env = JSON.parse(line); } catch { continue; }
    const dsse = env.dsseEnvelope || env;
    if (!dsse.payload) continue;
    let payload;
    try {
      payload = JSON.parse(Buffer.from(dsse.payload, 'base64').toString('utf8'));
    } catch { continue; }
    let cert = null;
    const certB64 = env.verificationMaterial?.certificate?.rawBytes;
    if (certB64) {
      try {
        cert = new X509Certificate(Buffer.from(certB64, 'base64'));
      } catch { /* ignore */ }
    }
    out.push({ predicateType: payload.predicateType, payload, cert });
  }
  return out;
}

function verifySignature(ref) {
  if (!COSIGN_AVAILABLE) return null;
  const identity = `^https://github\\.com/${owner}/${repo}/\\.github/workflows/release\\.yml@refs/heads/.+$`;
  const res = spawnSync('cosign', [
    'verify',
    ref,
    '--certificate-identity-regexp',
    identity,
    '--certificate-oidc-issuer',
    'https://token.actions.githubusercontent.com',
    '--output',
    'json',
  ], {
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (res.status !== 0 || !res.stdout) return null;
  let parsed;
  try { parsed = JSON.parse(res.stdout); } catch { return null; }
  const first = Array.isArray(parsed) ? parsed[0] : parsed;
  const optional = first?.optional || {};
  return {
    cosignBundlePresent: true,
    rekorLogIndex: optional.Bundle?.Payload?.logIndex ?? optional.Bundle?.payload?.logIndex ?? null,
    certificate: {
      subject: optional.Subject || null,
      issuer: optional.Issuer || 'https://token.actions.githubusercontent.com',
      runInvocation: null,
    },
  };
}

// Extract the workflow-identity SAN URI from a Sigstore cosign cert. The OIDC
// SAN is encoded as `URI:https://github.com/<owner>/<repo>/.github/workflows/...@<ref>`
// inside the cert's subjectAltName extension.
function certSubjectUri(cert) {
  if (!cert) return null;
  const san = cert.subjectAltName ?? '';
  const m = san.match(/URI:(https:\/\/github\.com\/[^,\s]+)/);
  return m ? m[1] : null;
}
function certIssuer(cert) {
  if (!cert) return null;
  // The OIDC issuer is recorded as a custom OID extension. Easier path: parse
  // the PEM and look for the OIDC issuer extension. Most cosign certs from
  // GitHub Actions have it at OID 1.3.6.1.4.1.57264.1.1 or 1.3.6.1.4.1.57264.1.8.
  // For our purposes we can pin the issuer as a known constant since we only
  // use GitHub Actions OIDC — record the well-known value.
  const issuer = cert.issuer ?? '';
  if (issuer.includes('sigstore')) return 'https://token.actions.githubusercontent.com';
  return null;
}

function releaseWorkflowIdentity(subject) {
  if (!subject) return false;
  return subject.includes(`github.com/${owner}/${repo}/.github/workflows/release.yml@`);
}

function signatureCertMetadata(attestations) {
  for (const attestation of attestations) {
    const subject = certSubjectUri(attestation.cert);
    if (!releaseWorkflowIdentity(subject)) continue;
    return {
      subject,
      issuer: certIssuer(attestation.cert) || 'https://token.actions.githubusercontent.com',
      runInvocation: attestation.payload?.predicate?.runDetails?.metadata?.invocationId || null,
    };
  }
  return null;
}

function firstGitDependency(pred) {
  return (
    pred.buildDefinition?.resolvedDependencies || pred.materials || []
  ).find((dep) => typeof dep?.uri === 'string' && dep.uri.includes('github.com'));
}

function summarizeProvenance(payload) {
  const pred = payload.predicate || {};
  const buildDefinition = pred.buildDefinition || {};
  const workflow = buildDefinition.externalParameters?.workflow || {};
  const configSource = pred.invocation?.configSource || buildDefinition.externalParameters?.source;
  const gitDependency = firstGitDependency(pred);
  return {
    predicateType: payload.predicateType,
    builder: { id: pred.builder?.id || pred.runDetails?.builder?.id || 'unknown' },
    buildType: pred.buildType || buildDefinition.buildType || null,
    sourceUri:
      configSource?.uri ||
      workflow.repository ||
      buildDefinition.externalParameters?.sourceUri ||
      gitDependency?.uri ||
      null,
    sourceRevision:
      configSource?.digest?.sha1 ||
      configSource?.digest?.gitCommit ||
      buildDefinition.externalParameters?.source?.digest?.sha1 ||
      buildDefinition.externalParameters?.source?.digest?.gitCommit ||
      gitDependency?.digest?.gitCommit ||
      gitDependency?.digest?.sha1 ||
      null,
    slsaLevel: payload.predicateType?.includes('slsa.dev/provenance/v1')
      ? 3
      : payload.predicateType?.includes('slsa')
        ? 3
        : null,
  };
}

function extractTestResults(payload) {
  // cosign `--type custom` wraps the predicate as { Data: "<json string>", Timestamp }.
  const pred = payload.predicate || {};
  if (typeof pred.Data === 'string') {
    try { return JSON.parse(pred.Data); } catch { return null; }
  }
  // Fallback: the predicate may already be the JSON object
  if (pred.assertions || pred.status) return pred;
  return null;
}

function enrichOne(tag, target) {
  const langKey = target.slice(0, target.lastIndexOf('-'));
  const tier = target.slice(target.lastIndexOf('-') + 1);
  const baseImage = `${REGISTRY_BASE}/clearcutt-${langKey.toLowerCase()}`;
  const versionedRef = `${baseImage}:${tag}-${tier}`;
  const rollingRef = `${baseImage}:${tier}`;

  const ml = manifestList(versionedRef) || manifestList(rollingRef);
  if (!ml) return null;

  const result = {
    manifestDigest: null,
    architectures: [],
    signature: null,
    provenance: null,
    testResults: null,
  };

  try {
    result.manifestDigest = sh(`crane digest ${versionedRef} 2>/dev/null`).trim();
  } catch {
    try { result.manifestDigest = sh(`crane digest ${rollingRef} 2>/dev/null`).trim(); } catch {}
  }

  const manifests = Array.isArray(ml.manifests) ? ml.manifests : [];
  for (const m of manifests) {
    const arch = m.platform?.architecture === 'arm64' ? 'arm64' : 'amd64';
    const archRef = `${baseImage}@${m.digest}`;
    const cfg = imageConfig(archRef);
    const mf = manifestList(archRef);
    const diffIds = cfg?.rootfs?.diff_ids || cfg?.config?.rootfs?.diff_ids || [];
    const layers = (mf?.layers || []).map((l, idx) => ({
      digest: l.digest,
      size: l.size,
      diffID: diffIds[idx] || null,
    }));
    const labels =
      cfg?.config?.Labels ||
      cfg?.config?.labels ||
      cfg?.Labels ||
      {};
    result.architectures.push({
      arch,
      digest: m.digest,
      size: m.size || layers.reduce((s, l) => s + l.size, 0),
      layers,
      labels,
    });
  }

  // Signatures and attestations are now written directly to the production
  // repo (no bootstrap staging package). Probe the versioned + rolling tags;
  // cosign reads both OCI 1.1 referrers (current releases) and the legacy
  // tag-based fallback (older releases promoted via cosign copy). Dedupe by
  // predicateType + payload.subject[0].digest.sha256.
  const seen = new Set();
  const refsToProbe = [versionedRef, rollingRef];
  const allAttestations = [];
  for (const ref of refsToProbe) {
    if (!result.signature) {
      result.signature = verifySignature(ref);
    }
    for (const a of downloadAttestations(ref)) {
      const key = `${a.predicateType}|${a.payload.subject?.[0]?.digest?.sha256 ?? ''}|${a.payload.predicate?.Timestamp ?? a.payload.predicate?.createdOn ?? ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      allAttestations.push(a);
    }
  }

  const signatureMeta = signatureCertMetadata(allAttestations);
  if (result.signature?.cosignBundlePresent && signatureMeta) {
    result.signature.certificate = {
      subject: result.signature.certificate?.subject || signatureMeta.subject,
      issuer: result.signature.certificate?.issuer || signatureMeta.issuer,
      runInvocation: result.signature.certificate?.runInvocation || signatureMeta.runInvocation,
    };
  }

  if (allAttestations.length > 0) {
    // Pick the first SLSA-provenance envelope if present.
    const provEnv = allAttestations.find((a) =>
      a.predicateType?.includes('slsa.dev/provenance'),
    );
    if (provEnv) {
      const summary = summarizeProvenance(provEnv.payload);
      result.provenance = {
        predicateType: summary.predicateType,
        builder: summary.builder,
        buildType: summary.buildType,
        sourceUri: summary.sourceUri,
        sourceRevision: summary.sourceRevision,
        slsaLevel: summary.slsaLevel ?? 3,
      };
    }

    // Test results (cosign --type custom)
    const testEnv = allAttestations.find((a) =>
      a.predicateType?.includes('cosign.sigstore.dev/attestation/v1'),
    );
    if (testEnv) {
      const tr = extractTestResults(testEnv.payload);
      if (tr) result.testResults = tr;
    }
  }

  return result;
}

// Old releases are immutable: once an image is published and signed, the
// GHCR manifest + attestations + labels never change. We refresh only the
// latest release every run; everything else is read from the on-disk cache.
//
// FORCE_REFRESH_TAGS=v0.3.0,v0.2.2 overrides which tags re-run. Set
// FORCE_REFRESH_ALL=1 to bypass the cache entirely (e.g. on schema changes).
function tagsToRefresh(allTags) {
  if (process.env.FORCE_REFRESH_ALL === '1') return new Set(allTags);
  if (process.env.FORCE_REFRESH_TAGS) {
    return new Set(process.env.FORCE_REFRESH_TAGS.split(',').map((t) => t.trim()).filter(Boolean));
  }
  // Default: refresh the first tag (the most recent non-draft release).
  return new Set(allTags.slice(0, 1));
}

async function main() {
  const tags = await listReleaseTags();
  mkdirSync(OUT, { recursive: true });
  const refresh = tagsToRefresh(tags);
  console.log(`[enrich] refreshing ${refresh.size} tag(s): ${[...refresh].join(', ') || '(none)'}`);
  console.log(`[enrich] cached tags will be skipped: ${tags.filter((t) => !refresh.has(t)).join(', ') || '(none)'}`);

  let fetched = 0;
  let cached = 0;
  let withProvenance = 0;
  let withSig = 0;
  for (const tag of tags) {
    const dir = path.join(OUT, tag);
    mkdirSync(dir, { recursive: true });
    const mustRefresh = refresh.has(tag);
    for (const langKey of LANG_KEYS) {
      for (const tier of TIERS) {
        const target = `${langKey}-${tier}`;
        if (!targetAllowed(target)) continue;
        const outFile = path.join(dir, `${target}.json`);
        if (!mustRefresh && existsSync(outFile)) {
          cached += 1;
          // Inspect cached entry once for the summary counters.
          try {
            const cachedData = JSON.parse(readFileSync(outFile, 'utf8'));
            if (cachedData.provenance) withProvenance += 1;
            if (cachedData.signature?.cosignBundlePresent) withSig += 1;
          } catch { /* ignore */ }
          continue;
        }
        const data = enrichOne(tag, target);
        if (!data) continue;
        writeFileSync(outFile, JSON.stringify(data, null, 2));
        fetched += 1;
        if (data.provenance) withProvenance += 1;
        if (data.signature?.cosignBundlePresent) withSig += 1;
        console.log(
          `[enrich] ${tag} ${target}  ` +
            `sig=${data.signature?.cosignBundlePresent ? 'yes' : 'no'}  ` +
            `prov=${data.provenance ? 'yes' : 'no'}  ` +
            `archs=${data.architectures.length}`,
        );
      }
    }
  }
  console.log(
    `[enrich] done. fetched ${fetched}, reused ${cached} from cache ` +
      `(${withSig} with sig, ${withProvenance} with provenance total).`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(0); // never fail the pipeline on enrichment
});
