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

import { execSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { X509Certificate } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const CORE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = path.resolve(CORE_ROOT, '..');
const OUT = process.env.ENRICHMENT_DIR || path.join(REPO_ROOT, 'site', 'src', 'data', 'enrichment');

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

// Async subprocess runner — never throws, returns { status, stdout, stderr }.
// Output is collected as Buffers and concatenated to safely handle the large
// (multi-MB) attestation streams cosign emits.
function run(cmd, args = [], opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], ...opts });
    const out = [];
    const err = [];
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', () => resolve({ status: -1, stdout: '', stderr: '' }));
    child.on('close', (code) =>
      resolve({
        status: code ?? -1,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
      }),
    );
  });
}

// Async equivalents of sh()/tryJson() so independent targets can be enriched
// concurrently (the work is network-bound, not CPU-bound). shA rejects on a
// non-zero exit like execSync; tryJsonA swallows failures and returns null.
async function shA(cmd) {
  const r = await run('/bin/sh', ['-c', cmd]);
  if (r.status !== 0) throw new Error(`command failed (${r.status}): ${cmd}`);
  return r.stdout;
}
async function tryJsonA(cmd) {
  try { return JSON.parse(await shA(cmd)); } catch { return null; }
}

// Concurrency-limited worker pool: runs `worker` over `items` with at most
// `limit` in flight at once. Preserves index order in the returned array.
async function runPool(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const idx = next++;
      results[idx] = await worker(items[idx], idx);
    }
  });
  await Promise.all(runners);
  return results;
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
const GITHUB_API_VERSION = '2022-11-28';
let cachedGithubToken;

async function listReleaseTags() {
  if (process.env.GATHER_TAGS) {
    return process.env.GATHER_TAGS.split(',').map((t) => t.trim()).filter(Boolean);
  }
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/releases?per_page=10`,
    { headers: githubHeaders() },
  );
  if (!res.ok) throw new Error(`gh releases: ${res.status}`);
  const data = await res.json();
  return data.filter((r) => !r.draft).map((r) => r.tag_name);
}

function githubHeaders() {
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': GITHUB_API_VERSION,
  };
  const token = githubToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

function githubToken() {
  if (cachedGithubToken !== undefined) return cachedGithubToken;
  cachedGithubToken = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
  if (!cachedGithubToken && have('gh')) {
    try {
      cachedGithubToken = execSync('gh auth token', {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
    } catch {
      cachedGithubToken = '';
    }
  }
  return cachedGithubToken;
}

async function fetchJson(url) {
  const res = await fetch(url, { headers: githubHeaders() });
  if (!res.ok) return null;
  try {
    return await res.json();
  } catch {
    return null;
  }
}

async function listGithubAttestations(subjectDigest) {
  if (!subjectDigest) return [];
  const scopes = [`users/${owner}`, `orgs/${owner}`];
  for (const scope of scopes) {
    const apiUrl = `https://api.github.com/${scope}/attestations/${subjectDigest}`;
    const data = await fetchJson(apiUrl);
    if (!data) continue;
    return (data.attestations || []).map((attestation) => ({
      bundle: attestation.bundle,
      githubApiUrl: apiUrl,
      initiator: attestation.initiator || null,
      repositoryId: attestation.repository_id || null,
    }));
  }
  return [];
}

function manifestList(ref) {
  return tryJsonA(`crane manifest ${ref} 2>/dev/null`);
}
function imageConfig(ref) {
  return tryJsonA(`crane config ${ref} 2>/dev/null`);
}

// Pull attestations as a stream of sigstore bundles (cosign v2+ default).
// Returns array of { predicateType, payload, cert } where cert is X509Certificate.
async function downloadAttestations(ref) {
  if (!COSIGN_AVAILABLE) return [];
  const res = await run('cosign', ['download', 'attestation', ref]);
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
    out.push({ predicateType: payload.predicateType, payload, cert, bundle: env });
  }
  return out;
}

async function verifySignature(ref) {
  if (!COSIGN_AVAILABLE) return null;
  const identity = `^https://github\\.com/${owner}/${repo}/\\.github/workflows/release\\.yml@refs/heads/.+$`;
  const res = await run('cosign', [
    'verify',
    ref,
    '--certificate-identity-regexp',
    identity,
    '--certificate-oidc-issuer',
    'https://token.actions.githubusercontent.com',
    '--output',
    'json',
  ]);
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

function certificateFromBundle(bundle) {
  const certB64 = bundle?.verificationMaterial?.certificate?.rawBytes;
  if (!certB64) return null;
  try {
    return new X509Certificate(Buffer.from(certB64, 'base64'));
  } catch {
    return null;
  }
}

function payloadFromBundle(bundle) {
  const dsse = bundle?.dsseEnvelope || bundle;
  if (!dsse?.payload) return null;
  try {
    return JSON.parse(Buffer.from(dsse.payload, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

function subjectDigest(payload) {
  const digest = payload?.subject?.[0]?.digest || {};
  const alg = Object.keys(digest)[0];
  return alg ? `${alg}:${digest[alg]}` : null;
}

function subjectName(payload) {
  return payload?.subject?.[0]?.name || null;
}

function attestationKind(payload) {
  const type = payload?.predicateType || 'unknown';
  if (type.includes('spdx.dev/Document')) return 'sbom';
  if (type.includes('slsa.dev/provenance')) return 'slsa-provenance';
  if (type.includes('cosign.sigstore.dev/attestation')) {
    const testResults = extractTestResults(payload);
    return testResults ? 'test-results' : 'custom';
  }
  return 'custom';
}

function attestationRunUrl(payload) {
  return payload?.predicate?.runDetails?.metadata?.invocationId || null;
}

function attestationWorkflowUrl(signerIdentity) {
  if (!signerIdentity) return null;
  const match = signerIdentity.match(/github\.com\/([^/]+)\/([^/]+)\/\.github\/workflows\/([^@\s]+)@(.*)/);
  if (!match) return null;
  return `https://github.com/${match[1]}/${match[2]}/actions/workflows/${match[3]}`;
}

function transparencyLogIndex(bundle) {
  const entry = bundle?.verificationMaterial?.tlogEntries?.[0];
  const raw = entry?.logIndex;
  if (raw == null) return null;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : null;
}

function transparencyUrl(logIndex) {
  return logIndex == null ? null : `https://search.sigstore.dev/?logIndex=${logIndex}`;
}

function normalizeAttestation({ payload, cert, bundle, source, githubApiUrl = null }) {
  if (!payload) return null;
  const signerIdentity = certSubjectUri(cert);
  const logIndex = transparencyLogIndex(bundle);
  return {
    kind: attestationKind(payload),
    predicateType: payload.predicateType || 'unknown',
    subjectName: subjectName(payload),
    subjectDigest: subjectDigest(payload),
    signerIdentity,
    issuer: certIssuer(cert) || 'https://token.actions.githubusercontent.com',
    runUrl: attestationRunUrl(payload),
    workflowUrl: attestationWorkflowUrl(signerIdentity),
    githubApiUrl,
    transparencyLogIndex: logIndex,
    transparencyUrl: transparencyUrl(logIndex),
    sources: [source],
  };
}

function normalizeGithubAttestation(attestation) {
  const payload = payloadFromBundle(attestation.bundle);
  const cert = certificateFromBundle(attestation.bundle);
  return normalizeAttestation({
    payload,
    cert,
    bundle: attestation.bundle,
    source: 'github',
    githubApiUrl: attestation.githubApiUrl,
  });
}

function normalizeOciAttestation(attestation) {
  return normalizeAttestation({
    payload: attestation.payload,
    cert: attestation.cert,
    bundle: attestation.bundle,
    source: 'oci',
  });
}

function attestationMergeKey(attestation) {
  return [
    attestation.kind,
    attestation.predicateType,
    attestation.subjectDigest,
    attestation.signerIdentity,
    attestation.runUrl,
    attestation.transparencyLogIndex,
  ].join('|');
}

function mergeAttestations(attestations) {
  const byKey = new Map();
  for (const attestation of attestations.filter(Boolean)) {
    const key = attestationMergeKey(attestation);
    if (!byKey.has(key)) {
      byKey.set(key, attestation);
      continue;
    }
    const existing = byKey.get(key);
    for (const source of attestation.sources) {
      if (!existing.sources.includes(source)) existing.sources.push(source);
    }
    existing.githubApiUrl ||= attestation.githubApiUrl;
    existing.workflowUrl ||= attestation.workflowUrl;
    existing.runUrl ||= attestation.runUrl;
    existing.transparencyUrl ||= attestation.transparencyUrl;
  }
  return Array.from(byKey.values()).sort((a, b) => {
    const order = ['slsa-provenance', 'sbom', 'test-results', 'custom'];
    return order.indexOf(a.kind) - order.indexOf(b.kind) || a.predicateType.localeCompare(b.predicateType);
  });
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

async function enrichOne(tag, target) {
  const langKey = target.slice(0, target.lastIndexOf('-'));
  const tier = target.slice(target.lastIndexOf('-') + 1);
  const baseImage = `${REGISTRY_BASE}/clearcutt-${langKey.toLowerCase()}`;
  const versionedRef = `${baseImage}:${tag}-${tier}`;
  const rollingRef = `${baseImage}:${tier}`;

  const ml = (await manifestList(versionedRef)) || (await manifestList(rollingRef));
  if (!ml) return null;

  const result = {
    manifestDigest: null,
    architectures: [],
    signature: null,
    provenance: null,
    testResults: null,
    attestations: [],
  };

  try {
    result.manifestDigest = (await shA(`crane digest ${versionedRef} 2>/dev/null`)).trim();
  } catch {
    try { result.manifestDigest = (await shA(`crane digest ${rollingRef} 2>/dev/null`)).trim(); } catch {}
  }

  const manifests = Array.isArray(ml.manifests) ? ml.manifests : [];
  for (const m of manifests) {
    const arch = m.platform?.architecture === 'arm64' ? 'arm64' : 'amd64';
    const archRef = `${baseImage}@${m.digest}`;
    const [cfg, mf] = await Promise.all([imageConfig(archRef), manifestList(archRef)]);
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
    // verify (Rekor lookup) + attestation download are the two slow network
    // calls; run them concurrently for this ref.
    const [sig, atts] = await Promise.all([
      result.signature ? Promise.resolve(result.signature) : verifySignature(ref),
      downloadAttestations(ref),
    ]);
    if (!result.signature) result.signature = sig;
    for (const a of atts) {
      const key = `${a.predicateType}|${a.payload.subject?.[0]?.digest?.sha256 ?? ''}|${a.payload.predicate?.Timestamp ?? a.payload.predicate?.createdOn ?? ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      allAttestations.push(a);
    }
    // For the latest release the versioned and rolling tags point to the same
    // digest, so once the versioned ref yields both a signature and at least
    // one attestation there's nothing new on the rolling tag — skip the
    // redundant second cosign verify + download. Older releases that only
    // resolve via the rolling tag still fall through.
    if (result.signature && allAttestations.length > 0) break;
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

  const githubAttestations = await listGithubAttestations(result.manifestDigest);
  result.attestations = mergeAttestations([
    ...allAttestations.map(normalizeOciAttestation),
    ...githubAttestations.map(normalizeGithubAttestation),
  ]);

  return result;
}

// Every release is immutable: once an image is published and signed, the GHCR
// manifest + attestations + labels never change. So by default we refresh
// NOTHING from the network — every tag is read from the on-disk cache, and
// only tags whose per-target files are missing (i.e. brand-new releases not
// yet in the restored cache) get fetched. Vulnerability data, which *does*
// change between runs, is handled separately by the grype scan step.
//
// FORCE_REFRESH_TAGS=v0.3.0,v0.2.2 re-fetches specific tags (use when
// attestations were re-attached to an existing release). Set
// FORCE_REFRESH_ALL=1 to bypass the cache entirely (e.g. on schema changes).
function tagsToRefresh(allTags) {
  if (process.env.FORCE_REFRESH_ALL === '1') return new Set(allTags);
  if (process.env.FORCE_REFRESH_TAGS) {
    return new Set(process.env.FORCE_REFRESH_TAGS.split(',').map((t) => t.trim()).filter(Boolean));
  }
  // Default: refresh nothing — cached tags are reused, missing tags are fetched
  // by the cache-miss path in main().
  return new Set();
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

  // First pass (synchronous, cheap): account for cached entries and build the
  // list of (tag, target) pairs that actually need a network refresh.
  const work = [];
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
        work.push({ tag, target, outFile });
      }
    }
  }

  // Second pass: enrich the refresh targets concurrently. Each target is an
  // independent set of network round-trips (crane + cosign), so a bounded pool
  // turns ~N×latency of serial work into ~ceil(N/limit) batches. Override with
  // ENRICH_CONCURRENCY; 8 is a safe default against GHCR/Rekor rate limits.
  const concurrency = Math.max(1, parseInt(process.env.ENRICH_CONCURRENCY || '8', 10));
  console.log(`[enrich] enriching ${work.length} target(s) with concurrency ${concurrency}`);
  await runPool(work, concurrency, async ({ tag, target, outFile }) => {
    const data = await enrichOne(tag, target);
    if (!data) return;
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
  });

  console.log(
    `[enrich] done. fetched ${fetched}, reused ${cached} from cache ` +
      `(${withSig} with sig, ${withProvenance} with provenance total).`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(0); // never fail the pipeline on enrichment
});
