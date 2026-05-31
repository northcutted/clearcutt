#!/usr/bin/env node
// Scan every cached SBOM with Grype and emit a normalized vulnerability JSON
// per (tag, target, arch). The catalog gather script picks these up on its
// second pass and merges them into each image record.
//
// Inputs (env):
//   SBOM_CACHE_DIR  default: ../../site/src/data/sboms
//   VULN_DIR        default: ../../site/src/data/vulnerabilities
//   SCAN_MODE       catalog (default), remediation, or release
//   GRYPE_BIN       grype executable override for tests
//
// Requires:
//   grype on PATH. In catalog mode, missing/failed scans are best-effort so
//   Pages keeps publishing. In remediation/release modes, missing tooling or
//   failed scans fail closed.

import { execSync, spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CORE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = path.resolve(CORE_ROOT, '..');
const SBOM_DIR = process.env.SBOM_CACHE_DIR || path.join(REPO_ROOT, 'site', 'src', 'data', 'sboms');
const OUT_DIR = process.env.VULN_DIR || path.join(REPO_ROOT, 'site', 'src', 'data', 'vulnerabilities');
const GRYPE_OPTS = (process.env.GRYPE_OPTS || '').split(' ').filter(Boolean);
const GRYPE_BIN = process.env.GRYPE_BIN || 'grype';
const args = parseArgs(process.argv.slice(2));
const SCAN_MODE = args.mode || process.env.SCAN_MODE || 'catalog';
const STRICT_MODES = new Set(['remediation', 'release']);
const STRICT = STRICT_MODES.has(SCAN_MODE);

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const k = a.slice(2);
    const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true';
    out[k] = v;
  }
  return out;
}

function failOrWarn(message) {
  if (STRICT) {
    console.error(message);
    process.exit(1);
  }
  console.warn(message);
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

// Async subprocess runner — never rejects; returns { status, stdout, stderr }.
// Output collected as Buffers to safely handle large grype JSON payloads.
function run(cmd, args = [], opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], ...opts });
    const out = [];
    const err = [];
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', (e) => resolve({ status: -1, stdout: '', stderr: String(e) }));
    child.on('close', (code) =>
      resolve({
        status: code ?? -1,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
      }),
    );
  });
}

// Concurrency-limited worker pool: at most `limit` workers in flight at once.
async function runPool(items, limit, worker) {
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const idx = next++;
      await worker(items[idx], idx);
    }
  });
  await Promise.all(runners);
}

function have(cmd) {
  try { execSync(`command -v ${shellQuote(cmd)}`, { stdio: 'ignore' }); return true; } catch { return false; }
}

if (!have(GRYPE_BIN)) {
  failOrWarn(`[scan] ${GRYPE_BIN} not on PATH - install Grype to enable CVE reporting.`);
  process.exit(0);
}

function grypeVersion() {
  try {
    const res = spawnSync(GRYPE_BIN, ['version', '-o', 'json'], { encoding: 'utf8' });
    if (res.status !== 0) throw new Error(res.stderr || res.stdout || 'version failed');
    const j = JSON.parse(res.stdout);
    return { version: j.version || j.application, dbBuiltAt: j.db?.built || null };
  } catch {
    return { version: 'grype', dbBuiltAt: null };
  }
}
const { version: scannerVersion, dbBuiltAt } = grypeVersion();
console.log(`[scan] grype ${scannerVersion}, db built ${dbBuiltAt ?? 'unknown'}`);

async function runGrype(sbomPath) {
  const res = await run(
    GRYPE_BIN,
    ['sbom:' + sbomPath, '-o', 'json', '--quiet', ...GRYPE_OPTS],
  );
  if (res.status !== 0 && !res.stdout) {
    throw new Error(`grype exited ${res.status}: ${res.stderr?.slice(0, 200)}`);
  }
  try {
    return JSON.parse(res.stdout);
  } catch (err) {
    throw new Error(`grype produced unparseable JSON: ${err.message}`);
  }
}

function pickCvss(cvssArr) {
  if (!Array.isArray(cvssArr) || cvssArr.length === 0) return null;
  // Prefer Primary entries; fall back to highest baseScore across all entries.
  const primary = cvssArr.find((c) => (c.type || '').toLowerCase() === 'primary');
  const candidates = primary ? [primary] : cvssArr;
  let best = null;
  for (const c of candidates) {
    const score = c?.metrics?.baseScore;
    if (typeof score !== 'number') continue;
    if (!best || score > best.score) {
      best = { score, version: c.version || null, vector: c.vector || null };
    }
  }
  return best;
}

function pickEpss(epssArr) {
  if (!Array.isArray(epssArr) || epssArr.length === 0) return null;
  // EPSS entries are typically date-sorted; use the most recent.
  const sorted = [...epssArr].sort((a, b) => String(b.date || '').localeCompare(String(a.date || '')));
  const e = sorted[0];
  if (typeof e?.epss !== 'number') return null;
  return { score: e.epss, percentile: typeof e.percentile === 'number' ? e.percentile : null };
}

function targetMetadata(target) {
  const idx = target.lastIndexOf('-');
  const runtime = idx === -1 ? target : target.slice(0, idx);
  const tier = idx === -1 ? 'unknown' : target.slice(idx + 1);

  if (runtime === 'coreLTS') return { target, runtime, language: 'core', version: 'LTS', tier };

  const match = runtime.match(/^([a-z]+)(.+)$/);
  if (!match) return { target, runtime, language: runtime, version: '', tier };
  const [, language, version] = match;
  return { target, runtime, language, version, tier };
}

// This script is the authoritative producer of each finding's `inclusion` and
// `remediation` metadata; the catalog UI only recomputes it as a fallback. The
// pure predicates below (displayLanguage, isPrimaryRuntimePackage) are mirrored
// in site/src/lib/runtime-taxonomy.ts — they can't be shared directly because
// this runs as a plain Node process outside the site's TS build, so keep the
// two copies in sync when changing the runtime taxonomy.
function displayLanguage(language) {
  switch (language) {
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
    case 'rust':
      return 'Rust';
    case 'cc':
      return 'C/C++';
    default:
      return language;
  }
}

function isPrimaryRuntimePackage(meta, packageName) {
  const pkg = String(packageName || '').toLowerCase();
  switch (meta.language) {
    case 'python':
      return pkg === 'python' || /^python[0-9.]*$/.test(pkg);
    case 'java':
      return pkg.includes('jdk') || pkg.includes('jre') || pkg.includes('openjdk') || pkg.includes('zulu');
    case 'node':
      return pkg === 'node' || pkg === 'nodejs' || pkg.startsWith('nodejs');
    case 'go':
      return pkg === 'go' || pkg.startsWith('go-') || /^go_[0-9_]+$/.test(pkg);
    case 'dotnet':
      return pkg.includes('dotnet') || pkg.includes('aspnetcore');
    case 'rust':
      return pkg === 'rustc' || pkg === 'cargo';
    case 'cc':
      return pkg === 'gcc' || pkg === 'clang';
    default:
      return false;
  }
}

function classifyLayer(meta, artifact, purl) {
  if (purl && (purl.startsWith('pkg:nix') || purl.includes('outputhash='))) {
    return 'runtime';
  }
  if (typeof artifact.sourceInfo === 'string' && artifact.sourceInfo.includes('/nix/store/')) {
    return 'runtime';
  }
  if (typeof artifact.name === 'string' && (artifact.name.startsWith('nix') || artifact.name.includes('clearcutt'))) {
    return 'runtime';
  }
  // Some Grype CPE matches are emitted as pkg:generic even when the package is
  // the language runtime ClearCutt intentionally overlays into the image.
  if (isPrimaryRuntimePackage(meta, artifact.name)) {
    return 'runtime';
  }
  return 'base';
}

function remediationMetadata({ layer, severityKey, fixedIn, fixState }) {
  const highPriority = severityKey === 'critical' || severityKey === 'high';
  if (layer !== 'runtime') {
    return {
      status: 'deferred',
      reason: 'base_layer',
      summary:
        'This comes from the underlying base image, so ClearCutt lists it but cannot update it from the runtime layer.',
    };
  }
  if (!highPriority) {
    return {
      status: 'deferred',
      reason: 'below_priority_threshold',
      summary:
        'This is below the release-blocking severity threshold, so it is listed for awareness.',
    };
  }
  if (!fixedIn) {
    return {
      status: 'deferred',
      reason: 'no_fixed_version',
      summary:
        'No safe fixed version is currently listed for this package. We keep it visible until an upstream fix is available.',
    };
  }
  return {
    status: 'eligible',
    reason: 'fix_available',
    summary:
      'A safe fixed version is available for a package ClearCutt adds to this image.',
  };
}

function inclusionMetadata(meta, artifact, layer) {
  const pkg = String(artifact.name || '').toLowerCase();
  const lang = displayLanguage(meta.language);
  const version = meta.version ? ` ${meta.version}` : '';
  const variant = `${lang}${version} ${meta.tier}`;

  if (layer === 'base') {
    return {
      category: 'base_image',
      summary:
        'Inherited from the enterprise base image underneath the ClearCutt runtime layer.',
    };
  }
  if (isPrimaryRuntimePackage(meta, pkg)) {
    return {
      category: 'primary_runtime',
      summary: `Primary ${lang}${version} runtime required by this image variant.`,
    };
  }
  if (pkg === 'cacert' || pkg === 'nss-cacert') {
    return {
      category: 'trust_store',
      summary: 'TLS CA trust store required by networked runtimes.',
    };
  }
  if (meta.tier === 'slim' && (pkg === 'bash' || pkg === 'bash-interactive' || pkg === 'busybox')) {
    return {
      category: 'tier_tooling',
      summary:
        'Intentional slim-tier diagnostic utility. Distroless variants remove shells and core utilities.',
    };
  }
  if (meta.language === 'java' && pkg === 'cups') {
    return {
      category: 'java_compatibility',
      summary:
        'Pulled by the selected Java runtime closure for printing/AWT compatibility. Candidate for a headless-minimal profile.',
    };
  }
  if (meta.language === 'java' && pkg === 'libtiff') {
    return {
      category: 'java_compatibility',
      summary:
        'Pulled by the selected Java runtime closure for image/font stack compatibility. Candidate for a headless-minimal profile.',
    };
  }
  if (['glibc', 'gcc-unwrapped', 'libgcc', 'zlib', 'bzip2', 'xz', 'openssl'].includes(pkg)) {
    return {
      category: 'runtime_dependency',
      summary: `Runtime library required by the selected ${variant} closure.`,
    };
  }
  return {
    category: 'transitive_runtime',
    summary:
      `Transitive dependency of the selected ${variant} Nix runtime closure.`,
  };
}

function normalize(grypeResult, scannedAt, meta) {
  const matches = grypeResult.matches || [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0 };
  const findings = [];
  for (const m of matches) {
    const v = m.vulnerability || {};
    const a = m.artifact || {};
    const fix = v.fix || {};
    const sev = String(v.severity || 'Unknown').toLowerCase();
    const sevKey = ['critical', 'high', 'medium', 'low', 'negligible'].includes(sev)
      ? sev
      : 'unknown';
    counts[sevKey] += 1;

    let purl = null;
    if (Array.isArray(a.purl)) purl = a.purl[0] ?? null;
    else if (typeof a.purl === 'string') purl = a.purl;

    const fixedIn = Array.isArray(fix.versions) && fix.versions.length > 0 ? fix.versions.join(', ') : null;
    const fixState = fix.state || 'unknown';
    const layer = classifyLayer(meta, a, purl);

    const cvss = pickCvss(v.cvss);
    const epss = pickEpss(v.epss);

    findings.push({
      id: v.id || 'UNKNOWN',
      severity: v.severity || 'Unknown',
      packageName: a.name || '',
      packageVersion: a.version || '',
      purl,
      layer,
      fixedIn,
      fixState,
      remediation: remediationMetadata({ layer, severityKey: sevKey, fixedIn, fixState }),
      inclusion: inclusionMetadata(meta, a, layer),
      dataSource: v.dataSource || null,
      namespace: v.namespace || null,
      description: v.description || null,
      cvssScore: cvss?.score ?? null,
      cvssVersion: cvss?.version ?? null,
      cvssVector: cvss?.vector ?? null,
      epssScore: epss?.score ?? null,
      epssPercentile: epss?.percentile ?? null,
      // grype emits a single composite `risk` value (severity × EPSS, roughly).
      riskScore: typeof v.risk === 'number' ? v.risk : null,
    });
  }

  // Stable sort: severity (crit→neg→unknown), then by CVSS score desc, then
  // by package name, then id. Higher impact rises in the default view.
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, negligible: 4, unknown: 5 };
  findings.sort((a, b) => {
    const sa = sevOrder[a.severity.toLowerCase()] ?? 99;
    const sb = sevOrder[b.severity.toLowerCase()] ?? 99;
    if (sa !== sb) return sa - sb;
    const csa = a.cvssScore ?? -1;
    const csb = b.cvssScore ?? -1;
    if (csa !== csb) return csb - csa;
    if (a.packageName !== b.packageName) return a.packageName.localeCompare(b.packageName);
    return a.id.localeCompare(b.id);
  });

  return {
    scannedAt,
    scanner: `grype-${scannerVersion}`,
    dbBuiltAt,
    countsBySeverity: counts,
    findings,
  };
}

async function main() {
  if (!existsSync(SBOM_DIR)) {
    failOrWarn(`[scan] no SBOM cache at ${SBOM_DIR} - run gather first.`);
    return;
  }
  mkdirSync(OUT_DIR, { recursive: true });

  const tags = readdirSync(SBOM_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name);

  // Build the full work list up front, then scan concurrently. Each SBOM scan
  // is an independent grype process; the normalize step is cheap. grype is
  // CPU-bound (matching against the local DB), so the pool defaults to the
  // runner's core count — override with SCAN_CONCURRENCY.
  const work = [];
  for (const tag of tags) {
    const tagOut = path.join(OUT_DIR, tag);
    mkdirSync(tagOut, { recursive: true });
    const files = readdirSync(path.join(SBOM_DIR, tag)).filter((f) => f.endsWith('.sbom.json'));
    for (const f of files) {
      // Filename format: <target>-<arch>.sbom.json
      const m = f.match(/^(.+)-(amd64|arm64)\.sbom\.json$/);
      if (!m) continue;
      const [, target, arch] = m;
      work.push({
        tag,
        target,
        arch,
        sbomPath: path.join(SBOM_DIR, tag, f),
        outPath: path.join(tagOut, `${target}-${arch}.json`),
      });
    }
  }

  const concurrency = Math.max(
    1,
    parseInt(process.env.SCAN_CONCURRENCY || String(os.cpus().length || 4), 10),
  );
  console.log(`[scan] scanning ${work.length} SBOM(s) with concurrency ${concurrency}`);

  let total = 0;
  let failed = 0;
  await runPool(work, concurrency, async ({ tag, target, arch, sbomPath, outPath }) => {
    try {
      const grypeJson = await runGrype(sbomPath);
      const norm = normalize(grypeJson, new Date().toISOString(), targetMetadata(target));
      writeFileSync(outPath, JSON.stringify(norm, null, 2));
      const c = norm.countsBySeverity;
      console.log(
        `[scan] ${tag}/${target}/${arch}: ${norm.findings.length} findings ` +
          `(crit=${c.critical} high=${c.high} med=${c.medium} low=${c.low})`,
      );
      total += 1;
    } catch (err) {
      failed += 1;
      console.warn(`[scan] ${tag}/${target}/${arch}: ${err.message}`);
    }
  });
  console.log(`[scan] done. ${total} scans succeeded, ${failed} failed.`);
  if (STRICT && total === 0) {
    throw new Error(`[scan] strict ${SCAN_MODE} mode found zero SBOMs to scan.`);
  }
  if (STRICT && failed > 0) {
    throw new Error(`[scan] strict ${SCAN_MODE} mode had ${failed} failed scan(s).`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(STRICT ? 1 : 0);
});
