#!/usr/bin/env node
// Scan every cached SBOM with Grype and emit a normalized vulnerability JSON
// per (tag, target, arch). The catalog gather script picks these up on its
// second pass and merges them into each image record.
//
// Inputs (env):
//   SBOM_CACHE_DIR  default: site/src/data/sboms
//   VULN_DIR        default: site/src/data/vulnerabilities
//   SCAN_MODE       catalog (default), remediation, or release
//   GRYPE_BIN       grype executable override for tests
//
// Requires:
//   grype on PATH. In catalog mode, missing/failed scans are best-effort so
//   Pages keeps publishing. In remediation/release modes, missing tooling or
//   failed scans fail closed.

import { execSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SBOM_DIR = process.env.SBOM_CACHE_DIR || path.join(ROOT, 'site', 'src', 'data', 'sboms');
const OUT_DIR = process.env.VULN_DIR || path.join(ROOT, 'site', 'src', 'data', 'vulnerabilities');
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

function runGrype(sbomPath) {
  const res = spawnSync(
    GRYPE_BIN,
    ['sbom:' + sbomPath, '-o', 'json', '--quiet', ...GRYPE_OPTS],
    { encoding: 'utf8', maxBuffer: 128 * 1024 * 1024 },
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

function normalize(grypeResult, scannedAt) {
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

    // Stage 1/5 Classification: Determine if package is Nix-managed (runtime) or Base OS (base)
    let layer = 'base';
    if (purl && (purl.startsWith('pkg:nix') || purl.includes('outputhash='))) {
      layer = 'runtime';
    } else if (typeof a.sourceInfo === 'string' && a.sourceInfo.includes('/nix/store/')) {
      layer = 'runtime';
    } else if (typeof a.name === 'string' && (a.name.startsWith('nix') || a.name.includes('clearcutt'))) {
      layer = 'runtime';
    }

    const cvss = pickCvss(v.cvss);
    const epss = pickEpss(v.epss);

    findings.push({
      id: v.id || 'UNKNOWN',
      severity: v.severity || 'Unknown',
      packageName: a.name || '',
      packageVersion: a.version || '',
      purl,
      layer, // Add the layer classification field
      fixedIn: Array.isArray(fix.versions) && fix.versions.length > 0 ? fix.versions.join(', ') : null,
      fixState: fix.state || 'unknown',
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

  let total = 0;
  let failed = 0;
  for (const tag of tags) {
    const tagOut = path.join(OUT_DIR, tag);
    mkdirSync(tagOut, { recursive: true });
    const files = readdirSync(path.join(SBOM_DIR, tag)).filter((f) => f.endsWith('.sbom.json'));
    for (const f of files) {
      // Filename format: <target>-<arch>.sbom.json
      const m = f.match(/^(.+)-(amd64|arm64)\.sbom\.json$/);
      if (!m) continue;
      const [, target, arch] = m;
      const sbomPath = path.join(SBOM_DIR, tag, f);
      const outPath = path.join(tagOut, `${target}-${arch}.json`);
      try {
        const grypeJson = runGrype(sbomPath);
        const norm = normalize(grypeJson, new Date().toISOString());
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
    }
  }
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
