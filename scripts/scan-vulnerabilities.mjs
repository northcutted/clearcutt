#!/usr/bin/env node
// Scan every cached SBOM with Grype and emit a normalized vulnerability JSON
// per (tag, target, arch). The catalog gather script picks these up on its
// second pass and merges them into each image record.
//
// Inputs (env):
//   SBOM_CACHE_DIR  default: site/src/data/sboms
//   VULN_DIR        default: site/src/data/vulnerabilities
//
// Requires:
//   grype on PATH. If absent, the script no-ops (exits 0) so the rest of the
//   pipeline keeps working with whatever vulnerability data already exists.

import { execSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SBOM_DIR = process.env.SBOM_CACHE_DIR || path.join(ROOT, 'site', 'src', 'data', 'sboms');
const OUT_DIR = process.env.VULN_DIR || path.join(ROOT, 'site', 'src', 'data', 'vulnerabilities');
const GRYPE_OPTS = (process.env.GRYPE_OPTS || '').split(' ').filter(Boolean);

function have(cmd) {
  try { execSync(`command -v ${cmd}`, { stdio: 'ignore' }); return true; } catch { return false; }
}

if (!have('grype')) {
  console.warn('[scan] grype not on PATH — skipping. Install grype to enable CVE reporting.');
  process.exit(0);
}

function grypeVersion() {
  try {
    const v = execSync('grype version -o json 2>/dev/null', { encoding: 'utf8' });
    const j = JSON.parse(v);
    return { version: j.version || j.application, dbBuiltAt: j.db?.built || null };
  } catch {
    return { version: 'grype', dbBuiltAt: null };
  }
}
const { version: scannerVersion, dbBuiltAt } = grypeVersion();
console.log(`[scan] grype ${scannerVersion}, db built ${dbBuiltAt ?? 'unknown'}`);

function runGrype(sbomPath) {
  const res = spawnSync(
    'grype',
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

    findings.push({
      id: v.id || 'UNKNOWN',
      severity: v.severity || 'Unknown',
      packageName: a.name || '',
      packageVersion: a.version || '',
      purl,
      fixedIn: Array.isArray(fix.versions) && fix.versions.length > 0 ? fix.versions.join(', ') : null,
      fixState: fix.state || 'unknown',
      dataSource: v.dataSource || null,
      namespace: v.namespace || null,
      description: v.description || null,
    });
  }

  // Stable sort: severity (crit→neg→unknown), then by package name, then id.
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, negligible: 4, unknown: 5 };
  findings.sort((a, b) => {
    const sa = sevOrder[a.severity.toLowerCase()] ?? 99;
    const sb = sevOrder[b.severity.toLowerCase()] ?? 99;
    if (sa !== sb) return sa - sb;
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
    console.warn(`[scan] no SBOM cache at ${SBOM_DIR} — run gather first.`);
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
}

main().catch((err) => {
  console.error(err);
  process.exit(0); // never fail the pipeline on scan errors
});
