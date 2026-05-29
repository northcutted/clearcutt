#!/usr/bin/env node
// Verify that one published ClearCutt image ref has all release evidence
// expected by the catalog: Sigstore signature, SBOM attestation, test-results
// attestation, SLSA provenance, and GitHub-native provenance attestation.

import { spawnSync } from 'node:child_process';

const args = parseArgs(process.argv.slice(2));
const ref = required('ref');
const expectedDigest = args.digest || null;
const githubRepo = required('repo');
const workflowIdentity = required('workflow-identity');
const oidcIssuer = args['oidc-issuer'] || 'https://token.actions.githubusercontent.com';
const sourceRef = args['source-ref'] || 'refs/heads/main';
const sourceBranch = args['source-branch'] || sourceRef.replace(/^refs\/heads\//, '');
const digestRef = expectedDigest ? `${imageRepository(ref)}@${expectedDigest}` : null;

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    if (!key.startsWith('--')) continue;
    out[key.slice(2)] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true';
  }
  return out;
}

function required(name) {
  const value = args[name];
  if (!value) {
    console.error(`[evidence] missing --${name}`);
    process.exit(2);
  }
  return value;
}

function imageRepository(imageRef) {
  const withoutDigest = imageRef.split('@')[0];
  const lastColon = withoutDigest.lastIndexOf(':');
  const lastSlash = withoutDigest.lastIndexOf('/');
  return lastColon > lastSlash ? withoutDigest.slice(0, lastColon) : withoutDigest;
}

function run(label, command, commandArgs, { allowFailure = false } = {}) {
  const res = spawnSync(command, commandArgs, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 64 * 1024 * 1024,
  });
  if (res.status === 0) {
    console.log(`[evidence] ok: ${label}`);
    return res.stdout;
  }
  if (allowFailure) return null;
  const detail = [res.stdout, res.stderr].filter(Boolean).join('\n').trim();
  console.error(`[evidence] failed: ${label}`);
  if (detail) console.error(detail);
  process.exit(res.status || 1);
}

function cosignIdentityArgs() {
  return [
    '--certificate-identity',
    workflowIdentity,
    '--certificate-oidc-issuer',
    oidcIssuer,
  ];
}

const resolvedDigest = run('resolve image digest', 'crane', ['digest', ref]).trim();
if (expectedDigest && resolvedDigest !== expectedDigest) {
  console.error(`[evidence] digest mismatch for ${ref}: got ${resolvedDigest}, expected ${expectedDigest}`);
  process.exit(1);
}

const immutableRef = digestRef || `${imageRepository(ref)}@${resolvedDigest}`;

run('Sigstore keyless signature', 'cosign', [
  'verify',
  immutableRef,
  ...cosignIdentityArgs(),
  '--output',
  'json',
]);

run('SPDX SBOM attestation', 'cosign', [
  'verify-attestation',
  immutableRef,
  '--type',
  'spdxjson',
  ...cosignIdentityArgs(),
]);

run('test-results attestation', 'cosign', [
  'verify-attestation',
  immutableRef,
  '--type',
  'custom',
  ...cosignIdentityArgs(),
]);

// The SLSA generator publishes provenance that is validated end-to-end by
// slsa-verifier. Keep cosign checks focused on ClearCutt's own release
// signature, SBOM, and test-results attestations above.
run('slsa-verifier provenance check', 'slsa-verifier', [
  'verify-image',
  immutableRef,
  '--source-uri',
  `github.com/${githubRepo}`,
  '--source-branch',
  sourceBranch,
]);

run('GitHub-native provenance attestation', 'gh', [
  'attestation',
  'verify',
  `oci://${immutableRef}`,
  '--repo',
  githubRepo,
  '--cert-identity',
  workflowIdentity,
  '--source-ref',
  sourceRef,
]);

console.log(`[evidence] complete: ${immutableRef}`);
