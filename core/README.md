# ClearCutt Core Image Workspace

This workspace owns the Nix image factory backend, runtime overlays, the
retained legacy release pipeline fallback, the retained remediation drafting
agent, and image conformance tests.

```bash
cd core
nix develop --extra-experimental-features "nix-command flakes"
cd ..
./clearcutt fleet certify-target --core-dir core --system x86_64-linux --language coreLTS --tier slim
cd core
python3 -m unittest tests/test_remediation_pipeline.py
```

Use `./clearcutt fleet certify-target --engine shell ...` only when debugging
legacy `core/pipeline/pipeline.sh` parity. The fallback script still owns the
shell wrapper mechanics, but its closure-purity and runtime-CVE checks delegate
to `clearcutt verify ...`.

Catalog generation now lives in the Go CLI and writes site data into the root
`site/` workspace:

```bash
../clearcutt catalog gather
../clearcutt catalog enrich
../clearcutt catalog build
```

Catalog verification moved from a Node script into the Go CLI. Run it from the
repo root (the make target builds the CLI first):

```bash
make site-verify-catalog   # builds the CLI, then runs: clearcutt verify catalog
```

The representative PR-gate image-security boundary suite is also CLI-owned. It
realizes missing representative archives through the Nix flake, then runs native
Go closure-purity and runtime-CVE gates:

```bash
../clearcutt verify boundary-suite --core-dir .
```

Remediation scan planning, deterministic overlay rendering, evidence sidecars,
branch folding, and PR orchestration live in the Go CLI now. The retained
Python backend is an optional fallback for campaigns that still need hash
iteration, build probing, rescanning, or LLM-assisted drafting:

```bash
../clearcutt remediation plan --vuln-root ../site/src/data/vulnerabilities
../clearcutt remediation report --plan ../core/build-outputs/remediation-plan.json --out ../core/build-outputs/remediation-report.json
../clearcutt remediation validate-overlays --overlay-dir overlays/cve
../clearcutt remediation run --vuln-root ../site/src/data/vulnerabilities
../clearcutt remediation open-pr --branch cve-remediation/example --package zlib --cve CVE-2026-12345 --dry-run
```

`remediation run --llm off` discovers this workspace from the Nix core markers
and can draft deterministic source/patch URL plus hash remediations without the
retained Python backend on disk.

The scheduled flow is an approved remediation PR loop: scan, policy rank,
generate evidence-backed draft overlays when explicitly enabled, attach
evidence, and open a draft PR. PR-gate and release checks must rebuild and
rescan before merge. The flow does not merge, release, or deploy the change
automatically.

## Scan scoping

`clearcutt scan` scans every cached SBOM tag by default. CI can opt into a
bounded window without changing the output JSON shape:

```bash
SCAN_TAG_DEPTH=4 ../clearcutt scan --mode catalog
../clearcutt scan refresh-kev
SCAN_TAG_DEPTH=1 ../clearcutt scan --mode remediation --sbom-dir ../site/src/data/sboms --out-dir ../site/src/data/vulnerabilities --update-db
KEV_FILE=build-outputs/security-intel/known_exploited_vulnerabilities.json ../clearcutt scan --mode remediation
SCAN_ALL_TAGS=1 ../clearcutt scan --mode catalog
SCAN_TAGS=v0.11.1,v0.11.0 ../clearcutt scan --mode catalog
```

Precedence is explicit `SCAN_TAGS`, then `SCAN_ALL_TAGS`, then
`SCAN_TAG_DEPTH`, then the default full scan. Tag ordering mirrors the
Go remediation planner's version parser so the scanner's newest tag and the
planner's newest vulnerability directory stay aligned. `scan refresh-kev`
refreshes the CISA KEV cache used by `--kev-file`; refresh failures write an
unavailable status and continue. `--update-db` asks the CLI to refresh the local
Grype database before scanning; refresh failures warn and continue with the
active local database.

From the repository root, use:

```bash
make core-remediation-tests
make catalog-generate
make catalog-scan
make core-verify
```
