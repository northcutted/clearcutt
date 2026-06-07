# ClearCutt Core Image Workspace

This workspace owns the Nix image factory, runtime overlays, release pipeline,
the retained remediation drafting agent, and image conformance tests.

```bash
cd core
nix develop --extra-experimental-features "nix-command flakes"
./pipeline/pipeline.sh --system x86_64-linux coreLTS-slim
python3 -m unittest tests/test_remediation_pipeline.py
```

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

Remediation scan planning and PR orchestration also live in the Go CLI now. The
drafting agent remains in Python because it owns the LLM/Nix patch-authoring
loop:

```bash
../clearcutt remediation plan --vuln-root ../site/src/data/vulnerabilities
../clearcutt remediation report --plan ../core/build-outputs/remediation-plan.json --out ../core/build-outputs/remediation-report.json
../clearcutt remediation validate-overlays --overlay-dir overlays/cve
../clearcutt remediation run --vuln-root ../site/src/data/vulnerabilities
../clearcutt remediation open-pr --branch cve-remediation/example --package zlib --cve CVE-2026-12345 --dry-run
```

The scheduled flow is an approved remediation PR loop: scan, policy rank,
generate a draft patch, validate that expected CVE/package pairs disappeared,
and open a draft PR with evidence. It does not merge, release, or deploy the
change automatically.

## Scan scoping

`clearcutt scan` scans every cached SBOM tag by default. CI can opt into a
bounded window without changing the output JSON shape:

```bash
SCAN_TAG_DEPTH=4 ../clearcutt scan --mode catalog
SCAN_TAG_DEPTH=1 ../clearcutt scan --mode remediation --sbom-dir ../site/src/data/sboms --out-dir ../site/src/data/vulnerabilities
KEV_FILE=build-outputs/security-intel/known_exploited_vulnerabilities.json ../clearcutt scan --mode remediation
SCAN_ALL_TAGS=1 ../clearcutt scan --mode catalog
SCAN_TAGS=v0.11.1,v0.11.0 ../clearcutt scan --mode catalog
```

Precedence is explicit `SCAN_TAGS`, then `SCAN_ALL_TAGS`, then
`SCAN_TAG_DEPTH`, then the default full scan. Tag ordering mirrors the
Go remediation planner's version parser so the scanner's newest tag and the
planner's newest vulnerability directory stay aligned.

From the repository root, use:

```bash
make core-remediation-tests
make catalog-generate
make catalog-scan
make core-verify
```
