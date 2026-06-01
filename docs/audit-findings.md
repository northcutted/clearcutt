# ClearCutt Audit Findings & Inventory

This document maps all user-facing superlative, compliance, and metric claims identified across `site/` and `README.md` to their recommended action (Verifiable, Scoped, or Must-Delete/Downgrade). 

---

## 1. Inventory of Claims

| File Path | Line | Original Claim | Classification & Action | Proposed Replacement / Scoping |
| :--- | :--- | :--- | :--- | :--- |
| `site/src/pages/index.astro` | 123 | `"Zero Risk Supply Chain"` | **Must-Delete** (Violates Prime Directive) | `"Reduced Supply-Chain Attack Surface"` |
| `site/src/pages/index.astro` | 126 | `"Eliminate software supply chain surprises. Our hermetic building prevents outside package injection, yielding standard runtimes with absolute reproducibility."` | **Scoped** | `"Reduce software supply chain surprises. Our hermetic Nix-based compilation prevents untracked package injection, yielding standard runtimes with verifiable reproducibility."` |
| `site/src/pages/index.astro` | 35 | `"Hermetically Sealed."` (Hero) | **Scoped** (Seal has documented trade-off holes) | `"Hermetically Built."` |
| `site/src/pages/about.astro` | 70 | `"Hermetically Sealed."` | **Scoped** | `"Hermetically Built."` |
| `site/src/pages/index.astro` | 138 | `"ClearCutt Distroless images are STIG-Aligned out-of-the-box ... while all production runtimes support FIPS 140-3 capable cryptographic paths."` | **Scoped / Flagged** (Gated on FIPS/STIG verification) | Rework to scoped language unless backed: `"ClearCutt Distroless images reduce several STIG-relevant execution vectors by default ... while production runtimes can be customized to bind to FIPS-validated cryptographic modules."` |
| `site/src/pages/index.astro` | 228 | `"STIG / FIPS"` badge and `"Distroless STIG, Prod FIPS"` subtitle | **Scoped / Flagged** | Link to specific verification evidence (e.g. structural tests) or downgrade/remove badge. |
| `site/src/pages/about.astro` | 98-101 | `"STIG-Aligned ... Our distroless tier satisfies DISA STIG container requirements out-of-the-box..."` | **Scoped / Flagged** | Rework to reflect specific structural assertions. |
| `site/src/pages/about.astro` | 107-110 | `"FIPS 140-3 Capable ... By leveraging Nix configurations, images link only to FIPS-validated cryptographic modules..."` | **Scoped / Flagged** | Check CMVP validated module cert or downgrade to scoped customization options. |
| `site/src/pages/catalog.astro` | 137 | `"STIG-ALIGNED"` label on matrix cell | **Scoped / Flagged** | Downgrade or back with a checkable test suite. |
| `site/src/pages/catalog.astro` | 138 | `"FIPS READY"` label on matrix cell | **Scoped / Flagged** | Downgrade or back with a validated module cert. |
| `site/src/components/ImageHeader.astro` | 70 | `{image.tier.id === 'distroless' && <StatusPill kind="ok" label="STIG-Aligned" />}` | **Scoped / Flagged** | Rework or back with checks. |
| `site/src/components/ImageHeader.astro` | 71 | `{image.tier.id !== 'dev' && <StatusPill kind="ok" label="FIPS 140-3 Capable" />}` | **Scoped / Flagged** | Rework or back with checks. |
| `site/src/components/MatrixGrid.astro` | 304 | `"STIG-ALIGNED"` | **Scoped / Flagged** | Rework or back with checks. |
| `site/src/components/MatrixGrid.astro` | 307 | `"FIPS READY"` | **Scoped / Flagged** | Rework or back with checks. |
| `site/src/pages/index.astro` | 235 | `"Runtimes Managed"` (badge) | **Scoped** (implies hosted product) | `"Reference Runtimes"` or `"Blueprint Targets"` |
| `site/src/pages/index.astro` | 207 | `"100% keyless OIDC signed"` | **Verifiable** (but must be backed by real dynamic data & timestamp) | Wire to catalog index generation timestamp and verify `evidenceCoverage.signatures === published`. |
| `site/src/pages/index.astro` | 217 | `"SLSA Level 3 certified"` | **Verifiable** | Show verification source. |
| `README.md` | 8 | `"...easily fork the blueprint to customize and compile your own enterprise-wide base image fleet."` | **Scoped** | Reframer "fleet" to "blueprint reference" to clarify single-maintainer reference status. |

---

## 2. Infrastructure & Tooling Inventory

1. **Signing Workflows**:
   - Located in `.github/workflows/release.yml`.
   - Utilizes keyless OIDC signing via GitHub Actions OIDC token (`id-token: write`).
   - Uses `sigstore/cosign-installer@v4.1.2` with `cosign-release: 'v3.0.6'` to sign multi-arch manifests and attach SBOMs (`--type spdxjson`) and custom test results (`--type custom`).
2. **Build-Certify / Certify composite action**:
   - Located in `.github/actions/certify-app/action.yml`.
   - Currently hardcodes `https://github.com/northcutted/clearcutt/releases/download/...` to download the CLI utility.
   - Can be parameterized using standard Actions context variable `${{ github.action_repository }}` to make it completely fork-safe.
3. **Scripts & Conformance**:
   - `clearcutt catalog gather` / `clearcutt catalog enrich` (Go CLI): Core catalog aggregators that write `site/src/data/catalog/index.json` and registry enrichment data.
   - `clearcutt scan` (Go CLI, `cli/internal/commands/scan.go`): Invokes Grype to scan cached SBOMs and emits reports under `site/src/data/vulnerabilities`.
   - `core/tests/verify.sh`: Local automated PR gate running Container Structure Tests, credential checks, binary hermeticity, and overlays checking.
4. **Stats / Telemetry Sourcing**:
   - Stats shown on `site/src/pages/index.astro` are loaded at build-time using `loadIndex()` from `site/src/lib/catalog.ts`, which reads `site/src/data/catalog/index.json`.
   - Since `index.json` is generated directly from the release assets and live registry metadata by the Go catalog commands, these numbers are already dynamic, but lack a displayed generation timestamp.
