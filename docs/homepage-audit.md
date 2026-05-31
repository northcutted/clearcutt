# Homepage Claims Audit

This document maps every security, compliance, and supply chain claim on the ClearCutt homepage (`/`) to the source of truth on the About page (`/about`).

## Hero & Slogan

### 1. Title/Hero Slogan
* **Homepage Claim**: `Enterprise Compliance, Hermetically Built.` (index.astro:33-36)
* **About Alignment**: `/about` uses `Enterprise Compliance, Hermetically Built.` inside the brand slogan box.
* **Audit Result**: `matches About`
* **Refinement Plan**: The headline currently leads with "Enterprise Compliance" which carries sales connotations. Update it to lead with the blueprint identity ("Hardened Image Blueprint, Hermetically Built") to match About's technical framing and prevent managed-offering implications.

### 2. Slogan Box Slogans & Blueprint Framing
* **Homepage Claim**: `ClearCutt is an open-source container hardening blueprint built declaratively using Nix. The catalog below serves as a live worked-example of a production image feed. Downstream teams are expected to fork this blueprint to run and govern their own custom internal feeds.` (index.astro:39-41)
* **About Alignment**: `/about` says: `ClearCutt is not an opinionated OS—it is an open-source base image blueprint built with Nix. Downstream teams can fork and adapt the blueprint to compile, customize, and govern their own internal base image feeds or graft secure closures onto existing mandated base OS layers.`
* **Audit Result**: `matches About`

---

## Technical & Compliance Claims Cards

### 3. Claim Card 1: Supply Chain Safety
* **Homepage Claim**: `Reduced Attack Surface - Reduce software supply chain surprises. Our hermetic Nix-based compilation prevents untracked package injection, yielding standard runtimes with verifiable reproducibility.` (index.astro:123-128)
* **About Alignment**: `/about` explains: `Our supply chain pipeline compiles target runtimes as isolated, hermetically-built /nix/store closures. The catalog serves as a live worked-example proving the end-to-end verifiability of our OCI builds...`
* **Audit Result**: `contradicts About` (unverifiable claim: "yielding standard runtimes with verifiable reproducibility" is too strong and doesn't link to the actual step-by-step verification commands, nor does it address that reproducibility is lost when grafting closures onto non-Nix base OS layers).
* **Refinement Plan**: Change heading to `Hermetic store closures`. Rewrite to: "Nix-based hermetic compilation prevents untracked package injection. Read how to run bit-for-bit reproducibility checks." Link directly to the audit guide `/about?tab=audit`.

### 4. Claim Card 2: STIG & FIPS
* **Homepage Claim**: `Enterprise Suitability - ClearCutt Distroless images reduce several STIG-relevant execution vectors by default, while production runtimes can be customized to bind to FIPS-validated cryptographic modules.` (index.astro:135-140)
* **About Alignment**: `/about` says: `Our distroless tier satisfies structural container integrity guidelines by omitting all shells, package managers, and core system utilities—greatly reducing typical command injection escape paths.` and `Using declarative Nix definitions, runtimes can be customized to bind exclusively to verified cryptographic modules (like OpenSSL in FIPS mode) or graft closures directly onto validated government overlays.`
* **Audit Result**: `contradicts About` ("FIPS-validated cryptographic modules" implies dynamic CMVP validation, and card is titled "Enterprise Suitability" which is vague and sales-oriented).
* **Refinement Plan**: Downgrade header to `STIG-Relevant Structure`. Rewrite body to: "Omits all shells, package managers, and core system utilities, satisfying structural container integrity guidelines. Runtimes can be configured to bind to verified cryptographic modules such as OpenSSL in FIPS mode."

### 5. Claim Card 3: Blueprint Reusability
* **Homepage Claim**: `High Reusability - Forkable blueprint. Download reference runtimes, or easily spin up a fully customizable internal base image pipeline and feed for your organization.` (index.astro:147-152)
* **About Alignment**: `/about` says: `Downstream teams are expected to fork this repository to compile and govern their own custom internal container feeds...`
* **Audit Result**: `matches About`

---

## Telemetry Metrics

### 6. Dynamic Counts & Complete Attestations
* **Homepage Claims**:
  * Image Verification: `{evidenceCoverage.signatures} / {published}` (index.astro:215-217)
  * Subtext: `100% keyless OIDC signed` (index.astro:218)
  * SLSA Provenance: `{evidenceCoverage.provenance} / {published}` (index.astro:224-226)
  * Subtext: `SLSA Level 3 certified` (index.astro:228)
* **About Alignment**: `/about` states: `The catalog reports those channels independently; provenance never stands in for a missing signature, and vulnerability scans show as pending until every architecture has fresh scan data.`
* **Audit Result**: `contradicts About` (unverifiable/placeholder hardcoded labels like "100% keyless OIDC signed" and "SLSA Level 3 certified").
* **Refinement Plan**: Dynamically output subtext based on computed values to show pending/missing states cleanly if any channel is incomplete, and use honest, downgraded phrasing:
  * For signatures: `{evidenceCoverage.signatures === published ? 'All images keyless OIDC signed' : `${evidenceCoverage.signatures} of ${published} signed (pending completion)`}`
  * For provenance: `{evidenceCoverage.provenance === published ? 'All images SLSA Level 3 provenanced' : `${evidenceCoverage.provenance} of ${published} provenanced (pending completion)`}`

---

## Sales/Branding Artifacts

### 7. Perspective Switcher labels
* **Homepage Claim**: Switches between Platform Teams and Security Auditors (index.astro:97-113)
* **About Alignment**: Matches technical target audiences.
* **Audit Result**: `placeholder` (uses `executive` and `developer` internal variable IDs and comments which represent sales-oriented and executive perspectives).
* **Refinement Plan**: Clean up the comments and variable IDs, changing `executive` -> `operator` and `developer` -> `auditor` to align with the platform team vs security auditor focus.

### 8. Navigation & Header Branding
* **Homepage/Shared Title & Logo Subtitle**: `Hardened Fleet Catalog` (Base.astro:16, 73)
* **About Alignment**: `/about` makes it clear the project is a blueprint and reference catalog, not a managed enterprise fleet solution.
* **Audit Result**: `contradicts About` ("Hardened Fleet Catalog" implies a managed service or SaaS model instead of an open-source reference build/blueprint).
* **Refinement Plan**: Replace `Hardened Fleet Catalog` with `Reference Build Catalog` or `Hardened Image Blueprint` in `Base.astro` and page headers.
