// Single source of truth for product messaging. ClearCutt is a kit you fork and
// run — not a managed service or a registry you depend on. Keep one identity and
// one operating model; the homepage and About page both read from here.
export const claims = {
  identity: {
    name: "ClearCutt",
    category: "the forkable platform kit and reference implementation for hardened base images",
    slogan: "Fork the kit. Own the trust chain.",
  },
  hero: {
    title: "Hardened base images, evidence built in.",
    slogan: "Fork the kit. Own the trust chain.",
    description:
      "ClearCutt is a free, forkable platform kit and reference implementation for publishing your own hardened base-image fleet, with workflows configured for signatures, SBOM attestations, SLSA provenance, catalog evidence, app-team templates, and governance gates under your own GitHub OIDC identities. You run the pipeline; there is no hosted ClearCutt control plane to trust.",
  },
  // The product spine: manager-readable outcomes with engineer-readable controls.
  // The first two steps are the platform loop; the last three are the repeated
  // app delivery loop.
  lifecycle: [
    { phase: "Own the fleet", outcome: "Platform teams fork the kit and turn base images into governed source, not a vendor dependency.", detail: "fleet config · matrix add · runtime scaffold" },
    { phase: "Publish evidence", outcome: "Release workflows are configured to produce signed images, SBOMs, provenance, scans, and a catalog that shows each channel independently, including missing evidence.", detail: "catalog build · release evidence · SLSA + Sigstore" },
    { phase: "Onboard apps", outcome: "App teams get matching dev images, starter templates, and rebasable build paths without learning Nix.", detail: "list · inspect · dev · app template/build" },
    { phase: "Gate delivery", outcome: "CI and admission policies block images that miss your runtime, evidence, or vulnerability contract.", detail: "certify · verify · conformance · policy" },
    { phase: "Operate updates", outcome: "Security teams triage findings, document exceptions, and move compatible app layers onto patched bases under review.", detail: "scan · remediation · VEX · app diff-base/rebase" },
  ],
  stig: {
    title: "Structural Hardening",
    description: "The distroless tier omits shells, package managers, and core system utilities. That reduces common shell-spawn escape paths, while keeping the exact boundary visible in the security model."
  },
  cryptography: {
    title: "Cryptographic Evidence",
    description: "Catalog records expose Sigstore signature, SBOM attestation, SLSA provenance, test evidence, and release metadata channels that downstream gates can pin to exact workflow identities and verify against registry evidence when needed."
  },
  reproducibility: {
    title: "Nix Store Closures",
    description: "Nix-based builds constrain runtime inputs to declared store closures and support reproducibility checks by downstream forks."
  }
};
