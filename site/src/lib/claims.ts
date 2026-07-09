// Single source of truth for product messaging. ClearCutt bootstraps a
// user-owned GitHub control-plane repo; it is not a managed service or a
// registry you depend on. Keep one identity and one operating model; the
// homepage and About page both read from here.
export const claims = {
  identity: {
    name: "ClearCutt",
    category: "the CLI for GitHub-native container image control planes",
    slogan: "Bootstrap the control plane. Own the trust chain.",
  },
  hero: {
    title: "Container image control planes, generated into your repo.",
    slogan: "Bootstrap the control plane. Own the trust chain.",
    description:
      "ClearCutt is a free CLI for bootstrapping GitHub-native container image control planes: catalog, release, signing, attestation, policy, and app-team adoption workflows generated into your own repo. Start catalog-only from images.yaml without Nix, then graduate to the fleet profile when ClearCutt should build the image fleet.",
  },
  // The product spine: manager-readable outcomes with engineer-readable controls.
  // The first two steps are the platform loop; the last three are the repeated
  // app delivery loop.
  lifecycle: [
    { phase: "Own the control plane", outcome: "Platform teams generate the repository that owns catalog inputs, workflows, evidence, policies, and operating decisions.", detail: "platform bootstrap · platform plan · platform apply" },
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
