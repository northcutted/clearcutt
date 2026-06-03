// Single source of truth for product messaging. ClearCutt is a kit you fork and
// run — not a managed service or a registry you depend on. Keep one identity and
// one lifecycle spine; the homepage and About page both read from here.
export const claims = {
  identity: {
    name: "ClearCutt",
    category: "the forkable platform kit for hardened base images",
    slogan: "Fork the kit. Own the trust chain.",
  },
  hero: {
    title: "Hardened base images, evidence built in.",
    slogan: "Fork the kit. Own the trust chain.",
    description:
      "ClearCutt is a free, forkable platform kit for publishing your own hardened base-image fleet — every image signed, SBOM-attested, and SLSA-provenanced — under your own GitHub OIDC identities. You run the pipeline; there's no vendor to trust.",
  },
  // The product spine: one job per phase of the delivery lifecycle. A manager
  // reads the `outcome`; an engineer follows `detail` into the depth. The
  // homepage renders this as the phase map and the README mirrors it as a table.
  lifecycle: [
    { phase: "Author",   outcome: "Own your base-image fleet as code — fork it, don't depend on a vendor.", detail: "fleet.yaml · Nix matrix · platform init" },
    { phase: "Publish",  outcome: "Every image ships signed, SBOM'd, and SLSA-attested — automatically.", detail: "cosign keyless · SPDX · SLSA L3" },
    { phase: "Discover", outcome: "One catalog shows exactly what's signed and scanned. No guessing.", detail: "list · inspect · matrix" },
    { phase: "Adopt",    outcome: "App teams onboard in minutes — no Nix, no Dockerfile archaeology.", detail: "app template · dev tier · devcontainers" },
    { phase: "Certify",  outcome: "Block non-compliant images before they leave CI.", detail: "certify · verify · policy gates" },
    { phase: "Admit",    outcome: "Only signed, attested images run in your clusters.", detail: "Kyverno / OPA admission" },
    { phase: "Operate",  outcome: "Patch a base once, move every app onto it — no rebuild.", detail: "app rebase · VEX triage · mirror" },
  ],
  stig: {
    title: "Structural Hardening",
    description: "The distroless tier omits shells, package managers, and core system utilities. That reduces common shell-spawn escape paths, while keeping the exact boundary visible in the security model."
  },
  cryptography: {
    title: "Cryptographic Evidence",
    description: "Images expose independently verifiable Sigstore signatures, SBOM attestations, SLSA Build L3 provenance, test evidence, and release metadata that downstream gates can pin to exact workflow identities."
  },
  reproducibility: {
    title: "Hermetic Store Closures",
    description: "Nix-based hermetic compilation prevents untracked package injection. Read how downstream forks run bit-for-bit reproducibility checks on their Nix store closures."
  }
};
