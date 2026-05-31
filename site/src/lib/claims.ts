export const claims = {
  hero: {
    title: "Hardened Image Blueprints, Hermetically Built.",
    slogan: "Enterprise Compliance, Hermetically Built.",
    description: "ClearCutt is not an opinionated OS—it is an open-source base image blueprint built with Nix. Downstream teams can fork and adapt the blueprint to compile, customize, and govern their own internal base image feeds or graft secure closures onto existing mandated base OS layers."
  },
  stig: {
    title: "STIG-Relevant Structure",
    description: "Our distroless tier satisfies structural container integrity guidelines by omitting all shells, package managers, and core system utilities—greatly reducing typical command injection escape paths."
  },
  cryptography: {
    title: "Cryptographic Overlays",
    description: "Using declarative Nix definitions, runtimes can be customized to bind exclusively to verified cryptographic modules (like OpenSSL in FIPS mode) or graft closures directly onto validated government overlays."
  },
  reproducibility: {
    title: "Hermetic Store Closures",
    description: "Nix-based hermetic compilation prevents untracked package injection. Read how downstream forks run bit-for-bit reproducibility checks on their Nix store closures."
  }
};
