# ClearCutt Hardened Fleets Declarative Entrypoint
# Brand Owner & Principal Architect: Eddie Northcutt
# Paradigm: Declarative OCI Layer Compilation (SLSA L3 Ready)

{
  description = "ClearCutt Hardened Base Image Fleets - Declarative, CVE-aware Nix Store Layers";

  nixConfig = {
    extra-substituters = [ "https://nix-cache.clearcutt.dev" ];
    extra-trusted-public-keys = [ "clearcutt-cache-1:0O2A23T11EBggh2Uz+LJcaRMBpuS9eUjeWmXKP0QoDE=" ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }:
    utils.lib.eachDefaultSystem (system:
      let
        hostPkgs = import nixpkgs {
          inherit system;
          config = {
            # `allowUnfree` is required for JDKs (Zulu/Oracle) and a few fonts.
            # `allowBroken` was removed: it let Nix produce binaries from
            # packages maintainers had flagged broken, which is incompatible
            # with the project's fixable-CVE gate. If a specific package is
            # incorrectly marked broken, override it inside overlays/cve/.
            allowUnfree = true;
          };
          overlays = [
            (import ./overlays/cve-remediation.nix)
          ];
        };

        # Host package alignment: we build native OCI layers using the host system platform
        # to ensure absolute compilation stability across all runtime systems (JDK, Node, Python, Go, .NET).
        # We completely avoid unstable pkgsCross cross-compilation on macOS hosts, enabling 100% stable local
        # testing and development shells natively on Darwin, while relying on native Linux environments (GHA/runners)
        # for production release matrix compilation.
        pkgs = hostPkgs;

        # Import centralized language and runtime registry
        registry = import ./lib/registry.nix { inherit pkgs; };

        # Import our custom image compiler
        compiler = import ./lib/build-fleet.nix { inherit pkgs; };

        # Helper to generate standard package name attributes
        mkPackageName = lang: ver: tier: "${lang}${ver}-${tier}";

        # Matrix specifications - dynamically generated from the central registry
        languages = builtins.filter (lang: lang != "dotnet-runtime") (builtins.attrNames registry.languages);
        versions = builtins.mapAttrs (lang: spec: builtins.attrNames spec.versions) registry.languages;
        tiers = [ "dev" "slim" "distroless" ];

        # Generate a nested set representing the full combinations matrix
        # For each language, version, and tier:
        # e.g., packages.java21-distroless
        # We only evaluate and compile OCI image layered targets on Linux host systems.
        # This completely avoids trying to evaluate Linux-only packages (like Busybox) or cross-compilation
        # matrices on Darwin hosts, guaranteeing that `nix flake check` runs green on macOS.
        matrixPackages = if hostPkgs.stdenv.isLinux then pkgs.lib.listToAttrs (
          pkgs.lib.concatMap (lang:
            pkgs.lib.concatMap (ver:
              pkgs.lib.map (tier:
                let
                  attrName = mkPackageName lang ver tier;
                in
                {
                  name = attrName;
                  value = compiler.buildFleetImage {
                    name = "clearcutt-${lang}-${ver}";
                    tag = tier;
                    language = lang;
                    version = ver;
                    inherit tier;
                  };
                }
              ) tiers
            ) (pkgs.lib.attrByPath [ lang ] [] versions)
          ) languages
        ) else {};

        # Resolve raw, dynamic-link-patched matrix runtimes
        nativeHelpers = import ./lib/nix-native.nix { inherit self; pkgs = hostPkgs; };

        # Generate a set of raw, dynamic-link-patched matrix runtimes
        # e.g., packages.x86_64-linux.nodejs22-native
        rawPackages = pkgs.lib.listToAttrs (
          pkgs.lib.concatMap (lang:
            pkgs.lib.map (ver:
              let
                attrName = "${lang}${ver}-native";
              in
              {
                name = attrName;
                # Get the first package in the list returned by resolveRawPackages
                value = pkgs.lib.head (nativeHelpers.resolveRawPackages { language = lang; version = ver; });
              }
            ) (pkgs.lib.attrByPath [ lang ] [] versions)
          ) (pkgs.lib.filter (x: x != "core") languages)
        );

      in
      {
        # Expose all generated images and raw packages as outputs
        packages = matrixPackages // rawPackages;

        # Expose default dev shell equipped with the transient enterprise credentials broker
        devShells.default = hostPkgs.mkShell {
          name = "clearcutt-dev-shell";

          # System tools required for local builds, scanning, and inspection
          buildInputs = [
            hostPkgs.git
            hostPkgs.curl
            hostPkgs.patchelf
            hostPkgs.cosign
            hostPkgs.trivy
            hostPkgs.grype
            hostPkgs.syft
            hostPkgs.skopeo
            hostPkgs.container-structure-test
          ];

          shellHook = ''
            echo -e "\033[1;36m====================================================\033[0m"
            echo -e "\033[1;36m           ClearCutt Hardened Fleets Dev Shell      \033[0m"
            echo -e "\033[1;36m====================================================\033[0m"
            echo -e "Target Architectures: \033[32mx86_64-linux\033[0m, \033[32maarch64-linux\033[0m"
            echo -e "Status: \033[32mActive\033[0m"
            echo

            # Source transient credentials broker
            if [ -f ${./lib/credential-broker.sh} ]; then
              source ${./lib/credential-broker.sh}
            fi
          '';
        };
      }
    ) // {
      # Raw overlays for downstream consumers
      overlays.default = final: prev:
        let
          helpers = import ./lib/nix-native.nix { inherit self; pkgs = prev; };
        in
        helpers.overlay final prev;

      # Reusable Library Helper for creating custom brokered shells
      lib = {
        mkHardenedShell = { system, language, version, ... }@args:
          let
            pkgs = import nixpkgs { inherit system; };
            helpers = import ./lib/nix-native.nix { inherit self pkgs; };
          in
          helpers.mkHardenedShell (pkgs.lib.filterAttrs (n: v: n != "system") args);
      };
    };
}
