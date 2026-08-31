# ClearCutt Hardened Fleets Declarative Entrypoint

{
  description = "ClearCutt Hardened Base Image Fleets - Declarative, CVE-aware Nix Store Layers";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    # .NET is pinned to a NEWER nixpkgs than the rest of the fleet so it carries
    # the CVE-patched ASP.NET Core runtime (10.0.9 / 8.0.28 — fixes the High
    # GHSA-f8h2-vmm9-qhj6 in Microsoft.AspNetCore.App.Runtime, which the main
    # pin's 10.0.8 still ships). It is substituted from cache (no VMR rebuild)
    # and grafted to the openssl/sqlite floor in registry.nix. Pinned to an exact
    # rev so the bump's churn is scoped to .NET images and stays reproducible.
  };

  outputs = { self, nixpkgs }:
    let
      linuxSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      darwinSystems = [
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      systems = linuxSystems ++ darwinSystems;
      forAllSystems = nixpkgs.lib.genAttrs systems;
      forLinuxSystems = nixpkgs.lib.genAttrs linuxSystems;
      forDarwinSystems = nixpkgs.lib.genAttrs darwinSystems;
      slsaVerifierVersion = "2.7.1";
      slsaVerifierBinaries = {
        x86_64-linux = {
          asset = "slsa-verifier-linux-amd64";
          hash = "sha256-lG2+xykJQZXojveOFzQySieGnwPixr0vYcvAa9U1Azk=";
        };
        aarch64-linux = {
          asset = "slsa-verifier-linux-arm64";
          hash = "sha256-XTsjSe3nv+wZ56IVafGLn3QQFFrRLpWEsXU3BmnhQGE=";
        };
        x86_64-darwin = {
          asset = "slsa-verifier-darwin-amd64";
          hash = "sha256-S68lQVcngh+Eeji8ztyGw+WxfL/C61NM1VT+tshW1vE=";
        };
        aarch64-darwin = {
          asset = "slsa-verifier-darwin-arm64";
          hash = "sha256-Oav89fHWkMPoic49LWqLh3EUJNgzaFEYaNQU6Pi8sFw=";
        };
      };

      # The image matrix is the GENERATED enumeration compiled from
      # clearcutt.fleet.yaml by `clearcutt fleet compile` into
      # lib/fleet-matrix.nix. It is pure data (system-independent): the concrete
      # (language, version, tier) cells, the unique runtime lines, and the
      # realized-closure gate targets. It is read here and threaded into both
      # perSystem (image packages, native runtimes, dev shells) and the
      # closure-purity / runtime-patch checks, so the flake no longer derives the
      # matrix from registry.nix attr names. The hardened recipes, CVE overlays,
      # and build/runtime/crypto nixpkgs split stay curated and untouched.
      fleetMatrix = import ./lib/fleet-matrix.nix;

      nixpkgsConfig = {
        # `allowUnfree` is required for JDKs (Zulu/Oracle) and a few fonts.
        # `allowBroken` was removed: it let Nix produce binaries from
        # packages maintainers had flagged broken, which is incompatible
        # with the project's fixable-CVE gate. If a specific package is
        # incorrectly marked broken, override it inside overlays/cve/.
        allowUnfree = true;
      };
      importBuildNixpkgs = system: import nixpkgs {
        inherit system;
        config = nixpkgsConfig;
      };
      # Runtime and build package sets are the same stock nixpkgs now that the
      # CVE overlays are gone. The alias is kept so the call sites below still
      # read as "this is the set that ships inside images".
      importRuntimeNixpkgs = importBuildNixpkgs;
      # Dedicated .NET package set from the newer pin (carries aspnetcore 10.0.9 /
      # 8.0.28). registry.nix grafts the patched openssl/sqlite into these, so the
      # crypto floor still holds while the CVE-patched runtime ships. The crypto
      # variant is the from-source fallback used only if the graft is ever unsafe.

      perSystem = system:
      let
        buildPkgs = importBuildNixpkgs system;
        runtimePkgs = importRuntimeNixpkgs system;
        slsaVerifier =
          let
            binary = slsaVerifierBinaries.${system}
              or (throw "unsupported slsa-verifier host system: ${system}");
          in
          buildPkgs.stdenvNoCC.mkDerivation {
            pname = "slsa-verifier";
            version = slsaVerifierVersion;
            src = buildPkgs.fetchurl {
              url = "https://github.com/slsa-framework/slsa-verifier/releases/download/v${slsaVerifierVersion}/${binary.asset}";
              inherit (binary) hash;
            };
            dontUnpack = true;
            installPhase = ''
              install -Dm755 "$src" "$out/bin/slsa-verifier"
            '';
            meta = with buildPkgs.lib; {
              description = "Verifier for SLSA provenance";
              homepage = "https://github.com/slsa-framework/slsa-verifier";
              license = licenses.asl20;
              mainProgram = "slsa-verifier";
              platforms = builtins.attrNames slsaVerifierBinaries;
            };
          };

        # Host package alignment: build native OCI layers on Linux release
        # runners, and expose native development shells on Darwin for the local
        # inner loop instead of relying on pkgsCross for image builds.
        pkgs = buildPkgs;

        # Import centralized language and runtime registry once per system
        # and thread it into the compiler and native helpers, which would
        # otherwise each re-instantiate it against the same pkgs.
        registry = import ./lib/registry.nix {
          pkgs = runtimePkgs;
        };

        # Import our custom image compiler
        compiler = import ./lib/build-fleet.nix {
          pkgs = buildPkgs;
          inherit runtimePkgs registry;
        };

        # Configured first-class service image specs generated by
        # `clearcutt service scaffold` from clearcutt.fleet.yaml.
        serviceSpecs = import ./lib/service-extensions.nix {};

        # Fork-configurable output identity generated from clearcutt.fleet.yaml.
        platformMetadata = import ./lib/platform-metadata.nix;
        imagePrefix = platformMetadata.imagePrefix or "clearcutt";
        productName = platformMetadata.productName or "ClearCutt";

        # clearcutt:matrix:begin
        # This block reads the generated enumeration (top-level `fleetMatrix`,
        # from lib/fleet-matrix.nix) and SELECTS the hardened recipes from
        # lib/registry.nix. It no longer derives the matrix from registry attr
        # names. Everything outside these markers — the CVE overlays, the
        # build/runtime/crypto nixpkgs split, registry.nix, and the check bodies
        # — stays curated and is untouched.

        # Coverage gate (replaces the registry↔fleet drift test): the fleet
        # config is authoritative; the registry is the recipe library it selects
        # from. Every declared cell MUST resolve to a curated recipe, or it is
        # unbuildable and throws here at eval time rather than deep in image
        # assembly. Returns the cell so callers force the check by using it.
        assertRecipe = cell:
          if (registry.languages.${cell.language} or null) != null
             && ((registry.languages.${cell.language}.versions or { }) ? ${cell.version})
          then cell
          else throw "clearcutt fleet-matrix: cell ${cell.line}-${cell.tier} declares language=${cell.language} version=${cell.version} with no recipe in lib/registry.nix; add it there or remove the line from clearcutt.fleet.yaml matrix.languages";

        # Unique runtime lines (one per language+version) in fleet-config order,
        # for the per-line native packages and dev shells.
        fleetLines = pkgs.lib.unique (
          builtins.map (cell: { inherit (cell) line language version; }) fleetMatrix.cells
        );

        # Generate image package outputs for the Linux build systems only.
        # Darwin still exposes native runtime closures and dev shells, but not
        # OCI image attrs that require Linux container tooling.
        matrixPackages = pkgs.lib.listToAttrs (
          builtins.map (rawCell:
            let cell = assertRecipe rawCell; in
            {
              name = "${cell.line}-${cell.tier}";
              value = compiler.buildFleetImage {
                name = "${imagePrefix}-${cell.language}-${cell.version}";
                tag = cell.tier;
                language = cell.language;
                version = cell.version;
                tier = cell.tier;
              };
            }
          ) fleetMatrix.cells
        );

        servicePackages = pkgs.lib.listToAttrs (
          builtins.map (service: {
            name = service.id;
            value = compiler.buildServiceImage {
              name = "${imagePrefix}-${service.id}";
              tag = "current";
              inherit service;
            };
          }) serviceSpecs
        );

        # Resolve raw, dynamic-link-patched matrix runtimes
        nativeHelpers = import ./lib/nix-native.nix { inherit self registry; pkgs = runtimePkgs; };

        # Generate a set of raw, dynamic-link-patched matrix runtimes
        # e.g., packages.x86_64-linux.node22-native
        rawPackages = pkgs.lib.listToAttrs (
          builtins.map (line: {
            name = "${line.line}-native";
            # Get the first package in the list returned by resolveRawPackages
            value = pkgs.lib.head (nativeHelpers.resolveRawPackages { language = line.language; version = line.version; });
          }) (builtins.filter (line: line.language != "core") fleetLines)
        );

        # Per-target hardened dev shells mirror each dev image's runtime closure,
        # so `nix develop .#java21-dev` drops you into the same toolchain the
        # java21:dev image ships. Built natively per host (incl. Darwin) for the
        # local inner loop — this is what `clearcutt dev --nix` resolves to.
        devTargetShells = pkgs.lib.listToAttrs (
          builtins.map (line: {
            name = "${line.line}-dev";
            value = nativeHelpers.mkHardenedShell { language = line.language; version = line.version; };
          }) fleetLines
        );
        # clearcutt:matrix:end

      in
      {
        imagePackages = matrixPackages // servicePackages;
        nativePackages = rawPackages;

        # Default dev shell (build/gating tooling) plus per-target dev shells
        # (devTargetShells) for the local inner loop.
        devShells = {
          default = buildPkgs.mkShell {
            name = "${imagePrefix}-dev-shell";

            # System tools required for local builds, scanning, and inspection,
            # plus the contributor toolchains for the Go CLI and the Astro site.
            buildInputs = [
              buildPkgs.git
              buildPkgs.curl
              buildPkgs.patchelf
              buildPkgs.cosign
              buildPkgs.gh
              slsaVerifier
              buildPkgs.trivy
              buildPkgs.grype
              buildPkgs.syft
              buildPkgs.skopeo
              buildPkgs.container-structure-test
              buildPkgs.go
              buildPkgs.gopls
              buildPkgs.nodejs
            ];

            shellHook = ''
              if [ -f ${./lib/credential-broker.sh} ]; then
                source ${./lib/credential-broker.sh}
                install_credential_broker_trap
              fi
            '';
          };
        } // devTargetShells;
      };
      # Evaluate each system exactly once: packages and devShells previously
      # called perSystem independently, paying for the nixpkgs import and
      # matrix construction twice per system.
      evaluated = forAllSystems perSystem;
    in
    {
      packages =
        (forLinuxSystems (system:
          evaluated.${system}.imagePackages // evaluated.${system}.nativePackages
        ))
        // (forDarwinSystems (system: evaluated.${system}.nativePackages));
      devShells = forAllSystems (system: evaluated.${system}.devShells);

      # Raw overlay for downstream consumers.
      overlays.default = nixpkgs.lib.composeManyExtensions [
        (final: prev:
          let
            helpers = import ./lib/nix-native.nix { inherit self; pkgs = prev; };
          in
          helpers.overlay final prev)
      ];

      # Reusable Library Helper for creating custom brokered shells
      lib = {
        # Registry introspection surface: the flat list of runtime line ids the
        # registry can compile ("java21", "node22", "python3.14", ...). This is the library
        # of recipes the generated fleet matrix SELECTS from; the image matrix
        # itself is now driven by lib/fleet-matrix.nix, and recipe coverage for
        # every selected cell is enforced at eval by assertRecipe above. Retained
        # for downstream introspection of what the registry offers. Listing attr
        # names never forces the package values, so this stays cheap and
        # system-independent.
        runtimeLines =
          let
            pkgs = import nixpkgs {
              system = "x86_64-linux";
              config.allowUnfree = true;
            };
            registry = import ./lib/registry.nix { inherit pkgs; };
            imageLanguages = builtins.attrNames registry.languages;
          in
          nixpkgs.lib.concatMap (lang:
            map (ver: "${lang}${ver}")
              (builtins.attrNames registry.languages.${lang}.versions)
          ) imageLanguages;

        mkHardenedShell = { system, language, version, ... }@args:
          let
            runtimePkgs = importRuntimeNixpkgs system;
            registry = import ./lib/registry.nix { pkgs = runtimePkgs; };
            helpers = import ./lib/nix-native.nix { inherit self registry; pkgs = runtimePkgs; };
          in
          helpers.mkHardenedShell (runtimePkgs.lib.filterAttrs (n: v: n != "system") args);

        graftOntoBase =
          { system
          , fromImage
          , runtime ? null
          , language ? null
          , version ? null
          , tier ? "distroless"
          , tag ? "grafted"
          , name ? null
          , ...
          }@args:
          let
            buildPkgs = importBuildNixpkgs system;
            runtimePkgs = importRuntimeNixpkgs system;
            registry = import ./lib/registry.nix { pkgs = runtimePkgs; };
            compiler = import ./lib/build-fleet.nix { pkgs = buildPkgs; inherit runtimePkgs registry; };
            platformMetadata = import ./lib/platform-metadata.nix;
            imagePrefix = platformMetadata.imagePrefix or "clearcutt";
            parseRuntime = runtimeId:
                let
                  parsed = builtins.match "([A-Za-z]+)([0-9].*)" runtimeId;
                in
                if parsed == null then
                  throw "clearcutt.lib.graftOntoBase: runtime must look like java21, node22, python3.14, or go1.26"
                else {
                  language = builtins.elemAt parsed 0;
                  version = builtins.elemAt parsed 1;
                };
            parsedRuntime =
              if runtime != null then parseRuntime runtime else {};
            languageFinal =
              if language != null then language
              else parsedRuntime.language or (throw "clearcutt.lib.graftOntoBase requires runtime or language");
            versionFinal =
              if version != null then version
              else parsedRuntime.version or (throw "clearcutt.lib.graftOntoBase requires runtime or version");
            imageName = if name == null then "${imagePrefix}-${languageFinal}-${versionFinal}" else name;
            cleanArgs = buildPkgs.lib.filterAttrs (n: v: !(builtins.elem n [
              "system"
              "name"
              "runtime"
              "language"
              "version"
              "tag"
              "tier"
              "fromImage"
            ])) args;
          in
          compiler.buildFleetImage (cleanArgs // {
            name = imageName;
            tag = tag;
            language = languageFinal;
            version = versionFinal;
            tier = tier;
            fromImage = fromImage;
          });
      };

      # Closure-purity security gate for `nix flake check`, Linux-only because
      # the OCI image matrix is only exposed for Linux systems. For each
      # representative distroless image, closureInfo materializes the full
      # runtime closure of the image's contents and
      # tests/closure-purity-check.py fails the build if that closure provides
      # interactive shells (bin/sh|bash|ash|dash), package-manager binaries
      # (npm, npx, corepack, pip*, apk, dpkg, rpm), or setuid/setgid files —
      # honoring the same explained-exception allowlist
      # (tests/closure-purity-allowlist.txt), so a residual finding is
      # consciously accepted rather than silently weakening the gate. Add
      # coverage by appending to closurePurityTargets.
      #
      # The runtime-patch completeness gate that used to sit alongside this one
      # was retired with runtime-scoped CVE patching: it asserted the patch
      # state of shipped openssl/sqlite by store-path identity, and with the CVE
      # overlays gone there is no patched identity to assert against.
      checks = forLinuxSystems (system:
        let
          checkPkgs = import nixpkgs { inherit system; };
          # Realized-closure gate targets are the GENERATED, default-INCLUDE
          # lists from lib/fleet-matrix.nix (compiled from clearcutt.fleet.yaml).
          # closurePurityTargets covers every production distroless image. A new
          # production tier is gated automatically instead of waiting for
          # someone to remember to append it.
          # The dev tier is intentionally excluded (it ships stock runtimes so
          # the build shells stay cached).
          closurePurityTargets = fleetMatrix.closurePurityTargets;
          mkClosurePurityCheck = attrName:
            let
              image = self.packages.${system}.${attrName};
              closure = checkPkgs.closureInfo { rootPaths = image.clearcuttContents; };
            in
            checkPkgs.runCommand "closure-purity-${attrName}"
              {
                nativeBuildInputs = [ checkPkgs.python3 ];
              } ''
              python3 ${./tests/closure-purity-check.py} \
                --store-paths ${closure}/store-paths \
                --allowlist ${./tests/closure-purity-allowlist.txt}
              touch $out
            '';
        in
        (nixpkgs.lib.genAttrs
          (map (target: "closure-purity-${target}") closurePurityTargets)
          (name: mkClosurePurityCheck (nixpkgs.lib.removePrefix "closure-purity-" name)))
      );
    };
}
