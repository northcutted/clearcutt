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
    # UNSTABLE OPT-IN (soft, per-package): node22 is pinned to a newer nixpkgs
    # carrying nodejs 22.23.0, which fixes CVE-2026-48617 / CVE-2026-48937 that
    # the main pin's 22.22.3 still ships. Scoped to node22 only (the rest of the
    # fleet stays on the stable pin), grafted to the openssl/sqlite floor in
    # registry.nix, and governed by remediation.unstable in clearcutt.fleet.yaml.
    # Pinned to an exact rev so the bump is reproducible.
    nixpkgs-node.url = "github:NixOS/nixpkgs/89570f24e97e614aa34aa9ab1c927b6578a43775";
  };

  outputs = { self, nixpkgs, nixpkgs-node }:
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

      # Runtime-scoped CVE patching uses stock build packages for image
      # assembly, scanners, and dev tooling, then threads patched handles only
      # into package closures that ship inside images.
      cveRemediationOverlay = import ./overlays/cve-remediation.nix;
      # Some runtimes link the CVE-remediated libraries TRANSITIVELY through
      # dependencies whose openssl/sqlite inputs the runtime package never
      # exposes as `.override` arguments:
      #   * .NET bakes a top-level openssl path into its nixpkgs wrappers.
      #   * Node links nghttp2/ngtcp2/nghttp3 (each carrying their own openssl)
      #     and sqlite, none of which `nodejs.override` reaches (it only takes
      #     openssl + python3). A bare `.override { openssl = … }` patches the
      #     interpreter's own libssl but leaves stock openssl/sqlite in the
      #     shipped closure — which the runtime-patch completeness gate rejects.
      # For those runtimes we rebind openssl/sqlite at the top of a DEDICATED
      # package set used only for their runtime contents, so every transitive
      # linker resolves the patched build. The build toolchain, scanners, and
      # dev shell keep using stock `buildPkgs`, so this never rebinds the
      # cached toolchain — only the affected runtime's own subtree rebuilds.
      runtimeCryptoOverlay = final: _prev: {
        openssl_3_6 = final.clearcuttCveOpenssl;
        openssl = final.openssl_3_6;
        sqlite = final.clearcuttCveSqlite;
      };
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
      importRuntimeNixpkgs = system: import nixpkgs {
        inherit system;
        config = nixpkgsConfig;
        overlays = [ cveRemediationOverlay ];
      };
      importCryptoRuntimeNixpkgs = system: import nixpkgs {
        inherit system;
        config = nixpkgsConfig;
        overlays = [ cveRemediationOverlay runtimeCryptoOverlay ];
      };
      # Dedicated .NET package set from the newer pin (carries aspnetcore 10.0.9 /
      # 8.0.28). registry.nix grafts the patched openssl/sqlite into these, so the
      # crypto floor still holds while the CVE-patched runtime ships. The crypto
      # variant is the from-source fallback used only if the graft is ever unsafe.
      # node22's dedicated unstable pin (UNSTABLE OPT-IN), imported with the same
      # crypto overlays as the main runtime set so node's transitively-linked
      # openssl/sqlite (via nghttp2/ngtcp2/sqlite) still resolve to the patched
      # 3.6.3 / 3.53.2 floor. registry.nix sources ONLY node22 from this set.
      importNodeCryptoNixpkgs = system: import nixpkgs-node {
        inherit system;
        config = nixpkgsConfig;
        overlays = [ cveRemediationOverlay runtimeCryptoOverlay ];
      };

      perSystem = system:
      let
        buildPkgs = importBuildNixpkgs system;
        runtimePkgs = importRuntimeNixpkgs system;
        cryptoRuntimePkgs = importCryptoRuntimeNixpkgs system;
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
          cryptoPkgs = cryptoRuntimePkgs;
          nodeCryptoPkgs = importNodeCryptoNixpkgs system;
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

      # The fleet's CVE patch set, exported standalone so downstreams can
      # apply or audit the remediations directly. It exposes clearcuttCve*
      # handles without rebinding top-level build-toolchain packages.
      overlays.cveRemediation = cveRemediationOverlay;

      # Raw overlay for downstream consumers. The CVE remediation overlay is
      # composed in first so clearcuttCve* handles are available to consumers,
      # but top-level nixpkgs attrs stay stock unless a consumer opts into a
      # patched runtime handle explicitly.
      overlays.default = nixpkgs.lib.composeManyExtensions [
        cveRemediationOverlay
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
            cryptoPkgs = importCryptoRuntimeNixpkgs system;
            registry = import ./lib/registry.nix {
              pkgs = runtimePkgs;
              inherit cryptoPkgs;
            };
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
            cryptoPkgs = importCryptoRuntimeNixpkgs system;
            registry = import ./lib/registry.nix {
              inherit cryptoPkgs;
              pkgs = runtimePkgs;
            };
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

      # Known-good crypto identity surface for the runtime-patch completeness
      # gate. The gate (tests/closure-cve-check.py and its Go port) asserts the
      # CVE patch-state of shipped openssl/sqlite by IDENTITY — the exact store
      # path — not by version. This output resolves, per Linux system, the store
      # paths of the crypto-overlaid openssl/sqlite across EVERY shipped crypto
      # set (the main runtime pin plus the .NET and node unstable pins, which
      # build their own openssl/sqlite from their own nixpkgs revs), with full
      # provenance (pin name + locked rev + output + version). It is pure
      # evaluation — no build — so `clearcutt remediation generate-crypto-allowlist`
      # can stamp the committed allowlist (tests/runtime-dep-floor.json) locally
      # and it will match the realized closure in CI (same lock → same paths).
      cryptoIdentities = forLinuxSystems (system:
        let
          cryptoSets = [
            { pinName = "nixpkgs"; rev = nixpkgs.rev or "unlocked"; pkgs = importCryptoRuntimeNixpkgs system; }
            { pinName = "nixpkgs-node"; rev = nixpkgs-node.rev or "unlocked"; pkgs = importNodeCryptoNixpkgs system; }
          ];
          # The tracked crypto deps are exactly the packages runtimeCryptoOverlay
          # rebinds to the patched build; each carries the CVE it remediates.
          trackedDeps = [
            { name = "openssl"; cve = "CVE-2026-34182"; sel = p: p.openssl; }
            { name = "sqlite"; cve = "CVE-2026-11822"; sel = p: p.sqlite; }
          ];
          idsFor = set: dep:
            let drv = dep.sel set.pkgs;
            in map (o: {
              inherit (dep) name cve;
              inherit system;
              pin = set.pinName;
              rev = set.rev;
              output = o;
              version = drv.version;
              storePath = baseNameOf (builtins.getAttr o drv).outPath;
            }) drv.outputs;
        in
        nixpkgs.lib.concatMap (set: nixpkgs.lib.concatMap (dep: idsFor set dep) trackedDeps) cryptoSets
      );

      # Closure-purity security gate for `nix flake check`, Linux-only because
      # the OCI image matrix is only exposed for Linux systems. For each
      # representative distroless image, closureInfo materializes the full
      # runtime closure of the image's contents and
      # tests/closure-purity-check.py fails the build if that closure provides
      # interactive shells (bin/sh|bash|ash|dash), package-manager binaries
      # (npm, npx, corepack, pip*, apk, dpkg, rpm), or setuid/setgid files —
      # honoring the same explained-exception allowlist
      # (tests/closure-purity-allowlist.txt) as the verify.sh image gate, so
      # a residual finding is consciously accepted rather than silently
      # weakening the gate. Add coverage by appending to closurePurityTargets.
      #
      # Runtime-patch completeness gate (the security keystone of
      # runtime-scoped CVE patching). For each representative image — slim AND
      # distroless, because the slim tier also ships the openssl-linked runtime
      # — closureInfo materializes the SHIPPED runtime closure of the image's
      # contents (never a .drv build closure: under runtime-scoped patching the
      # build-time openssl is intentionally stock, so a build-graph walk would
      # false-positive). tests/closure-cve-check.py then fails the build if any
      # store path is an openssl/sqlite below the committed floor in
      # tests/runtime-dep-floor.json — default-deny, so stock 3.6.2 and the
      # unpatched older majors (openssl_3_5, openssl_3) are caught too. Add
      # coverage by appending to runtimePatchTargets.
      checks = forLinuxSystems (system:
        let
          checkPkgs = import nixpkgs { inherit system; };
          # Realized-closure gate targets are the GENERATED, default-INCLUDE
          # lists from lib/fleet-matrix.nix (compiled from clearcutt.fleet.yaml).
          # closurePurityTargets covers every production distroless image;
          # runtimePatchTargets covers every production tier (slim + distroless)
          # of every line that ships a production runtime — toolchain lines
          # (go/rust/cc) that ship no production runtime are excluded by the
          # compiler. This can ONLY add coverage versus the prior hand-list: a
          # new production tier is gated automatically instead of waiting for
          # someone to remember to append it. dotnet especially — its openssl is
          # a source-baked dlopen path invisible to graph/SBOM walks, so this
          # realized-closure gate is the ONLY thing that catches a stock copy.
          # The dev tier is intentionally excluded (it ships stock runtimes so
          # the build shells stay cached).
          closurePurityTargets = fleetMatrix.closurePurityTargets;
          runtimePatchTargets = fleetMatrix.runtimePatchTargets;
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
          mkRuntimePatchCheck = attrName:
            let
              image = self.packages.${system}.${attrName};
              closure = checkPkgs.closureInfo { rootPaths = image.clearcuttContents; };
            in
            checkPkgs.runCommand "runtime-patch-completeness-${attrName}"
              {
                nativeBuildInputs = [ checkPkgs.python3 ];
              } ''
              python3 ${./tests/closure-cve-check.py} \
                --store-paths ${closure}/store-paths \
                --floor ${./tests/runtime-dep-floor.json}
              touch $out
            '';
        in
        (nixpkgs.lib.genAttrs
          (map (target: "closure-purity-${target}") closurePurityTargets)
          (name: mkClosurePurityCheck (nixpkgs.lib.removePrefix "closure-purity-" name)))
        // (nixpkgs.lib.genAttrs
          (map (target: "runtime-patch-completeness-${target}") runtimePatchTargets)
          (name: mkRuntimePatchCheck (nixpkgs.lib.removePrefix "runtime-patch-completeness-" name)))
      );
    };
}
