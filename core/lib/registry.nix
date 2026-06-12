# ClearCutt Declarative Language & Runtime Registry

{ pkgs }:

let
  lib = pkgs.lib;

  # Safe package resolution helper
  # Loops through paths to find the first existing attribute, throwing a clean error if none exist
  getPkg = paths: errorMsg:
    let
      foundPath = lib.findFirst (path: lib.hasAttrByPath path pkgs) null paths;
    in
    if foundPath != null then lib.attrByPath foundPath null pkgs
    else throw errorMsg;

  # Like getPkg, but resolves to null instead of throwing so a version spec can
  # express "use the preferred attr when this nixpkgs has it, otherwise fall
  # back to an in-registry transformation" without aborting evaluation.
  getPkgOrNull = paths:
    let
      foundPath = lib.findFirst (path: lib.hasAttrByPath path pkgs) null paths;
    in
    if foundPath != null then lib.attrByPath foundPath null pkgs else null;

  stripRuntimeReferences = { pkg, references, suffix ? "clearcutt-runtime" }:
    let
      removeTargets = lib.concatMapStringsSep " " (ref: "-t ${ref}") references;
    in
    pkgs.runCommand "${pkg.name}-${suffix}" {
      nativeBuildInputs = [ pkgs.removeReferencesTo ];
    } ''
      mkdir -p "$out"
      cp -a ${pkg}/. "$out/"
      find "$out" -type f -exec chmod u+w '{}' +
      find "$out" -type f -exec remove-references-to ${removeTargets} '{}' +
    '';

  # A helper to remove npm/npx/corepack from Node.js for slim/distroless runtimes.
  # symlinkJoin materializes a new store path whose bin/ and lib/ entries are
  # symlinks into the upstream nodejs derivation; postBuild then unlinks the
  # package-manager entry points and the npm/corepack module trees so the
  # production tiers ship the bare `node` binary only.
  removeNpm = nodePkg: pkgs.symlinkJoin {
    name = "${nodePkg.name}-no-npm";
    paths = [ nodePkg ];
    postBuild = ''
      rm -f $out/bin/npm
      rm -f $out/bin/npx
      rm -f $out/bin/corepack
      rm -rf $out/lib/node_modules/npm
      rm -rf $out/lib/node_modules/corepack
    '';
  };

  # Declarative specifications for every supported language runtime and version
  baseLanguages = {
    core = {
      versions = {
        "LTS" = {
          overlayName = "clearcuttCore";
          raw = [ (pkgs.coreutils-full or pkgs.coreutils) (pkgs.bashInteractive or pkgs.bash) ];
        };
      };
    };

    java = let
      # Production tiers build a JRE-shaped runtime from the headless OpenJDK.
      # Temurin/Semeru binary JREs in the locked nixpkgs carry shell-bearing
      # launcher wrappers or desktop/printing closures (cups -> avahi -> bash).
      # `jre*_minimal` normally links against the full JDK; overriding its JDK
      # inputs to the headless JDK keeps the runtime shell-free while jlink still
      # emits a JRE output without javac/jshell entry points. ALL-MODULE-PATH is
      # intentionally broader than java.base so general Java services keep the
      # standard headless runtime modules instead of a toy minimal subset.
      javaProductionRuntime = javaVersion:
        let
          minimalJre = getPkg [
            [ "jre${javaVersion}_minimal" ]
          ] "No Java ${javaVersion} jre${javaVersion}_minimal builder is available in this nixpkgs version";
          headlessJdk = getPkg [
            [ "jdk${javaVersion}_headless" ]
            [ "openjdk${javaVersion}_headless" ]
          ] "No Java ${javaVersion} headless JDK is available in this nixpkgs version";
          buildHeadlessJdk = lib.attrByPath [ "buildPackages" "jdk${javaVersion}_headless" ] headlessJdk pkgs;
        in
        [
          (minimalJre.override {
            jdk = headlessJdk;
            jdkOnBuild = buildHeadlessJdk;
            modules = [ "ALL-MODULE-PATH" ];
          })
        ];
    in {
      versions = {
        "21" = {
          overlayName = "clearcuttJava21";
          raw = [ (getPkg [ [ "zulu21" ] [ "temurin-bin-21" ] [ "jdk21" ] [ "openjdk21" ] ] "Java 21 is not available in this nixpkgs version") ];
          devExtra = [ pkgs.maven pkgs.ant pkgs.gradle ];
          slimOverride = javaProductionRuntime "21";
          distrolessOverride = javaProductionRuntime "21";
        };
        "25" = {
          overlayName = "clearcuttJava25";
          raw = [ (getPkg [ [ "zulu25" ] [ "temurin-bin-25" ] [ "jdk25" ] [ "openjdk25" ] ] "Java 25 is not available in this nixpkgs version") ];
          devExtra = [ pkgs.maven pkgs.ant pkgs.gradle ];
          slimOverride = javaProductionRuntime "25";
          distrolessOverride = javaProductionRuntime "25";
        };
      };
    };

    node = let
      # `raw` stays the full nodejs attr: it feeds the dev tier and the
      # -native packages, which need npm. Production tiers prefer upstream's
      # nodejs-slim_<v> (built with enableNpm = false — no npm/npx/corepack
      # and no bundled npm module tree to scan), and fall back to removeNpm
      # over the full attr on nixpkgs revisions without a slim build, so the
      # fallback never silently re-ships npm.
      nodeProductionRuntime = nodeVersion: rawPkgs:
        let
          slimPkg = getPkgOrNull [ [ "nodejs-slim_${nodeVersion}" ] ];
        in
        if slimPkg != null then [ slimPkg ] else map removeNpm rawPkgs;
      nodeRaw22 = [ (getPkg [ [ "nodejs_22" ] [ "nodejs-22_x" ] ] "Node.js 22 is not available in this nixpkgs version") ];
      nodeRaw24 = [ (getPkg [ [ "nodejs_24" ] [ "nodejs-24_x" ] ] "Node.js 24 is not available in this nixpkgs version") ];
    in {
      versions = {
        "22" = {
          overlayName = "clearcuttNode22";
          raw = nodeRaw22;
          slimOverride = nodeProductionRuntime "22" nodeRaw22;
          distrolessOverride = nodeProductionRuntime "22" nodeRaw22;
          # Kept as the final resolveForTier fallback for forks whose registry
          # forks drop the overrides while pinned to an older nixpkgs.
          useRemoveNpm = true;
        };
        "24" = {
          overlayName = "clearcuttNode24";
          raw = nodeRaw24;
          slimOverride = nodeProductionRuntime "24" nodeRaw24;
          distrolessOverride = nodeProductionRuntime "24" nodeRaw24;
          useRemoveNpm = true;
        };
      };
    };

    python = let
      # Distroless override evaluation (2026-06): python3Minimal exists in the
      # locked nixpkgs (python3-minimal-3.13.13) but was deliberately NOT
      # adopted as a distrolessOverride:
      #   * it is built with withMinimalDeps = true, which disables OpenSSL,
      #     sqlite, expat, mpdecimal, and readline — so the `ssl`, `sqlite3`,
      #     and `pyexpat` stdlib modules are missing and HTTPS, pip-installed
      #     wheels, and most real services break out of the box;
      #   * it tracks the 3.13 sources only, so it could never serve the
      #     3.14/3.15 lines and would silently downgrade interpreters.
      # Instead, distroless keeps the per-version full interpreter but strips
      # the stale bash store references that live in config/helper scripts such
      # as pythonX.Y-config, install-sh, makesetup, and ctypes test helpers.
      # The interpreter and ssl/sqlite/readline runtime references are retained.
      pythonDistrolessRuntime = py: [
        (stripRuntimeReferences {
          pkg = py;
          references = [ pkgs.bash ];
          suffix = "distroless-runtime";
        })
      ];
    in {
      versions = {
        "3.13" = {
          overlayName = "clearcuttPython313";
          raw = let py = getPkg [ [ "python313" ] ] "Python 3.13 is not available in this nixpkgs version"; in [ py ];
          distrolessOverride = let py = getPkg [ [ "python313" ] ] ""; in pythonDistrolessRuntime py;
          devExtra = let py = getPkg [ [ "python313" ] ] ""; in [ py.pkgs.pip pkgs.uv pkgs.poetry ];
        };
        "3.14" = {
          overlayName = "clearcuttPython314";
          raw = let py = getPkg [ [ "python314" ] ] "Python 3.14 is not available in this nixpkgs version"; in [ py ];
          distrolessOverride = let py = getPkg [ [ "python314" ] ] ""; in pythonDistrolessRuntime py;
          devExtra = let py = getPkg [ [ "python314" ] ] ""; in [ py.pkgs.pip pkgs.uv pkgs.poetry ];
        };
        "3.15" = {
          overlayName = "clearcuttPython315";
          raw = let py = getPkg [ [ "python315" ] ] "Python 3.15 is not available in this nixpkgs version"; in [ py ];
          distrolessOverride = let py = getPkg [ [ "python315" ] ] ""; in pythonDistrolessRuntime py;
          devExtra = let py = getPkg [ [ "python315" ] ] ""; in [ py.pkgs.pip pkgs.uv pkgs.poetry ];
        };
      };
    };

    go = {
      versions = {
        "1.25" = {
          overlayName = "clearcuttGo125";
          raw = [ (getPkg [ [ "go_1_25" ] ] "Go 1.25 is not available in this nixpkgs version") ];
          omitInProduction = true;
        };
        "1.26" = {
          overlayName = "clearcuttGo126";
          raw = [ (getPkg [ [ "go_1_26" ] ] "Go 1.26 is not available in this nixpkgs version") ];
          omitInProduction = true;
        };
      };
    };

    dotnet = {
      versions = {
        "8" = {
          overlayName = "clearcuttDotnet8";
          raw = [ (getPkg [ [ "dotnetCorePackages" "sdk_8_0" ] ] ".NET 8 SDK is not available in this nixpkgs version") ];
          slimOverride = [ (getPkg [ [ "dotnetCorePackages" "aspnetcore_8_0" ] ] ".NET 8 ASP.NET Core Runtime is not available in this nixpkgs version") ];
          distrolessOverride = [ (getPkg [ [ "dotnetCorePackages" "runtime_8_0" ] ] ".NET 8 Base Runtime is not available in this nixpkgs version") ];
        };
        "10" = {
          overlayName = "clearcuttDotnet10";
          raw = [ (getPkg [ [ "dotnetCorePackages" "sdk_10_0" ] ] ".NET 10 SDK is not available in this nixpkgs version") ];
          slimOverride = [ (getPkg [ [ "dotnetCorePackages" "aspnetcore_10_0" ] ] ".NET 10 ASP.NET Core Runtime is not available in this nixpkgs version") ];
          distrolessOverride = [ (getPkg [ [ "dotnetCorePackages" "runtime_10_0" ] ] ".NET 10 Base Runtime is not available in this nixpkgs version") ];
        };
      };
    };

    dotnet-runtime = {
      # Virtual language definition strictly for downstreams requesting the bare dotnet runtime overlay
      versions = {
        "8" = {
          overlayName = "clearcuttDotnet8Runtime";
          raw = [ (getPkg [ [ "dotnetCorePackages" "aspnetcore_8_0" ] ] ".NET 8 ASP.NET Core Runtime is not available in this nixpkgs version") ];
        };
        "10" = {
          overlayName = "clearcuttDotnet10Runtime";
          raw = [ (getPkg [ [ "dotnetCorePackages" "aspnetcore_10_0" ] ] ".NET 10 ASP.NET Core Runtime is not available in this nixpkgs version") ];
        };
      };
    };

    rust = {
      versions = {
        "1.95" = {
          overlayName = "clearcuttRust195";
          raw = [ pkgs.rustc pkgs.cargo pkgs.rustfmt pkgs.clippy ];
          omitInProduction = true;
        };
      };
    };

    cc = {
      versions = {
        "15" = {
          overlayName = "clearcuttCc15";
          raw = [ pkgs.gcc pkgs.gnumake pkgs.cmake pkgs.ninja ];
          omitInProduction = true;
        };
      };
    };
  };

  runtimeExtensions = import ./runtime-extensions.nix { inherit pkgs getPkg removeNpm; };

in
rec {
  # Declarative specifications for every supported language runtime and version.
  # Built-ins stay in this file; CLI-scaffolded custom runtime lines live in
  # runtime-extensions.nix and are merged here so the flake remains the backend
  # implementation detail rather than the public extension surface.
  languages = lib.recursiveUpdate baseLanguages (runtimeExtensions.languages or {});

  # Resolves a raw package list for local development / overlays
  resolveRaw = { language, version }:
    let
      langSpec = languages.${language} or (throw "Unsupported language target: ${language}");
      verSpec = langSpec.versions.${version} or (throw "Unsupported version ${version} for language ${language}");
    in
    verSpec.raw;

  # Resolves packages for a specific lifecycle tier and matrix configuration
  resolveForTier = { language, version, tier }:
    let
      langSpec = languages.${language} or (throw "Unsupported language target: ${language}");
      verSpec = langSpec.versions.${version} or (throw "Unsupported version ${version} for language ${language}");
    in
    if language == "core" then
      []
    else if tier == "dev" then
      verSpec.raw ++ (verSpec.devExtra or [])
    else if verSpec.omitInProduction or false then
      []
    else if tier == "distroless" && verSpec ? distrolessOverride then
      verSpec.distrolessOverride
    else if tier == "slim" && verSpec ? slimOverride then
      verSpec.slimOverride
    else if verSpec ? runtimeTransformer then
      map verSpec.runtimeTransformer verSpec.raw
    else if verSpec.useRemoveNpm or false then
      map removeNpm verSpec.raw
    else
      verSpec.raw;
}
