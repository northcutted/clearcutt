# ClearCutt Declarative Language & Runtime Registry
# Design: Eddie Northcutt
# Paradigm: Declarative base registry for OCI base fleets and native shells

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

in
rec {
  # Declarative specifications for every supported language runtime and version
  languages = {
    core = {
      versions = {
        "LTS" = {
          overlayName = "clearcuttCore";
          raw = [ (pkgs.coreutils-full or pkgs.coreutils) (pkgs.bashInteractive or pkgs.bash) ];
        };
      };
    };

    java = {
      versions = {
        "21" = {
          overlayName = "clearcuttJava21";
          raw = [ (getPkg [ [ "zulu21" ] [ "temurin-bin-21" ] [ "jdk21" ] [ "openjdk21" ] ] "Java 21 is not available in this nixpkgs version") ];
          devExtra = [ pkgs.maven pkgs.ant pkgs.gradle ];
        };
        "25" = {
          overlayName = "clearcuttJava25";
          raw = [ (getPkg [ [ "zulu25" ] [ "temurin-bin-25" ] [ "jdk25" ] [ "openjdk25" ] ] "Java 25 is not available in this nixpkgs version") ];
          devExtra = [ pkgs.maven pkgs.ant pkgs.gradle ];
        };
      };
    };

    node = {
      versions = {
        "22" = {
          overlayName = "clearcuttNode22";
          raw = [ (getPkg [ [ "nodejs_22" ] [ "nodejs-22_x" ] ] "Node.js 22 is not available in this nixpkgs version") ];
          useRemoveNpm = true;
        };
        "24" = {
          overlayName = "clearcuttNode24";
          raw = [ (getPkg [ [ "nodejs_24" ] [ "nodejs-24_x" ] ] "Node.js 24 is not available in this nixpkgs version") ];
          useRemoveNpm = true;
        };
      };
    };

    python = {
      versions = {
        "3.13" = {
          overlayName = "clearcuttPython313";
          raw = [ (getPkg [ [ "python313" ] ] "Python 3.13 is not available in this nixpkgs version") ];
          devExtra = let py = getPkg [ [ "python313" ] ] ""; in [ py.pkgs.pip pkgs.uv pkgs.poetry ];
        };
        "3.14" = {
          overlayName = "clearcuttPython314";
          raw = [ (getPkg [ [ "python314" ] ] "Python 3.14 is not available in this nixpkgs version") ];
          devExtra = let py = getPkg [ [ "python314" ] ] ""; in [ py.pkgs.pip pkgs.uv pkgs.poetry ];
        };
        "3.15" = {
          overlayName = "clearcuttPython315";
          raw = [ (getPkg [ [ "python315" ] ] "Python 3.15 is not available in this nixpkgs version") ];
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
