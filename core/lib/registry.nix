# ClearCutt Declarative Language & Runtime Registry

# `cryptoPkgs` is a package set whose openssl/sqlite are rebound to the
# CVE-patched builds at the top level (see runtimeCryptoOverlay in flake.nix).
# Runtimes that link the remediated libraries through dependencies they cannot
# `.override` (node -> nghttp2/ngtcp2/sqlite; .NET's baked openssl) are sourced
# from it so every transitive linker resolves the patched build. Everything
# else stays on the plain `pkgs` (CVE handles available, stock openssl/sqlite).
{ pkgs
, cryptoPkgs ? pkgs
  # `.NET` is sourced from its own (newer) package set carrying the CVE-patched
  # aspnetcore/runtime; `dotnetCryptoPkgs` is its from-source crypto-rebuild
  # fallback. Both default to the main sets so callers that don't thread a
  # dedicated .NET pin keep the prior behaviour.
, dotnetPkgs ? pkgs
, dotnetCryptoPkgs ? cryptoPkgs
  # `nodeCryptoPkgs` is node22's dedicated unstable pin (UNSTABLE OPT-IN), with
  # the same crypto rebinding as `cryptoPkgs`, carrying nodejs 22.23.0. Defaults
  # to `cryptoPkgs` so a fork without the dedicated pin keeps the prior node22.
, nodeCryptoPkgs ? cryptoPkgs
}:

let
  lib = pkgs.lib;

  # Safe package resolution helper
  # Loops through paths to find the first existing attribute, throwing a clean error if none exist
  getPkgFrom = packageSet: paths: errorMsg:
    let
      foundPath = lib.findFirst (path: lib.hasAttrByPath path packageSet) null paths;
    in
    if foundPath != null then lib.attrByPath foundPath null packageSet
    else throw errorMsg;

  getPkg = getPkgFrom pkgs;

  # Like getPkg, but resolves to null instead of throwing so a version spec can
  # express "use the preferred attr when this nixpkgs has it, otherwise fall
  # back to an in-registry transformation" without aborting evaluation.
  getPkgOrNullFrom = packageSet: paths:
    let
      foundPath = lib.findFirst (path: lib.hasAttrByPath path packageSet) null paths;
    in
    if foundPath != null then lib.attrByPath foundPath null packageSet else null;

  getPkgOrNull = getPkgOrNullFrom pkgs;

  # Zero out store-path references INSIDE the package's own derivation.
  # Copy-and-strip wrappers (runCommand + cp) do not work for this: the copy
  # keeps self-references to the original store path, so Nix records the
  # original package as a runtime dependency and its references (e.g. the
  # build shell) come right back into the closure — plus the image then
  # ships two copies of the package. Appending to postFixup rewrites the
  # files before Nix scans the single, real output for references.
  severRuntimeReferences = { pkg, references }:
    pkg.overrideAttrs (old: {
      nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.removeReferencesTo ];
      postFixup = (old.postFixup or "") + ''
        find "$out" -type f -exec remove-references-to ${lib.concatMapStringsSep " " (ref: "-t ${ref}") references} '{}' +
      '';
    });

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

  # Graft the CVE-patched crypto libraries into a STOCK, cache-substitutable
  # build instead of rebuilding it from source. Rebinding openssl in the package
  # set a runtime is built from (cryptoPkgs) changes that runtime's derivation
  # hash, so it loses its cache.nixos.org substitute and rebuilds from source —
  # for .NET that is the ~3h VMR build. `replaceDependencies` instead rewrites
  # every reference to the stock crypto lib (including .NET's baked absolute
  # dlopen path, which an RPATH change cannot redirect) byte-for-byte across the
  # closure, producing a cheap rewrite of the cached output. This is the same
  # mechanism nixpkgs uses to ship openssl security fixes without rebuilding the
  # world.
  #
  # A graft is only sound when the patched lib is a drop-in for the stock one:
  #   * same MAJOR version — openssl/sqlite hold a stable SONAME across a major
  #     (libssl.so.3 for all of openssl 3.x; libsqlite3.so.0 for all sqlite 3),
  #     so a stock-compiled binary runs against the patched lib. (Major, not
  #     major.minor: sqlite 3.51 -> 3.53 is ABI-stable.)
  #   * identical store-path length — replaceDependencies rewrites in place, so
  #     the swap must be byte-exact (a name-length change like 3.6.9 -> 3.6.10
  #     would not be).
  # When either fails, the openssl graft is dropped and the caller falls back to
  # the from-source crypto rebuild. The runtime-cve closure gate independently
  # proves the shipped result in BOTH paths, so a missed graft fails the gate
  # loudly rather than silently shipping a stock library.
  # ABI gate: a stock-compiled binary runs against the patched lib only within a
  # stable SONAME, which openssl/sqlite hold across a whole MAJOR (not minor —
  # sqlite 3.51 -> 3.53 is ABI-stable).
  graftAbiOk = old: new: lib.versions.major old.version == lib.versions.major new.version;
  # Byte-exact gate: replaceDependencies rewrites store paths in place, so each
  # swapped pair must be the same length.
  graftSameLen = a: b:
    builtins.stringLength (builtins.unsafeDiscardStringContext a)
    == builtins.stringLength (builtins.unsafeDiscardStringContext b);

  # One replacement PER OUTPUT (out/bin/dev/...). A closure references a library's
  # `out` (lib) output, while the derivation's DEFAULT output is openssl's `bin`,
  # so targeting the derivation itself would miss the runtime reference (and the
  # floor gate flags every output anyway — openssl-X-dev included). Each output is
  # gated on length independently.
  graftOutputs = old: new:
    if old == null || new == null || !(graftAbiOk old new) then [ ]
    else builtins.concatMap
      (o:
        if (builtins.hasAttr o new) && graftSameLen (old.${o}.outPath) (new.${o}.outPath)
        then [ { oldDependency = old.${o}; newDependency = new.${o}; } ]
        else [ ])
      old.outputs;

  # Compute the crypto replacements within ONE package set: the drv and the stock
  # crypto it links come from the same `base`, and the patched handle is built
  # from that same base, so the swap is self-consistent even when `base` is a
  # different nixpkgs pin than the rest of the fleet (the .NET case).
  cryptoGraftsFor = base:
    let
      opensslGrafts =
        graftOutputs (base.openssl_3_6 or null) (base.clearcuttCveOpenssl or null)
        ++ graftOutputs (base.openssl or null) (base.clearcuttCveOpenssl or null);
      sqliteGrafts = graftOutputs (base.sqlite or null) (base.clearcuttCveSqlite or null);
      # openssl and openssl_3_6 are the same derivation on most pins; de-dup by
      # the old output path so replaceDependencies never sees a target twice.
      key = r: builtins.unsafeDiscardStringContext r.oldDependency.outPath;
      dedup = builtins.foldl'
        (acc: r: if builtins.elem (key r) (map key acc) then acc else acc ++ [ r ])
        [ ] (opensslGrafts ++ sqliteGrafts);
    in
    {
      grafts = dedup;
      # openssl is the load-bearing graft: if it can't be grafted safely we must
      # rebuild from source rather than ship a half-grafted closure the gate rejects.
      opensslGraftable = opensslGrafts != [ ];
    };

  # Source a crypto-linked runtime from `base`, grafting the patched libs into the
  # stock cached build when it is an ABI-safe drop-in, else falling back to
  # `rebuildBase` (the from-source crypto rebuild). Same (paths, errorMsg) tail as
  # getPkgFrom.
  graftedOrRebuiltFrom = base: rebuildBase: paths: errorMsg:
    let g = cryptoGraftsFor base; in
    if g.opensslGraftable then
      base.replaceDependencies {
        drv = getPkgFrom base paths errorMsg;
        replacements = g.grafts;
      }
    else getPkgFrom rebuildBase paths errorMsg;

  # .NET resolves from the dedicated newer pin (dotnetPkgs), grafted to the floor.
  graftedOrRebuilt = graftedOrRebuiltFrom dotnetPkgs dotnetCryptoPkgs;

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
      # inputs to the headless JDK keeps the runtime shell-free.
      #
      # The module set must be explicit: ALL-MODULE-PATH would include every
      # jmod of the headless JDK, and jlink copies each included module's bin/
      # launchers into the image — javac, jshell, jar, jlink, jcmd, and the
      # rest of the toolchain that production tiers must not ship. The list
      # below mirrors what vendors put in a standalone JRE: every java.*
      # platform module plus the jdk.* service/runtime modules (crypto
      # providers, locales, management/JFR, DNS naming, unsupported APIs),
      # and none of the jdk.* developer-tool modules. Every name exists in
      # both the JDK 21 and JDK 25 headless jmods of the locked nixpkgs.
      jreModules = [
        "java.base"
        "java.compiler" # javax.tools/javax.lang.model API only - javac itself lives in the excluded jdk.compiler
        "java.datatransfer"
        "java.desktop"
        "java.instrument"
        "java.logging"
        "java.management"
        "java.management.rmi"
        "java.naming"
        "java.net.http"
        "java.prefs"
        "java.rmi"
        "java.scripting"
        "java.se"
        "java.security.jgss"
        "java.security.sasl"
        "java.smartcardio"
        "java.sql"
        "java.sql.rowset"
        "java.transaction.xa"
        "java.xml"
        "java.xml.crypto"
        "jdk.accessibility"
        "jdk.charsets"
        "jdk.crypto.cryptoki"
        "jdk.crypto.ec"
        "jdk.dynalink"
        "jdk.httpserver"
        "jdk.incubator.vector"
        "jdk.jdwp.agent"
        "jdk.jfr"
        "jdk.jsobject"
        "jdk.localedata"
        "jdk.management"
        "jdk.management.agent"
        "jdk.management.jfr"
        "jdk.naming.dns"
        "jdk.naming.rmi"
        "jdk.net"
        "jdk.nio.mapmode"
        "jdk.sctp"
        "jdk.security.auth"
        "jdk.security.jgss"
        "jdk.unsupported"
        "jdk.unsupported.desktop"
        "jdk.xml.dom"
        "jdk.zipfs"
      ];
      javaProductionRuntime = javaVersion:
        let
          minimalJre = getPkg [
            [ "jre${javaVersion}_minimal" ]
          ] "No Java ${javaVersion} jre${javaVersion}_minimal builder is available in this nixpkgs version";
          # OpenJDK's generic builder does not expose openssl/sqlite override
          # arguments. The runtime completeness gate is the source of truth for
          # whether the jlink'd production closure retains those libraries.
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
            # jdk.random (extra RandomGenerator algorithms) exists as a
            # separate jmod only in the JDK 21 headless package of the
            # locked nixpkgs; the JDK 25 jmods directory does not have it.
            modules = jreModules ++ lib.optional (javaVersion == "21") "jdk.random";
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
      # Node is sourced from `cryptoPkgs` (openssl/sqlite rebound to the patched
      # builds). `nodejs.override` only exposes `openssl` + `python3`, so it can
      # patch the interpreter's own libssl but NOT the openssl that nghttp2 /
      # ngtcp2 / nghttp3 each link, nor node's `sqlite` input — all of which
      # ship inside the runtime closure and trip the runtime-patch completeness
      # gate. Building node from the crypto-rebound set makes every transitive
      # linker resolve openssl-3.6.3 / sqlite-3.53.2 instead.
      #
      # `raw` stays the full nodejs attr: it feeds the dev tier and the
      # -native packages, which need npm. Production tiers prefer upstream's
      # nodejs-slim_<v> (built with enableNpm = false — no npm/npx/corepack
      # and no bundled npm module tree to scan), and fall back to removeNpm
      # over the full attr on nixpkgs revisions without a slim build, so the
      # fallback never silently re-ships npm.
      # nodejs embeds its configure metadata (process.config) in the binary,
      # which keeps icu4c's dev output - and through icu-config's shebang the
      # build shell - plus node's bash-interactive build input in the runtime
      # closure, failing the distroless closure purity gate. Nothing at runtime
      # resolves those paths, so sever them in the derivation itself. If a
      # future nixpkgs decouples pkgs.icu from the icu node links against, the
      # strip becomes a no-op and the purity gate surfaces it again rather than
      # failing silently.
      # node22 is sourced from a dedicated UNSTABLE pin (nodeCryptoPkgs) so it
      # ships 22.23.0 — the fix for CVE-2026-48617 / CVE-2026-48937 the main pin's
      # 22.22.3 still carries. node24 stays on the main crypto set until its fix
      # (24.17.0) lands in the pinned nixpkgs. The node helpers are parameterised
      # by package set so the slim build AND its severed icu/zstd/bash references
      # come from the SAME set as the node attr — a cross-set sever would miss the
      # unstable pin's store paths and re-leak bash into the distroless closure.
      node22Set = nodeCryptoPkgs;
      node24Set = cryptoPkgs;
      nodeProductionRuntimeFrom = set: nodeVersion: rawPkgs:
        let
          slimPkg = (getPkgOrNullFrom set) [ [ "nodejs-slim_${nodeVersion}" ] ];
          # nodejs bakes its build config (process.config in the binary +
          # include/node/config.gypi) with the `-dev` store paths of every build
          # input. Two of those dev outputs ship a `*-config` helper with a
          # bashNonInteractive shebang — `icu4c-*-dev/bin/icu-config` and
          # `zstd-*-dev` (-> zstd-*-bin) — which is the ONLY way bash-5.3p9 reaches
          # the distroless closure (verified with `nix why-depends --all node bash`:
          # node -> {icu4c-dev, zstd-dev} -> bash are the only chains). Nothing at
          # runtime resolves those build-config paths, so sever node's references
          # to BOTH dev outputs; remove-references-to zeroes the hash in the binary
          # and config.gypi alike (verified: icu 4->0, zstd 2->0 occurrences). The
          # leaked shell is bashNonInteractive (the locked nixpkgs aliases `bash`
          # and `bashInteractive` to bash-interactive-*, a DIFFERENT store path), so
          # target it explicitly; `stdenv.shell` is kept as a backstop. If a future
          # build still ships bash, the purity gate surfaces the new referrer rather
          # than failing silently.
          severShellChain = pkg: severRuntimeReferences {
            inherit pkg;
            references = [
              (set.icu.dev or set.icu)
              (set.zstd.dev or set.zstd)
              pkg.stdenv.shell
              (set.bashNonInteractive or set.bash)
              (set.bashInteractive or set.bash)
            ];
          };
        in
        if slimPkg != null then [ (severShellChain slimPkg) ] else map removeNpm rawPkgs;
      nodeRaw22 = [ ((getPkgFrom node22Set) [ [ "nodejs_22" ] [ "nodejs-22_x" ] ] "Node.js 22 is not available in this nixpkgs version") ];
      nodeRaw24 = [ ((getPkgFrom node24Set) [ [ "nodejs_24" ] [ "nodejs-24_x" ] ] "Node.js 24 is not available in this nixpkgs version") ];
    in {
      versions = {
        "22" = {
          overlayName = "clearcuttNode22";
          raw = nodeRaw22;
          slimOverride = nodeProductionRuntimeFrom node22Set "22" nodeRaw22;
          distrolessOverride = nodeProductionRuntimeFrom node22Set "22" nodeRaw22;
          # Kept as the final resolveForTier fallback for forks whose registry
          # forks drop the overrides while pinned to an older nixpkgs.
          useRemoveNpm = true;
        };
        "24" = {
          overlayName = "clearcuttNode24";
          raw = nodeRaw24;
          slimOverride = nodeProductionRuntimeFrom node24Set "24" nodeRaw24;
          distrolessOverride = nodeProductionRuntimeFrom node24Set "24" nodeRaw24;
          useRemoveNpm = true;
        };
      };
    };

    python = let
      # Distroless override evaluation: python3Minimal exists in the locked
      # nixpkgs (currently python3-minimal-3.14.6) but is deliberately NOT
      # adopted as a distrolessOverride:
      #   * it is built with withMinimalDeps = true, which disables OpenSSL,
      #     sqlite, expat, mpdecimal, and readline — so the `ssl`, `sqlite3`,
      #     and `pyexpat` stdlib modules are missing and HTTPS, pip-installed
      #     wheels, and most real services break out of the box;
      #   * it tracks nixpkgs' default Python line rather than the requested
      #     per-version runtime, so it cannot serve both 3.13 and 3.14 and can
      #     silently change interpreter lines when the pin moves.
      # Instead, distroless keeps the per-version full interpreter but severs
      # the build-shell store references that live in dev-facing helper files
      # (pythonX.Y-config, config-*/Makefile, install-sh, makesetup, ctypes
      # test fixtures, _sysconfigdata). Nothing the interpreter executes at
      # runtime resolves them, and removing them drops bash from the image
      # closure. The target is the interpreter's own stdenv shell - NOT
      # pkgs.bash, which the locked nixpkgs aliases to bashInteractive, a
      # different store path that python never references. The ssl/sqlite/
      # readline runtime references are retained.
      pythonDistrolessRuntime = py: [
        (severRuntimeReferences {
          pkg = py;
          references = [ py.stdenv.shell ];
        })
      ];
    in {
      versions = {
        "3.13" = {
          overlayName = "clearcuttPython313";
          raw = let py = getPkg [ [ "python313" ] ] "Python 3.13 is not available in this nixpkgs version"; in [ py ];
          slimOverride = [ (getPkg [ [ "clearcuttCve15308Python313" ] ] "Patched Python 3.13 runtime is not available") ];
          distrolessOverride = let py = getPkg [ [ "clearcuttCve15308Python313" ] ] ""; in pythonDistrolessRuntime py;
          devExtra = let py = getPkg [ [ "python313" ] ] ""; in [ py.pkgs.pip pkgs.uv pkgs.poetry ];
        };
        "3.14" = {
          overlayName = "clearcuttPython314";
          raw = let py = getPkg [ [ "python314" ] ] "Python 3.14 is not available in this nixpkgs version"; in [ py ];
          slimOverride = [ (getPkg [ [ "clearcuttCve15308Python314" ] ] "Patched Python 3.14 runtime is not available") ];
          distrolessOverride = let py = getPkg [ [ "clearcuttCve15308Python314" ] ] ""; in pythonDistrolessRuntime py;
          devExtra = let py = getPkg [ [ "python314" ] ] ""; in [ py.pkgs.pip pkgs.uv pkgs.poetry ];
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
          raw = [ (graftedOrRebuilt [ [ "dotnetCorePackages" "sdk_8_0" ] ] ".NET 8 SDK is not available in this nixpkgs version") ];
          slimOverride = [ (graftedOrRebuilt [ [ "dotnetCorePackages" "aspnetcore_8_0" ] ] ".NET 8 ASP.NET Core Runtime is not available in this nixpkgs version") ];
          distrolessOverride = [ (graftedOrRebuilt [ [ "dotnetCorePackages" "runtime_8_0" ] ] ".NET 8 Base Runtime is not available in this nixpkgs version") ];
        };
        "10" = {
          overlayName = "clearcuttDotnet10";
          raw = [ (graftedOrRebuilt [ [ "dotnetCorePackages" "sdk_10_0" ] ] ".NET 10 SDK is not available in this nixpkgs version") ];
          slimOverride = [ (graftedOrRebuilt [ [ "dotnetCorePackages" "aspnetcore_10_0" ] ] ".NET 10 ASP.NET Core Runtime is not available in this nixpkgs version") ];
          distrolessOverride = [ (graftedOrRebuilt [ [ "dotnetCorePackages" "runtime_10_0" ] ] ".NET 10 Base Runtime is not available in this nixpkgs version") ];
        };
      };
    };

    dotnet-runtime = {
      # Virtual language definition strictly for downstreams requesting the bare dotnet runtime overlay
      versions = {
        "8" = {
          overlayName = "clearcuttDotnet8Runtime";
          raw = [ (graftedOrRebuilt [ [ "dotnetCorePackages" "aspnetcore_8_0" ] ] ".NET 8 ASP.NET Core Runtime is not available in this nixpkgs version") ];
        };
        "10" = {
          overlayName = "clearcuttDotnet10Runtime";
          raw = [ (graftedOrRebuilt [ [ "dotnetCorePackages" "aspnetcore_10_0" ] ] ".NET 10 ASP.NET Core Runtime is not available in this nixpkgs version") ];
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
