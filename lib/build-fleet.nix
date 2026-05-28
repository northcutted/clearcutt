# ClearCutt Modular Fleet Base Image Compiler
# Designed by: Eddie Northcutt
# Paradigm: Declarative Nix Base Image Injection (Anti-Migration Tax)

{ pkgs ? import <nixpkgs> {} }:

let
  # Injected user configurations for secure, rootless compliance
  uid = "10001";
  gid = "10001";
  username = "appuser";
  groupname = "appuser";

  # Define static rootless account structures
  passwdContents = ''
    root:x:0:0:root:/root:/bin/sh
    ${username}:x:${uid}:${gid}:ClearCutt Secure App User:/app:/sbin/nologin
  '';

  groupContents = ''
    root:x:0:
    ${groupname}:x:${gid}:
  '';

  # Static rootless system configuration derivations
  passwdFile = pkgs.writeTextDir "etc/passwd" passwdContents;
  groupFile = pkgs.writeTextDir "etc/group" groupContents;

  # Isolated filesystem workspaces with optimized permissions
  tmpDir = pkgs.runCommand "cc-tmp-dir" {} ''
    mkdir -p $out/tmp
    chmod 1777 $out/tmp
  '';

  appDir = pkgs.runCommand "cc-app-dir" {} ''
    mkdir -p $out/app
    # Set permissions so the rootless appuser can read/write inside their workspace
    chmod 755 $out/app
  '';

  # A helper to remove npm/npx/corepack from Node.js for slim/distroless runtimes.
  # symlinkJoin materializes a new store path whose bin/ and lib/ entries are
  # symlinks into the upstream nodejs derivation; postBuild then unlinks the
  # package-manager entry points and the npm/corepack module trees so the
  # production tiers ship the bare `node` binary only. The upstream derivation
  # is untouched, so this is a cheap, override-free trim.
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

  # Resolve the exact language packages based on the supported combinations matrix
  resolveLanguagePackage = { language, version, tier }:
    if language == "core" then
      []
    else if language == "java" then
      (let
         jdkPackage = if version == "21" then
                        (if pkgs ? jdk21 then pkgs.jdk21
                         else if pkgs ? openjdk21 then pkgs.openjdk21
                         else throw "Java 21 is not available in this nixpkgs version")
                      else if version == "25" then
                        (if pkgs ? jdk25 then pkgs.jdk25
                         else if pkgs ? openjdk25 then pkgs.openjdk25
                         else throw "Java 25 is not available in this nixpkgs version")
                      else throw "Unsupported Java version: ${version}";
       in
       if tier == "dev" then
         [ jdkPackage pkgs.maven pkgs.ant pkgs.gradle ]
       else
         [ (if jdkPackage ? jre then jdkPackage.jre else jdkPackage) ])
    else if language == "node" then
      (let
         baseNode = if version == "22" then
                      (if pkgs ? nodejs_22 then pkgs.nodejs_22
                       else if pkgs ? nodejs-22_x then pkgs.nodejs-22_x
                       else throw "Node.js 22 is not available in this nixpkgs version")
                    else if version == "24" then
                      (if pkgs ? nodejs_24 then pkgs.nodejs_24
                       else if pkgs ? nodejs-24_x then pkgs.nodejs-24_x
                       else throw "Node.js 24 is not available in this nixpkgs version")
                    else throw "Unsupported Node version: ${version}";
       in
       if tier == "dev" then [ baseNode ] else [ (removeNpm baseNode) ])
    else if language == "python" then
      (let
         pythonPackage = if version == "3.13" then
                           (if pkgs ? python313 then pkgs.python313 else throw "Python 3.13 is not available in this nixpkgs version")
                         else if version == "3.14" then
                           (if pkgs ? python314 then pkgs.python314 else throw "Python 3.14 is not available in this nixpkgs version")
                         else throw "Unsupported Python version: ${version}";
       in
       if tier == "dev" then
         [ pythonPackage pythonPackage.pkgs.pip pkgs.uv pkgs.poetry ]
       else
         [ pythonPackage ])
    else if language == "go" then
      (if version == "1.25" then
         (if pkgs ? go_1_25 then [ pkgs.go_1_25 ]
          else throw "Go 1.25 is not available in this nixpkgs version")
       else if version == "1.26" then
         (if pkgs ? go_1_26 then [ pkgs.go_1_26 ]
          else throw "Go 1.26 is not available in this nixpkgs version")
       else throw "Unsupported Go version: ${version}")
    else if language == "dotnet" then
      (if tier == "dev" then
         # Dev tier gets full SDK
         (if version == "8" then
            (if pkgs ? dotnetCorePackages && pkgs.dotnetCorePackages ? sdk_8_0 then [ pkgs.dotnetCorePackages.sdk_8_0 ]
             else throw ".NET 8 SDK is not available in this nixpkgs version")
          else if version == "10" then
            (if pkgs ? dotnetCorePackages && pkgs.dotnetCorePackages ? sdk_10_0 then [ pkgs.dotnetCorePackages.sdk_10_0 ]
             else throw ".NET 10 SDK is not available in this nixpkgs version")
          else throw "Unsupported .NET SDK version: ${version}")
       else if tier == "slim" then
         # Slim tier gets aspnetcore runtime (for web support with a diagnostic shell)
         (if version == "8" then
            (if pkgs ? dotnetCorePackages && pkgs.dotnetCorePackages ? aspnetcore_8_0 then [ pkgs.dotnetCorePackages.aspnetcore_8_0 ]
             else throw ".NET 8 ASP.NET Core Runtime is not available in this nixpkgs version")
          else if version == "10" then
            (if pkgs ? dotnetCorePackages && pkgs.dotnetCorePackages ? aspnetcore_10_0 then [ pkgs.dotnetCorePackages.aspnetcore_10_0 ]
             else throw ".NET 10 ASP.NET Core Runtime is not available in this nixpkgs version")
          else throw "Unsupported .NET ASP.NET Core Runtime version: ${version}")
       else if tier == "distroless" then
         # Distroless tier gets pure, hyper-minimal .NET base Runtime (no ASP.NET Core web stack)
         (if version == "8" then
            (if pkgs ? dotnetCorePackages && pkgs.dotnetCorePackages ? runtime_8_0 then [ pkgs.dotnetCorePackages.runtime_8_0 ]
             else throw ".NET 8 Base Runtime is not available in this nixpkgs version")
          else if version == "10" then
            (if pkgs ? dotnetCorePackages && pkgs.dotnetCorePackages ? runtime_10_0 then [ pkgs.dotnetCorePackages.runtime_10_0 ]
             else throw ".NET 10 Base Runtime is not available in this nixpkgs version")
          else throw "Unsupported .NET Base Runtime version: ${version}")
       else throw "Unsupported lifecycle tier: ${tier}")
    else if language == "rust" then
      (if tier == "dev" then
         (if version == "1.95" then
            (if pkgs ? rustc && pkgs ? cargo then [ pkgs.rustc pkgs.cargo pkgs.rustfmt pkgs.clippy ]
             else throw "Rust 1.95 is not available in this nixpkgs version")
          else throw "Unsupported Rust version: ${version}")
       else [])
    else if language == "cc" then
      (if tier == "dev" then
         (if version == "15" then
            [ pkgs.gcc pkgs.gnumake pkgs.cmake pkgs.ninja ]
          else throw "Unsupported C/C++ version: ${version}")
       else [])
    else
      throw "Unsupported language matrix target: ${language}";

  # Resolve tier-specific toolings and shells
  resolveTierPackages = { tier, languagePackages }:
    if tier == "dev" then
      # Dev/Builder tier: Full interactive capabilities
      [
        pkgs.coreutils
        pkgs.bashInteractive
        pkgs.git
        pkgs.curl
        pkgs.cacert
      ] ++ languagePackages
    else if tier == "slim" then
      # Slim/Runtime tier: Minimal diagnostic capabilities (bash & busybox)
      [
        pkgs.bash
        pkgs.busybox
        pkgs.cacert
      ] ++ languagePackages
    else if tier == "distroless" then
      # Distroless tier: Pure zero-utility footprint (No Shell, No Coreutils)
      [
        pkgs.cacert
      ] ++ languagePackages
    else
      throw "Unsupported lifecycle tier: ${tier}";

in
{
  # Core function to build the hardened image
  buildFleetImage = {
    name,
    tag ? "latest",
    language,
    version ? "LTS",
    tier ? "slim",
    fromImage ? null,
    maxLayers ? 100,
    extraPackages ? [],
    extraConfig ? {}
  }:
  let
    langPkgs = resolveLanguagePackage { inherit language version tier; };
    tierPkgs = resolveTierPackages { inherit tier; languagePackages = langPkgs; };
    
    # Injected file structures common to secure configurations
    baseContents = [
      passwdFile
      groupFile
      tmpDir
      appDir
    ];

    allContents = baseContents ++ tierPkgs ++ extraPackages;

    # Define standard OCI Annotations/Labels (compliant with opencontainers image-spec)
    ociLabels = {
      "org.opencontainers.image.title" = "clearcutt-${language}-${version}";
      "org.opencontainers.image.description" = "Hardened ClearCutt Base Image for ${language} (${version}) - Tier: ${tier}";
      "org.opencontainers.image.url" = "https://github.com/northcutted/clearcutt";
      "org.opencontainers.image.source" = "https://github.com/northcutted/clearcutt";
      "org.opencontainers.image.version" = version;
      "org.opencontainers.image.vendor" = "Eddie Northcutt";
      "org.opencontainers.image.authors" = "Eddie Northcutt";
      "org.opencontainers.image.licenses" = "Apache-2.0";
      "org.opencontainers.image.ref.name" = tier;
    };

    # OCI Image Config block mapping non-root execution parameters
    defaultConfig = {
      User = "${uid}:${gid}";
      WorkingDir = "/app";
      Env = [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        "HOME=/app"
        "TMPDIR=/tmp"
        "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
      ];
      Labels = ociLabels;
    };

    # Merge OCI configuration overrides
    mergedConfig = pkgs.lib.recursiveUpdate defaultConfig extraConfig;

  in
  pkgs.dockerTools.buildLayeredImage {
    inherit name tag fromImage maxLayers;
    contents = allContents;
    config = mergedConfig;
  };
}
