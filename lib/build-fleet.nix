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

  # A helper to remove npm/npx/corepack from Node.js for slim/distroless runtimes
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
      (if version == "21" then
         (if pkgs ? jdk21 then [ pkgs.jdk21 ]
          else if pkgs ? openjdk21 then [ pkgs.openjdk21 ]
          else throw "Java 21 is not available in this nixpkgs version")
       else if version == "25" then
         (if pkgs ? jdk25 then [ pkgs.jdk25 ]
          else if pkgs ? openjdk25 then [ pkgs.openjdk25 ]
          else throw "Java 25 is not available in this nixpkgs version")
       else throw "Unsupported Java version: ${version}")
    else if language == "node" then
      (if version == "22" then
         (let
            baseNode = if pkgs ? nodejs_22 then pkgs.nodejs_22
                       else if pkgs ? nodejs-22_x then pkgs.nodejs-22_x
                       else throw "Node.js 22 is not available in this nixpkgs version";
          in
          if tier == "dev" then [ baseNode ] else [ (removeNpm baseNode) ])
       else throw "Unsupported Node version: ${version}")
    else if language == "python" then
      (if version == "3.13" then
         (if pkgs ? python313 then [ pkgs.python313 ]
          else throw "Python 3.13 is not available in this nixpkgs version")
       else throw "Unsupported Python version: ${version}")
    else if language == "go" then
      (if version == "1.25" then
         (if pkgs ? go_1_25 then [ pkgs.go_1_25 ]
          else throw "Go 1.25 is not available in this nixpkgs version")
       else throw "Unsupported Go version: ${version}")
    else if language == "dotnet" then
      (if tier == "dev" then
        # Dev tier gets full SDK
        (if version == "8.0" then
           (if pkgs ? dotnetCorePackages && pkgs.dotnetCorePackages ? sdk_8_0 then [ pkgs.dotnetCorePackages.sdk_8_0 ]
            else throw ".NET 8.0 SDK is not available in this nixpkgs version")
         else if version == "10.0" then
           (if pkgs ? dotnetCorePackages && pkgs.dotnetCorePackages ? sdk_10_0 then [ pkgs.dotnetCorePackages.sdk_10_0 ]
            else throw ".NET 10.0 SDK is not available in this nixpkgs version")
         else throw "Unsupported .NET SDK version: ${version}")
      else
        # Runtime/Distroless tiers get aspnetcore runtime (smaller, secure)
        (if version == "8.0" then
           (if pkgs ? dotnetCorePackages && pkgs.dotnetCorePackages ? aspnetcore_8_0 then [ pkgs.dotnetCorePackages.aspnetcore_8_0 ]
            else throw ".NET 8.0 Runtime is not available in this nixpkgs version")
         else if version == "10.0" then
           (if pkgs ? dotnetCorePackages && pkgs.dotnetCorePackages ? aspnetcore_10_0 then [ pkgs.dotnetCorePackages.aspnetcore_10_0 ]
            else throw ".NET 10.0 Runtime is not available in this nixpkgs version")
         else throw "Unsupported .NET Runtime version: ${version}"))
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
