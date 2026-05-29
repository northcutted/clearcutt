# ClearCutt Modular Fleet Base Image Compiler
# Designed by: Eddie Northcutt
# Paradigm: Declarative Nix Base Image Injection (Anti-Migration Tax)

{ pkgs ? import <nixpkgs> {} }:

let
  # Import centralized language and runtime registry
  registry = import ./registry.nix { inherit pkgs; };

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

  # Resolve tier-specific base tools
  resolveTierPackages = { tier }:
    if tier == "dev" then
      [
        pkgs.coreutils
        pkgs.bashInteractive
        pkgs.git
        pkgs.curl
        pkgs.cacert
      ]
    else if tier == "slim" then
      [
        pkgs.bash
        pkgs.busybox
        pkgs.cacert
      ]
    else if tier == "distroless" then
      [
        pkgs.cacert
      ]
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
    langPkgs = registry.resolveForTier { inherit language version tier; };
    tierPkgs = resolveTierPackages { inherit tier; };
    
    # Injected file structures common to secure configurations
    baseContents = [
      passwdFile
      groupFile
      tmpDir
      appDir
    ];

    allContents = baseContents ++ tierPkgs ++ langPkgs ++ extraPackages;

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
