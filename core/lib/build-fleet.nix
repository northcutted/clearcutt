# ClearCutt Modular Fleet Base Image Compiler
# Designed by: Eddie Northcutt
# Paradigm: Declarative Nix Base Image Injection (Anti-Migration Tax)

{ pkgs ? import <nixpkgs> {}
, platformMetadata ? import ./platform-metadata.nix
}:

let
  # Import centralized language and runtime registry
  registry = import ./registry.nix { inherit pkgs; };

  # Injected user configurations for secure, rootless compliance
  uid = "10001";
  gid = "10001";
  username = "appuser";
  groupname = "appuser";

  # Fork-configurable product identity, supplied via platform-metadata.nix
  # (written by `clearcutt platform init` from clearcutt.fleet.yaml). Defaults
  # keep the upstream brand when no fork metadata is present.
  productName = platformMetadata.productName or "ClearCutt";
  imagePrefix = platformMetadata.imagePrefix or "clearcutt";

  # Define static rootless account structures
  passwdContents = ''
    root:x:0:0:root:/root:/bin/sh
    ${username}:x:${uid}:${gid}:${productName} Secure App User:/app:/sbin/nologin
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

  # Compile standard FHS dynamic linker symlinks to support running FHS dynamic binaries natively
  lib64Symlink = pkgs.runCommand "lib64-symlink" {} ''
    mkdir -p $out/lib64 $out/lib
    if [ -f ${pkgs.glibc}/lib/ld-linux-x86-64.so.2 ]; then
      ln -s ${pkgs.glibc}/lib/ld-linux-x86-64.so.2 $out/lib64/ld-linux-x86-64.so.2
    fi
    if [ -f ${pkgs.glibc}/lib/ld-linux-aarch64.so.1 ]; then
      ln -s ${pkgs.glibc}/lib/ld-linux-aarch64.so.1 $out/lib/ld-linux-aarch64.so.1
    fi
    
    # Symlink core libraries to both /lib and /lib64 for complete architecture robustness
    for dir in lib lib64; do
      mkdir -p $out/$dir
      ln -s ${pkgs.glibc}/lib/libc.so.6 $out/$dir/libc.so.6
      ln -s ${pkgs.glibc}/lib/libm.so.6 $out/$dir/libm.so.6
      ln -s ${pkgs.glibc}/lib/libdl.so.2 $out/$dir/libdl.so.2
      ln -s ${pkgs.glibc}/lib/libpthread.so.0 $out/$dir/libpthread.so.0
      ln -s ${pkgs.glibc}/lib/librt.so.1 $out/$dir/librt.so.1
      ln -s ${pkgs.stdenv.cc.cc.lib}/lib/libstdc++.so.6 $out/$dir/libstdc++.so.6
      ln -s ${pkgs.stdenv.cc.cc.lib}/lib/libgcc_s.so.1 $out/$dir/libgcc_s.so.1
    done
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
      lib64Symlink
    ];

    allContents = baseContents ++ tierPkgs ++ langPkgs ++ extraPackages;
    sourceURL = platformMetadata.sourceURL or "https://github.com/northcutted/clearcutt";
    vendor = platformMetadata.vendor or "ClearCutt";
    authors = platformMetadata.authors or "ClearCutt maintainers";

    # Define standard OCI Annotations/Labels (compliant with opencontainers image-spec)
    ociLabels = {
      "org.opencontainers.image.title" = "${imagePrefix}-${language}-${version}";
      "org.opencontainers.image.description" = "Hardened ${productName} Base Image for ${language} (${version}) - Tier: ${tier}";
      "org.opencontainers.image.url" = sourceURL;
      "org.opencontainers.image.source" = sourceURL;
      "org.opencontainers.image.version" = version;
      "org.opencontainers.image.vendor" = vendor;
      "org.opencontainers.image.authors" = authors;
      "org.opencontainers.image.licenses" = "Apache-2.0";
      "org.opencontainers.image.ref.name" = tier;
    };

    # OCI Image Config block mapping non-root execution parameters
    defaultConfig = {
      User = "${uid}:${gid}";
      WorkingDir = "/app";
      Env = [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        "LD_LIBRARY_PATH=/lib:/lib64:/usr/lib:/usr/lib64"
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
    extraCommands = ''
      mkdir -p etc
      rm -f etc/passwd etc/group
      cp ${passwdFile}/etc/passwd etc/passwd
      cp ${groupFile}/etc/group etc/group
      chmod 0644 etc/passwd etc/group
    '';
    config = mergedConfig;
  };
}
