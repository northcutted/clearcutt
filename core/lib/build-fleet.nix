# ClearCutt modular fleet base image compiler.

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
    root:x:0:0:root:/root:/sbin/nologin
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
    # Ownership is applied in dockerTools extraCommands, where numeric chown
    # metadata can be represented in the image layer.
    chmod 755 $out/app
  '';

  # Compile standard FHS dynamic linker symlinks for non-distroless compatibility
  # tiers. Distroless omits these and relies only on store-bound RPATH/RUNPATH.
  lib64Symlink = pkgs.runCommand "lib64-symlink" {} ''
    mkdir -p $out/lib64 $out/lib
    if [ -f ${pkgs.glibc}/lib/ld-linux-x86-64.so.2 ]; then
      ln -s ${pkgs.glibc}/lib/ld-linux-x86-64.so.2 $out/lib64/ld-linux-x86-64.so.2
    fi
    if [ -f ${pkgs.glibc}/lib/ld-linux-aarch64.so.1 ]; then
      ln -s ${pkgs.glibc}/lib/ld-linux-aarch64.so.1 $out/lib/ld-linux-aarch64.so.1
    fi
    
    # Symlink core libraries to both /lib and /lib64 for FHS compatibility.
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

  # Injected file structures common to secure configurations
  baseContents = [
    passwdFile
    groupFile
    tmpDir
    appDir
  ];

  baseEnv = [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    "HOME=/app"
    "TMPDIR=/tmp"
    "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
  ];

  fhsCompatibilityEnv = [
    "LD_LIBRARY_PATH=/lib:/lib64:/usr/lib:/usr/lib64"
  ];

  imageContentsForTier = tier:
    baseContents ++ pkgs.lib.optionals (tier != "distroless") [ lib64Symlink ];

  envForTier = tier:
    baseEnv ++ pkgs.lib.optionals (tier != "distroless") fhsCompatibilityEnv;

  splitNixAttrPath = path:
    pkgs.lib.filter (segment: segment != "") (pkgs.lib.splitString "." path);

  getPkg = attrPath: pkgs.lib.attrByPath attrPath null pkgs;

  resolvePackageCandidate = candidates: errorMessage:
    let
      resolved = builtins.filter (pkg: pkg != null) (
        builtins.map (candidate: getPkg (splitNixAttrPath candidate)) candidates
      );
    in
    if resolved == [] then throw errorMessage else builtins.head resolved;

  entrypointPath = command:
    if pkgs.lib.hasPrefix "/" command then command else "/bin/${command}";

  portKey = port:
    "${toString port.port}/${port.protocol or "tcp"}";

  exposedPorts = ports:
    pkgs.lib.listToAttrs (builtins.map (port: {
      name = portKey port;
      value = {};
    }) ports);

  mkdirDataDirs = dataDirs:
    pkgs.lib.concatMapStringsSep "\n" (dir: ''
      mkdir -p ".${dir}"
      chown ${uid}:${gid} ".${dir}"
      chmod 0750 ".${dir}"
    '') dataDirs;

  postgresEntrypoint = pkgs.writeShellScriptBin "clearcutt-postgres-entrypoint" ''
    set -euo pipefail
    export PGDATA="''${PGDATA:-/var/lib/postgresql/data}"
    if [ -d "$PGDATA" ] && [ ! -O "$PGDATA" ] && [ ! -s "$PGDATA/PG_VERSION" ]; then
      export PGDATA="$PGDATA/pgdata"
    fi
    mkdir -p "$PGDATA"
    if [ ! -s "$PGDATA/PG_VERSION" ]; then
      initdb -D "$PGDATA"
    fi
    postgres -D "$PGDATA" \
      -h 127.0.0.1 \
      -k /tmp \
      -c log_destination=stderr \
      -c logging_collector=off \
      "$@" &
    postgres_pid="$!"
    stop_postgres() {
      kill -TERM "$postgres_pid" >/dev/null 2>&1 || true
      wait "$postgres_pid" 2>/dev/null || true
      exit 0
    }
    trap stop_postgres INT TERM
    attempts=0
    while [ "$attempts" -lt 30 ]; do
      if ! kill -0 "$postgres_pid" >/dev/null 2>&1; then
        wait "$postgres_pid"
        exit "$?"
      fi
      if pg_isready -h 127.0.0.1 -p 5432 >/dev/null 2>&1; then
        wait "$postgres_pid"
        exit "$?"
      fi
      attempts=$((attempts + 1))
      sleep 1
    done
    echo "[clearcutt-postgres] postgres did not become ready within 30 seconds" >&2
    kill -TERM "$postgres_pid" >/dev/null 2>&1 || true
    wait "$postgres_pid" 2>/dev/null || true
    exit 1
  '';

  serviceTemplatePackages = service:
    if service.template == "postgres" then
      [ postgresEntrypoint pkgs.bash pkgs.coreutils ]
    else
      [];

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

    allContents = (imageContentsForTier tier) ++ tierPkgs ++ langPkgs ++ extraPackages;
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
      "org.opencontainers.image.licenses" = "NOASSERTION";
      "dev.clearcutt.recipe.license" = "Apache-2.0";
      "org.opencontainers.image.ref.name" = tier;
    };

    # OCI Image Config block mapping non-root execution parameters
    defaultConfig = {
      User = "${uid}:${gid}";
      WorkingDir = "/app";
      Env = envForTier tier;
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
      chown ${uid}:${gid} app
      chmod 0755 app
    '';
    config = mergedConfig;
  };

  buildServiceImage = {
    name,
    tag ? "current",
    service,
    fromImage ? null,
    maxLayers ? 100,
    extraPackages ? [],
    extraConfig ? {}
  }:
  let
    servicePkg = resolvePackageCandidate (service.packageCandidates or [])
      "No Nix package candidate is available for service ${service.id}";
    servicePkgs = [ pkgs.cacert servicePkg ] ++ serviceTemplatePackages service ++ extraPackages;
    allContents = baseContents ++ [ lib64Symlink ] ++ servicePkgs;
    sourceURL = platformMetadata.sourceURL or "https://github.com/northcutted/clearcutt";
    vendor = platformMetadata.vendor or "ClearCutt";
    authors = platformMetadata.authors or "ClearCutt maintainers";
    servicePorts = service.ports or [];
    dataDirs = service.dataDirs or [];
    serviceEnv = service.env or [];
    serviceEntrypoint = builtins.map entrypointPath (service.entrypoint or []);
    serviceCmd = service.cmd or [];
    serviceRuntimeCommands =
      if service.template == "postgres" then ''
        mkdir -p bin
        ln -sf ${pkgs.bash}/bin/bash bin/sh
      '' else "";

    ociLabels = {
      "org.opencontainers.image.title" = "${imagePrefix}-${service.id}";
      "org.opencontainers.image.description" = service.description or "Hardened ${productName} service image for ${service.template}";
      "org.opencontainers.image.url" = sourceURL;
      "org.opencontainers.image.source" = sourceURL;
      "org.opencontainers.image.version" = service.version;
      "org.opencontainers.image.vendor" = vendor;
      "org.opencontainers.image.authors" = authors;
      "org.opencontainers.image.licenses" = "NOASSERTION";
      "dev.clearcutt.recipe.license" = "Apache-2.0";
      "org.opencontainers.image.ref.name" = "service";
      "dev.clearcutt.image.kind" = "service";
      "dev.clearcutt.service.id" = service.id;
      "dev.clearcutt.service.template" = service.template;
      "dev.clearcutt.service.version" = service.version;
    };

    defaultConfig = {
      User = "${uid}:${gid}";
      WorkingDir = "/app";
      Env = baseEnv ++ fhsCompatibilityEnv ++ serviceEnv;
      Labels = ociLabels;
    }
    // pkgs.lib.optionalAttrs (servicePorts != []) {
      ExposedPorts = exposedPorts servicePorts;
    }
    // pkgs.lib.optionalAttrs (serviceEntrypoint != []) {
      Entrypoint = serviceEntrypoint;
    }
    // pkgs.lib.optionalAttrs (serviceCmd != []) {
      Cmd = serviceCmd;
    };

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
      chown ${uid}:${gid} app
      chmod 0755 app
      ${serviceRuntimeCommands}
      ${mkdirDataDirs dataDirs}
    '';
    config = mergedConfig;
  };
}
