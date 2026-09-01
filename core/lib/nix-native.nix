# ClearCutt Nix Native Consumer Integration Library

{ self
, pkgs
, platformMetadata ? import ./platform-metadata.nix
, registry ? import ./registry.nix { inherit pkgs; }
}:

let
  # Fork-configurable product identity (see clearcutt.yaml -> branding).
  productName = platformMetadata.productName or "ClearCutt";
  imagePrefix = platformMetadata.imagePrefix or "clearcutt";

  # Get all combinations of (lang, version, verSpec) that name an overlay
  # attribute. Computed from this module's own registry (never an overlay
  # fixpoint): an overlay's output attr NAMES must not depend on `final`,
  # or evaluating the fixpoint's attr set recurses.
  overlaySpecs =
    let
      allSpecs = pkgs.lib.concatMap (lang:
        let
          langSpec = registry.languages.${lang};
        in
        pkgs.lib.mapAttrsToList (ver: verSpec: {
          inherit lang ver verSpec;
        }) langSpec.versions
      ) (builtins.attrNames registry.languages);
    in
    builtins.filter (spec: spec.verSpec ? overlayName) allSpecs;

in
{
  # Raw package matrix resolver
  resolveRawPackages = registry.resolveRaw;

  # Declarative Overlay
  # Downstreams can apply this overlay to inject ClearCutt's verified package
  # matrix. Attr values resolve against `final`, so packages pick up the CVE
  # remediation overlay (and any other overlays the consumer stacks); only the
  # attr names come from the prev-side registry above.
  overlay = final: prev:
    let
      finalRegistry = import ./registry.nix { pkgs = final; };
    in
    builtins.listToAttrs (map (spec: {
      name = spec.verSpec.overlayName;
      value = finalRegistry.resolveRaw { language = spec.lang; version = spec.ver; };
    }) overlaySpecs);

  # Downstream Development Shell Builder
  # Automatically wraps a host development shell with ClearCutt's transient enterprise credentials broker
  mkHardenedShell = {
    name ? "${imagePrefix}-hardened-shell",
    language,
    version,
    extraBuildInputs ? [],
    shellHook ? ""
  }:
  let
    langPkgs = registry.resolveRaw { inherit language version; };
    allBuildInputs = [
      pkgs.git
      pkgs.curl
    ] ++ langPkgs ++ extraBuildInputs;

  in
  pkgs.mkShell {
    inherit name;
    buildInputs = allBuildInputs;

    shellHook = ''
      if [ -f "${self}/lib/credential-broker.sh" ]; then
        source "${self}/lib/credential-broker.sh"
        install_credential_broker_trap
      fi
    '' + shellHook;
  };
}
