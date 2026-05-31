# ClearCutt Nix Native Consumer Integration Library
# Brand Owner & Principal Architect: Eddie Northcutt
# Paradigm: Declarative overlay and development shells for host platforms

{ self, pkgs }:

let
  # Import centralized language and runtime registry
  registry = import ./registry.nix { inherit pkgs; };

  # Dynamic Overlay Generation
  # Iterates through languages and versions in the registry to construct the overlay attributes
  dynamicOverlayAttrs =
    let
      # Get all combinations of (lang, version, verSpec)
      allSpecs = pkgs.lib.concatMap (lang:
        let
          langSpec = registry.languages.${lang};
        in
        pkgs.lib.mapAttrsToList (ver: verSpec: {
          inherit lang ver verSpec;
        }) langSpec.versions
      ) (builtins.attrNames registry.languages);

      # Filter for specs that specify an overlayName
      validSpecs = builtins.filter (spec: spec.verSpec ? overlayName) allSpecs;

      # Map each to a name/value pair
      pairs = map (spec: {
        name = spec.verSpec.overlayName;
        value = registry.resolveRaw { language = spec.lang; version = spec.ver; };
      }) validSpecs;
    in
    builtins.listToAttrs pairs;

in
{
  # Raw package matrix resolver
  resolveRawPackages = registry.resolveRaw;

  # Declarative Overlay
  # Downstreams can apply this overlay to inject ClearCutt's verified package matrix
  overlay = final: prev: dynamicOverlayAttrs;

  # Downstream Development Shell Builder
  # Automatically wraps a host development shell with ClearCutt's transient enterprise credentials broker
  mkHardenedShell = {
    name ? "clearcutt-hardened-shell",
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
      echo -e "\033[1;35m====================================================\033[0m"
      echo -e "\033[1;35m     ClearCutt Nix Native Hardened Development Shell \033[0m"
      echo -e "\033[1;35m====================================================\033[0m"
      echo -e "Host System: \033[32m${pkgs.system}\033[0m"
      echo -e "Hardened Target: \033[32m${language}-${version}\033[0m"
      echo
 

      # Source transient credentials broker from the Flake store path!
      if [ -f "${self}/lib/credential-broker.sh" ]; then
        source "${self}/lib/credential-broker.sh"
      fi
    '' + shellHook;
  };
}
