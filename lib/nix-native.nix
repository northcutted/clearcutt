# ClearCutt Nix Native Consumer Integration Library
# Brand Owner & Principal Architect: Eddie Northcutt
# Paradigm: Declarative overlay and development shells for host platforms

{ self, pkgs }:

let
  # Reusable core language packages resolver
  resolveRawPackages = { language, version }:
    if language == "core" then
      [ pkgs.coreutils pkgs.bashInteractive ]
    else if language == "java" then
      (if version == "21" then [ pkgs.jdk21 ]
       else if version == "25" then [ pkgs.jdk25 ]
       else throw "Unsupported Java version: ${version}")
    else if language == "node" then
      (if version == "22" then [ pkgs.nodejs_22 ]
       else if version == "24" then [ pkgs.nodejs_24 ]
       else throw "Unsupported Node version: ${version}")
    else if language == "python" then
      (if version == "3.13" then [ pkgs.python313 ]
       else if version == "3.14" then [ pkgs.python314 ]
       else throw "Unsupported Python version: ${version}")
    else if language == "go" then
      (if version == "1.25" then [ pkgs.go_1_25 ]
       else if version == "1.26" then [ pkgs.go_1_26 ]
       else throw "Unsupported Go version: ${version}")
    else if language == "dotnet" then
      (if version == "8.0" then [ pkgs.dotnetCorePackages.sdk_8_0 ]
       else if version == "10.0" then [ pkgs.dotnetCorePackages.sdk_10_0 ]
       else throw "Unsupported .NET SDK version: ${version}")
    else if language == "dotnet-runtime" then
      (if version == "8.0" then [ pkgs.dotnetCorePackages.aspnetcore_8_0 ]
       else if version == "10.0" then [ pkgs.dotnetCorePackages.aspnetcore_10_0 ]
       else throw "Unsupported .NET Runtime version: ${version}")
    else
      throw "Unsupported language: ${language}";

in
{
  # Raw package matrix resolver
  inherit resolveRawPackages;

  # Declarative Overlay
  # Downstreams can apply this overlay to inject ClearCutt's verified package matrix
  overlay = final: prev: {
    clearcuttCore = resolveRawPackages { language = "core"; version = "LTS"; };
    clearcuttJava21 = resolveRawPackages { language = "java"; version = "21"; };
    clearcuttJava25 = resolveRawPackages { language = "java"; version = "25"; };
    clearcuttNode22 = resolveRawPackages { language = "node"; version = "22"; };
    clearcuttNode24 = resolveRawPackages { language = "node"; version = "24"; };
    clearcuttPython313 = resolveRawPackages { language = "python"; version = "3.13"; };
    clearcuttPython314 = resolveRawPackages { language = "python"; version = "3.14"; };
    clearcuttGo125 = resolveRawPackages { language = "go"; version = "1.25"; };
    clearcuttGo126 = resolveRawPackages { language = "go"; version = "1.26"; };
    clearcuttDotnet8 = resolveRawPackages { language = "dotnet"; version = "8.0"; };
    clearcuttDotnet8Runtime = resolveRawPackages { language = "dotnet-runtime"; version = "8.0"; };
    clearcuttDotnet10 = resolveRawPackages { language = "dotnet"; version = "10.0"; };
    clearcuttDotnet10Runtime = resolveRawPackages { language = "dotnet-runtime"; version = "10.0"; };
  };

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
    langPkgs = resolveRawPackages { inherit language version; };
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
