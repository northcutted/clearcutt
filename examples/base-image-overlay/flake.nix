{
  description = "ClearCutt Java 21 runtime grafted onto a mandated UBI base";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    clearcutt.url = "github:northcutted/clearcutt?dir=core";
  };

  outputs = { self, nixpkgs, clearcutt }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          mandatedBase = pkgs.dockerTools.pullImage {
            imageName = "registry.access.redhat.com/ubi9/ubi-minimal";
            imageDigest = "sha256:REPLACE_WITH_PINNED_BASE_DIGEST";
            sha256 = "sha256-REPLACE_WITH_NIX_PREFETCH_DOCKER_HASH";
          };
        in {
          overlayImage = clearcutt.lib.graftOntoBase {
            inherit system;
            fromImage = mandatedBase;
            runtime = "java21";
            tier = "distroless";
            name = "acme-java21-ubi";
            tag = "latest";
          };
        });
    };
}
