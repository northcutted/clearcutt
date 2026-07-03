{
  lib,
  stdenv,
  fetchurl,
  buildPackages,
  perl,
  coreutils,
  withCryptodev ? false,
  cryptodev,
  withZlib ? false,
  zlib,
  static ? stdenv.hostPlatform.isStatic,
}:

let
  common =
    {
      version,
      hash,
      patches ? [ ],
      withDocs ? false,
      extraMeta ? { },
    }:
    stdenv.mkDerivation (finalAttrs: {
      pname = "openssl";
      inherit version;

      src = fetchurl {
        url = "https://github.com/openssl/openssl/releases/download/openssl-${version}/openssl-${version}.tar.gz";
        inherit hash;
      };

      inherit patches;

      postPatch = ''
        patchShebangs Configure
      '';

      outputs = [
        "bin"
        "dev"
        "out"
        "man"
      ];
    });
in
{
  openssl_3_0 = common {
    version = "3.0.18";
    hash = "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=";
    patches = [
      ./3.0/nix-ssl-cert-file.patch
      ./use-etc-ssl-certs.patch
    ];
  };

  openssl_3_5 = common {
    version = "3.5.4";
    hash = "sha256-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=";
    patches = [
      ./3.5/nix-ssl-cert-file.patch
      ./use-etc-ssl-certs.patch
    ];
  };

  openssl_3_6 = common {
    version = "3.6.3";
    hash = "sha256-ddddddddddddddddddddddddddddddddddddddddddd=";
    patches = [
      ./3.5/nix-ssl-cert-file.patch
      ./use-etc-ssl-certs.patch
    ];
  };
}
