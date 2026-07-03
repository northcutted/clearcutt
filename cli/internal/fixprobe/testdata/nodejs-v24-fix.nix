{
  callPackage,
  fetchpatch2,
  openssl,
  python3,
  enableNpm ? true,
}:

let
  buildNodejs = callPackage ./nodejs.nix {
    inherit openssl;
    python = python3;
  };
in
buildNodejs {
  inherit enableNpm;
  version = "24.18.0";
  sha256 = "sha256-ggggggggggggggggggggggggggggggggggggggggggg=";
  patches = [
    ./configure-emulator.patch
    ./configure-armv6-vfpv2.patch
    ./disable-darwin-v8-system-instrumentation-node19.patch
    ./bypass-darwin-xcrun-node16.patch
    ./node-npm-build-npm-package-logic.patch
    ./fix-default-npm-path.patch
    (fetchpatch2 {
      url = "https://github.com/nodejs/node/commit/f9a4bd6b28ec8cc95b3195105f3f608a4d88b41d.patch?full_index=1";
      hash = "sha256-fffffffffffffffffffffffffffffffffffffffffff=";
    })
  ];
}
