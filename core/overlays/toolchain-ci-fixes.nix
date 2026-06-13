# Build-toolchain CI fixes — deliberately NOT under overlays/cve/ (these are not
# CVE remediations and carry no evidence files; the cve barrel only loads that
# directory).
#
# The CVE remediation overlays rebind the top-level `openssl` and `sqlite` and
# patch the default `python3` (python313). That is intentional: the fleet ships
# those patched runtimes. The side effect is that every build-toolchain package
# linking them — meson, glib, gobject-introspection, p11-kit, gnutls, gnupg,
# skopeo — no longer matches cache.nixos.org and is rebuilt from source on every
# cold CI leg. p11-kit's `test-server.sh` check then fails inside the sandboxed
# GitHub runner: it is a socket-server smoke test that fails instantly (~0.05s)
# while the other 66 checks pass, and Hydra builds the identical source cleanly
# (the stock derivation is cached). The failure cascades through gnutls → gnupg
# → skopeo → clearcutt-dev-shell-env and breaks the PR gate.
#
# Skip p11-kit's test phase in this build toolchain so the forced-from-source
# rebuild succeeds. p11-kit is only a build/scan-tool dependency (pulled via
# skopeo in the dev shell); it is never part of a shipped hardened image, so
# this does not weaken any published artifact. If a narrower per-test exclusion
# becomes possible (meson lacks a clean single-test skip today), prefer it.
final: prev: {
  p11-kit = prev.p11-kit.overrideAttrs (_old: {
    doCheck = false;
    doInstallCheck = false;
  });
}
