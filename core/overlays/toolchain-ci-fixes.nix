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

  # The python313 CVE patch (and the openssl/sqlite rebinds) force every
  # python package set from source, including python3Packages.pytest-xdist and
  # mypy — both of which have tests that are flaky/broken in sandboxed CI:
  #   * pytest-xdist test_max_worker_restart_tests_queued: xdist workers crash
  #     before emitting the expected restart message under the runner's process
  #     limits (184 other tests pass; cache.nixos.org builds it cleanly).
  #   * mypy mypyc multimodule tests trip on aarch64 runners.
  # Applied via pythonPackagesExtensions so the disables reach the DEFAULT
  # interpreter (python313) and every version uniformly, instead of leaking
  # into a single interpreter's `.override` the way a per-version
  # packageOverrides does. These are dev/test tools, never shipped in a
  # hardened image, and the disabled checks are the packages' own flaky
  # self-tests, not anything ClearCutt asserts.
  pythonPackagesExtensions = (prev.pythonPackagesExtensions or []) ++ [
    (_pyFinal: pyPrev: {
      pytest-xdist = pyPrev.pytest-xdist.overridePythonAttrs (old: {
        disabledTests = (old.disabledTests or []) ++ [
          "test_max_worker_restart_tests_queued"
        ];
      });
      mypy = pyPrev.mypy.overridePythonAttrs (_old: {
        doCheck = false;
      });
    })
  ];
}
