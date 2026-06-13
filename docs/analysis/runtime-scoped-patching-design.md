# Design: Runtime-Scoped CVE Patching

Status: design intake (2026-06-13). Validated by eval-grounded investigation;
not yet implemented. Goal: make a CVE patch rebuild only what **ships** in
images, not the entire build toolchain — so patching stops being a 5-hour cold
world-rebuild and the warm-cache seeding ritual goes away.

## Problem (recap)

The CVE overlays rebind **top-level** `openssl`/`sqlite` and patch the default
`python313`. Because the dev shell, the scanners, and the build toolchain
(meson, glib, gobject-introspection, p11-kit, gnutls) all link those, every
patch forces a from-source rebuild of the whole build universe. Stock packages
are on cache.nixos.org (HTTP 200); the overlaid ones 404 and rebuild. A minimal
`coreLTS` leg takes ~5h because it rebuilds the scanner toolchain.

## Three findings that shape the design (all eval-proven)

1. **`python` is the real poison, not `openssl`.** Rebinding top-level
   `python313` — even just its `openssl` input — rebuilds glib/p11-kit/skopeo,
   because `python3` is the build-time interpreter for meson/glib/g-i. Rebinding
   only `nodejs-slim_22` does **not** cascade. So python must move to a
   namespaced attr; you cannot just scope openssl.
2. **The separate-attr shape leaves the toolchain fully cached.** With
   `clearcuttRuntimePython313 = prev.python313.override { openssl = patched; }`
   and **no** top-level rebind: top-level `python313`, `openssl`, `p11-kit`,
   `glib`, `skopeo` all stay stock/cached, while the shipped attr carries the
   patch. Confirmed by drvPath compare.
3. **`.NET` cannot be cleanly scoped.** The wrapped dotnet runtime is a prebuilt
   blob with **no `.override`**; openssl is baked via a source patch
   (`vmr.nix:249-250` hardcodes `${openssl.out}/lib/libssl.so`) and dlopen'd at
   runtime — invisible to a buildInputs/SBOM walk. Only a **realized-closure**
   gate catches a stock openssl in a dotnet image. (See decision below.)

Also: **java** reaches openssl/sqlite only transitively via `cups`
(java.desktop) → gnutls/avahi → openssl, and util-linux → sqlite. Whether the
jlink'd minimal JRE **retains** that linkage in its realized closure could not
be settled by eval (no substituters on the dev host) — it must be confirmed by
a Linux build in CI. If it retains stock openssl, java under-patches.

## The split (validated)

Two nixpkgs instances in `core/flake.nix`:

- `buildPkgs` = **stock** nixpkgs (no CVE overlay) — for the image-assembly
  machinery (`dockerTools.buildLayeredImage`, `runCommand`/`writeText` helpers),
  the dev shell, and the scanners. Stays on cache.nixos.org → never rebuilt.
- `runtimePkgs` = stock + `cveRemediationOverlay` — for everything that **ships
  inside an image**.

**Split boundary:** `allContents` (build-fleet.nix:239) = `runtimePkgs`;
everything that *assembles* the image = `buildPkgs`.

Eval-confirmed **contents are CVE-sensitive and must be `runtimePkgs`**: `cacert`
(ships in every tier), `busybox`, `bash`, `git`, `curl` all diverge stock↔patched.
The reversed failure mode to fear: using `buildPkgs` for a *runtime* package =
silently shipping unpatched. So the safe default for any contents-bound use is
`runtimePkgs`.

`registry` is instantiated against `runtimePkgs` (every package it returns
ships). `devShells.default` → `buildPkgs` (this is what makes legs fast).
`graftOntoBase` passes both; `mkHardenedShell` → `runtimePkgs` (it mirrors a
shipped toolchain). The existing `checks.*` block already walks patched contents
with a **stock** `closureInfo` — the cross-pkgs pattern is sound and partly
established.

## The completeness gate (the security keystone)

A `checks.<system>.runtime-patch-completeness-<target>` gate that, for each
shipped image, materializes the **runtime closure** (reuse
`closureInfo { rootPaths = image.clearcuttContents }`) and a walker
(extend `core/tests/closure-purity-check.py`) that fails if any store path is an
`openssl-*`/`sqlite-*` (and the python case) below the required patched version.

Non-negotiable properties:
- Walks the **shipped closure**, never the `.drv` build closure — under Option 3
  the *build-time* openssl is intentionally stock 3.6.2; only what ships must be
  patched. (A build-closure check would false-positive.)
- **Default-deny**: any `openssl-<v>` with `v` below the floor fails — this also
  catches the unpatched majors that exist in nixpkgs (`openssl_3_5`=3.5.6,
  `openssl_3`=3.0.20), not just the known stock 3.6.2.
- Matches by **version**, accepting all 6 openssl outputs of the required
  version (a hash-exact check would false-positive on dev/bin/man outputs).
- Covers **slim + distroless + service** tiers (not just distroless — slim ships
  the openssl-linked runtime too), and the graft/service paths. Floor driven by
  a committed `core/tests/runtime-dep-floor.json` (`{dep, minVersion}` from the
  evidence JSONs). Wired into verify.sh, `nix flake check`, and the pipeline
  evidence predicate.

This gate is what converts a `.NET`/java under-patch from a **silent ship** into
a **hard build failure**.

## Migration sequence (gate-before-flip is the safety invariant)

1. **Split overlays into `clearcutt*` attrs, keep the global alias.** No behavior
   change (drvs identical to today). Rewrite `verify.sh:674` (the
   `attrNames(cveRemediation base base)` gate — its `base ? name` semantics flip
   because `clearcutt*` attrs are absent from stock).
2. **Land the completeness gate; prove it GREEN under the current global rebind.**
   Establishes the baseline (today every shipped closure is all-patched —
   eval-confirmed: python313/node22/java21 distroless closures = openssl-3.6.3 +
   sqlite-3.53.2, zero stock). The gate must exist and pass *before* anything
   flips.
3. **Flip the overlays to runtime-scoped** (two-pkgs split + per-runtime
   `.override`). The gate stays green only if every shipped path is patched; a
   missed runtime fails loudly *at this step* — catching under-patching at
   cutover, not in production.
4. **Delete the coping machinery.** Remove `toolchain-ci-fixes.nix` (p11-kit/
   pytest-xdist/mypy are now substituted, never built → flaky tests never run),
   and retire `warm-nix-cache.yml` + `publish-cache --include-build-deps` + the
   gc-cache changes (toolchain cached → no world rebuild → no seed ritual).

## Per-runtime decisions

- **python**: ship `clearcuttPython313/314/315` (patched interpreter, openssl/
  sqlite inputs overridden); leave `python313`/`python3` stock for the build
  toolchain. Dev tier (`raw`) stays stock so dev shells stay cached.
- **node**: `nodejs-slim_22/24` already accept `.override { openssl = …; }`
  (registry uses them for production). No extra plumbing. `nodejs_22` is a
  symlinkJoin and rejects the override — irrelevant (it's the dev tier).
- **java**: confirm via CI build whether the jlink'd JRE retains cups→openssl /
  util-linux→sqlite. If yes, override those inputs on the JRE; if the linkage is
  dead-on-arrival post-jlink, java ships no openssl and needs nothing.
- **.NET**: open decision (below).

## Open decisions for the maintainer

1. **.NET handling** — it can't be cleanly per-runtime-scoped:
   (a) a narrow top-level openssl override accepted as a dotnet-only toolchain
   rebuild cost; (b) patchelf the dotnet RPATH onto the patched openssl in a
   `clearcuttRuntimeDotnet*` derivation; (c) drop the ".NET production tier"
   openssl claim and document it as a non-claim in security-model.md §3. In all
   cases the completeness gate must cover dotnet8/10 closures.
2. **Dev tier**: keep on stock runtimes (recommended — dev shells stay cached)
   vs ship patched for parity.
3. **Linkage-map source of truth**: generate `ALLOWED_RUNTIME_ATTRS` (draft-agent
   allowlist), the registry threading, and the gate's expected set from one
   committed `linkage-map.json` so they cannot drift.
4. **`cve-draft-agent.py`**: add a `runtime_input` recipe route (patched dep +
   per-runtime input override) with an allowlist of `clearcuttRuntime*` targets;
   update `validate_recipe` + `test_remediation_pipeline.py`.
