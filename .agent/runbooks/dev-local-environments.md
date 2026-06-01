# Runbook: `clearcutt dev` — drop into a ClearCutt environment locally

Status: **proposed, not started.** Self-contained handoff. Owner approved the
concept and the two-path design (native Nix preferred, dev container fallback).

## Goal & why

Add the missing "inner loop" to the platform: let a developer work *in* the exact
runtime closure ClearCutt ships, pinned to a released tag — so "works in prod /
works on my machine" is literally the same closure. This realizes the vision's
"dev images as dev containers locally, especially with our Nix options." It pairs
with `app`/`overlay` (those *produce* images; `dev` *consumes* one locally).

Principle to preserve: **consumable regardless of investment.** Nix users get the
pure/fast path; everyone else gets a container; nobody is forced into either.

## Grounded facts (verified in the repo — build on these, don't re-derive)

- **Container path is nearly free.** `<lang>:dev` images are published to GHCR.
  `cli/internal/catalog` already models everything needed to construct a correct
  run: `ImageRecord` has `Registry`, `ImageName`, `FullName`; `RuntimeContract`
  has `User` (`"10001"`), `WorkingDir` (`/app`), `ShellPresent`, `ProductionTier`,
  `DefaultEntrypoint`. `ReleaseEntry` has `Tag` + `ManifestDigest`. Use
  `catalog.LoadImageRecord(catalogPath, id)` / `LoadCatalogIndex` to resolve.
- **Nix path is half-there.** `core/flake.nix` exposes per-target `packages`
  (`packages.<system>.<lang><ver>-<tier>`, e.g. `java21-distroless`) AND `-native`
  raw runtime closures (`packages.<system>.<lang><ver>-native`, e.g.
  `java21-native`). It also exposes a single `devShells.default` (the repo's
  build/gating shell) — there are **no per-target dev shells yet**. See
  `mkPackageName`, `tiers = [ "dev" "slim" "distroless" ]` (flake.nix ~lines
  50–80) and `devShells.default` (~line 111).
- **The flake-input consumption pattern already exists** (documented, not
  CLI-wrapped): `site/src/components/UsageTabs.astro` and `release.yml` (~line 885)
  generate `inputs.clearcutt.url = "github:<owner>/<repo>/<tag>"` +
  `devShells.x86_64-linux.default = ... mkShell { ... }`. So consumers can already
  do this by hand; the CLI packages it ergonomically and pins it.
- **GHCR image naming**: `ghcr.io/<owner>/<repo>/clearcutt-<normLang>:<tag>-<tier>`
  where `normLang` is lowercased (e.g. `coreLTS` → `clearcutt-corelts`). Prefer
  reading `ImageRecord.Registry`/`ImageName`/`FullName` from the catalog rather
  than reconstructing the string.

## Command shape

```
clearcutt dev <image-id> [--tag vX.Y.Z] [--nix|--container|--devcontainer]
                         [--engine docker|podman] [--mount <hostdir>] [--no-rm]
```
- **Group**: add a new Cobra group `"Develop Locally:"` in `root.go` (next to the
  five pillars; use the existing `add(groupID, cmd)` helper + `rootCmd.AddGroup`).
- **Auto-detect default**: prefer Nix when `nix` is on `PATH`; else container.
  `--nix`/`--container`/`--devcontainer` force a mode.
- `<image-id>` is a catalog image id (e.g. `java21-distroless`). The dev env always
  uses the **dev tier** — if the id is a non-dev tier, swap to the `-dev` sibling
  (or require dev); validate via `RuntimeContract.ShellPresent` (slim/distroless
  may lack a shell — you cannot drop into them).
- `--tag` defaults to the catalog's latest release tag. **Always pin** (tag, ideally
  digest) — exact-version reproducibility is the entire value over a generic run.

## Resolution logic (shared by all modes)

1. Load catalog (`GlobalOpts.CatalogPath`). Resolve `<image-id>` → `ImageRecord`;
   pick the `-dev` tier sibling. Resolve `--tag` (default latest).
2. From the record: GHCR ref = `Registry`/`ImageName` (or `FullName`) + `:<tag>-dev`
   (+ digest if available); `WorkingDir`, `User` from `RuntimeContract`.
3. For Nix: owner/repo from catalog index (`Owner`/`Repo`/`RegistryBase`), flake
   attr = the dev target's closure (see flake work below). Catalog-less fallback:
   derive ref + attr from `<image-id> + --tag` so consumers who never cloned the
   repo still work.

## The three modes

**`--nix` (preferred).**
- v1 (works today, no flake change): `nix shell github:<owner>/<repo>/<tag>#<lang><ver>-native --command $SHELL`
  — drops the runtime closure into `PATH`, pinned to that tag's `flake.lock`.
- v2 (after flake work): `nix develop github:<owner>/<repo>/<tag>#<target>` against
  a real per-target dev shell (toolchain + shell + env). This is the proper path.
- Shell out to `nix` (exec). Honor `--extra-experimental-features "nix-command flakes"`
  and `--accept-flake-config` like the rest of the repo (see pr-gate.yml:84).

**`--container`.**
- `docker|podman run -it --rm -v <mount>:<workingDir> -w <workingDir> <ghcr-ref>`,
  default `<mount>` = `$PWD`, drop to the dev shell.
- **UID handling (real ergonomics gap):** images run as `10001`; a bind-mounted host
  dir will hit ownership/write issues. Resolve deliberately — e.g. `--user $(id -u):$(id -g)`
  on Linux, or document the tradeoff. Don't ship without addressing this; it's the
  difference between "feels native" and "feels broken on first run."
- Engine: detect docker→podman→nerdctl, or `--engine`.

**`--devcontainer` (highest leverage, lowest effort).**
- Emit `.devcontainer/devcontainer.json` referencing the `:dev` GHCR image
  (`"image": "<ghcr-ref>"`, `workspaceFolder`, `remoteUser`, sensible defaults).
  Instant VS Code / Codespaces support; declarative + committable. This is "dev
  images as dev containers" in the literal spec sense — do this one first.

## Net-new flake work (the main non-trivial piece)

Add `devShells.<system>.<target>` to `core/flake.nix` for each **dev** target,
mirroring the dev image's closure (toolchain + shell + the env vars the dev image
sets). Today only `devShells.default` exists. Build them from the same package
set the dev image is assembled from (find where the dev tier closure is composed
near `mkPackageName`/`tiers`, ~lines 50–80, and the `-native`/raw package
construction). Goal: `nix develop .#java21-dev` gives the *same* tools as the
`java21:dev` image. Until this lands, the CLI uses `nix shell #<…>-native` (runtime
in PATH) as a working v1.

## Sharp edges / must-validate

- **Dev tier only** — gate on `RuntimeContract.ShellPresent`; never try to shell
  into distroless.
- **Always pin** to a tag (and digest when present).
- Ephemeral (`--rm`) by default; consider `--no-rm`/named for re-enter.
- Minimal catalog dependency: `image-id + --tag` must be enough for a consumer
  without the repo (don't hard-require a local catalog clone for the container path).

## Implementation increments

1. **`clearcutt dev` skeleton + resolution + `--devcontainer`** — new
   `cli/internal/commands/dev.go`; `NewDevCmd()`; register in `root.go` under a new
   `"develop"` group. Resolve image-id→record→ref/tier/runtimeContract; emit
   `devcontainer.json`. (Fastest visible win; offline-testable.)
2. **`--container`** — engine detection, run-arg construction, UID handling.
   Golden-test the constructed `docker run` argv against a stub `docker` on `PATH`.
3. **`--nix` v1** — `nix shell #…-native`, pinned; auto-detect default (nix→container).
   Stub `nix` on `PATH`, assert argv.
4. **Flake `devShells.<system>.<target>`** + switch `--nix` to `nix develop .#<target>`.
   Verify `nix develop .#java21-dev --command true` works.
5. **Polish**: `clearcutt dev --help` examples; a docs page; surface in the site
   UsageTabs (replace the hand-rolled snippet with `clearcutt dev …`).

## Tests (follow the established patterns in this repo)

- Use `runCLI(t, "dev", "java21-distroless", "--container", ...)` and a **stub
  binary on `PATH`** (see `verifyreleaseevidence_test.go` / `remediation_run_test.go`
  for the fake-tool-on-PATH + `writeExecutable` pattern) that records its argv;
  assert the constructed `docker`/`nix` args (image ref, `-it`, mount, `-w`,
  pinned tag/attr).
- `--devcontainer`: assert the generated JSON (image ref, workspaceFolder, remoteUser).
- Resolution: a test against `cli/internal/testdata/catalog` (fixture) that a non-dev
  id resolves to the `-dev` sibling and that a no-shell tier is rejected.

## Verification

`cd cli && go test ./... -count=1 && go vet ./... && gofmt -l internal/`. For the
flake: `cd core && nix develop .#java21-dev --command true`. Keep everything
offline-testable (stub the engines/nix; never hit the network or a real registry
in unit tests).

## Cohesion / placement

New top-level verb `clearcutt dev <image-id>` in a `"Develop Locally:"` group, so
`--help` reads: Build → Secure → Verify → Certify → Manage Applications → **Develop
Locally** → Browse. It's the inner-loop facet; keep it distinct from `app`
(produces app images) and `overlay` (BYO bases).

## Open decisions for the implementer / owner

- `dev` vs `shell`/`up` as the verb (recommend `dev` — matches the tier name).
- Per-target devShells: derive from the dev image's exact closure (preferred) vs a
  lighter "runtime + shell" shell. Aim for parity with the image.
- Container UID strategy (Linux `--user` mapping vs documented workspace pattern).
- Whether `--devcontainer` writes into the cwd or prints to stdout (recommend write
  with `--print` to emit instead).
