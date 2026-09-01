---
name: nix-validate
description: Evaluate this repo's Nix flake in a container to catch core/ errors before pushing. Use whenever core/flake.nix, core/lib/*.nix, clearcutt.yaml, or the fleet matrix changes — and always before pushing a branch that touches core/.
---

# Validating core/ without Nix installed

This repo's flake cannot be evaluated on a machine without Nix, so changes to
`core/` used to be verified only by CI. That cost five round trips on this
branch alone, every one an **evaluation** error that takes seconds to catch:

| Failure | Symptom in CI |
| --- | --- |
| `flake.nix` imported a deleted overlay | `Path 'core/overlays/cve-remediation.nix' does not exist` — 25 of 26 jobs |
| flake passed `cryptoPkgs` to a registry that dropped the parameter | `called with unexpected argument 'cryptoPkgs'` |
| a gate defaulted to a runtime line the matrix removed | `does not provide attribute 'java21-distroless'` |
| unquoted dotted attribute | `.#python3.14-distroless` parsed as `python3` → `14-distroless` |

Run the validator instead.

## Use it

```bash
.claude/skills/nix-validate/scripts/validate.sh
```

Pure evaluation, no images built. ~1s per attribute on a warm store; the first
run pays a few minutes for nixpkgs. It checks that the flake evaluates, that
**every cell in the generated fleet matrix** resolves as a flake attribute on
every configured system, and that `checks`/`devShells`/`lib` enumerate.

To also realize one image (slow — a real build):

```bash
.claude/skills/nix-validate/scripts/validate.sh --build java25-distroless
```

For anything else, use the raw runner:

```bash
.claude/skills/nix-validate/scripts/nix-run.sh eval --raw '.#packages.x86_64-linux."python3.14-slim".name'
.claude/skills/nix-validate/scripts/nix-run.sh flake check --no-build
```

## When to run it

Always, before pushing, if the change touches any of:

- `core/flake.nix`, `core/flake.lock`, `core/lib/**`
- `clearcutt.yaml` matrix, or anything that regenerates
  `core/lib/fleet-matrix.nix`
- a default that names a runtime line (gates, app templates, scripts)

## The one thing to understand: laziness

**Nix only reports errors in code it actually forces.** A dangling import that
nothing references evaluates fine — this was confirmed by planting one and
watching the validator pass.

That is why `validate.sh` evaluates every matrix cell rather than just running
`nix flake metadata`. Forcing each cell's derivation pulls in `registry.nix`,
the package sets, and the recipes, which is where these bugs live. If you add a
new code path to the flake that no cell reaches, this validator will not cover
it — extend the script rather than assuming.

## Requirements

Podman or Docker. Nothing else; Nix runs in the container.

- macOS + podman: needs `podman machine start`.
- The `/nix` store persists in a named volume (`clearcutt-nix-store`), which is
  what makes repeat runs fast. `podman volume rm clearcutt-nix-store` resets it.
- The repo is mounted **read-only**, so validation cannot mutate the working
  tree.

Override with `CLEARCUTT_CONTAINER_ENGINE`, `CLEARCUTT_NIX_IMAGE`,
`CLEARCUTT_NIX_VOLUME`.

## Relationship to the Go guards

`cli/internal/commands/core_nix_paths_test.go` statically checks the same two
failure classes (dangling paths, undeclared arguments) with no container at all,
so `go test` catches them in milliseconds. It is a cheap first line; this skill
is the real evaluator and catches everything the static checks cannot — missing
attributes, recipe errors, type errors, anything inside nixpkgs.

Run the Go tests always; run this when `core/` changes.
