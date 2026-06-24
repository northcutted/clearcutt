# CLI Pivot Plan — From Forkable Monorepo to a Released, Self-Contained CLI

**Status:** proposed · **Owner:** platform · **Audience:** an implementer (human or
AI agent) executing this in phases.

## Goal

Turn ClearCutt from "fork this monorepo" into "download a signed `clearcutt`
binary, point it at (or scaffold) a GitHub repo, and it deploys a working
SLSA-grade fleet." The released binary must be **self-contained**: it carries
everything needed to build, gate, verify, sign, remediate, and scaffold a fleet,
and works against an arbitrary repo without a checkout of *this* tree.

## The core insight (why "native Go" and "the pivot" are one initiative)

Today the CLI is a thin orchestrator that **shells into a second logic tier** in
`core/` by hardcoded relative paths:

- `core/pipeline/pipeline.sh` — build + SBOM (syft) + scan (grype) + push
  (skopeo) + sign (cosign). Reached by `fleet certify-target`/`fleet
  publish-target`/`service build` via `nix develop --command ./pipeline/pipeline.sh`.
- `core/tests/verify.sh` (+ `closure-*.py`) — the ~10 image-security gates.
  Reached by an opaque `nix develop -- ./tests/verify.sh` passthrough.
- `core/scripts/cve-draft-agent.py` — deterministic patch routing + the optional
  LLM tier. `remediation run` `exec()`s it.

A binary cannot scaffold or run logic it does not contain. **So making the logic
native Go is the mechanism that makes the CLI self-contained, which is what makes
scaffolding possible.** Q1 ("make it all native Go") and Q2 ("the pivot") are the
same work.

### What becomes Go vs what stays Nix

"All native Go" means the **ClearCutt logic** is Go. It still *invokes* a few
external binaries — and that is correct, not a gap:

| Concern | Disposition |
| --- | --- |
| Hermetic build engine (`nix build`, flake eval, closures) | **Stays Nix.** Go shells out to `nix`, like it shells out to `git`. This is the SLSA/reproducibility value prop; do not reimplement. |
| `flake.nix`, `core/lib/*.nix`, `core/overlays/**` (recipes/data) | **Stays Nix, embedded as assets.** The CLI carries and templates these; it does not "port" them. |
| Build/SBOM/scan/sign orchestration (`pipeline.sh`) | **Becomes Go** in `internal/build`. Calls `nix`, `syft`/`grype` (or their Go libs), `cosign`, `go-containerregistry` (already a dep, replaces `skopeo`). |
| Image-security gates (`verify.sh`, `closure-*.py`) | **Becomes Go** in `internal/gates` (closure walk, CVE-floor tuple compare, structure checks — all pure logic). |
| Remediation deterministic routing (`cve-draft-agent.py`) | **Becomes Go** in `internal/remediation`. The **LLM tier becomes an optional pluggable HTTP provider** (off by default), satisfying the "optional, not required" requirement. |
| Supply-chain tools (`grype`, `syft`, `cosign`, `crane`) | **External deps.** Several are Go libraries you can import directly; otherwise pinned subprocesses resolved via the embedded Nix shell. |

Net: the *ClearCutt codebase* becomes all-Go; it orchestrates `nix` + a handful
of pinned, mostly-Go supply-chain tools.

### Design rule: zero shell, zero ambient tools

The released binary must run with **no shell and no ambient toolbox** — ideally
runnable in a `scratch`/distroless context where only `nix` is on PATH (fitting,
given what we ship). Concretely:

- **Never invoke a shell.** No `exec.Command("bash", "-c", ...)`, no `sh -c`, no
  reliance on `/bin/sh`. All subprocesses use `exec.Command(bin, args...)` with an
  explicit argv so there is no shell parsing, quoting, or injection surface.
- **Prefer Go libraries over subprocesses** where a solid one exists:
  - OCI build/copy/push/index → `go-containerregistry` (**already a dependency**;
    retires `skopeo`/`crane`).
  - SBOM → `anchore/syft` Go API (retires the `syft` binary).
  - Scan → `anchore/grype` Go API (retires the `grype` binary; DB refresh handled
    in-process).
  - Sign/verify → `sigstore-go` / cosign libraries (retires most `cosign` shelling).
- **`nix` is the one unavoidable external binary**, invoked directly via
  `exec.Command("nix", "build", ...)` — never through a shell. Because we use Go
  libraries for SBOM/scan/sign/push, we no longer need `nix develop`'s ambient
  toolbox at all; we only need `nix build` to realize the image.
- **Pinned-subprocess fallback is allowed** when a library is too heavy or
  immature (e.g. cosign signing initially), but it still goes through
  `exec.Command(bin, args...)` — the no-shell rule is absolute even for fallbacks.
- The `core/lib/credential-broker.sh` and `core/scripts/agent-sandbox.sh` logic
  becomes Go too; nothing in the hot path requires a shell interpreter.

Caveat to manage: importing syft+grype+cosign as libraries pulls large dependency
trees. Adopt them incrementally behind the engine seam (below), measuring binary
size and build time, and keep the pinned-subprocess fallback as the escape hatch.

## Target end-state (acceptance for "done")

```bash
clearcutt platform new --owner acme --repo golden-images   # scaffold a full fleet repo
cd golden-images && clearcutt fleet certify-target ...      # build+gate locally, no core/ checkout
clearcutt remediation run ...                               # zero-touch patch, no python on disk
clearcutt verify boundaries <image>                         # the verify.sh gates, as a Go subcommand
```

None of these require this monorepo on disk. `platform new` can optionally
`gh repo create` + push.

---

## Phase 1 — Consolidate the `core/` logic into Go

Move logic, **not** Nix recipes, into Go. Each workstream lands behind the
*existing* CLI verbs so workflows and tests don't change shape; the bash/python
becomes a thin shim (or is deleted) once parity is proven.

1. **`internal/build` (replaces `pipeline.sh` `certify_target`)**
   - Port: `nix build` invocation → SBOM (syft) → scan (grype `--fail-on`,
     policy-driven, **not** a bash literal) → push (go-containerregistry) → sign
     + attest (cosign). Make the grype threshold and SBOM format come from
     `fleet.yaml`/flags.
   - DoD: `fleet certify-target` produces byte-equivalent evidence (SBOM, test
     predicate, signatures) to the bash path for a fixture target; old
     `pipeline.sh` kept temporarily behind `--engine=legacy` for A/B.
2. **`internal/gates` (replaces `verify.sh` + `closure-*.py`)**
   - Port each gate: closure-purity `/nix/store` walk, runtime-CVE floor tuple
     compare, structure tests, credential-broker/sandbox isolation, matrix/floor
     drift. Expose as `clearcutt verify boundaries [--local]`.
   - DoD: gate verdicts match `verify.sh` on the same images; `pr-gate.yml`
     calls `clearcutt verify boundaries` instead of `./tests/verify.sh`.
3. **`internal/remediation` (replaces `cve-draft-agent.py`)**
   - Port deterministic Tier-1 (version bump) / Tier-2 (fetchpatch) overlay
     synthesis + the rebuild-and-rescan proof loop. Define an `LLMProvider`
     interface; ship a no-op default and an optional OpenRouter/Anthropic
     provider gated by an explicit `--llm` flag + key. LLM is strictly a
     fallback tier.
   - DoD: `remediation run` drafts+verifies a known overlay with `--llm=off`;
     `cve-patch-agent.yml` no longer calls a `.py` file.

**Verification gate for Phase 1:** `go test ./...` green; the PR-gate matrix
green on a real branch; evidence diff between Go and legacy engines is empty.

## Phase 2 — Embed the fleet skeleton into the binary

Use the established `//go:embed` pattern (already used for schemas in
`internal/catalog/schema_files.go`, plus `sitetemplate` and `versionpolicy`).

1. New `internal/scaffold` package embedding the **skeleton tree**:
   - `.github/workflows/*` (release, pr-gate, rebase, scheduled-scan, etc.)
   - `.github/actions/*` (setup-nix, certify-app, and a new `registry-login` if
     extracted)
   - `core/flake.nix`, `core/flake.lock`, `core/lib/*.nix`, `core/overlays/**`,
     and any residual `.sh`/`.py` not yet ported
   - `schemas/*.json`
   - These are stored as templates with `{{ .Registry.Host }}` etc. placeholders
     fed from `fleet.Config`.
2. **Drift guard:** a sync test (mirror `versionpolicy/sync_test.go`) asserting
   the embedded skeleton is byte-identical to the source tree, so the binary can
   never silently ship a stale flake/workflow.

**Verification gate:** `go test ./...` green incl. the new drift test; binary
size sanity-checked; `go vet`/`gofmt` clean.

## Phase 3 — `platform new` / `platform scaffold`

1. New verb `platform new --owner O --repo R [--dir PATH] [--registry HOST]`:
   - Materialize the embedded skeleton into `--dir` (default `./<repo>`).
   - Run the **existing** `runPlatformInit` localization over it (config, docs,
     metadata, app templates, example localization — already implemented in
     `platform.go`).
   - Emit the `CLEARCUTT_REGISTRY_HOST/USER/TOKEN` setup guidance (see
     [registry-swap.md](../registry-swap.md)).
2. Optional bootstrap `--push`: `git init` + `gh repo create O/R` + initial
   commit + push (guarded; no-op without `gh`/auth, with a clear message).
3. Single-source the registry host: have the scaffolded `fleet-matrix` job emit
   `registry_host` from `fleet.yaml` as a job output and reference it in the
   login steps, retiring the `CLEARCUTT_REGISTRY_HOST` double-source noted in
   registry-swap.md.

**Verification gate:** `platform new` into a temp dir produces a tree where
`platform status` reports all checks pass, `go`/`nix` build the CLI, and
`actionlint` passes on the generated workflows. Add an integration test that
scaffolds → `platform status` → asserts green.

## Phase 4 — Reposition

1. Lead `README.md`, `getting-started.md`, `platform-kit.md` with: install signed
   binary → `platform new` → own the generated repo. Demote "fork the monorepo"
   to the **contributor** path.
2. Derive the template-pinned CLI version from the binary build version
   (`-ldflags`), not the hardcoded `currentClearCuttRelease` literal
   (`app_template.go`), validated in CI against the latest tag.
3. Publish the binary install path prominently (it already exists and is
   cosign-verifiable).

**Verification gate:** a clean-machine walkthrough (install → `platform new` →
build → verify) works end to end and matches the README.

---

## Sequencing & risk

- **Phase 1 is the critical path and the biggest effort** (porting ~2.5k lines of
  bash/python to Go with parity tests). Do it workstream-by-workstream behind the
  existing verbs; keep the legacy engine selectable until each parity diff is
  empty. This de-risks the whole pivot — Phases 2–4 are mechanical once the logic
  is Go.
- **Do not port Nix.** The most common failure mode here is an agent trying to
  reimplement `nix build`/closures in Go. The flake and recipes are embedded
  assets, not logic to translate.
- **Keep evidence shape stable.** Schemas (`schemas/*`) are the contract; the Go
  engines must emit the same predicates the bash engines do, validated against
  the committed schemas.

## Progress

- **Port-map (done).** A survey confirmed the native-Go foundation is already
  substantial and the port should EXTEND it, not rewrite: `internal/oci`
  (go-containerregistry: daemon-free pull/push/build/rebase, fixture-testable via
  in-memory registry), `internal/certify` (walks docker-save + OCI-layout layers),
  `internal/scan` (grype-JSON → catalog findings), `internal/sign` (cosign behind
  an `exec` seam — keep as a pinned subprocess, no sigstore libs), `internal/attest`
  and `internal/catalogbuild` (pure in-toto/SPDX transforms). So Phase-1
  `internal/build` is largely **wiring these together around `nix build`**, not a
  from-scratch translation. Only `internal/sign` and `internal/commands/scan.go`
  shell out today, both via explicit-argv `exec.Command` (already zero-shell).
- **Boundary gates landed (2/?).** Both image-security gates that previously lived
  only in Python are now native Go, behind a shared layer-walker
  (`internal/certify/layers.go`):
  - `closure-purity-check.py` → `internal/certify/closure.go` + `clearcutt verify
    closure-purity` (full `/nix/store` walk — shells, package managers incl.
    versioned pip, setuid/setgid, whiteouts, explained-exception allowlist).
  - `closure-cve-check.py` → `internal/certify/runtimecve.go` + `clearcutt verify
    runtime-cve` (runtime-patch completeness: default-deny any shipped
    openssl/sqlite below the `runtime-dep-floor.json` floor; tuple version compare;
    artifact-skip anchoring). The port also fixes a latent leading-slash bug where
    store-level whiteouts never discarded.
  - Umbrella `clearcutt verify boundaries` runs both over one closure.
  All fixture-tested without a live `nix` build (18 certify tests). `verify.sh` now
  calls the Go gates (CLI-or-`go run` fallback). Remaining call sites to migrate:
  `pipeline.sh:265,290` (need `clearcutt` on PATH in the dev shell) and
  `flake.nix:445,459` (build-sandbox gates — need the CLI in the build closure);
  Python stays until those move.
- **Aggregated single-PR (3A) landed.** `clearcutt remediation run` now accumulates
  every campaign overlay onto ONE rolling branch (`cve-remediation/auto`, configurable)
  and opens/updates a single draft PR with a `gh pr list --head` dedup guard — not a
  PR per CVE. The agent branches off the rolling HEAD, so the orchestrator fast-forwards
  the rolling branch to fold each overlay in (`resetRollingBranch`/`foldIntoRolling`/
  `openOrUpdateAggregatedPR` in `remediation_run.go`). Git/gh run behind a `cmdRunner`
  seam; 6 unit tests (fake runner) + the updated real-git integration test. This is the
  Go-only slice of the remediation port; the deterministic patch-routing + optional LLM
  provider port of `cve-draft-agent.py` is still ahead.
- **Native-Go build engine landed (certify path).** `internal/build` ports
  `pipeline.sh certify_target`: `nix build` → Syft → Grype (with the tier/kind
  warning-vs-fail policy) → the **in-process** closure-purity + runtime-cve gates
  (no python) → the same test-results predicate. Subprocesses run behind a `Runner`
  seam (zero shell); wired as opt-in `fleet certify-target --engine=go` (default
  `shell`/pipeline.sh unchanged, so the release path is untouched). 8 unit tests with
  a fake Runner over a crafted image archive + a real-gate verdict; the actual
  `nix build` of a Linux image is CI-verified (a Darwin box has no linux-builder, and
  the engine fails fast on `*-darwin`).
- **Next:** port the `publish`/push/sign leg into `internal/build`, then the
  deterministic patch-routing + optional-LLM-provider port of `cve-draft-agent.py`
  (the aggregated-PR Go slice is already done). Finally, migrate the residual
  `pipeline.sh`/`flake.nix` python call sites and embed `core/` for the scaffolding
  pivot (Phases 2-3).

## Related workstreams (separate from this pivot, cross-referenced)

- **Aggregated single CVE PR** (one rolling branch + `gh pr list` dedup) — lands
  naturally inside the Phase-1 `internal/remediation` port. See
  [autonomous remediation notes].
- **Rebase auto-update via an opt-in app-supplied smoke hook** — platform does
  not own app tests; it runs a user-provided probe and gates on exit code.
- **Honest SLSA level + reproducibility evidence** — derive the level from the
  predicate; wire the already-implemented `verify rebuild --require-layer-match`
  into CI as differentiated evidence. See [security-model.md](../security-model.md).
