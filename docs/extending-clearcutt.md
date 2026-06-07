# Extending ClearCutt Without Learning Nix First

ClearCutt uses Nix to build reproducible runtime closures, but Nix is not the
public configuration model for most users. Treat it as the backend compiler.
The extension surface is layered so teams can choose the smallest tool that
matches the job.

## 1. App Teams: Use Templates And Dev Environments

Application teams should not edit flakes to adopt ClearCutt.

```bash
clearcutt app template java --output examples/my-java-service --name my-java-service
clearcutt dev java21-distroless --devcontainer
clearcutt dev java21-distroless --container --engine docker
clearcutt certify my-app.tar --base java21-distroless --policy certification-policy.yaml
```

This path gives teams a Dockerfile, devcontainer, certification policy, release
workflow, and matching dev-tier image without requiring a local Nix install.

## 2. Fleet Owners: Add And Remove Known Runtime Lines

Fork owners extend the supported product surface through `clearcutt.fleet.yaml`,
but they do not need to edit the file by hand for common matrix changes:

```bash
clearcutt matrix explain java25
clearcutt matrix add java25
clearcutt matrix remove python3.13
clearcutt --format json matrix export --source fleet --github-actions --matrix release
clearcutt platform status
```

- `matrix.languages` selects runtime lines such as `java21`, `node24`, or
  `python3.15`.
- `matrix.tiers` selects `dev`, `slim`, and `distroless`.
- `matrix.systems` selects Linux release architectures.
- `templates.runtimes` controls generated app starters.
- `admission`, `catalog`, `remediation`, `branding`, and `release.nixCache`
  configure policy, evidence, and fork identity.

Unsupported runtime IDs fail while loading the fleet config, not during a later
flake build.

## 3. Platform Maintainers: Scaffold A New Runtime Line

When the fleet needs a runtime line that is not built in, use
`runtime scaffold`. The command writes a custom `runtimeLines` entry in
`clearcutt.fleet.yaml`, selects it in `matrix.languages` by default, enables a
matching app-template runtime when one is known, and regenerates
`core/lib/runtime-extensions.nix`.

```bash
clearcutt runtime scaffold ruby3.4
clearcutt runtime validate ruby3.4
clearcutt matrix explain ruby3.4
clearcutt app template ruby --output examples/my-ruby-service --name my-ruby-service
clearcutt platform status
```

Ruby is the reference scaffold candidate. With no extra flags,
`clearcutt runtime scaffold ruby3.4` derives:

- runtime ID: `ruby3.4`
- language/version: `ruby` / `3.4`
- package candidates: `ruby_3_4`, then `ruby`
- image IDs: `ruby3.4-dev`, `ruby3.4-slim`, `ruby3.4-distroless`
- app-template runtime: `ruby`
- smoke hint: `ruby --version`

For less obvious packages, pass explicit candidates and dev packages:

```bash
clearcutt runtime scaffold elixir1.18 \
  --language elixir \
  --version 1.18 \
  --package beam.packages.erlang.elixir_1_18 \
  --package elixir \
  --dev-package beam.packages.erlang.rebar3 \
  --smoke 'elixir --version'
```

`runtime validate` is the guardrail. It checks that the runtime line is known,
selected in `matrix.languages`, app-template wiring is aligned, package
candidates exist for custom runtimes, and `core/lib/runtime-extensions.nix`
matches the custom runtime lines in `clearcutt.fleet.yaml`. Add `--nix` when a
builder has Nix installed and you want a flake eval as part of validation:

```bash
clearcutt runtime validate ruby3.4 --nix --system x86_64-linux
```

## 4. Nix Backend Escape Hatch

Most runtime additions should go through `runtime scaffold`. Hand-edit
`core/lib/registry.nix` only when the runtime needs custom closure-shaping logic
that cannot be represented as package candidates, dev packages, and
`omitInProduction`.

When that happens:

1. Add or adjust backend runtime machinery under `core/lib/registry.nix`.
2. Keep the public runtime ID visible through `clearcutt.fleet.yaml` or the
   built-in CLI runtime contract.
3. Add or update app templates only when the runtime has a supported app-team
   starter.
4. Run `clearcutt runtime validate <runtime-line>`, `clearcutt matrix explain
   <runtime-line>`, and `clearcutt platform status`.
5. Run the fleet build and conformance gates on a Linux builder.

The design rule is simple: app teams use images and templates; fleet owners use
YAML and CLI checks; Nix remains the backend for people changing how the fleet is
compiled.
