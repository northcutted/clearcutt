# Extending ClearCutt Without Learning Nix First

ClearCutt uses Nix to build reproducible runtime closures, but Nix is not the
public configuration model for most users. Treat it as the backend compiler.
The extension surface is layered so teams can choose the smallest tool that
matches the job.

## 1. App Teams: Use Templates And Dev Environments

Application teams should not edit flakes to adopt ClearCutt.

```bash
clearcutt app template java --output examples/my-java-service --name my-java-service
clearcutt --catalog cli/internal/testdata/dev-catalog dev java21-distroless --devcontainer --print
clearcutt --catalog cli/internal/testdata/dev-catalog dev java21-distroless --container --engine docker --command 'java -version'
APP_IMAGE=ghcr.io/acme/my-app:1.0.0
APP_DIGEST=$(docker buildx imagetools inspect "$APP_IMAGE" --format '{{json .Manifest.Digest}}' | tr -d '"')
docker save "$APP_IMAGE" -o my-app.tar
clearcutt certify my-app.tar --base java21-distroless --policy certification-policy.yaml --image-ref "${APP_IMAGE%:*}@${APP_DIGEST}"
```

This path gives teams a Dockerfile, devcontainer, certification policy, release
workflow, and matching dev-tier image without requiring a local Nix install.

## 2. Fleet Owners: Add And Remove Known Runtime Lines

Fork owners extend the supported product surface through `clearcutt.yaml`,
but they do not need to edit the file by hand for common matrix changes:

```bash
clearcutt matrix explain java25
clearcutt matrix add java25
clearcutt matrix remove java25
clearcutt --format json matrix export --source fleet --github-actions --matrix release
clearcutt platform status
```

- `matrix.languages` selects runtime lines such as `java21`, `node22`, or
  `python3.14`.
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
`clearcutt.yaml`, selects it in `matrix.languages` by default, enables a
matching app-template runtime when one is known, and regenerates
`core/lib/runtime-extensions.nix`.

```bash
clearcutt runtime scaffold ruby3.4
clearcutt runtime validate ruby3.4
clearcutt matrix explain ruby3.4
clearcutt app template ruby --config clearcutt.yaml --output examples/my-ruby-service --name my-ruby-service
clearcutt platform status
```

Ruby is the reference scaffold candidate. With no extra flags,
`clearcutt runtime scaffold ruby3.4` derives:

- runtime ID: `ruby3.4`
- language/version: `ruby` / `3.4`
- package candidates: `ruby_3_4`, then `ruby`
- image IDs: `ruby3.4-dev`, `ruby3.4-slim`, `ruby3.4-distroless`
- app-template runtime: `ruby`, enabled in `templates.runtimes` by the scaffold
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
matches the custom runtime lines in `clearcutt.yaml`. Add `--nix` when a
builder has Nix installed and you want a flake eval as part of validation:

```bash
clearcutt runtime validate ruby3.4 --nix --system x86_64-linux
```

## 4. Corporate Base Grafts

When a platform owner must layer a ClearCutt runtime closure onto a mandated
corporate base image, use the flake library helper instead of editing generated
packages directly:

```nix
{
  packages.x86_64-linux.java21-corporate =
    clearcutt.lib.graftOntoBase {
      system = "x86_64-linux";
      fromImage = corporateBaseImage;
      runtime = "java21";
      tier = "slim";
      tag = "corporate";
    };
}
```

`fromImage` should be a `dockerTools.pullImage`-style derivation or another
compatible OCI image derivation. This is a compatibility escape hatch: grafted
images inherit the parent image's shell, package manager, and CVE footprint, so
they do not carry the same zero-utility guarantee as native ClearCutt
`distroless` images.

Verify a graft by comparing the source runtime archive against the grafted archive,
and digest-pinned runtime/grafted refs to emit an offline in-toto
closure-equivalence predicate before promotion.

## 5. Nix Backend Escape Hatch

Most runtime additions should go through `runtime scaffold`. Hand-edit
`core/lib/registry.nix` only when the runtime needs custom closure-shaping logic
that cannot be represented as package candidates, dev packages, and
`omitInProduction`.

When that happens:

1. Add or adjust backend runtime machinery under `core/lib/registry.nix`.
2. Keep the public runtime ID visible through `clearcutt.yaml` or the
   built-in CLI runtime contract.
3. Add or update app templates only when the runtime has a supported app-team
   starter.
4. Run `clearcutt runtime validate <runtime-line>`, `clearcutt matrix explain
   <runtime-line>`, and `clearcutt platform status`.
5. Run the fleet build and conformance gates on a Linux builder.

The design rule is simple: app teams use images and templates; fleet owners use
YAML and CLI checks; Nix remains the backend for people changing how the fleet is
compiled.
