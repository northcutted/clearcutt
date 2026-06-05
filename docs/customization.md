# Catalog Site Customization

The generated Astro portal is intended to be branded and deployed by the team
that owns the image fleet. You should not need to edit generated TypeScript or
Astro components for ordinary branding, navigation, feature, terminology, or
link changes.

## Site Config

Create a `clearcutt.site.yaml` file:

```yaml
site:
  title: "Acme Base Image Catalog"
  description: "Verified base images for Acme engineering"
  logo: "./branding/logo.svg"

  theme:
    mode: "dark"
    accent: "#7c3aed"

  navigation:
    showMarketingHome: true
    showGettingStarted: true
    showCliDocs: true
    showAuditGuide: true

  features:
    sbomTable: true
    vulnerabilityTable: true
    layerExplorer: true
    provenance: true
    ociLabels: true
    versionHistory: true
    kyvernoPolicies: false

  terminology:
    distroless: "Hardened runtime"
    slim: "Diagnostic runtime"
    dev: "Builder image"

  links:
    sourceRepo: "https://github.com/acme/base-images"
    registry: "https://ghcr.io/acme/base-images"
    support: "https://internal.example.com/platform-support"
    docs: "https://internal.example.com/base-images"
```

Pass it to scaffold, build, preview, or eject:

```bash
clearcutt catalog site scaffold \
  --catalog ./dist/catalog \
  --site-config ./clearcutt.site.yaml \
  --output ./clearcutt-catalog-site
```

`site.navigation` controls header links for built-in pages. It does not remove
the underlying static routes from the generated site.

## Feature Flags

`site.features` controls large evidence sections:

- `sbomTable`
- `vulnerabilityTable`
- `layerExplorer`
- `provenance`
- `ociLabels`
- `versionHistory`
- `kyvernoPolicies`

Turning a feature off hides that UI section. It does not mutate catalog data.

## Terminology

`site.terminology` changes human-facing tier labels. It does not rename image
IDs, routes, OCI tags, or policy IDs. Those remain `distroless`, `slim`, and
`dev` so automation stays stable.

## Override Roots

Use a `site-overrides/` directory for targeted content changes:

```text
site-overrides/
  components/
    ImageHeader.astro
  pages/
    index.md
    about.md
  styles/
    theme.css
  public/
    branding/
      logo.svg
```

Supported roots map to generated project paths:

| Override root | Destination |
| :--- | :--- |
| `components/` | `src/components/` |
| `pages/` | `src/pages/` |
| `styles/` | `src/styles/` |
| `public/` | `public/` |

Unsupported roots fail fast so a misspelled override does not silently do
nothing.

## Markdown Page Overrides

Markdown and MDX page overrides automatically receive the default
`Base.astro` layout when they do not declare a `layout:` frontmatter field.
When a page override is copied, conflicting `.astro`, `.md`, or `.mdx` routes
with the same path are removed.

Example homepage override:

```markdown
# Acme Base Images

Use these images for application workloads that need signed runtime evidence,
SBOMs, and reviewed vulnerability policy.
```

## Brand Assets

Put static assets under `site-overrides/public/` and reference them from
`clearcutt.site.yaml`:

```text
site-overrides/public/branding/logo.svg
```

```yaml
site:
  logo: "./branding/logo.svg"
```

The generated site serves public assets from the site root.
