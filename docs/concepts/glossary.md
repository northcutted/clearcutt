# ClearCutt Glossary

| Term | Meaning |
| --- | --- |
| Forkable platform kit | A repository a platform team forks and operates under its own registry, workflow identities, policies, and catalog. |
| Reference implementation | The upstream repo demonstrates the pattern and implementation, but downstream owners must validate and operate their own fork. |
| Runtime lane | Platform-owned language base images such as Java, Node.js, Python, Go, .NET, Rust, C/C++, and Core. |
| Service lane | Platform-owned service images such as Postgres, Valkey, and oauth2-proxy. |
| Application image | A downstream app-team image built on, certified against, or rebased onto ClearCutt bases. |
| `dev` tier | Build-time tier with toolchains, shells, and utilities. |
| `slim` tier | Runtime tier with fewer tools than `dev`, but with a shell for diagnostics. |
| `distroless` tier | Runtime tier intended to omit shells and package managers. |
| Catalog | Generated JSON records describing images, releases, evidence, vulnerabilities, tests, and lifecycle state. |
| Evidence portal | Static Astro site that renders generated catalog data and raw evidence links. |
| Evidence channel | One reported proof stream, such as signature, SBOM, provenance, scan, tests, exceptions, or VEX. |
| Missing evidence | A reported gap in a channel. It is not the same thing as failed verification. |
| `verify image` | Catalog policy gate over recorded catalog data. |
| `verify release-evidence` | Registry-side verification path for a published OCI ref. |
| Certification | Local/offline audit of an app image archive against a hardening policy. |
| Conformance | Runtime/container assertions such as UID, CA trust, timezone, and interpreter availability. |
| Rebase | Swap compatible base layers under a preserved app layer, then sign and attest the result when configured. |
| Exception | Time-bounded accepted-risk record for a vulnerability finding. |
| VEX | Machine-readable exploitability statement generated from exceptions and triage state. |
| Preview | Lifecycle status for a catalog image that is visible but not recommended for production by default. |
| Scaffold | Generate starter files for a runtime, service, app template, site, or overlay. |
