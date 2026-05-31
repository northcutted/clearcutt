# Agent Developer Instructions

This document defines the core guidelines, command mappings, and coding standards for all AI agents working in this repository.

---

## 1. Directory Layout & Core Commands

Always navigate to the correct workspace and run the appropriate commands:

| Path | Purpose | Key Commands |
| :--- | :--- | :--- |
| `core/` | Nix image factory, Python remediation tests, Nix gating shell. | `cd core && nix develop`<br>`make core-verify`<br>`make core-remediation-tests` |
| `cli/` | Go governance CLI. | `make cli-build`<br>`make cli-test`<br>`make cli-vet` |
| `site/` | Astro catalog site. | `make site-install`<br>`make site-dev`<br>`make site-build`<br>`make site-typecheck` |

---

## 2. Gating and Verification Protocols

Never finalize a pull request or commit without running the automated local verification checks.

### A. The Go CLI & Ecosystem Gating
Run the unified verification script:
```bash
.claude/skills/test-clearcutt/scripts/verify.sh
```
This script checks Go compilation, format (`gofmt`), unit tests, composite GitHub actions, and schema conformances. **Formatting drift will fail CI**, so `gofmt -l` must return zero output.

### B. Nix & Remediation Gating
To run Nix integration checks (including unprivileged boundaries and CA paths):
```bash
cd core && nix develop --extra-experimental-features "nix-command flakes" --accept-flake-config --command ./tests/verify.sh
```
To run Python remediation unit tests:
```bash
make core-remediation-tests
```

### C. Astro Catalog Site
Building the Astro site requires catalog generation first. Never try to build without generating metadata:
```bash
make catalog-generate
make site-build
```

---

## 3. Go Coding Standards

When writing Go code inside `cli/`:
1. **Error Handling:** Always wrap returned errors with context: `fmt.Errorf("unable to read catalog: %w", err)` rather than returning raw errors.
2. **Formatting:** Always run `gofmt` on all modified files.
3. **Mocks:** When writing unit tests, point `--catalog` at the bundled fixture catalog (`cli/internal/testdata/catalog`) to ensure tests can run completely offline without hitting network paths.
4. **Signatures:** When dealing with signature and attestation verification, ensure strict OIDC issuer and subject checks. Never use wildcard matching patterns in production code paths.
