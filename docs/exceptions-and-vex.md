# Vulnerability Exceptions & OpenVEX Compliance

This document explains how the ClearCutt platform manages vulnerability exceptions and dynamically exports standard-compliant OpenVEX documents.

---

## 1. Exception Governance Policy
In enterprise environments, blocking builds on every detected CVE is operationally impractical. Vulnerabilities require governance, not just blockers. 

ClearCutt implements an explicit, schema-validated exception model:
- All exceptions are declared inside an `exceptions.yaml` file conforming to `schemas/exceptions.schema.json`.
- Initialize a boilerplate exceptions configuration template file using the CLI:
  ```bash
  clearcutt exceptions init [output-file]
  ```
- Every exception **must** specify:
  - The target `CVE` ID and package name.
  - An unexpired expiration date (`expiresAt` formatted as `YYYY-MM-DD`).
  - An owner and detailed remediation reasoning (`reason`).
  - Cryptographic references if status is `accepted_risk`.

---

## 2. Dynamic OpenVEX Generation
The `clearcutt vex` command queries exceptions and dynamically outputs OpenVEX (`https://openvex.dev/ns/v0.2.0`) documents:
- Only **active** exceptions are honored; expired ones are ignored so the document never carries a stale `not_affected` claim.
- Maps exceptions onto **valid** OpenVEX statements:
  - `status` is always one of the four spec values: `not_affected`, `affected`, `fixed`, `under_investigation`. Exception statuses without a direct equivalent (`accepted_risk`, `false_positive`) collapse to `not_affected`.
  - `justification` is emitted **only** when `status` is `not_affected` (as the spec requires). Reasons map as: `vulnerable_code_not_present`/`scanner_false_positive` → `vulnerable_code_not_present`; `vulnerable_code_not_executed`/`inherited_from_base` → `vulnerable_code_not_in_execute_path`; everything else → `vulnerable_code_cannot_be_controlled_by_adversary`.

---

## 3. Enforcement in CI Verification
When executing policy gating:
```bash
clearcutt verify image java25-distroless \
  --max-critical 0 --max-high 3 \
  --exceptions exceptions.yaml
```
Supplying `--exceptions` is enough to honour active exceptions — the older `--allow-exceptions` flag is now implied and optional. This deducts all active (non-expired) exempted CVEs from the severity thresholds. An expired exception is **never** applied; with `--fail-on-expired-exceptions` (the default) a matched-but-expired exception additionally raises a dedicated `exceptions.expired` failure, so stale waivers actively break the build rather than silently lapsing. Pass `--fail-on-expired-exceptions=false` to downgrade that to a silent skip.

> Note: exceptions are only evaluated when a threshold is set (`--max-critical` / `--max-high`).
