# Vulnerability Exceptions & OpenVEX Compliance

This document explains how the ClearCutt platform manages vulnerability exceptions and dynamically exports standard-compliant OpenVEX documents.

---

## 1. Exception Governance Policy
In enterprise environments, blocking builds on every detected CVE is operationally impractical. Vulnerabilities require governance, not just blockers. 

ClearCutt implements an explicit, schema-validated exception model:
- All exceptions are declared inside an `exceptions.yaml` file conforming to `schemas/exceptions.schema.json`.
- Every exception **must** specify:
  - The target `CVE` ID and package name.
  - An unexpired expiration date (`expiresAt` formatted as `YYYY-MM-DD`).
  - An owner and detailed remediation reasoning (`reason`).
  - Cryptographic references if status is `accepted_risk`.

---

## 2. Dynamic OpenVEX Generation
The `clearcutt vex` command queries exceptions and dynamically outputs OpenVEX (`https://openvex.dev/ns/v0.2.0`) documents:
- Bypasses expired exceptions.
- Maps exceptions to standard OpenVEX statements:
  - `status`: `not_affected`, `under_investigation`, `affected`, or `fixed`.
  - `justification`: maps `vulnerable_code_not_present` to `component_not_present`, `vulnerable_code_not_executed` to `vulnerable_code_not_in_execute_path`, and `accepted_risk` to `vulnerable_code_cannot_be_controlled_by_adversary`.

---

## 3. Enforcement in CI Verification
When executing policy gating:
```bash
clearcutt verify java25-distroless \
  --exceptions exceptions.yaml \
  --allow-exceptions \
  --fail-on-expired-exceptions
```
This deducts all valid, non-expired exempted CVEs from active severity thresholds. Bypassing expired exceptions ensures teams actively review and remediate technical debt.
