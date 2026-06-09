# ClearCutt CI Triage

Diagnose the failing ClearCutt GitHub Actions run. Do not patch until the root cause is bounded.

Steps:

1. Identify the workflow, job, matrix entry, command, and first meaningful error.
2. Inspect the workflow and local command it maps to.
3. Reproduce locally with the smallest relevant command when possible.
4. Propose a narrow fix and the regression test that should accompany it.
5. If implementation is requested, make only that fix and run the smallest relevant validation.

Never weaken signing, provenance, OIDC identity, catalog validation, vulnerability gates, or policy checks just to make CI green.
