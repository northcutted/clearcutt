# ClearCutt Core Image Workspace

This workspace owns the Nix image factory, runtime overlays, release pipeline,
catalog/remediation scripts, and image conformance tests.

```bash
cd core
nix develop --extra-experimental-features "nix-command flakes"
./pipeline/pipeline.sh --system x86_64-linux coreLTS-slim
python3 -m unittest tests/test_remediation_pipeline.py
```

Catalog scripts live here but write site data into the root `site/` workspace:

```bash
node scripts/gather-catalog.mjs
node scripts/verify-catalog-data.mjs
```

From the repository root, use:

```bash
make core-remediation-tests
make catalog-generate
make core-verify
```
