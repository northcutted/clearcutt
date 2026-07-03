# Embedded platform source archive

This directory is the `//go:embed` root for the reference source archive that
makes a released `clearcutt` binary able to scaffold a fleet repo offline
(`clearcutt platform new`).

- `source.zip` is **generated, not committed** (see `.gitignore`). Regenerate it
  with `go run ./internal/platformsource/internal/genplatformsource` from
  `cli/`, or implicitly via `make cli-build` / `fleet build-cli-assets`.
- This README is committed so the package always compiles from a fresh clone.
  A binary built without `source.zip` reports `ErrNotEmbedded` and
  `platform new` falls back to downloading a release source archive.

The archive's contents are defined by `../rules`; the drift test in
`../source_test.go` asserts the generated archive stays byte-identical to the
live tree.
