# ClearCutt CLI Workspace

This workspace owns the Go `clearcutt` governance CLI.

```bash
cd cli
go test ./...
go vet ./...
go build -o ../clearcutt ./cmd/clearcutt
```

From the repository root, the same operations are available through:

```bash
make cli-test
make cli-vet
make cli-build
```

The CLI defaults to reading generated catalog data from
`site/src/data/catalog` when executed from the repository root. For a quick
offline fixture, pass `--catalog cli/internal/testdata/catalog`.
