## What & why

<!-- What does this change do, and why is it needed? Link related issues. -->

## Surface

<!-- Which area(s) does this touch? core / cli / site / docs / workflows / examples -->

## Checklist

- [ ] `go -C cli vet ./...` passes
- [ ] `go -C cli test ./...` passes
- [ ] `go -C cli build -o ../clearcutt ./cmd/clearcutt && ./scripts/validate-doc-commands.sh ./clearcutt` passes
- [ ] Docs updated if commands, flags, or output changed
