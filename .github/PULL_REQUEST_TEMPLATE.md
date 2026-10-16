## What & why

<!-- What does this change do, and why is it needed? Link related issues. -->

## Surface

<!-- Which area(s) does this touch? cli / contract / action / docs / workflows / examples -->

## Checklist

- [ ] `make check` passes (vet, gofmt, build, tests with the coverage floor, documented commands, workflow hardening)
- [ ] Docs updated if commands, flags, or output changed
- [ ] Contract schemas regenerated if `cli/internal/report` changed (`go -C cli test ./internal/report -run TestContractSchemasCurrent -update`)
- [ ] `CHANGELOG.md` has an entry under Unreleased for any user-visible change
