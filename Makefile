.PHONY: cli-build cli-test cli-vet site-install site-dev site-build site-typecheck site-verify-catalog core-verify core-remediation-tests catalog-generate test agent-sync

agent-sync:
	bash .agent/sync.sh

cli-build:
	cd cli && go build -o ../clearcutt ./cmd/clearcutt

cli-test:
	cd cli && go test ./...

cli-vet:
	cd cli && go vet ./...

site-install:
	cd site && npm ci

site-dev:
	cd site && npm run dev

site-build:
	cd site && npm run build

site-typecheck:
	cd site && npm run typecheck

site-verify-catalog:
	cd site && npm run verify:catalog

catalog-generate:
	node core/scripts/gather-catalog.mjs

core-verify:
	cd core && nix develop --extra-experimental-features "nix-command flakes" --accept-flake-config --command ./tests/verify.sh

core-remediation-tests:
	cd core && python3 -m unittest tests/test_remediation_pipeline.py

test: cli-vet cli-test site-typecheck site-build core-remediation-tests
