.PHONY: cli-build cli-test cli-vet site-install site-dev site-build site-typecheck site-verify-catalog core-verify core-remediation-tests catalog-generate catalog-enrich catalog-build catalog-scan test agent-sync e2e-test

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

site-verify-catalog: cli-build
	./clearcutt verify catalog --catalog site/src/data/catalog

catalog-generate: cli-build
	./clearcutt catalog gather

catalog-enrich: cli-build
	./clearcutt catalog enrich

catalog-build: cli-build
	./clearcutt catalog build

catalog-scan: cli-build
	./clearcutt scan --mode catalog

core-verify:
	cd core && nix develop --extra-experimental-features "nix-command flakes" --accept-flake-config --command ./tests/verify.sh

core-remediation-tests:
	cd core && python3 -m unittest tests/test_remediation_pipeline.py

e2e-test: cli-build
	bash core/tests/e2e-runtimes.sh $(STACK)

test: cli-vet cli-test site-typecheck site-build core-remediation-tests
