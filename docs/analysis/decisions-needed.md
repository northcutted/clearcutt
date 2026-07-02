# ClearCutt Decisions Needed

Date: 2026-06-30

## D1: Product packaging direction

- **Decision:** Should the primary product become a released CLI that scaffolds and operates a standalone fleet repo, with forking the monorepo demoted to contributor/reference mode?
- **Recommended answer:** Yes.
- **Why:** This matches the desired user mental model: a platform engineer downloads `clearcutt`, points it at or asks it to create a GitHub repo, and gets the code, workflows, Nix recipes, catalog, verification, and remediation setup needed to own a base image fleet.
- **Implication:** Keep `platform new` as the released-CLI scaffold path now that it has an embedded source archive, drift guard, and verified released-CLI workflow install action, then prioritize native Go release/remediation engines over new fleet breadth.

## D2: SLSA claim boundary

- **Decision:** What exact SLSA language should the project use?
- **Recommended answer:** "SLSA Build L3 provenance for images published by the configured GitHub Actions release workflow from `refs/heads/main`, when verified against the pinned workflow identity."
- **Why:** The project uses the GitHub SLSA generator and registry-side verification, but the CLI does not itself produce all SLSA evidence independent of Actions.
- **Implication:** Avoid broad "SLSA-compliant" or registry-agnostic SLSA claims until other build engines are proven.

## D3: Registry support posture

- **Decision:** Is GHCR the only fully supported registry for the first serious release?
- **Recommended answer:** Yes. Position GHCR as the reference path. Document other registries as configurable but support-tiered.
- **Why:** The repo defaults to GHCR and GitHub APIs; non-GHCR registries need proof for auth, referrers, GitHub attestations, SLSA verifier compatibility, and catalog enrichment.
- **Implication:** Fix single-source registry config now, but do not promise complete portability before testing a second registry.

## D4: Remediation autonomy

- **Decision:** Should the project market remediation as zero-touch?
- **Recommended answer:** No, not yet.
- **Why:** Current implementation supports weekly scan/report, optional scheduled deterministic draft PRs for evidence-backed recipes, manual bounded AI-assisted patch drafting, aggregate draft PRs, overlay validation, VEX, exceptions, and human review. That is valuable, but not autonomous patching or merging.
- **Implication:** Use "approved remediation PR drafting" as the release-facing phrase. Keep scheduled drafting deterministic-only by default, and keep LLM assistance optional and explicitly untrusted.

## D5: LLM role in remediation

- **Decision:** What should the LLM tier be allowed to do?
- **Recommended answer:** Optional draft assistance only, behind an explicit flag/key, with no merge authority and no credentials beyond what draft generation needs.
- **Why:** Advisory text is prompt-injection capable and model output is untrusted code. The deterministic route and validation gates are the product.
- **Implication:** Continue porting deterministic remediation into Go; scheduled drafting should stay LLM-off, while manual LLM assistance remains explicit and replaceable.

## D6: Service image release policy

- **Decision:** Should preview service images publish by default?
- **Recommended answer:** Either is defensible, but the release policy must be explicit. If the goal is Show HN clarity, publish preview services only when clearly labeled and never imply production approval.
- **Why:** Service images are useful catalog content, but `productionAllowed: false` must not look like production endorsement.
- **Implication:** Add release matrix behavior and docs that align with lifecycle status.

## D7: First-run proof

- **Decision:** What should a new visitor be able to do in 10-15 minutes?
- **Recommended answer:** Install or run the CLI, inspect fixture catalog data, verify catalog policy gates, generate an app template, and build/render a fixture-backed catalog site. Full registry-side release proof should be a second path.
- **Why:** Requiring a registry, fork, Pages setup, and release workflow before seeing value is too much for Show HN.
- **Implication:** Add a demo-local/app path that is honest about what cannot be proven offline.

## D8: Native Go engine sequencing

- **Decision:** Should native Go publish/remediation ports block the CLI-first repositioning?
- **Recommended answer:** They should block the full "self-contained CLI" claim, but not all docs repositioning.
- **Why:** The CLI already owns many release verbs, but still shells into `pipeline.sh` and `cve-draft-agent.py` for important paths.
- **Implication:** Phrase near-term positioning as "CLI-scaffolded, GitHub Actions-oriented fleet ownership"; reserve "fully self-contained released CLI" for after scaffolded workflows install the released CLI and native ports replace remaining shell/Python paths.
