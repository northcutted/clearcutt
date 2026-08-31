# ClearCutt Analysis History

Current readout: ClearCutt has been repositioned from "operate a hardened image
fleet" to "govern container image estates, including ones it did not build". The
CVE remediation subsystem, the shell build engine, and most of the image matrix
were removed in that pass; the fleet that remains is four LTS reference
fixtures. Design docs describing the removed machinery are in
[history/](history/).

The files in [history/](history/) are audit snapshots and owner-review inputs.
They are preserved because they explain earlier credibility risks, action-plan
choices, and validation evidence, but their original blocker language should not
be read as the current branch state.

## Start Here

| File | Use it for |
|---|---|
| [history/post-hardening-readiness.md](history/post-hardening-readiness.md) | Readiness verdict and validation commands from the post-hardening pass. |
| [history/cve-triage-design.md](history/cve-triage-design.md) | The priced-route CVE triage design, removed with the remediation subsystem. Worth reading before rebuilding the idea on `graph`/`import assess`. |
| [history/cli-pivot-plan.md](history/cli-pivot-plan.md) | The Go-port plan that produced the current CLI-owned orchestration. |
| [history/clearcutt-audit.md](history/clearcutt-audit.md) | Historical deep audit of product, trust, docs, CLI, site, and release surfaces. |
| [history/clearcutt-action-plan.md](history/clearcutt-action-plan.md) | Historical audit-derived backlog and phase plan. |
| [history/decisions-needed.md](history/decisions-needed.md) | Historical owner decisions and tradeoffs. |
| [history/critical-path-0-review.md](history/critical-path-0-review.md) | Historical follow-up review of the critical-path polish pass. |

## How To Read These Files

- Treat the historical audit findings as QA process evidence, not as the current
  public story.
- Prefer current source, tests, generated fixture proof, and live release
  evidence over old snapshots when they disagree.
- For a new audit, write a fresh report in `docs/analysis/` and move superseded
  snapshots into `docs/analysis/history/` when the follow-up work lands.
