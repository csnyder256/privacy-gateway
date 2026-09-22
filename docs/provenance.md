# Implementation provenance ledger

This ledger is append-only once the repository receives its first commit.

## Synthetic subsystem reset — 2026-09-21

- Status: no Stage 4 implementation is approved or present.
- An early untested `src/privacy_gateway/synthetic.py` prototype and its CLI hook
  were created before the clean-room procedure was written and then removed. At
  the 2026-09-21 reset check, the current tree contained no synthetic source, the
  local repository had zero commits and no remotes, and GitHub returned
  repository-not-found for `csnyder256/privacy-gateway`. Those are the bounded,
  reproducible observations; no stronger historical publication claim is required.
  The prototype is not a requirement, fixture, reference behavior, or input.
- The primary implementer inspected SDV's current LICENSE, README, and public docs
  descriptions, but did not use or inspect SDV package implementation files.
- The Stage 0 reviewers do not author Stage 4 implementation.
- The temporary SDV clone is research-only and must be removed before Stage 4.

## Required entries before Stage 4 code

1. Independently authored Privacy Gateway metadata/schema specification.
2. User-story-derived fixtures with documented origin and no upstream fixture lineage.
3. Black-box acceptance tests derived from `PLAN.md`, not SDV APIs.
4. Dependency-license allowlist and CI rejection of `sdv`, `rdt`, and `sdmetrics`.
5. Named implementation files with author, requirements source, dependencies, and
   an attestation that restricted upstream source was not consulted or copied.

No Stage 4 code may be added while this section is incomplete.
