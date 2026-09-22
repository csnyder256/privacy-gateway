# Consolidated release contract: onboarding, packaging, and publication

Status: active first-release gate.

Stages 5 through 7 are intentionally one bounded release stage. They receive one automated
release gate and one zero-context refutational review, rather than separate reviewers for UI,
packaging, and publication.

## Included in v0.1

- Responsive five-step wizard: preset, per-entity policy, trust mode/retention,
  false-positive review/live preview, and generated integration.
- All 17 entity types, all seven actions, confidence thresholds, reversibility,
  locale, allow terms, deny terms, and retention are user-controlled.
- Five presets and four honest trust choices: client-held capsule, local encrypted vault,
  self-hosted single-operator network vault, and one-way, with an explicit conversion warning.
- Browser-local preview, generated policy JSON, policy download, and local policy
  draft persistence. Sample/source text is never persisted.
- Executable snippets for Python, TypeScript, Docker, MCP, OpenAI, Anthropic,
  signed webhooks, and structured synthesis.
- Keyboard-native controls, visible focus, labels, live result announcement,
  responsive layouts, and reduced-motion behavior.

## Acceptance

- Static manifest tests prove every preset/entity/action/mode/snippet is present and
  policy output uses the server schema field names.
- Playwright Chromium happy paths verify preset selection, individual edits, trust mode,
  allow/deny review, preview, policy download, persistence, and snippet selection.
- No sample input is written to local storage or included in downloaded policy.
- WCAG-oriented structural checks: language, labels, headings, live region, focus
  styling, reduced motion, and no horizontal clipping at mobile width.
- FastAPI and Pages asset paths both resolve.
- Python lint/format, all Python and TypeScript tests, TypeScript typecheck/build, Python
  sdist/wheel build, CLI verification, example compilation, and shell syntax checks pass.
- The hardened container builds and passes health plus verification probes as a non-root,
  read-only workload on the actual host Docker daemon.
- README, agent guide, security/threat/operations/limitations documents, CI, dependency review,
  release/SBOM automation, Pages workflow, license, contribution files, and issue templates are
  present and internally consistent.
- The profile README and portfolio-site branch diffs describe only implemented behavior and
  carry the exact verified test count.
- Before the release stage is marked done, the repository is published through a review branch,
  GitHub description/homepage/topics are set, Pages and CI complete, profile and portfolio pull
  requests are merged, and the public URLs are checked.

The browser preview is a deterministic demonstration, not a substitute for the
installed detector set; the UI states that distinction.
