# Changelog

All notable changes to this project are recorded here. Versions follow semantic
versioning; while the project is pre-1.0, new backward-compatible features raise the
minor version and fixes raise the patch version.

## Unreleased

### Fixed
- The onboarding page's top bar still said `v0.1`, both on the published site and
  under `privacy-gateway serve`. It now shows the package version, and a test fails
  when the two drift apart. A release's version bump therefore updates the page,
  and the Pages workflow republishes it when the bump reaches `main`. Two
  policy-builder hints no longer name a version either.

## 0.4.0 - 2026-09-25

### Added
- MCP tool annotations. Every MCP tool now declares all four hints as explicit
  booleans: `protect_text` and `protect_json` write to the gateway's own vault
  (`readOnlyHint` false, `destructiveHint` false, `idempotentHint` false), and
  `restore_client_text`, `inspect_policy` and `verify_round_trip` are read-only and
  idempotent. No tool reaches outside the gateway (`openWorldHint` false). Hosts read
  these to decide what to confirm with the user, and without them they assume the
  most cautious reading of every tool. The values are fixed in
  `contracts/compatibility-v1.json` (`adapters.mcp_tool_annotations`), and a test
  holds the tools to them: read-only tools must leave the vault unchanged.

### Changed
- The `[mcp]` extra now needs `mcp>=1.14`. The old `mcp>=1.2` floor was never true:
  releases before 1.14 cannot register this server's tools (they fail on its
  postponed type annotations), and tool annotations need 1.7 or later anyway. CI now
  runs the MCP tests on the floor as well as on the newest 1.x and 2.x.

## 0.3.0 - 2026-09-24

### Changed
- **Breaking (MCP only):** the MCP server now exposes exactly the five tools that
  `docs/normative-contract.md` and `contracts/compatibility-v1.json` name:
  `protect_text`, `protect_json`, `restore_client_text`, `inspect_policy` and
  `verify_round_trip`. `restore_text` and `privacy_summary` are no longer MCP tools. The
  contract forbids exposing side-effect restoration as a generic MCP tool, because an MCP
  client is usually a model, and a tool that turns surrogates back into originals hands it
  what the gateway exists to keep from it. Both remain available over HTTP
  (`POST /v1/restore`, `GET /v1/sessions/{id}/summary`). A test now checks the served tool
  set against the manifest, so the two cannot drift apart again.

### Added
- `protect_json` MCP tool: protects every string inside a JSON value, such as tool
  arguments or a record, and keeps its structure.
- `verify_round_trip` MCP tool: runs the same round-trip, tolerant-token and fail-closed
  probes as `privacy-gateway verify`, against the running gateway's detectors.

### Fixed
- On mcp 2.1 and later, tool failures (an unknown preset, a tampered capsule, an invalid
  policy) reached the client only as "Error executing tool". They now carry the reason,
  as the HTTP API's 422 responses do.
- `privacy-gateway-mcp` without the `[mcp]` extra no longer creates
  `./data/privacy-gateway.db`, or connects to PostgreSQL, before reporting that the extra
  is missing.

## 0.2.1 - 2026-09-23

### Fixed
- `privacy-gateway-mcp` works with the mcp 2.x SDK. The `[mcp]` extra now allows
  `mcp>=1.2,<3`, and on 2.x the server used to exit with "Install the MCP extra" even
  though the extra was installed, because 2.x renamed `FastMCP` to `MCPServer`. Both SDK
  lines are now supported and tested in CI.
- The API reports its version from the package instead of a second hardcoded copy.

### Changed
- The container image is built on Python 3.14 (was 3.12).
- The TypeScript packages build with TypeScript 7.
- CI tests Python 3.11 through 3.14, and the secret scan runs on pull requests again.

## 0.2.0 - 2026-09-22

### Added
- Optional PostgreSQL vault backend. A `postgresql://` database URL now selects
  PostgreSQL instead of the default SQLite file, with no other code changes, via the
  `PRIVACY_GATEWAY_DB` variable or `serve --database`. Install with
  `pip install 'privacy-gateway[postgres]'`. Both backends share the same encrypted,
  expiry-enforcing schema.

### Changed
- Rebuilt the onboarding site (also the GitHub Pages site) with a print-technical
  design: a paper and ink palette with a single signal color, Archivo and Space Mono
  typography, hairline rules, a monospace before-and-after specimen, and a mobile-first
  layout. Removed the per-entity confidence percentage control from the wizard; presets
  still set sensible detection thresholds that the generated policy carries.

### Fixed
- The client capsule restore endpoint now returns a clean 422 when a key or capsule is
  wrong or tampered, instead of a 500 with a stack trace.
- SQLite connections are always closed. Previously they leaked, which also broke the
  `verify` command on Windows during temporary-directory cleanup.
- The CLI `anonymize` command reports the reason and exits non-zero when a policy blocks
  a value, rather than printing nothing.
- Conformance and fixture files are read as UTF-8 on every platform, fixing two test
  failures on Windows.
- The onboarding preview server resolves its static root correctly on Windows.
- Pinned the optional MCP dependency to `mcp>=1.2,<2`, since 2.x removed the API the
  server targets.

## 0.1.0 - 2026-09-22

- Initial release: local-first PII detection, a policy engine with seven per-entity
  actions, encrypted reversible mappings and client-held restoration capsules, OpenAI
  and Anthropic proxies, ASGI middleware, signed webhooks, a CLI, MCP tools, Python and
  TypeScript cores, local synthetic structured data, and the guided onboarding wizard.
