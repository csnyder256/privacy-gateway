# Changelog

All notable changes to this project are recorded here. Versions follow semantic
versioning; while the project is pre-1.0, new backward-compatible features raise the
minor version and fixes raise the patch version.

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
