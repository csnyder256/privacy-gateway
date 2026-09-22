# Stage 3 contract: integration surfaces

Status: active first-release gate.

This stage is complete only when all automated checks pass and one zero-context
skeptic returns the exact verdict `FAILED TO REFUTE`.

## Included in v0.1

- Synchronous/asynchronous Python and browser/Node TypeScript HTTP clients for
  sessions, transforms, summaries, capsule restoration, and deletion.
- OpenAI Chat Completions/Responses and Anthropic Messages JSON adapters.
- Provider adapters transform only user-controlled prompt text, reuse one gateway
  session per request, restore only client-visible response text, and reject
  surrogate-bearing tool/side-effect arguments.
- Proxy upstreams are operator-configured, never request-selected. Redirects are
  disabled; upstream URLs must use HTTPS except for loopback development.
- Only an explicit header allowlist crosses the proxy boundary. Cookies and
  `x-privacy-*` control headers never reach providers.
- Unsupported endpoints, malformed bodies, oversized bodies, non-JSON provider
  responses, and `stream: true` block before forwarding. Streaming is an explicit
  v0.1 limitation, not a passthrough.
- Generic Python ASGI JSON/text middleware with an injected outbound handler.
- HMAC-SHA-256 signed JSON webhook envelopes with timestamp skew and replay checks.
- The CLI, five named MCP tools, OpenAPI service, Docker, and Compose remain
  executable integration surfaces.

## Acceptance

- Provider path and prompt-shape fixtures; single-session proof; blocked transform
  propagation; response restoration; tool-argument blocking.
- Upstream allowlist, TLS/loopback, redirect, header isolation, body-size, streaming,
  and non-JSON response tests.
- Client error and capsule round-trip tests.
- Middleware text/JSON tests and webhook signature/timestamp/replay tests.
- Exact MCP tool-name source check.
- Full Python/TypeScript regression suites, lint, typecheck, and builds pass.

## Not claimed in v0.1

SSE streaming, OIDC/multi-tenant authorization, PostgreSQL, browser persistence,
and transparent restoration of executable tool arguments are documented roadmap
items. They must block or remain absent; the repository must not claim them.
