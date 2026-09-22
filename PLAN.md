# Privacy Gateway — Build Contract and Evidence Ledger

## Implementation checkpoint — 2026-09-21

The earlier Stage 0 review process was stopped after it became an unbounded sequence of
fresh architecture reviews. That was a process failure: it expanded the specification
without producing the requested repository. The implementation workflow is now bounded:

1. implement a declared stage against the written contract;
2. run and record its automated checks;
3. run one zero-context refutational review of the built artifacts;
4. fix sustained, concrete findings and re-run the same gate;
5. mark a stage done only on an explicit `FAILED TO REFUTE` verdict.

No fresh reviewer is started merely because wording changed. Stage 0 remains honestly
unclosed because its last review was interrupted; the existing evidence is frozen as
design input while implementation proceeds.

Current implementation state:

- Stage 1 portable text core is **FAILED TO REFUTE** under
  `docs/stage-1-contract.md` as of 2026-09-21.
- Stage 2 client/stream restoration is **FAILED TO REFUTE** under
  `docs/stage-2-contract.md` as of 2026-09-21.
- Stage 3 integration surfaces are **FAILED TO REFUTE** under
  `docs/stage-3-contract.md` as of 2026-09-21.
- Stage 4 structured synthesis is **FAILED TO REFUTE** under
  `docs/stage-4-contract.md` as of 2026-09-21.
- Python: 107 tests passing; Ruff lint and format checks passing.
- TypeScript: 22 tests passing (20 unit/conformance and two real-browser); typecheck and build passing.
- Verified implemented slice: typed 17-entity/seven-action policies and five presets,
  UTF-8 byte offsets, deterministic merge precedence, regex/checksum recognition,
  explicit detector failure blocking, encrypted SQLite reversible mappings, queryable
  decision rows, expiry-on-read/purge, client-held capsules, tolerant tagged-token
  restoration, recursive JSON transformation, and shared Python/TypeScript fixtures.
- Host Docker image build, health, and packaged verification probes pass under an
  unprivileged/read-only runtime. Final release/portfolio publication is still in progress.

The bounded first-release Stage 1 gate is now
[`docs/stage-1-contract.md`](docs/stage-1-contract.md). The older enterprise-hardening list
below is retained as design history and future scope, not as the active first-release gate.

Exact commands last run successfully from the repository root:

```text
PYTHONPATH=src .venv/bin/pytest -q                 # 107 passed
.venv/bin/ruff check src tests                     # All checks passed
.venv/bin/ruff format --check src tests            # 23 files already formatted
npm run check                                      # TypeScript clean
npm test                                           # 20 passed
npm run test:browser                               # 2 passed in Chromium
npm run build                                      # TypeScript build clean
.venv/bin/python -m pip install -e '.[dev]'         # editable package built/installed
.venv/bin/privacy-gateway --help                    # CLI entry point loaded
.venv/bin/privacy-gateway verify                    # five probes true
.venv/bin/python -m build                           # sdist and wheel built
```

### Entry 020 — 2026-09-21 — Stage 1 portable text core

- Active contract: `docs/stage-1-contract.md`.
- First skeptic verdict: `REFUTED` for configurable fail-open detector behavior,
  non-bijective reversible generalization, incomplete TypeScript validation/recognition,
  overbroad/absent token tolerance, and insufficient conformance coverage.
- Same-cycle fixes: unconditional failure blocking; fail-closed policy validation;
  collision-safe reversible surfaces; TypeScript policy/required-detector enforcement;
  IBAN, IPv6, and strict URL validation; bounded ASCII token tolerance in both runtimes;
  shared checksum/Unicode/operator fixtures; database plaintext scans; mapping-expiry tests.
- Follow-up refutations narrowed URL userinfo/ASCII handling and Unicode case folding; both
  runtimes now reject raw authority userinfo, including empty `@`/`:@` forms.
- Final exact verdict from the same reviewer: `VERDICT: FAILED TO REFUTE`.
- Evidence: 32 Python tests and eight TypeScript tests passed; Ruff, TypeScript check/build,
  CLI verification, and Python sdist/wheel build passed. Docker image execution remains
  unverified because no Docker daemon is available in this environment.

### Entry 021 — 2026-09-21 — Stage 2 client and streaming restoration

- Active contract: `docs/stage-2-contract.md`.
- First skeptic verdict: `REFUTED` because reversible composite surrogates were split before
  their tags and JavaScript Unicode case folding accepted forbidden variants.
- Same-cycle fixes: composite-aware tolerant restoration and candidate-prefix buffering in
  Python/TypeScript; explicit ASCII token grammar; exhaustive split-point and Unicode tests.
- Follow-up refutations found a malformed-composite cap bypass, then valid surfaces exceeding
  a fixed cap through maximum email domains and unbounded money literals.
- Final design: 512-character bounded candidate buffer derived above the largest v1 composite;
  128-byte money recognition bound; compact magnitude generalization; maximum-domain and
  malformed-candidate fixtures in both runtimes.
- Final exact verdict: `VERDICT: FAILED TO REFUTE`.
- Evidence: 44 Python tests and 15 TypeScript tests passed; Ruff, TypeScript typecheck, and
  TypeScript build passed.

### Entry 022 — 2026-09-21 — Stage 3 integration surfaces

- Active contract: `docs/stage-3-contract.md`.
- The zero-context skeptic initially refuted incomplete prompt surfaces, malformed provider
  shapes, incomplete side-effect blocking/restoration, async-client parity, ASGI content length,
  webhook JSON validation, proxy boundary coverage, tool descriptions, and session/failure tests.
- Corrections were made against the same bounded reviewer: supported OpenAI/Anthropic text
  surfaces and tools are protected; malformed/streaming shapes block; all non-display response
  types block authenticated surrogates; clients/middleware/webhooks/proxy tests cover the contract.
- Final exact verdict: `VERDICT: FAILED TO REFUTE`.

### Entry 023 — 2026-09-21 — Stage 4 structured synthesis

- Active contract: `docs/stage-4-contract.md`.
- The zero-context skeptic refuted CSV boolean inference, PK/FK constraints, incomplete privacy
  metrics, non-preserved coarse distributions, degenerate reporting, numeric ranges, relationship
  ordering/type integrity, and a raw-value exception path.
- Corrections were made against the same bounded reviewer: inference stores aggregate moments,
  category weights, and null rates; generators enforce format/capacity/range/relation invariants;
  reports validate all-row columns and never echo invalid raw examples.
- Final exact verdict: `VERDICT: FAILED TO REFUTE`.

This file is the durable source of truth for the build. It records the original
inspection findings, research synthesis, promised scope, stage gates, evidence,
and refutational reviews. Nothing is "done" because code exists; a stage is done
only when its acceptance checks pass and a zero-context skeptic fails to refute it.

## Product identity

- Repository: `csnyder256/privacy-gateway`
- Product name: **Privacy Gateway**
- License: MIT
- Description: **Local-first, source-agnostic privacy gateway for reversible PII
  masking, policy-controlled redaction, and synthetic data.**
- Site: `https://csnyder256.github.io/privacy-gateway/`

## Verified starting point: CLM PII proxy

The existing CLM system has a useful starting shape: regex, spaCy, and Presidio
detection; realistic replacements; tenant gating; mapping storage; and
server-side restoration around AI calls.

The new platform must deliberately correct these deficiencies:

- [ ] Replace the on/off switch with per-entity, per-action policy controls.
- [ ] Support client-side restoration instead of requiring server-side restoration.
- [ ] Fail closed when required detection or protection fails.
- [ ] Never silently fall back from encrypted mapping storage to plaintext.
- [ ] Enforce expiry when reading and physically purge expired mappings.
- [ ] Use stable cryptographic derivation, never Python's randomized `hash()`.
- [ ] Prevent replacement collisions and ambiguous reverse mappings.
- [ ] Rescan every input so an existing session still discovers newly introduced PII.
- [ ] Restore altered and streamed surrogates tolerantly and incrementally.
- [ ] Store a queryable record for every classification, confidence, detector,
      policy decision, and transformation—not only an opaque blob and count.
- [ ] Provide granular onboarding and preview/review controls.

### Reverification rule

Before relying on any finding above, Stage 0 must reopen the CLM implementation,
record exact file/line evidence in this ledger, and distinguish implementation
facts from documentation/UI claims. If evidence contradicts a finding, update the
finding rather than forcing the evidence to fit it.

## Research synthesis to preserve

- `daslabhq/pii-proxy`: plausible format-aware surrogates, local detection,
  recursive object traversal, and the goal of reversible mapping. Its current
  collision behavior is not safe enough to adopt; Privacy Gateway must prove its
  own bijection invariant independently.
- `jfreemansh/Anonproxy`: isolated encrypted vaults, consistency rescans,
  tolerant streaming restoration, verification probes, deployment wizard, and
  an explicit threat model.
- `akazah/prompt-anonymizer`: browser/client-side operation, multilingual and
  opt-in policies, allow/deny lists, multiple SDK/UI surfaces, MCP, CI scanning,
  and auditable local behavior.
- `data-privacy-stack/presidio`: pluggable recognizers/operators and text,
  structured-data, and image extensibility.
- `sdv-dev/SDV`: metadata, relationships, constraints, and quality-evaluation
  workflows only.

### License boundary

SDV is Business Source License 1.1 and its Additional Use Grant restricts a
derivative used as a synthetic-data service. Privacy Gateway must not copy,
vendor, import, or derive implementation code from SDV. The synthetic-data
subsystem is a clean-room MIT implementation based only on general workflow
ideas. Stage 0 must reverify this against the current upstream `LICENSE` file.

## Original broad target and v0.1 disposition

This checklist prevents broad research ideas from being silently presented as shipped code.
Checked items are implemented and tested in v0.1. Unchecked items are explicit post-v0.1 work,
are excluded from current product claims, and are repeated in `docs/limitations.md`. The release
does not claim managed-service, PostgreSQL, image/OCR, or additional ML-detector support.

### Policy and detection

- [x] Actions: keep, redact, label, tokenize, hash, generalize, and format-aware synthetic replacement.
- [ ] Per-entity enablement, confidence threshold, reversibility, scope, locale,
      mapping-value retention, mandatory positive detection-audit retention, and
      positive transform-lifecycle audit retention.
- [x] Presets: Balanced, Strict, Healthcare, Finance, and DevSecOps.
- [x] Deterministic regex/checksum floor.
- [x] Allow lists, deny lists, scope lists, and deterministic overlap precedence.
- [x] Presidio adapter.
- [ ] spaCy adapter.
- [ ] Optional GLiNER adapter.
- [ ] Multilingual policy/model selection.
- [ ] Pluggable recognizer and transformation interfaces.
- [ ] Text and recursive structured-data transforms plus tested PNG/JPEG/WebP OCR
      detection, pixel redaction, metadata stripping, and image-adapter extension surface.

### Vault, audit, and restoration

- [x] Client-local mode where original values and restoration map never persist on the gateway.
- [x] Local encrypted gateway mode.
- [ ] Managed tenant-isolated encrypted mode.
- [ ] SQLite default and PostgreSQL support.
- [x] Fail-closed encryption configuration; no plaintext fallback.
- [ ] Queryable sessions, mappings, detections, policy versions, and audit events.
- [ ] Every detection records type, confidence, detector, action, a typed source
      locator (text offsets, JSON Pointer, or raster bounding box/OCR span), keyed
      source/region digest, and policy version.
- [x] Enforced expiry plus tested deletion primitives; adapter-level scheduled and
      manual CLI/API deletion is owned separately by Stage 3. Reports distinguish
      logical expiry, live-row deletion, storage reclamation, and backup expiry.
- [x] Collision-safe bijective mapping within each transform and configured active
      consistency window, with surrogate generations/reservations lasting through
      the later of mapping-value and capsule expiry; expiry tradeoff is explicit.
- [x] Client-side encrypted restoration capsules.
- [x] Exact, bounded tolerant, JSON/tool-argument-aware, and incremental token restoration.
- [x] Round-trip and leakage verification probes.

### Integration surfaces

- [x] FastAPI service and OpenAPI schema.
- [x] Python SDK.
- [x] TypeScript/Node SDK.
- [x] Browser/WebCrypto SDK.
- [x] CLI.
- [x] MCP tools.
- [x] OpenAI-compatible proxy.
- [x] Anthropic-compatible proxy.
- [x] Generic HTTP middleware/adapters.
- [x] Webhook adapter.
- [x] Agent-framework/harness examples.
- [x] Docker and Docker Compose deployment.

### Synthetic structured data

- [x] CSV, JSON, and JSONL.
- [x] Schema inference and explicit metadata schema.
- [x] Primary-key and foreign-key preservation across related tables.
- [x] Constraints and nullability.
- [x] Locale-aware, format-valid generators.
- [x] Deterministic referential mapping.
- [x] Quality report and privacy-risk report.
- [x] Clean-room implementation and documented non-goals/statistical limitations.

### Onboarding and documentation

- [x] Guided wizard: deployment/trust mode → preset → individual entities/actions
      → false-positive review → live preview → retention → generated integration.
- [x] Generated snippets for every supported adapter.
- [x] `AGENT-GUIDE.md` with non-technical interview and executable agent protocol.
- [x] `THREAT-MODEL.md`, `SECURITY.md`, architecture, operations, and limitations.
- [x] Evaluation corpus and leak, collision, expiry, round-trip, and streaming tests.
- [x] CI: lint, unit/integration tests, secret/PII fixture scan, dependency review,
      container build, SBOM, and release workflow.
- [x] Badge-rich README with honest guarantees/non-guarantees.
- [x] GitHub Pages project site source and deployment workflow.
- [ ] Repository description and topics.
- [ ] `csnyder256` profile README entry.
- [ ] `csnyder256.github.io` portfolio entry.

## Stage plan and hard gates

Every stage follows the same protocol:

1. Implement only the stage's declared scope.
2. Run its automated checks and record exact commands/results below.
3. Give a zero-context skeptic only the stage contract and artifacts.
4. Ask the skeptic to actively disprove completeness, security, and test claims.
5. Fix every sustained objection and repeat the review.
6. Mark the stage **failed to refute** only when no material objection remains.

"Passed tests" and "failed to refute" are separate facts. Neither implies
production deployment or security certification.

### Stage 0 — Reverify evidence and freeze architecture

Deliverables:

- Exact CLM file/line evidence for every starting-point claim.
- Current primary-source evidence and license classification for all five repos.
- Architecture decision record, data-flow diagrams, trust modes, threat boundaries,
  scope matrix, normative cross-runtime/security/compatibility contract, and explicit
  non-goals.
- Inventory of portfolio conventions from the target account.

Acceptance:

- Every original claim is confirmed, narrowed, corrected, or rejected with evidence.
- No promised feature lacks an owning stage.
- SDV boundary is explicit enough to guide implementation.

Status: **evidence and architecture drafted — awaiting zero-context refutational review**

### Stage 1 — Core policy, detection, transformation, and vault invariants

Deliverables:

- Typed policy model and all promised actions, presets, per-entity confidence,
  reversibility, scope, locale, retention, allow/deny/scope lists.
- Pluggable detector/operator interfaces and deterministic merge rules.
- Python and TypeScript core engines implementing the same generated policy schema,
  deterministic regex/checksum/scope floor, pure operators, merge rules, surrogate
  grammar, and conformance corpus. Runtime-specific ML adapters may differ only
  where policy explicitly declares equivalent or unavailable capabilities.
- Normative UTF-8 byte-offset translation, pinned Unicode 15.1 origin-mapped match
  view, RFC 8785 canonical bytes, domain-separated digests, integer time/confidence,
  and shared immutable golden vectors.
- Implemented regex/checksum, Presidio, spaCy, and optional GLiNER recognizers,
  with multilingual policy/model selection and explicit required/optional failure modes.
- Text and recursive structured-data transforms plus a PNG/JPEG/WebP image adapter
  with OCR detection, pixel redaction, metadata stripping, and extension interfaces.
- SQLite and PostgreSQL repositories; local encrypted and managed tenant-isolated
  vault modes; encryption, expiry, collision-safe mappings, and queryable audit.
- Tamper-evident exact-expiry audit cohorts that commit every detection row,
  authenticated external monotonic anchor segments, and tenant-scoped versioned
  value/integrity/mapping/policy-key lifecycle plus independent wrapping-key,
  per-anchor-segment encryption-key, and anchor-root lifecycles.
- Versioned AEAD envelopes with unique nonces and row/field/tenant/purpose/expiry
  AAD; separated policy-value/commitment and audit-metadata/integrity/blind-index
  subkeys; encrypted-at-rest queryable audit metadata.
- Role/scope/object authorization primitives and an injected authenticated clock
  with persisted high-water, latched expiry, and fail-closed uncertainty behavior.
- Non-null tenant/application ownership on every Stage-1 session child; only
  opaque IDs/state/expiry/blind indexes remain plaintext in transform/detection/
  audit storage.
- Structured recursive transforms, reversible mapping material, and the bounded
  surrogate grammar with one canonical equivalence enumerator consumed by Stage 2.

Acceptance tests:

- Fail-closed behavior, no plaintext fallback, expiry read/write/purge, collision
  handling, new-PII rescans, deterministic output across processes, audit completeness,
  direct tests of domain `purge_expired` and `delete_session` primitives,
  policy-version/detection/transform mutation or deletion and audit-chain tamper/
  whole-cohort retention tests, canonical policy-digest creation/use/deletion checks,
  exact absolute-expiry constraints, blocked/bypassed/protected transform expiry
  and child-before-parent purge, staggered mapping-identity reuse/expiry,
  both independent retention orderings where a live mapping value or live detection
  keeps its mapping identity,
  retention-bounded remapping, database suffix/rollback,
  crash-after-each-anchor-transition, concurrent-writer recovery,
  multi-cohort transition-group crash/concurrency/deadlock/atomic-visibility tests,
  crash-after-each-whole-segment-purge phase including signed purge-abort and
  next-writer resumption, anchor expiry/purge, anchor-root rotation and compromise-
  marker verification proving an old compromised root alone cannot authorize a
  successor; wrapping-key rewrap/rotation/
  retirement/compromise; segment-key create/wrap/destroy/receipt crash recovery;
  encrypted policy-secret query/reveal/fail-closed behavior, policy-attestation
  renewal/retirement/deletion through last-session expiry, cross-tenant key rejection,
  exact reservation generation/key lineage and extension through the later of
  mapping-value and capsule expiry (including both lifetime orderings),
  allocator/restorer canonicalizer contract tests, wrapper-free reversible synthetic
  format/checksum validation for every entity generator, and value/integrity/mapping/policy-key
  rotation/reservation-aware retirement/suspected-compromise migration/revocation
  tests; image fixtures proving target-region redaction, non-target preservation,
  metadata removal, unsupported-format blocking, and required-OCR failure blocking.
  Image audit fixtures must reconstruct each decision from dimensions, integer
  bounding box, OCR span/digest, and redacted-region digest without storing OCR text.
  The shared Python/TypeScript conformance corpus must prove identical validation,
  decisions, deterministic operators, collision grammar, and blocked states.
  Storage tests prove live-row absence plus SQLite secure-delete/WAL/VACUUM and
  PostgreSQL vacuum-policy execution/configuration; they validate backup-retention
  bounds without mislabeling row absence as forensic media erasure.
  Cross-runtime fixtures additionally prove UTF-8 byte locations for astral/
  combining/expanding casefold text, RFC 8785 record bytes/digests, duplicate-key
  rejection, and integer time/confidence behavior. Crypto tests force nonce
  collision and ciphertext row/field/tenant/purpose/expiry substitution, reject
  cross-purpose subkeys, and scan database/WAL/dump/API defaults for plaintext audit
  classifications. Authorization tests cover every role/scope, cross-tenant object,
  revoked credential, migration/purge/break-glass boundary; clock tests inject exact
  deadline, backward/forward jump, reboot, source loss, excess skew, and DB/anchor
  disagreement.
  Schema tests reject sessions/children without the application composite FK.
  Storage scans prove
  policy digests, event kinds, and scope ingredients are ciphertext while only opaque
  scope digests remain clear. HKDF goldens freeze seed IKM, JCS salt, binary info
  framing, owner/scope enums, legal scope-label tuples, ID encoding, and 32-byte
  outputs; illegal tuples reject. Money fixtures cover every sign, ISO/symbol
  position, grouping, separator, leading-zero, decimal, whitespace, and locale case.
  Clock fixtures reject negative uncertainty/reversed validity, freeze time-authority
  key/nonce/signature encoding, advance process-monotonic time, expire attestations,
  and enforce the PostgreSQL 30-second bound.

Status: **partial implementation exists — not complete, not reviewed**

### Stage 2 — Client capsule and tolerant streaming restoration

Deliverables:

- Browser/Node WebCrypto transform-bound capsule API and Python equivalent.
- One-handoff X25519 recipient keys and exact RFC 9180 gateway-capsule open/binding
  API that atomically re-seals opened mappings under the session seed before
  acknowledgement and then destroys the recipient private key; symmetric client-
  local capsules remain a separate mode.
- Exact RFC 9180 Base-mode profile `0020-0001-0002`, canonical binding/AAD and wire
  JSON, exporter-derived acknowledgement proof, and frozen cross-runtime vector.
- Capability-bound exact/tolerant incremental restorer for text, JSON, tool
  arguments, and streams, consuming the Stage 1 canonicalizer and emitting labeled
  segments until the final adapter authorizes materialization.
- Durable one-use capability store with hashed 256-bit secrets, pinned Ed25519
  application issuers, exact object bindings, revocation, atomic consume/dispatch
  state, and crash recovery.
- In-process local privacy runtimes (`privacy_gateway.local` and
  `@privacy-gateway/local`) composing the Stage 1 Python/TypeScript cores with no
  gateway dependency, no original persisted
  server-side, and a required local audit database (IndexedDB in browsers;
  SQLite in Python/Node).
- Client-local expiry-on-read, opportunistic/background purge, explicit delete,
  and capsule expiry enforcement in browser, Python, and Node stores.
- Client-local root-key creation/storage and HKDF purpose-separated capsule,
  mapping-match/generation, audit-metadata/integrity, value-encryption,
  policy-value/commitment, capability-store-integrity, and project-store subkeys;
  rotation, retirement,
  session deletion/key destruction, and suspected-compromise blocking.
- Queryable local audit parity for every detection/policy decision using the Stage 1
  field contract and a client audit-integrity-keyed chain. The local runtime does
  not claim rollback resistance against an attacker controlling both store and key.
- Active verification command/API that runs adversarial echo, tool-argument,
  capsule, altered-surrogate, and split-stream leakage/round-trip probes.

Acceptance tests:

- Chunk-boundary fuzzing, altered-surrogate fixtures, JSON/tool-call fixtures,
  capsule tamper/wrong-handle rejection, unresolved foreign tags, full tolerant-
  equivalence-domain source/surrogate collisions,
  mapping-expiry reuse, cross-language compatibility, zero stored originals,
  one-time capabilities bound to tenant/application/session/policy/transform/capsule ID, exact
  mapping generation, operation, sink, and JSON Pointer; replay/swap/duplicate and
  same-generation cross-transform attempts blocked even at otherwise authorized paths,
  complete side-effect payload preflight and atomic capability-set consumption
  before any original is materialized; side-effect streaming materialization rejected,
  authorized-client-text replay documented and tested as a residual risk,
  Python/Node/WebCrypto HKDF conformance vectors, cross-purpose key rejection,
  HPKE known-answer/cross-language/wrong-recipient/binding/replay tests, atomic
  local re-seal-before-ack, recipient-private-key destruction, restoration after
  destruction, capsule/session-expiry bounding, and local-store failure blocking,
  plus a malicious-custom-client fixture proving acknowledgement cannot be treated
  as trusted storage attestation,
  unavailable-secure-store blocking, rotation/retirement/deletion/key-destruction
  and compromise tests; local query-field completeness plus row mutation/deletion/
  reorder detection in browser, Python, and Node,
  verification probes that fail when originals leak or restoration breaks, and
  client-store expiry-on-read plus live-record purge/delete tests in all three
  runtimes; Python/Node SQLite secure-delete/WAL/VACUUM evidence; browser IndexedDB
  deletion with forensic reclamation explicitly reported as unavailable.
  Capability tests include issuer revocation, forged/wrong-tenant/wrong-application
  grants, mixed transform/capsule/generation/issuer associations, compare-and-set
  races, full dispatch-intent/capability composite-scope enforcement, crash before/
  after dispatch, idempotent recovery, and indeterminate
  dispatch blocking.
  The Stage 1 canonicalizer fixtures must cover every exact accepted/rejected phone,
  card, SSN, IBAN, routing, ASCII email, locale date, and locale money surface.
  Tagged-token fixtures freeze exact/tolerant grammar, base32 lengths, HMAC input/
  truncation, constant-time failure, and SSE-scanner parity. Capsule vectors include
  every sorted mapping-entry byte and request-nonce/expected-proof-digest framing.
  Handoff deletion must leave the durable capsule identity and live capability
  associations intact through capsule expiry.

Status: **not started**

### Stage 3 — Service, SDKs, proxies, middleware, MCP, and webhooks

Deliverables:

- API plus network gateway clients (`privacy_gateway.client` and
  `@privacy-gateway/client`), browser facade, and CLI. Network packages may
  re-export Stage 1 core or Stage 2 local-runtime APIs but cannot reimplement them.
- OpenAI/Anthropic proxies, generic middleware, webhook adapter, MCP, agent examples.
- The exact first-release adapter manifest in `docs/normative-contract.md`: OpenAI
  Responses/Chat Completions JSON+SSE, Anthropic Messages JSON+SSE, Python ASGI and
  TypeScript Fetch JSON/text middleware, signed JSON webhooks, and the five named
  MCP tools; unsupported body/protocol shapes block.
- Direct-to-provider adapters that compose Stage 2 local runtimes without a gateway,
  keep provider credentials outside capsules/audit, bind responses to transform
  handles, enforce configured provider allowlists, TLS, and no redirects.
- Authenticated two-step gateway transform/capsule handoff: bind client recipient
  public key to tenant/application/session/policy/request, return and acknowledge an openable
  capsule before downstream send, erase plaintext handoff state, and block on any
  seal/open/ack failure. Transparent proxies use gateway-owned restoration.
- Auth, tenant isolation, request limits, SSRF boundary, streaming backpressure.
- OIDC JWT/workload enforcement for the frozen issuer/audience/tenant/application/subject/time/
  JTI/scopes contract, with per-operation role checks and credential revocation.
- Manual gateway-vault deletion through CLI/API plus the scheduled gateway purge
  worker that calls Stage 1 deletion primitives. Client-local background/manual
  cleanup remains wholly inside Stage 2 SDK runtimes.

Acceptance tests:

- Provider fixture compatibility, streaming integration, tenant isolation,
  failure propagation, recursive structured payloads, auth/security tests, and
  end-to-end gateway-vault scheduled/manual deletion through CLI/API adapters;
  gateway-bypass credential/header isolation, redirect rejection, egress allowlist,
  request/handle pairing, body-limit, and streaming-backpressure tests; two-step
  capsule-before-send ordering, plaintext-handoff erasure, failure blocking, and
  proof that transparent proxy mode never claims client-owned restore and blocks
  surrogate-bearing tool/side-effect fields while restoring client-visible text only.
  Dated provider fixture manifests, SSE chunk permutations, unsupported endpoint/
  body blocking, JWT claim/scope/revocation/cross-tenant tests, webhook signature/
  timestamp/delivery replay tests, and exact MCP tool-surface tests are mandatory.
  PGPath wildcard/object rejection, every named provider SSE delta/terminal/error,
  unknown-event surrogate blocking, multiline data, premature EOF, and event-size
  limits are explicit fixtures.
  Webhook vectors freeze all header names, timestamp/UUID encodings, signed bytes,
  hex signature, exclusive boundary, absolute delivery-retention deadline, and key
  rotation.

Status: **FAILED TO REFUTE for the bounded v0.1 contract in `docs/stage-3-contract.md`**

### Stage 4 — Clean-room structured synthetic data

Deliverables:

- CSV/JSON/JSONL ingestion and emission; schema inference with ambiguous-type
  diagnostics and explicit overrides; metadata model, multi-table relationships,
  constraints, locales, generators, quality report, privacy-risk report.
- Privacy-risk report implements the frozen quasi-identifier attacker model,
  exact-match/uniqueness, k-anonymity, l-diversity, train/holdout DCR, and nearest-
  neighbor distance-ratio metrics and default warning thresholds.
- Local-only execution boundary: no gateway/network/telemetry path, streaming input,
  encrypted owner-only spill through the Stage 2 Python profile-root API when
  required, fail-closed memory bounds when secure spill keys are unavailable,
  explicit output paths, and sensitive metadata/report handling without raw example
  values by default. Saved project stores use a random project seed wrapped by the
  Stage 2 profile root; explicit plaintext export is a separate warned and audited
  action.

Acceptance tests:

- Inference golden files and override fixtures; PK uniqueness, FK integrity,
  constraints, determinism, format validity, missingness/type preservation,
  report fixtures, license/code-origin audit; network-denial, original-value log/
  report scan, crash/cancel spill cleanup, no-gateway-write, unavailable-spill-key
  blocking above the memory limit, explicit-output tests, project-store ciphertext
  inspection, decrypt/rewrap/delete coverage, secure-root-unavailable persistence
  failure, and warned/audited explicit plaintext export.
  Hand-computed metric goldens, small/degenerate `not_evaluable` cases, threshold
  warning/CI failure, and adversarial memorization fixtures are required.
  Goldens cover nulls, zero-range numbers, date normalization, categorical mismatch,
  exact-match denominators, DCR ties, all zero-denominator ratio branches,
  k quasi-identifier tuple grouping, per-sensitive-attribute l-diversity, and non-key
  cell-copy denominators.
  An explicitly empty evaluation-column list yields `not_evaluable`, never division
  by zero or a passing result.

Status: **FAILED TO REFUTE for the bounded v0.1 contract in `docs/stage-4-contract.md`**

### Stage 5 — Guided onboarding UI

Deliverables:

- Complete wizard, live preview, false-positive review, policy editor, trust-mode
  selector, retention controls, generated adapter snippets, accessible responsive UI.

Acceptance tests:

- Browser happy paths for every preset and trust mode, keyboard/accessibility checks,
  persisted policy round-trip, dangerous configuration warnings, and a manifest
  test proving every supported adapter has a generated, executable snippet.

Status: **implemented and browser-verified — included in the consolidated release review**

### Stage 6 — Security, operations, documentation, and release engineering

Deliverables:

- Agent guide, threat model, security policy, architecture/ops/limitations docs,
  Docker/Compose, CI, fixture scanning, SBOM, release automation, evaluation corpus.

Acceptance tests:

- Fresh-machine setup, container health, documented workflows, CI parity,
  secret scan, dependency audit, agent-guide dry run from zero context, and the
  packaged Stage 2 verification suite run against local/container deployments.

Status: **not started**

### Stage 7 — Portfolio and GitHub publication

Deliverables:

- Fancy README, Pages site, topics/description/homepage, profile README entry,
  portfolio-site entry, screenshots/OG asset, tagged release.

Acceptance:

- All repository checks green.
- Links, install snippets, Pages deployment, and package/container instructions verified.
- Existing portfolio repositories updated through their required PR workflow.
- Publication state recorded separately from deployment/site health.

Status: **not started**

## Evidence and refutational review log

Append entries; do not rewrite history. Each entry must include UTC timestamp,
stage, commands/sources, result, skeptic objections, corrections, and final verdict.

### Entry 000 — 2026-09-21 — Build contract created

- Reason: implementation began before the original scope was written down.
- Existing code at this point: package metadata; policy/preset model; regex and
  optional Presidio detector; AES-GCM helpers; SQLite tables; text transform;
  client-capsule emission; a basic API/CLI/MCP skeleton; and a small single-table
  synthetic prototype.
- This code has not yet been installed, tested, threat-reviewed, or refutationally
  reviewed. It does not satisfy any completed stage.
- Verdict: **not done**.

### Entry 001 — 2026-09-21 — Stage 0 direct reverification

- CLM source inspected at `c52d594ddc2e16c0cbbf06a58a888b8c9e747868`.
- Five upstream repositories shallow-cloned and inspected at the exact revisions
  recorded in `docs/research-verification.md`; their license files were read directly.
- Portfolio profile/site and local portfolio conventions were inspected directly.
- Two original claims were corrected: CLM encryption is conditional with a plaintext
  fallback, and its declared source priority is unused dead code.
- Architecture, trust modes, fail-closed contract, persistence model, scope ownership,
  and non-goals are recorded in `docs/architecture.md`.
- Automated checks: documentation-only stage; link/file validation still pending.
- Skeptic verdict: **pending**.

### Entry 002 — 2026-09-21 — Stage 0 refutation round 1

- Reviewer context: fresh agent with no conversation history; read-only instructions.
- Verdict: **REFUTED**.
- Sustained objections:
  1. `pii-proxy` claims a bijection, but its map/generator can overwrite a reverse
     entry after collisions; the research summary overstated implementation safety.
  2. CLM handles missing spaCy gracefully at import, but spaCy inference failure
     escapes and produces fail-open behavior in integration wrappers.
  3. Detector implementations, multilingual support, PostgreSQL, local/managed
     vaults, CLI, and CSV/JSON/JSONL lacked explicit stage ownership.
  4. “Every detection is audited” conflicted with optional gateway metadata and
     policy-conditional audit failure.
  5. The persistence list lacked tenant/session foreign keys and mapping identity.
  6. The SDV rule lacked a concrete clean-room process.
  7. Portfolio conventions were asserted without an enumerated revision inventory.
  8. The required scope matrix and concrete threat-boundary artifact were absent.
- Corrections: recorded in the revised Stage 0 artifacts and scope assignments.
- Rereview verdict: **pending fresh zero-context review**.

### Entry 003 — 2026-09-21 — Stage 0 refutation round 2

- Reviewer context: second fresh agent with no prior review or conversation history.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. Per-entity retention could not be represented. Mappings/detections now own
     `expires_at`; session expiry is the cap; reads and purge rules are explicit.
  2. Reverse uniqueness was per entity and allowed mixed-entity collisions. It is
     now unique on `(session_id, replacement)` across entity types.
  3. Client metadata crossed the boundary without a schema and was incorrectly
     called non-sensitive. Default transmission is now none; the opt-in aggregate
     schema is allowlisted and still classified sensitive.
  4. Active leak/round-trip probes lacked ownership. Stage 2 implements them and
     Stage 6 reruns the packaged probes against deployable artifacts.
  5. The portfolio inventory omitted root-level Pages. All ten projects currently
     listed in the target profile are now inventoried, including the alternate
     root `index.html` convention.
- Rereview verdict: **pending third fresh zero-context review**.

### Entry 004 — 2026-09-21 — Stage 0 refutation round 3

- Reviewer context: third fresh agent with no prior review or conversation history.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. Exact restoration had two owners. Stage 1 now owns reversible mapping material;
     Stage 2 solely owns exact and tolerant restoration implementations.
  2. Scheduled/manual deletion and adapter-snippet completeness lacked acceptance
     checks. Both now have explicit executable gates in their owning stages.
  3. Zero retention contradicted mandatory detection audit. Mapping-value retention
     and positive audit retention are now distinct policy fields.
  4. Policy versions lacked tenant ownership. Every effective policy/version is now
     tenant-owned; built-in presets are materialized before use.
  5. Audit/telemetry expiry and purge were undefined. Both stores now have hard
     expiry fields, read filters, and physical deletion ownership.
- Rereview verdict: **pending fourth fresh zero-context review**.

### Entry 005 — 2026-09-21 — Stage 0 refutation round 4

- Reviewer context: fourth fresh agent with no prior review or conversation history.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. Stage 1 deletion tests depended on Stage 3 CLI/API. Stage 1 now owns only
     deletion semantics/primitives; Stage 3 owns CLI/API/scheduler exposure.
  2. Client-local stores lacked expiry, purge, and explicit-delete ownership.
     Stage 2 now implements/tests these in browser, Python, and Node.
  3. Tenant/session child rows could cross-reference other tenants. Composite
     foreign keys now align mappings, detections, audit events, and mapping refs.
  4. Client-local transport both forbade and required a session ID. It is now
     tenant-authenticated and request/idempotency-bound but carries no restoration
     or local audit session identifier; gateway-vault modes bind a gateway session.
- Rereview verdict: **pending fifth fresh zero-context review**.

### Entry 006 — 2026-09-21 — Stage 0 refutation round 5

- Reviewer context: fifth fresh agent with no prior review or conversation history.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. Detection retention could outlive a composite-referenced mapping value.
     Mapping identity and sensitive mapping value are now separate tables; the
     value expires physically while the non-value identity can satisfy audit refs.
  2. Composite parent uniqueness and detection policy alignment were incomplete.
     Parent unique keys and composite child references are now explicit.
  3. A gateway scheduler cannot purge remote client stores. Stage 2 owns all local
     background/manual cleanup; Stage 3 schedules only gateway-vault deletion.
  4. Audit append integrity and key rotation lacked ownership. Stage 1 now owns
     tamper-evident chains, key IDs, rotation, retirement, and their tests.
- Rereview verdict: **pending sixth fresh zero-context review**.

### Entry 007 — 2026-09-21 — Stage 0 refutation round 6

- Reviewer context: sixth fresh agent with no prior review or conversation history.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. Entity alignment was absent from mapping composites. Entity is now present in
     value rows and all identity/value/detection composite references.
  2. A reused identity could expire before a later detection. Reuse extends its
     audit expiry transactionally; purge requires no unexpired references.
  3. Audit prefix expiry broke hash-chain verification and integrity keys lacked a
     lifecycle. Signed retention checkpoints and separately retained verify keys
     now make authorized prefix deletion distinguishable and testable.
  4. Stage 2 local stores overlapped Stage 3 SDK ownership. Stage 2 owns in-process
     privacy runtimes/core; Stage 3 owns network gateway clients and facades.
  5. A synthetic prototype existed before the clean-room process. It was removed
     before testing, commit, or publication; Stage 4 now begins with only the
     independent specification/provenance contract and no implementation.
- Rereview verdict: **pending seventh fresh zero-context review**.

### Entry 008 — 2026-09-21 — Stage 0 refutation round 7

- Reviewer context: seventh fresh agent with no prior review or conversation history.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. Policy/policy-version composite parent keys were implicit. Both now declare
     portable `(id, tenant_id)` uniqueness and the exact composite references.
  2. One global audit chain could suffer interior expiry gaps under per-entity
     retention. Chains are now scoped by immutable policy/entity/retention class,
     making expiry prefix-ordered and checkpoint-verifiable.
  3. Stage 4 status still said a prototype existed. It now states not started and
     gated. At correction time the local repository had zero commits, no remotes,
     no `synthetic.py`, and GitHub returned repository-not-found for
     `csnyder256/privacy-gateway`; these facts establish current non-publication,
     without claiming an externally provable history beyond those observations.
- Rereview verdict: **pending eighth fresh zero-context review**.

### Entry 009 — 2026-09-21 — Stage 0 refutation round 8

- Reviewer context: eighth fresh agent with no prior review or conversation history.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. Session-wide stable bijection contradicted zero/expired mapping retention.
     Stability is now explicitly per transform and within the active retention
     window; capsules define the restoration lifetime after value expiry.
  2. Checkpoints retained classification metadata too long and lacked schema/purge
     guarantees. They now store an opaque scope digest, use composite tenancy,
     expire with the retained chain, and are included in schema/deletion gates.
  3. Stable-mapping HMAC keys lacked a lifecycle. Sessions pin a tenant mapping key;
     rotation affects new sessions, retirement waits for live sessions, and
     compromise revocation blocks affected sessions instead of inventing continuity.
- Rereview verdict: **pending ninth fresh zero-context review**.

### Entry 010 — 2026-09-21 — Stage 0 refutation round 9

- Reviewer context: ninth fresh agent with no prior review or conversation history.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. A database rollback could remove a valid audit suffix. Audit heads are now
     compared to an authenticated monotonic anchor in a separate persistence domain,
     with write-ahead/finalize crash recovery and rollback/truncation tests.
  2. Checkpoint expiry lacked explicit fields. Checkpoints now declare expiry and
     retained-event boundary fields plus composite tenant/session references.
  3. Key registries and value/integrity compromise behavior were incomplete.
     A tenant-scoped key registry, composite references, and honest per-purpose
     compromise/revocation semantics are now frozen.
  4. Retention-bounded remapping could conflict with an older capsule or ordinary
     source literal. Capsules and reversible surrogate IDs are transform-bound;
     allocation rejects source collisions and mixed/wrong capsules fail authentication.
- Rereview verdict: **pending tenth fresh zero-context review**.

### Entry 011 — 2026-09-21 — Stage 0 refutation round 10

- Reviewer context: tenth fresh agent with no prior review or conversation history.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. A capsule cannot authenticate a later downstream response. The contract now
     authenticates capsule state/transform handles only and surfaces foreign tags;
     it makes no response-provenance claim.
  2. Exact-only collision checks conflicted with tolerant restoration. Allocation
     now rejects intersections across the restorer's complete bounded equivalence set.
  3. Revoked value-key migration was impossible. A narrow audited
     `compromised_migrating` state precedes irreversible revocation/deletion.
  4. Anchors lacked expiry and key-retention rules. They now expire/purge with their
     audit scope and keep integrity verify keys live only as long as referenced.
  5. The anchor transaction was underspecified. The single-writer pending/DB/final
     protocol, schemas, CAS, recovery decisions, and crash/race tests are explicit.
- Rereview verdict: **pending eleventh fresh zero-context review**.

### Entry 012 — 2026-09-21 — Stage 0 refutation round 11

- Reviewer context: eleventh fresh agent with no prior review or conversation history.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. An append-only anchor journal contradicted deletion of individual expired
     records. Anchors are now per-retention-scope encrypted segments, deleted only
     as a whole through a five-phase purge protocol with explicit crash recovery.
  2. Reused mappings lacked exact reservation lineage and capsule-expiry extension.
     Reservations now pin mapping/generation/mapping-key IDs and extend
     transactionally through the latest issued capsule expiry.
  3. A compromised integrity key could forge its own compromise marker. External
     transitions and markers are now signed by an independently controlled anchor
     root, with dual-signed rotation and an explicit break-glass discontinuity.
  4. A valid transform handle could be replayed into a dangerous output sink.
     Capsules now authenticate allowed sink classes/JSON Pointer paths; restoration
     remains labeled until the final adapter authorizes materialization, and the
     default is client-visible text only.
  5. Stage 1 collision tests depended on Stage 2's restorer. Stage 1 now owns the
     bounded surrogate grammar and canonical equivalence enumerator; Stage 2 must
     consume the same implementation.
- Rereview verdict: **pending twelfth fresh zero-context review**.

### Entry 013 — 2026-09-21 — Stage 0 refutation round 12

- Reviewer context: twelfth fresh agent with no prior review or conversation history.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. Client-local mode falsely promised that no originals cross the gateway despite
     `keep`, out-of-policy data, and missed detections. The guarantee is now limited
     to detected values assigned a protecting action; all three pass-through cases
     are explicit in the architecture and threat boundary.
  2. Duration-keyed audit scopes could not have one absolute anchor-segment expiry.
     Chains now use per-transform, per-entity exact-expiry cohorts; every row/head/
     segment shares one constrained absolute deadline and purges as a whole.
  3. Capsule expiry could outlive the session, and zero mapping retention could be
     paired with impossible gateway restoration. Capsules are now capped by session
     expiry; policy validation allows zero retention only with client-owned restore.
  4. Sink/path allowlists still allowed a malicious provider to swap originals at
     an authorized side-effecting path. Side effects now require a pre-issued,
     one-time capability bound to exact mapping generation, operation, sink, and
     path; broad grants are invalid and replay/swap/duplicate tests are mandatory.
  5. Queryable detections were not committed by the audit chain. Every immutable
     detection is now inserted transactionally with an event containing its
     composite reference and canonical row digest; verified reads recompute both.
  6. Schema inference lacked an owner. Stage 4 now explicitly owns inference,
     ambiguity diagnostics, overrides, golden files, and fixtures.
  7. Several research statements lacked exact/reproducible evidence. CLM restoration
     call sites and scoped search commands/results are now recorded, and Presidio's
     recognizer/operator/text/structured/image claims cite exact primary-source lines.
- Automated evidence checks: upstream revisions were re-read with `git rev-parse`;
  all six Stage 0 artifacts passed non-empty file checks; `git diff --check` passed.
- Rereview verdict: **pending thirteenth fresh zero-context review**.

### Entry 014 — 2026-09-21 — Stage 0 refutation round 13

- Reviewer context: thirteenth fresh agent with no prior review or conversation
  history; the reviewer repeatedly re-read the corrected artifacts before issuing
  the final verdict.
- Initial verdict: **REFUTED**.
- Sustained objections and corrections:
  1. Local key ownership was ambiguous. A profile wrapping root now wraps random
     per-session, per-policy-version, and project-store seeds; deletion, rotation,
     purpose separation, compromise quarantine, and unrelated-session behavior are
     explicit.
  2. Surrogate generations, reservations, mapping identity liveness, and capsule
     lifetime had conflicting cardinality/expiry rules. Parent generations and
     per-equivalence reservations now have exact transactional uniqueness, lineage,
     lifetime, collision, and reuse invariants.
  3. Audit integrity lacked complete transform/detection commitments, multi-scope
     atomicity, portable locking, honest purge/reclamation semantics, and recoverable
     external-anchor states. The architecture now defines row digests, group
     manifests, SQLite/PostgreSQL locks, exact logical expiry, runtime-specific
     reclamation evidence, signed `purge_abort`, and next-writer recovery.
  4. Root, wrapping, segment, tenant-purpose, and policy-key lifecycles were
     incomplete. Routine and compromise rotations, break-glass authority, rewrap,
     destruction receipts, revocation, quarantine, and tests now have separate
     contracts; a compromised old anchor root cannot authorize its successor.
  5. Policy-secret persistence and sessionless policy audit were missing. Encrypted
     secret storage, canonical public digests plus keyed commitments, attestation,
     renewal/retirement/deletion, immutable policy audit tables, and fail-closed
     restart/rotation behavior are now Stage 1/2 gates.
  6. Image support, direct-to-provider mode, transparent-proxy behavior, and
     side-effect restoration were underspecified. First-release raster formats,
     OCR/pixel/metadata evidence, direct adapters, text-only proxy restore, full
     side-effect preflight, exact one-time capabilities, and atomic dispatch are
     now bounded and tested.
  7. Gateway-to-client capsule handoff lacked durable client key/state ownership.
     The official SDK now atomically re-seals under the session seed before ack and
     destroys its one-handoff X25519 private key. The documentation explicitly says
     ack proves capsule opening, not trusted durable-storage attestation; a custom
     client can lie and lose its own restore state.
  8. Structured synthesis could leak through spill, reports, project storage, or
     implicit output. It is now Python-local-only with network/gateway/telemetry
     denial, encrypted spill/project stores, profile-root ownership, ciphertext/
     rewrap/delete/failure tests, and separate warned/audited plaintext export.
  9. Research evidence had citation and search-scope gaps. Exact upstream revisions,
     primary-source line references, the SDV clean-room boundary, and a reproducible
     full-tree CLM mapping-expiry search are recorded.
- Stable-artifact final verdict: **FAILED TO REFUTE**.
- Confirmation verdict: **pending one fresh zero-context review of the frozen
  artifacts**.

### Entry 015 — 2026-09-21 — Stage 0 refutation round 14

- Reviewer context: fourteenth fresh agent with no prior review or conversation
  history, reviewing the stable round-13 artifacts read-only.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. Cross-runtime Unicode spans and canonical digest bytes were not normative.
     `docs/normative-contract.md` now requires well-formed UTF-8, original byte
     offsets, a pinned Unicode 15.1 origin-mapped match view, RFC 8785 canonical
     records, integer time/confidence, domain separation, and immutable shared
     vectors.
  2. Vault cryptography omitted envelope/AAD/nonce invariants and reused policy key
     material across encryption and commitments. The contract now freezes a
     versioned AES-256-GCM envelope, nonce uniqueness, full row/field/scope/expiry
     AAD, and HKDF-separated encryption, match, integrity, blind-index, capsule,
     capability, and project-store keys with substitution/nonce tests.
  3. Sensitive detection/audit metadata was queryable but not confidential. It is
     now AEAD ciphertext at rest with separate keyed blind indexes, authorized
     in-boundary query decryption, no free-text search, and database/WAL/dump/API
     plaintext scans.
  4. Privileged operations named authorities without defining them. The normative
     role/scope table, OIDC/workload credential claims, object/tenant checks,
     revocation, offline two-person break-glass process, pinned application issuer,
     and durable atomic capability state now give Stage 1-3 concrete ownership and
     negative-test oracles.
  5. Exact expiry ignored clock rollback, skew, and authority. Integer UTC deadlines,
     authenticated time, 30-second uncertainty, persisted high-water marks, latched
     expiry, local offline limitations, reversible fail-closed behavior, and injected
     clock/reboot/disagreement tests are now frozen.
  6. Entity/action/preset/locale/precedence/tolerance and provider compatibility
     claims lacked objective boundaries. The first-release catalogs, matrices,
     precedence, finite tolerant grammar, exact OpenAI/Anthropic endpoint surfaces,
     ASGI/Fetch middleware, webhook protocol, and MCP tools are now normative.
  7. The synthesis privacy-risk report had no metric or attacker model. It now fixes
     quasi-identifier knowledge, exact matches, k-anonymity, l-diversity, train/
     holdout DCR, nearest-neighbor ratio, thresholds, degenerate behavior, goldens,
     and explicit no-anonymity/no-DP interpretation.
- Rereview verdict: **pending fifteenth fresh zero-context review**.

### Entry 016 — 2026-09-21 — Stage 0 refutation round 15

- Reviewer context: fifteenth fresh agent with no prior review or conversation
  history, reviewing the stable round-14 artifacts read-only.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. Mapping identities could be deleted while a longer-lived mapping value still
     referenced them. Liveness now derives from both verified detections and the
     live mapping value, with both independent retention orderings tested.
  2. Tenant authorization did not distinguish applications. Every session child,
     transform, lookup, and capability now carries and composite-binds non-null
     `application_id`; same-tenant cross-application denial is mandatory.
  3. Transform metadata contradicted the encrypted-audit boundary. Source kind/
     digest, policy digest, timestamps, and reason are now inside the AEAD metadata
     envelope; only opaque IDs, state, expiry, and approved blind indexes are clear.
  4. Blind indexes lacked a derivation label. `audit-blind-index` is now a distinct
     normative HKDF label and machine-manifest entry.
  5. Gateway capsules lacked an interoperable cryptographic profile. The contract
     now fixes RFC 9180 Base mode, suite `0020-0001-0002`, encodings, info, JCS AAD/
     wire/plaintext, exporter context, acknowledgement HMAC, and shared vectors.
  6. Healthcare prose and JSON differed. The manifest now includes every named
     financial/government/license redaction and explicit reversible synthetic
     PERSON/LOCATION/DATE_TIME overrides.
  7. Synthetic equivalence canonicalizers were vague. Exact accepted punctuation,
     validation, locale formats, ambiguity rejection, and canonical output now cover
     phone/card/SSN/IBAN/routing/email/date/money; reservation hashes canonical form.
  8. Adapter wildcards and SSE were not executable. PGPath-v1 now defines `*`,
     escaping/order, and duplicate-key behavior; each provider freezes delta,
     terminal, error, unknown-event, multiline, size, and EOF semantics.
  9. Privacy-risk metric names lacked math. Exact denominators, type/null distance,
     ranges, aggregation, DCR ties, zero ratios, k/l grouping, cell-copy rate, and
     precise `not_evaluable` conditions now have hand-computable definitions.
- Rereview verdict: **pending sixteenth fresh zero-context review**.

### Entry 017 — 2026-09-21 — Stage 0 refutation round 16

- Reviewer context: sixteenth fresh agent with no prior review or conversation
  history, reviewing the stable round-15 artifacts read-only.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. Application ownership lacked complete relational enforcement. Sessions now
     reference `(application_id, tenant_id)`; every child carries the composite; an
     exact transform/capsule/generation association and issuer composite FK prevents
     mixed-object capabilities.
  2. Policy digests, event kinds, and cohort scopes leaked outside ciphertext. They
     now reside in audit-metadata AEAD; clear heads/events carry only a keyed opaque
     scope digest plus allowed ID/state/expiry fields.
  3. HKDF had labels but no derivation bytes. The contract now fixes 32-byte random
     seed IKM, RFC 8785 SHA-256 salt, binary versioned info framing, UTF-8 ID rules,
     SHA-256 extract/expand, 32-byte outputs, and separates independently generated
     Ed25519 issuer keys from `capability-store-integrity`.
  4. Capsule mapping plaintext and stored expected proof were undefined. The sorted
     entry schema, encodings, canonicalizer verification, per-entry expiry, ack nonce,
     and domain-separated SHA-256 expected-proof storage are now exact.
  5. Optional reversibility left presets ambiguous. Tokenize is always reversible;
     generalize/synthetic default false; only explicit manifest overrides turn them
     on, fixing Balanced, Finance, and Healthcare behavior.
  6. Tagged surrogate syntax did not exist. The exact ASCII PG1 grammar, base32
     generation/auth lengths, HMAC input/truncation, accepted spaces/case, rejection
     rules, and constant-time validation are now normative and power SSE scanning.
  7. Overlapping PGPaths could double-transform. PGPath-v1 now requires typed string
     leaves, full expansion, concrete-pointer dedupe/order, and recursive no-restore
     scans only for blocked side-effect paths.
  8. Signed-time accepted malformed intervals and did not advance. It now rejects
     reversed validity/negative uncertainty, advances from a monotonic receipt
     snapshot, transactionally persists high-water, expires attestations, and fixes
     PostgreSQL disagreement at 30 seconds.
  9. Capability states conflicted. The only consumption path is now `active →
     consumed_pending_dispatch → dispatched|indeterminate`, with definitive pre-send
     failure to `revoked` and recovery only from verifiable downstream idempotency.
  10. l-diversity and threshold names disagreed. l-diversity is explicitly per
      sensitive attribute, and the manifest threshold now names the cataloged
      `unique_real_row_match_count` metric.
  11. Webhook signing was not interoperable. Header names, epoch/UUID/key/signature
      encodings, exact signed bytes, lowercase hex, authenticated-clock window,
      replay persistence, and active/retired/revoked key behavior are now fixed.
- Rereview verdict: **pending seventeenth fresh zero-context review**.

### Entry 018 — 2026-09-21 — Stage 0 refutation round 17

- Reviewer context: seventeenth fresh agent with no prior review or conversation
  history, reviewing the stable round-16 artifacts read-only.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. Issuer keys and mixed capability objects lacked candidate composite parents.
     `application_issuer_keys` now defines the triple key, and the transform/capsule/
     generation association is the exact parent of every capability.
  2. Clear policy digests and mapping entity columns violated audit confidentiality.
     Policy snapshots/digests and entity/action metadata are encrypted; only approved
     entity blind indexes participate in identity/value/detection foreign keys.
  3. HKDF scope strings remained variable. Owner/scope enums, nullability, 16-byte
     ID encodings, salt object, info bytes, output size, and manifest values are now
     frozen.
  4. Capsule acknowledgement did not bind its clear request nonce after cleanup.
     The handoff row retains the original nonce through ack/timeout and compares it
     before the domain-separated expected-proof hash.
  5. Signed-time wire/key/uncertainty semantics were incomplete. Exact source/key
     IDs, key table, nonce/signature encodings, interval validation, conservative
     upper-bound effective time, monotonic advance, and DB tolerance are fixed.
  6. Capability crash recovery lacked a set-wide durable intent. `dispatch_intents`
     and its unique capability association atomically own set digest, payload digest,
     idempotency, state, encrypted prior result/ack, and recovery.
  7. Card/routing/SSN/email canonicalizers still admitted incompatible parsers. Exact
     grouping/separator rules, checksums, invalid SSN ranges, ASCII email code points,
     label lengths, and manifest variants now define one oracle.
  8. SSE size limits were undefined. v1 fixes 1 MiB joined-event data and 16 MiB
     total stream input, counted as pre-restoration UTF-8 bytes.
  9. Future-dated webhook deliveries could replay after a receipt-relative TTL.
     Delivery retention is now through signed timestamp plus window; retired-key
     verification is bounded by both signature time and that absolute deadline.
  10. Synthesis formulas did not name their sets/columns. `R`, `H`, `S`, included
      non-key columns, ordered evaluation columns, and quasi/sensitive subsets are
      now normative and mirrored in the manifest.
  11. Capability and clock work had duplicate primary owners. Stage 1 now owns only
      its session-child authorization/clock primitives; Stage 2 solely owns capability
      association/store/crash tests; signed-time/PostgreSQL fixtures occur only in
      Stage 1.
- Rereview verdict: **pending eighteenth fresh zero-context review**.

### Entry 019 — 2026-09-21 — Stage 0 refutation round 18

- Reviewer context: eighteenth fresh agent with no prior review or conversation
  history, reviewing the stable round-17 artifacts read-only.
- Verdict: **REFUTED**.
- Sustained objections and corrections:
  1. Webhook validity was inclusive where replay retention expired. Validity is now
     exclusive at 300 seconds and the manifest names that same boundary.
  2. Capability association referenced a transient handoff row. A value-free durable
     capsule identity now outlives ack cleanup through capsule/capability expiry.
  3. Dispatch-intent association did not enforce common scope. Intent, association,
     and capability now share tenant/application/session/transform/capsule composite
     keys, with capability ID unique to one intent.
  4. HKDF allowed invalid label/scope combinations and lacked synthesis spill.
     Closed legal tuples and an ephemeral `synthesis_spill` scope/label now reject
     cross-purpose derivation before HKDF.
  5. HPKE request nonce length was omitted. It is exactly 32 random bytes encoded
     base64url without padding.
  6. Money parsing remained non-executable. Sign, ISO and locale-symbol positions,
     whitespace, integer/grouping, leading-zero, decimal, currency, and canonical
     signed-minor-unit rules are now exact and mirrored in the manifest.
  7. An explicit empty evaluation column list produced an undefined mean. It now
     yields `not_evaluable` for distance/DCR metrics.
- Rereview verdict: **pending nineteenth fresh zero-context review**.
