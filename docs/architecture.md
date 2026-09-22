# Architecture decision record: local-first privacy boundary

Status: proposed for Stage 0 refutational review.

## Decision

Privacy Gateway is a policy engine with adapters, not an LLM vendor wrapper. The
same core must protect text and structured payloads whether it is called in
process, through an SDK, via MCP, or through an HTTP proxy.

`normative-contract.md` is part of this decision. It freezes Unicode/offset and
canonical-byte semantics, cryptographic envelopes, authorization, time behavior,
policy/catalog compatibility, adapter boundaries, and synthesis risk metrics. A
runtime that does not satisfy that contract is not Privacy Gateway compatible.

The default trust mode is **client-local**: detection, replacement mapping, and
restoration happen inside the caller's boundary. The gateway receives the
policy-transformed payload but no classification metadata by default. Values that
are detected and configured for a protecting action remain local; values configured
as `keep`, values outside policy, and undetected sensitive data pass through by
design or limitation. An explicit telemetry opt-in may transmit the restricted
aggregate schema defined below, but never detected original values or the local
queryable audit ledger. Two
explicit opt-in modes add an encrypted local vault or a tenant-isolated managed
vault. There is no automatic downgrade between modes.

## Trust modes

| Mode | Originals seen by gateway | Originals persisted by gateway | Restoration owner | Required key |
| --- | --- | --- | --- | --- |
| Client-local | Not for detected values assigned a protecting action; `keep`/out-of-policy/missed values can pass | No mapping originals | Client | Client root key with purpose-separated subkeys |
| Local gateway | Yes, in the operator's network | AES-GCM ciphertext | Gateway, or client via two-step capsule flow | Operator master key; client recipient public key for capsule flow |
| Managed vault | Yes, inside tenant boundary | Per-tenant envelope ciphertext | Client via two-step capsule flow by default | KMS-wrapped tenant key; client recipient public key |

Any requested reversible persistent mode without its required key fails closed.
Irreversible actions may continue only when the policy explicitly permits them.

## Data flow

```text
source payload
  → validate UTF-8 and build an origin-mapped matching view
  → detectors (regex/checksum, scope, Presidio, spaCy, optional GLiNER)
  → deterministic overlap/confidence policy
  → per-entity action operator
  → collision-safe mapping + queryable detection audit
  → policy-transformed payload → configured downstream system
  → streamed downstream response
  → client-owned tolerant restorer → destination
```

For client-local mode, the mapping, audit, and capsule steps execute in the client
SDK. Browser clients use IndexedDB; Python and Node clients use SQLite. The service
receives the policy-transformed payload, which can still contain deliberately kept,
out-of-policy, or missed sensitive values. If telemetry is explicitly enabled,
the only permitted fields are tenant pseudonym, policy version, action, entity
enum, integer count, coarse duration bucket, and success/blocked state. Those
fields are still classified sensitive, encrypted in transit/at rest, access
controlled, and separately retained. Offsets, source hashes, detector evidence,
confidence values, replacements, restoration/local-audit session IDs, and free-form
fields never leave the client-local boundary. Requests are authenticated to a
tenant and carry a fresh request ID/idempotency nonce, not the local session ID.
Disabling telemetry never disables the local audit.

Each client-local profile creates a random wrapping root that never leaves that
runtime. Every session and policy version receives an independent random seed,
wrapped by the profile root and stored with its opaque ID. The exact v1 HKDF salt,
info framing, labels, encodings, and 32-byte outputs are defined in
`normative-contract.md`; labels include `capsule-encryption`, `mapping-match`,
`mapping-generation`, `audit-integrity`,
`audit-metadata-encryption`, `value-encryption`, `policy-value-encryption`, and
`policy-match-commitment`
derives non-interchangeable subkeys; shared conformance vectors cover Python, Node,
and WebCrypto. Local
allow/deny/scope/custom-recognizer secrets use distinct policy-value-encryption and
policy-match-commitment subkeys, redacted-by-default queries, and fail-closed
decryption. Browsers keep
the root as a non-extractable WebCrypto key in IndexedDB where supported; Python and
Node require an OS keystore or an explicitly configured encrypted key file. Missing
secure key storage blocks reversible/audited local operation. Profile-root rotation
rewraps still-live session/policy seeds without changing derived subkeys or immutable
digests, then retires the old root after no seed references it. Explicit local-
session deletion deletes that session's wrapped seed plus stores, making all of its
symmetric capsules undecryptable while leaving other sessions usable; browser/OS
forensic remnants remain the stated non-goal. Policy-version deletion likewise
deletes its seed after references end. Profile deletion erases all seeds/stores and
destroys every root. Suspected profile-root compromise quarantines that entire root
generation and blocks every bound session, policy version, capsule, local audit, and
project store. It offers deletion/export of non-sensitive incident metadata, not
invented key continuity. These client keys are distinct from all
tenant/server keys and are wholly owned and tested by Stage 2.

The client-local ledger implements the same encrypted queryable detection/decision
fields, keyed blind indexes, and exact-expiry cohorts as the Stage 1 contract. Its
`audit-metadata-encryption` subkey protects classification metadata and its separate
`audit-integrity` subkey covers canonical ciphertext records and chain order. Stage
2 must detect local row mutation,
deletion, and reorder in Python, Node, and browser stores. Without an independent
external anchor, a same-device attacker controlling both local store and root key
can roll both back; client-local mode states this non-goal instead of inheriting the
managed-vault rollback guarantee.

Client-local expiry guarantees immediate read rejection and bounded live-record
deletion. Python/Node SQLite stores use `secure_delete=ON`, WAL checkpoint/truncate,
and the same configured reclamation/VACUUM reporting as gateway SQLite. Browser
IndexedDB deletion and transaction completion are tested, but browsers expose no
forensic page-reclamation primitive; remnants controlled by the browser/OS remain
an explicit non-goal even after full local-session deletion destroys that session's
wrapped seed and logical records. The profile root remains available to unrelated
sessions; destroying it is a separate profile-deletion action.
The UI distinguishes logical expiry, IndexedDB record deletion, and unavailable
forensic-erasure evidence rather than calling all three “physical purge.”

Gateway-created client capsules use an authenticated two-step flow, not the
client-local symmetric key. The SDK creates a one-handoff X25519 recipient keypair
and binds the public key to tenant/application/session/policy/request nonce. The
gateway seals mapping material with the exact RFC 9180 Base-mode
`0020-0001-0002` profile, binding/AAD, canonical wire object, and exporter-derived
acknowledgement proof in `normative-contract.md`,
commits `awaiting_capsule_ack`, returns the protected payload and capsule before any
downstream call, and erases plaintext handoff material. The client proves successful
open only after atomically re-sealing the mapping into its Stage 2 local store under
that session's mapping/value subkeys with an expiry no later than the capsule and
session expiries. It then destroys the one-handoff private key. The acknowledgement
nonce is inside the capsule and bound to the request, and its proof attests to that
capsule open but is only a client assertion about the durable local commit; the
official SDK emits it only after the transaction commits. Without a trusted-client
storage-attestation mechanism, the gateway cannot prove that a custom or compromised
client persisted the mapping. The gateway records a second anchored transition to
`protected` (or timeout/failure to
`blocked`). Only after that acknowledgement may the direct-to-provider adapter send
the transformed request. Wrong recipient, binding mismatch, replay, seal/open
failure, local-store commit failure, or missing acknowledgement blocks. A client
without secure local key storage cannot acknowledge this mode. Later restoration
uses the locally re-sealed mapping, never the destroyed X25519 private key.
Lying about durable commit can make that client's later restoration unavailable,
but does not give the gateway a basis to retain zero-retention mapping values or to
send before an acknowledgement.
Transparent OpenAI/Anthropic proxy mode therefore uses gateway-owned restoration;
client-owned restoration uses the SDK/two-step flow and is not falsely advertised
as wire-transparent. Stage 3 owns the network protocol and streaming timing; Stage 2
owns recipient keys and capsule cryptography. Zero mapping retention is permitted
only after successful client capsule handoff, with no gateway value persistence.
Wire-transparent mode restores only client-visible response text. If a tool argument
or other side-effecting field contains a restorable surrogate, the proxy returns a
structured blocked error and neither restores nor dispatches it; side-effect
restoration requires the explicit nonstandard SDK capability flow.

## Core boundaries

- `policy`: versioned policy schema, presets, validation, scopes, locales, retention.
- `recognizers`: detector protocol and optional adapters; failures are surfaced to
  the policy engine, never silently converted into “no PII.”
- `operators`: keep/redact/label/tokenize/hash/generalize/synthetic transforms.
- `mapping`: bijective allocation with collision checks and deterministic reuse.
- `vault`: storage protocol with SQLite and PostgreSQL implementations.
- `capsule`: authenticated client-owned restoration state.
- `restore`: exact and tolerant incremental state machine, including structured
  JSON and tool arguments.
- `structured`: recursive dictionaries/lists and schema-aware tabular synthesis.
- `image`: PNG/JPEG/WebP OCR recognition, irreversible pixel redaction, metadata
  stripping, and an adapter protocol; unsupported formats block rather than pass.
- `adapters`: API/SDK/CLI/MCP/proxy/webhook integrations that cannot weaken core policy.

All portable text locations, record bytes, hashes, and signatures follow the
normative UTF-8 byte-offset and RFC 8785 serialization contract. The original input
is not normalized in place. Any normalized/case-folded matching view carries an
origin map back to one contiguous original byte span; otherwise protection blocks.

Stage 1 ships both `privacy_gateway.core` and `@privacy-gateway/core`. They consume
one generated JSON Schema and one language-neutral conformance corpus for policy
validation, deterministic regex/checksum/scope detection, merge decisions, pure
operators, surrogate grammar, and blocked-state semantics. Python-only Presidio/
spaCy and runtime-specific GLiNER/OCR adapters advertise capability IDs; policy
validation blocks when a required capability is unavailable instead of pretending
cross-runtime equivalence. Stage 2 composes these cores into `privacy_gateway.local`
and `@privacy-gateway/local` with local storage, capsules, and restoration; it does
not reimplement Stage 1 semantics.

## Fail-closed contract

The transform result has one of three explicit states: `protected`, `blocked`, or
`bypassed_by_policy`. Detector initialization failure, required-detector failure,
missing encryption, any required local or server audit write failure, malformed
structured content, or replacement collision returns `blocked`. Adapters must not
forward a blocked payload. No catch-all exception handler may return the original.

## Mapping and restoration invariants

1. Within one transform, one original maps to one replacement. Across requests in
   a session, that mapping is stable only while its `mapping_values` row remains
   active under the configured retention window.
2. Within one transform—and among all concurrently active mappings in a
   session—one replacement maps to at most one original across every entity type,
   so any restorable payload remains unambiguous.
3. Stable mapping uses HMAC-SHA-256 with a scoped secret, never runtime `hash()`.
4. Every new payload is detected again before known mappings are applied.
5. Original values are absent from logs, error messages, and audit details.
6. Session expiry is a hard upper bound. Per-rule retention creates an
   `expires_at` on every mapping/detection; expired rows are rejected on read and
   excluded from restoration before asynchronous cleanup occurs.
7. Capsules are AEAD-authenticated and bound to tenant/application/session/policy version and
   a unique transform ID. The SDK handle supplies that transform ID as AEAD
   associated data; a wrong handle cannot open the capsule. This authenticates
   restoration state, not downstream response authorship.
8. Tolerant restoration has a finite documented mutation budget and never fuzzy
   matches arbitrary natural language. The allocator and restorer share the exact
   same canonicalization/equivalence implementation.
9. A capsule's expiry is never later than its session hard expiry. Policy validation
   rejects gateway-owned restoration when mapping retention is zero; that setting
   is valid only when the client capsule is the sole restoration owner.

## Persistence model

Every session-scoped child row carries non-null `tenant_id`, `application_id`, and
`session_id` and references the same composite parent. The abbreviated field lists
below do not waive those three columns. Every API/repository lookup includes all
three; a same-tenant caller from another application cannot name or join the row.

- `tenants`: identity and wrapped data-encryption key metadata.
- `applications`: random `id`, `tenant_id`, name, active/retired/revoked state, and
  pinned capability-issuer Ed25519 public-key versions; `UNIQUE(id, tenant_id)`.
- `application_issuer_keys`: `issuer_key_id`, `application_id`, `tenant_id`, raw
  Ed25519 public key, active/retired/revoked state and timestamps;
  `UNIQUE(issuer_key_id, application_id, tenant_id)` with
  `(application_id, tenant_id)` referencing applications.
- `time_authority_keys`: `(source_id, key_id)` primary key, raw Ed25519 public key,
  active/retired/revoked state and timestamps; only active keys accept new
  nonce-bound time attestations.
- `policies`: `id`, non-null `tenant_id` foreign key, name, timestamps,
  `UNIQUE(id, tenant_id)`. Built-in presets are templates only and are
  materialized as tenant-owned policies before use.
- `policy_versions`: `id`, `policy_id` foreign key, non-null `tenant_id` foreign key,
  one AEAD envelope containing the immutable policy snapshot, canonical policy
  digest, mapping-retention rules, audit-retention rules, and non-expiry timestamps;
  plus clear state (`active`, `retired`, `deleted`) and `attestation_expires_at`. A
  composite `(policy_id, tenant_id)` foreign key references policies and
  `UNIQUE(id, tenant_id)` supplies the portable parent key for sessions.
- `policy_secrets`: tenant/policy-version composite foreign key, opaque field ID,
  encrypted allow/deny/scope/custom-recognizer material, optional exact-match keyed
  digest, distinct value-encryption and match-commitment subkey versions derived
  from the pinned policy seed, `policy_key_id`,
  `policy_key_purpose CHECK (... = 'policy')`, versioned AEAD envelope, and
  expiry/state. Default queries return only permitted opaque IDs/state/expiry and
  blind indexes, never
  plaintext; a separately authorized reveal decrypts inside the trust boundary and
  is audited. Missing/decryption-failed policy keys block policy use.
- `sessions`: `id`, `tenant_id` foreign key, non-null `application_id` owned by that
  tenant, `policy_version_id` foreign key,
  copied canonical policy digest inside an audit-metadata envelope, `mapping_key_id`,
  `mapping_key_purpose CHECK (... = 'mapping')`, trust mode,
  timestamps, hard expiry. Composite foreign keys to
  `(policy_version_id, tenant_id)` prevents cross-tenant policy selection and
  `(application_id, tenant_id)` references the exact tenant-owned application.
  IDs are globally random, but every constraint still includes tenant/application:
  `UNIQUE(id, tenant_id, application_id)` and
  `UNIQUE(id, tenant_id, application_id, policy_version_id)` are parent
  keys for portable composite references.
- `transforms`: cryptographically random `id`, `tenant_id`, `application_id`,
  `session_id`, `policy_version_id`, result state (`pending`,
  `awaiting_capsule_ack`, `protected`, `blocked`, `bypassed_by_policy`), capsule
  expiry when applicable, immutable `audit_expires_at`, and a versioned
  `audit_metadata_ciphertext` containing copied canonical `policy_digest`, source
  kind, keyed source digest, integer requested/result timestamps, and reason code.
  Only IDs, state, and expiry remain plaintext. `audit_expires_at` is fixed at
  request acceptance. For a protected request it is the latest absolute deadline
  among enabled entity rules and the policy's transform-lifecycle retention; for a
  blocked/bypassed request it uses the positive transform-lifecycle retention.
  All are capped by session expiry. `(session_id, tenant_id, application_id,
  policy_version_id)` references the exact application-owned session policy and
  `UNIQUE(id, session_id, tenant_id, application_id, policy_version_id)` is the portable parent key
  for detections/events/capsules. An accepted request creates this row before
  detection; policy/audit failures update it to `blocked` in the same durable
  transaction when storage is available. A storage outage returns a value-free
  blocked result and cannot truthfully promise a durable failure record.
- `mapping_identities`: `id`, `tenant_id`, `application_id`, `session_id`, keyed
  `entity_blind_index`,
  created timestamp;
  contains no original HMAC, ciphertext, replacement, or mutable retention field.
  `(session_id, tenant_id, application_id)` references sessions and
  `UNIQUE(id, session_id, tenant_id, application_id, entity_blind_index)` supports same-scope, same-entity
  value and detection references.
- `mapping_values`: `mapping_id` primary/composite foreign key to the identity,
  tenant/application/session/entity blind index, random `generation_id`, keyed
  original match digest, encrypted original plus entity/action/collision metadata
  when allowed, replacement, `mapping_key_id`,
  `mapping_key_purpose CHECK (... = 'mapping')`, `value_key_id`,
  `value_key_purpose CHECK (... = 'value')`, algorithm version, timestamps,
  `expires_at`; `(tenant_id, application_id,
  session_id, entity_blind_index,
  original_hmac)` is unique for the forward direction and `(session_id,
  tenant_id, application_id, replacement)` is unique across all entity types for the reverse direction.
  `UNIQUE(tenant_id, application_id, session_id, generation_id)` makes the restoration identifier
  unambiguous and references the matching surrogate generation row.
  `(mapping_id, session_id, tenant_id, application_id, entity_blind_index)` references the exact identity.
  Expiry removes this sensitive live row within the purge SLA without invalidating
  detection audit; forensic page/WAL/backup reclamation follows the separate storage
  contract below.
- `surrogate_generations`: tenant/application/session composite foreign key, globally random
  `generation_id`, pinned `mapping_key_id`,
  `mapping_key_purpose CHECK (... = 'mapping')`, opaque
  `mapping_lineage_digest = HMAC(mapping_id, generation_id, mapping_key_id)`, and
  explicit `expires_at` equal to the later of the active mapping-value expiry and
  every issued capsule expiry. With no capsule it follows mapping-value expiry;
  with zero mapping retention it follows capsule expiry.
  `UNIQUE(tenant_id, application_id, session_id, generation_id)` is the portable parent key and
  allocation retries then blocks on a collision.
- `surrogate_reservations`: tenant/application/session/generation composite foreign key to
  `surrogate_generations`, one keyed digest for a tolerant-equivalence form, and
  the same explicit `expires_at` as its generation row.
  `UNIQUE(tenant_id, application_id, session_id, equivalence_digest)` prevents reuse while any
  capsule is valid. Neither table has a foreign key to `mapping_identities` or
  contains an original, replacement plaintext, entity, or classification, so both
  can safely outlive sensitive values and classification audit.
- `detections`: `id`, `tenant_id` foreign key, `session_id` foreign key,
  `transform_id`, nullable `mapping_id` foreign key to `mapping_identities`, keyed
  blind indexes for approved entity/detector/action/policy exact filters,
  `audit_metadata_ciphertext` containing the source digest, typed source locator,
  entity, detector, integer confidence ppm, action, policy data including copied
  canonical `policy_digest`, and decision reason, `policy_version_id`,
  `audit_expires_at` (always a future time for a successful transform).
  `(session_id, tenant_id, application_id)` references sessions; when non-null,
  `(mapping_id, session_id, tenant_id, application_id, entity_blind_index)` references the same-scoped,
  same-entity identity;
  `(session_id, tenant_id, application_id, policy_version_id)` references the exact policy/session
  triple, preventing cross-tenant, cross-application, and wrong-version records;
  `(transform_id, session_id, tenant_id, application_id, policy_version_id)` references the exact
  queryable transformation;
  `UNIQUE(id, session_id, tenant_id, application_id)` supplies the portable parent key for audit events.
  A text locator stores half-open original UTF-8 byte offsets; a structured locator
  stores RFC 6901 JSON Pointer plus value-relative UTF-8 byte offsets; an image
  locator stores source-image
  digest, decoded width/height, integer pixel bounding box, OCR-text keyed digest
  and text-relative span, and redacted-region digest. Animated WebP is unsupported
  and blocks, so first-release image locators require exactly one raster frame.
- `audit_events`: `id`, `tenant_id` foreign key, `session_id` foreign key,
  `transform_id`, opaque keyed `chain_scope_digest`, sequence, hashes,
  `integrity_key_id`, `integrity_key_purpose CHECK (... = 'integrity')`, nullable
  `detection_id`, and encrypted metadata envelope containing event kind, canonical
  detection/transform digests, integer timestamp, and scope ingredients; plus exact
  `expires_at`.
  Its composite `(session_id, tenant_id, application_id)` reference prevents cross-application
  attachment; transform-scoped events reference the composite transform parent and
  detection events use a composite detection/session/tenant/application reference.
- `telemetry_events`: gateway-side opt-in aggregate allowlist fields only, stored as
  an audit-metadata AEAD envelope with opaque tenant pseudonym, integer timestamp,
  and `expires_at`; never joins to mappings or client session identifiers.
- `audit_heads`: tenant/application/session/opaque keyed scope digest, current generation, last sequence/hash,
  `integrity_key_id`, `integrity_key_purpose CHECK (... = 'integrity')`, last anchor
  transition ID, explicit `expires_at`; composite
  tenant and integrity-key+tenant+purpose references.
- `policy_audit_events` and `policy_audit_heads`: tenant/policy-version lifecycle
  counterparts with no session/transform columns or foreign keys. They commit
  creation, renewal, retirement, and deletion attestations using the same chain,
  integrity-key purpose, exact-expiry segment, transition, and external-anchor
  invariants. They reference the policy version's `(id, tenant_id)` parent key;
  each head is unique on `(policy_version_id, tenant_id, chain_scope)`.
- `tenant_keys`: `tenant_id`, `key_id`, purpose (`value`, `integrity`, `mapping`,
  `policy`, `audit_metadata`, `blind_index`, `capability`),
  algorithm/version, `wrapping_key_id`, wrapped key material or opaque external-KMS
  handle (exactly one), state, created/rotated/revoked/retired timestamps;
  `UNIQUE(tenant_id, key_id, purpose)`. Sessions, mapping values, surrogate
  generations/reservations, policy secrets, audit events, and heads each store the checked purpose constant and reference
  `(tenant_id, key_id, purpose)`; no child relies on a literal inside a foreign key.
- `anchor_root_keys`: operator/KMS-owned signing keys isolated from tenant integrity
  keys and the audit database. Root-key transitions are dual-signed by old+new
  keys (or recovered via an offline break-glass key) and stored in the external ledger.
- `wrapping_keys`: operator/KMS or local-OS-keystore key-encryption-key metadata,
  purpose and lifecycle only; raw material never enters the database. Tenant
  value/integrity/mapping/policy keys reference the wrapping-key version that protects them.
  `UNIQUE(wrapping_key_id)` is referenced by `tenant_keys`; external handles are
  allowlisted to the configured KMS namespace and never accepted from callers.
- `anchor_segment_keys`: opaque segment/key ID, wrapped random data-encryption key,
  exact cohort expiry, wrapping-key version, and state. It has
  no tenant/entity/policy plaintext; the external segment references its opaque ID.
- `purge_receipts`: independent opaque transition/segment/key IDs, reason, deadline,
  KMS/keystore destruction status and provider receipt, segment-deletion status,
  and root signature. It survives segment-key metadata deletion and is deleted only
  after key destruction, segment deletion, and `purge_final` are all verified.
- `capsule_handoffs`: tenant/application/session/transform/capsule composite key,
  request nonce, expected acknowledgement-proof digest,
  `awaiting_ack|acknowledged|expired|blocked`
  state, and expiry; it contains no mapping, ack nonce, exporter key, or plaintext
  handoff material and is deleted after final transition/timeout verification.
- `capsules`: durable non-value identity `(tenant_id, application_id, session_id,
  policy_version_id, transform_id, capsule_id)`, owner, state, and expiry. It stores
  no mapping or proof material, outlives the transient `capsule_handoffs` ack row,
  and is purged only after capsule expiry and all capability/association references
  end.
- `side_effect_capabilities`: random capability ID, tenant/application/session/
  policy/transform/capsule/generation plus operation/sink/PGPath bindings, hash of
  the 256-bit presented secret, issuer key ID, expiry, idempotency key, and state
  `active|consumed_pending_dispatch|dispatched|indeterminate|expired|revoked`.
  Compare-and-set consumption and dispatch-state recording follow the normative
  authorization contract; presented capability secrets are never stored.
- `dispatch_intents`: random intent ID, tenant/application/session/transform/capsule,
  sorted capability-set digest, protected payload digest, unique downstream
  idempotency key, state `pending|dispatched|indeterminate|revoked`, timestamps,
  and encrypted prior-result/acknowledgement metadata. It exposes a composite
  parent key `(intent_id, tenant_id, application_id, session_id, transform_id,
  capsule_id)`. The association table carries that full key plus `capability_id`,
  references the identically scoped composite capability parent, and is unique on
  capability ID. The same transaction inserts one intent plus every association and CASes the
  entire capability set to `consumed_pending_dispatch`; recovery reads this
  aggregate, never reconstructs a set from unrelated per-capability rows.
- `transform_mapping_generations`: exact composite association
  `(tenant_id, application_id, session_id, policy_version_id, transform_id,
  capsule_id, generation_id)` created with the capsule. It references the exact
  transform, durable capsule identity (not the transient handoff row), and session-
  owned surrogate generation.
  `side_effect_capabilities` has composite foreign keys to this association and to
  `(issuer_key_id, application_id, tenant_id)`, so fields from different transforms,
  capsules, applications, tenants, or generations cannot be combined even if they
  belong to one session.

Every encrypted field uses the versioned AEAD envelope and row/field/tenant/expiry
associated-data binding in `normative-contract.md`, including a per-key nonce-
uniqueness constraint. No persistence mode stores sensitive audit classification
metadata in plaintext. Queryability uses keyed blind indexes and authorized in-
boundary decryption, not plaintext denormalization.

Audit rows are split into exact-expiry cohorts. At the start of a transform, each
entity rule resolves one absolute `audit_expires_at`; detection decisions derive an
opaque HMAC scope digest from
`(tenant, application, session, transform, entity, policy_version,
audit_expires_at)`. Those ingredients appear only inside audit-metadata ciphertext;
every row, head, and anchor carrying the opaque digest is constrained to that
identical timestamp.
Lifecycle events likewise receive a named scope and one immutable absolute expiry.
A later transform always starts a new cohort even when the retention duration is
the same. Physical retention therefore deletes the whole cohort and its anchor
segment at once—never an interior prefix and never a live later event.

Policy-version creation computes its canonical digest over the public snapshot plus
opaque secret-field commitments and commits a creation attestation through the same
externally anchored protocol, using the sessionless `policy_audit_*` scope, before
that version can be selected.
Every session/transform/detection copies the digest as well as the version ID, and
verified reads recompute the immutable snapshot digest and compare every copy.
Policy-version mutation, secret substitution, digest substitution, or a decision
bound to a different snapshot therefore invalidates the anchored view. An active
version must have an unexpired attestation covering the hard expiry of any new
session. Before that bound would be exceeded, an anchored renewal commits the same
digest with a later exact expiry; selection blocks if renewal fails. Retirement
forbids new sessions and retains the latest attestation through the maximum live
session expiry. Version/secret deletion is a separate authorized whole-policy audit
transition and is blocked while live sessions refer to it; its segment and secrets
then follow the standard logical-expiry and bounded-purge protocol.

Rows include `chain_scope`, `previous_event_hash`, canonical `event_hash`,
`integrity_key_id`, and a keyed HMAC over tenant/application/session/scope, sequence, canonical
metadata, and previous hash. Each detection insert is paired in the same database
transaction with an audit event that references the detection's composite identity
and commits a canonical digest of every queryable detection field. Detection rows
are immutable; only the authorized whole-cohort purge procedure may delete them,
whether triggered by maximum-TTL expiry or an explicit authorized session deletion.
Verified reads recompute the digest and chain before returning detection data, so
mutation or deletion cannot leave a valid audit view. Lifecycle events commit their
own canonical payload digest. Every allowed transform-state transition and its
canonical digest event occur in the same transaction. Non-state result fields become
immutable after leaving `pending`; state/reason/time may move only through the
anchored state machine `pending → awaiting_capsule_ack → protected|blocked` or
`pending → protected|blocked|bypassed_by_policy`. Verified transform reads recompute
every transition digest and chain. A request is never forwarded while its transform
is `pending` or `awaiting_capsule_ack`. A storage outage may leave a stale nonterminal
row but cannot create a false completed record; recovery transitions it to `blocked`
when audit storage returns, or expires it as an incomplete attempt without claiming
a cryptographically finalized failure event.
Forging a consistent false history requires compromise of the database, external
anchor store, and anchor-root credential together and remains out of scope. Erasing
both database and anchor store can remove all evidence without forging signatures
and is a separate availability/evidence-destruction non-goal.

Database integrity is compared with a monotonic authenticated anchor outside the
database. Each audit scope has its own encrypted append-only anchor segment. Local
deployments fsync segments beneath a separate OS identity/path/permission; managed
deployments use independently authorized immutable object/ledger segments. Anchor
records contain an opaque tenant pseudonym and scope digest—not entity/policy
fields—plus `transition_id`, generation, expected prior generation/hash, new
database sequence/hash or authorized-empty marker, cohort expiry, state
(`pending`, `final`, `aborted`, `purge_pending`, `purge_abort`, or `purge_final`),
integrity key ID,
explicit `expires_at`, and an anchor-root signature. The segment encryption key and
operator/KMS anchor-root signing key are separate from tenant value, mapping, and
integrity keys and from database credentials.

One writer per tenant/scope is enforced by backend-specific primitives plus an
anchor compare-and-swap on expected generation. PostgreSQL takes a transaction-
scoped advisory lock derived from tenant/scope and `SELECT ... FOR UPDATE` on the
head. SQLite first takes a per-scope POSIX file lock in a local (non-NFS) lock
directory, then uses `BEGIN IMMEDIATE` and an `audit_heads` generation compare-and-
swap; its coarser database writer serialization is accepted. Every path acquires
external scope lock before database lock and releases in reverse order. Failure to
obtain or verify either lock blocks; network filesystems are unsupported for the
SQLite anchor/lock adapter. The transition protocol is:

1. Verify the latest finalized anchor equals the database `audit_heads` row.
2. Append and fsync/CAS a signed `pending` record with a random transition ID,
   expected prior head, proposed new head, and expiry.
3. Commit one database transaction containing detections/events, the new head,
   and that transition ID.
4. Append and fsync/CAS a signed `final` record referencing the transition.
5. Release the scope lock.

Recovery serializes on the same lock. Pending + absent DB transition appends
`aborted`; pending + exactly matching DB transition appends `final`; a DB transition
without its fsynced pending record, a final record that disagrees with the database,
or an unexpected generation blocks protection and raises an integrity incident.
Tests crash after each step and race two writers. Database suffix deletion or
rollback disagrees with the latest final anchor. An attacker able to delete both
database and external anchor remains out of scope.

A transform normally spans a lifecycle cohort plus one cohort per detected entity/
retention deadline. It therefore uses a random `transition_group_id`. The writer
sorts all opaque scope digests bytewise, acquires every scope lock in that order,
verifies every head, and appends/fsyncs a `pending` record to every segment. Each
record commits the group ID plus a digest of the complete ordered `(scope,
expected_head, proposed_head)` manifest. Only after every pending record is durable
does one database transaction commit mappings, generations/reservations, detections,
all events/heads, the finalized transform row, and the same group-manifest digest.
The writer then appends/fsyncs `final` to every segment; no payload is forwarded
until all finals are durable. Recovery under the same ordered lock set aborts every
written pending when the DB group is absent, completes every missing final when the
DB group exactly matches, and blocks on any partial/mismatched manifest or DB group
without all pendings. Tests crash after each pending/final in groups of differing
scope counts and race overlapping transforms to prove atomic visibility and
deadlock-free ordering.

An anchor segment expiry is the common retention deadline of the scope it
authenticates, capped by session expiry. Records are never removed from the middle
of a segment. At expiry—or during an explicit authorized full-session deletion—the
purge worker serializes on the scope lock and uses this protocol. Retention is a
maximum TTL, not a minimum legal hold; legal-hold semantics are outside the first
release, and a future hold adapter must reject deletion before this protocol begins:

1. Verify the latest finalized anchor against `audit_heads`, append and fsync a
   root-signed `purge_pending` record containing `expired` or `session_delete`, and
   retain its transition ID.
2. Mark the database head `purge_pending` with that transition ID.
3. In one database transaction delete the scope's detections, events, and head,
   then commit a minimal purge receipt containing only opaque scope/transition
   digests and the segment deadline.
4. Append and fsync a root-signed `purge_final` record.
5. Idempotently destroy (or query destroyed state for) the segment encryption key,
   persist the provider destruction receipt in independent `purge_receipts`, delete
   segment-key metadata, delete the target segment, and finally delete the purge
   receipt only after key destruction, segment deletion, and `purge_final` all verify.

Recovery is deterministic: database live plus only `purge_pending` rolls the database
purge marker back and appends/fsyncs a root-signed `purge_abort` record that names
the transition, prior finalized head, and current anchor generation. The abort is
the new CAS head, so later writers advance from it without pretending the durable
pending record vanished. Database absent plus `purge_pending` or `purge_final` finishes whole-
segment deletion; segment missing while the database scope is live is corruption
and blocks protection; both scope and segment absent is completed expiry. Tests
crash after every phase. At the configured deadline, all normal reads and verification
APIs reject the cohort and only the isolated purge/recovery principal may access its
encrypted rows/segment. Physical deletion is asynchronous and must complete within
the deployment's explicit `purge_grace_seconds` SLA; metrics and health turn failed
when that bound is exceeded. Thus logical retention is exact while crash-tolerant
physical erasure is bounded, not falsely described as instantaneous. Recovery tests
include resuming an ordinary writer after the crash-before-database-delete abort.
No individual
record is deleted from an otherwise live append-only segment.
Integrity-key retirement waits for events/heads and any live segment that
names it. Segment and root-key retirement waits for all live signed segments.

Integrity keys have a lifecycle separate from value-encryption keys. Old verify
keys remain available until no unexpired audit event or head references
them; retirement is otherwise blocked. Encrypted value rows carry `key_id` and
algorithm version. Rotation writes with the new key and re-encrypts existing
unexpired rows transactionally (or in checkpointed batches); value-key retirement
is blocked until no live value row references the old key.

Suspected value-key compromise first marks the key `compromised_migrating`: normal
decryptions stop, but a separately authorized, isolated, audited migration principal
may decrypt each live row once to re-encrypt under a new key. A fully `revoked` key
can never decrypt; remaining ciphertext is deleted. Old ciphertext/backups are
treated as exposed either way. Integrity-key compromise closes the affected chain
segment with an anchor-root-signed compromise marker, starts a new integrity key
and segment, and marks prior integrity as untrusted after the known compromise
time. The marker cannot be forged with the compromised tenant integrity key alone.
Routine anchor-root rotation requires old+new dual signatures. Suspected compromise
never treats an old-root signature as authority even if the key remains available:
the offline break-glass root signs a compromise marker containing the last trusted
anchor, compromise time, revoked root, and successor root; all later old-root
transitions are rejected and the affected interval is labeled untrusted. If the
break-glass root is unavailable, anchoring halts. An operator may explicitly start
a fresh root only with a recorded discontinuity and no claim of continuous trust.
Tests prove that a compromised old root alone cannot authorize its successor or
erase the marker. Neither path claims to undo exposure.

Operator/KMS wrapping keys have a lifecycle independent from tenant and signing
keys. Rotation creates a new wrapping version and rewraps each still-live tenant or
segment data key without re-encrypting payload data; retirement is blocked until no
live wrapped key references the old version. Suspected compromise blocks ordinary
unwraps and permits only an isolated audited rewrap principal; irreversible
revocation makes remaining wrapped material unavailable and triggers configured
deletion/block behavior. Anchor segments receive a fresh random data key before the
first `pending` record. Whole-segment purge destroys that key and stores an idempotent
receipt in independent `purge_receipts` before deleting key metadata; recovery
repeats or queries destruction by opaque key ID and never recreates a key for an
expired segment. Crash tests cover key creation, wrapping, each rewrap step,
destruction before/after receipt persistence, key-metadata deletion while the
receipt survives, segment deletion, receipt deletion, and KMS/keystore unavailability.

Stable mapping derivation and reservation equivalence digests use a third per-tenant
key class with `mapping_key_id`. Each surrogate generation and reservation pins the
key ID used to derive it. Rotation assigns the new key only to new sessions, so
existing active lookups do not change. Retirement is blocked while any unexpired
session, generation, or reservation references the key. Compromise revocation explicitly blocks
affected sessions and deletes their active mapping values, but retains immutable
reservation digests until capsule expiry so old surrogates cannot be reallocated.
The compromised key is quarantined for verification only until those reservations
expire; it cannot authorize new allocation. The system does not pretend to preserve
deterministic continuity with a new key.

Each policy version pins one tenant policy seed, from which HKDF derives separate
policy-value-encryption and policy-match-commitment subkeys. Neither subkey is
accepted for the other's operation. Rotation assigns a new seed to new policy
versions; it never
silently changes an immutable version or its digest. Retirement waits until no
active/retired version, secret, attestation, or live session references the key.
Suspected compromise blocks affected versions and new sessions. An isolated audited
migration may decrypt once to create a distinct version under a new key/digest and
attestation; full revocation makes remaining secrets unavailable and schedules their
deletion. No path claims stable commitments across a key change without creating a
new policy version.

## Authorization and time boundary

Security-critical primitives enforce the principal, credential, scope, object-
binding, revocation, and atomic capability-consumption contract in
`normative-contract.md`. “Separately authorized,” “trusted application,” “purge
worker,” “migration principal,” and “break-glass” are those concrete roles, not
informal operator promises. Stage 1 owns the authorization decision protocol and
object checks, Stage 2 owns durable one-use restoration capabilities, and Stage 3
owns OIDC/workload-token enforcement at network adapters.

All expiry comparisons use the injected authenticated clock contract and integer
UTC epoch microseconds. Expiry is latched and can never be reversed by a backward
clock jump. Reversible reads/writes block when the authoritative source is missing,
rolled back, or beyond the allowed uncertainty. Offline local mode states its
weaker clock boundary and fails closed on uncertainty rather than advertising an
unqualified wall-clock guarantee.

SQLite is the local default. PostgreSQL uses the same repository interface and
tenant predicates; managed mode additionally requires database row-level security
and per-tenant envelope keys.

“Physical purge” means the live row is deleted and no application/key path can read
it after logical expiry; it does not falsely promise instantaneous forensic erasure
from database pages, WAL, filesystem snapshots, replicas, or backups. SQLite gateway
vaults require `secure_delete=ON`, bounded WAL checkpoint/truncation after purge
batches, and a configured `VACUUM`/file-reclamation SLA. PostgreSQL deployments
must publish and preflight autovacuum/manual-vacuum, WAL/archive, replica, snapshot,
and backup-retention bounds. The operations/status report distinguishes logical
expiry, live-row deletion, storage reclamation, and backup expiry. Deployments whose
reclamation/backup bounds exceed policy warn or block according to an explicit
policy setting. Tests prove immediate read rejection and live-row absence, exercise
SQLite secure-delete/WAL/VACUUM and PostgreSQL vacuum paths, and validate configured
backup bounds; they do not claim that a row-absence assertion proves media erasure.

Per-entity retention is resolved from the immutable policy version when rows are
created. `mapping_retention_seconds=0` means return reversible material in the
client capsule but do not persist the original or `mapping_values` row; the
non-value identity remains for the detection ledger. It does **not**
disable the detection record. `audit_retention_seconds` is independently required
to be positive for every successful transform; it controls detections and their
metadata-only audit events. Neither duration may outlive the session hard expiry.
Capsule expiry is also capped by that hard expiry. A policy that requests gateway-
owned restoration with zero mapping retention is invalid and blocks before input
is accepted. Telemetry has a separate positive retention setting at opt-in time.

Zero/expired mapping retention intentionally ends cross-request surrogate reuse.
A later transform may allocate a different replacement, but it must still avoid
every active mapping and unexpired surrogate reservation. The prior response remains
restorable only through its client capsule until that capsule expires. The UI and
generated configuration must show this consistency-window tradeoff explicitly.

Every transform has a cryptographically random ID included in its capsule. Every
new reversible mapping allocation has a separate random generation ID included in
the reserved surrogate namespace; reuse during the active retention window reuses
that mapping generation and replacement. After expiry, a new generation prevents
collision with still-valid older capsules. `tokenize` always uses the tagged
generation ID. A reversible `synthetic` operator emits only the entity-specific,
format-valid value; its generation ID stays inside the capsule and reservation
tables so an email, phone, card, date, or identifier is not invalidated by a generic
wrapper. The transform-bound capsule maps that value's complete bounded equivalence
set to the generation/original. Policy validation rejects a reversible synthetic
generator that lacks a bounded canonicalizer or cannot prove its emitted value
passes the entity format/checksum validator. Allocation rejects any candidate—or
any form in its complete equivalence set—that overlaps source payload windows,
another active/current-transform surrogate's
equivalence set, or a stored unexpired reservation. Stage 1 owns this grammar plus
one canonical equivalence enumerator, which both allocation and Stage 2 restoration
must consume. Allocation writes all digests through capsule expiry, retries, and
then blocks on any intersection. When an existing mapping is reused, the allocator
computes the exact `(mapping_id, generation_id, mapping_key_id)` reservation-lineage
digest and locates that generation plus all child reservations
and transactionally extends its `expires_at` to the latest issued capsule expiry
before returning the protected payload. Shared active mappings restore to the same
original. Foreign/unresolved tokenize tags are surfaced as errors; a plausible
synthetic value absent from the bound capsule is left unchanged and labeled
unresolved, never guessed.

The SDK keeps a provider response paired with its transform handle. A wrong handle
cannot open the capsule, but a capsule does not authenticate downstream response
authorship. Restoration is therefore capability-bound. The default permits only
client-visible text. Every side-effecting destination—tool argument, webhook, file,
database write, URL, or header—is blocked unless the trusted application issues a
one-time capability *before the downstream call* naming tenant, application,
session, policy
version, unique transform/capsule ID, exact mapping generation, sink class,
tool/operation identity, and JSON Pointer path. Broad entity-type or
path-only grants are invalid. The provider cannot mint or widen this authenticated
capability. The incremental restorer emits labeled restored/unresolved segments;
incremental materialization is permitted only for client-visible text. A
side-effecting sink buffers and parses the complete payload, enumerates every
surrogate occurrence, validates an exact one-to-one capability set, atomically
consumes the entire set, and only then materializes and dispatches once. Any late
duplicate, swap, or unresolved occurrence rejects the whole payload before an
original is exposed; side-effect streams are never partially materialized. A valid
surrogate replay at another authorized path, from another
mapping or transform (even when the mapping generation was reused), or after
capability consumption blocks. The platform cannot infer semantic
intent: issuing a capability delegates that one exact side effect to the downstream
provider and is displayed as such in onboarding. Client-visible replay can reveal
only values already owned by that client and is an explicit residual risk. Replay,
swap, duplicate, and capability-consumption tests cover every sink class.

Mapping-identity liveness is derived from both its verified child detections and its
live `mapping_values` row, never from a mutable expiry on the identity. Identity
purge runs after detection and mapping-value purge and only when neither an
unexpired verified detection nor a live mapping value references the identity;
independent reservations neither block that purge nor cascade with it. Tests cover
both retention orderings (`audit < mapping` and `mapping < audit`), reuse, and
staggered detection expiry.

Every read filters its applicable expiry before returning data. The gateway
scheduled purger removes expired mapping values, detections, mapping identities,
surrogate reservations/generations, audit events, audit heads, external anchors, telemetry
events, expired transforms (only after all child detections/events are gone), and
then empty/expired sessions. Manual CLI/API full-session deletion
invokes the same whole-cohort/anchor-segment protocol first, then deletes
reservations/generations, mapping values/identities, transforms, telemetry, and the
session; partial audit
deletion is not exposed.
Client-local SDKs perform their
own expiry-on-read plus runtime-local background/opportunistic purge and explicit
delete; no gateway process claims access to browser or local SDK stores. Deletion tests
verify logical read rejection and live-record/row removal, plus only the runtime-
specific reclamation evidence described above; they do not equate row absence with
forensic media erasure.

## Synthetic data boundary

The tabular generator is independent from the PII transform engine. It accepts a
Privacy Gateway metadata document describing tables, fields, primary/foreign
keys, constraints, nullability, locale, and generator types. It uses deterministic
referential maps and distributions measured from the input, then produces quality
and the frozen attacker-model/metric/threshold privacy-risk report defined in
`normative-contract.md`. It does not train or bundle SDV, promise formal privacy,
or claim statistical equivalence without measured evidence.

The first release runs structured synthesis only inside the local Python CLI/SDK
process. Raw CSV/JSON/JSONL, inferred distributions, metadata, and reports never
enter the gateway, telemetry, or a network connector. Input is streamed and is not
persisted by default. If bounded-memory processing requires spill, the runtime uses
an owner-only temporary directory and a random ephemeral `synthesis_spill` seed
wrapped by the Stage 2 Python profile root; only the normative
`synthesis-spill-encryption` label is legal for it. Unavailable secure key storage
disables spill and blocks inputs that exceed the
configured in-memory bound rather than writing plaintext. Normal
exit, cancellation, and crash recovery delete spill records and report the same
browser/SQLite storage-reclamation limitations defined above. Outputs are written
only to an explicit user-selected path. Metadata and reports are classified
sensitive: defaults include aggregates/keyed digests, not raw example values, and
are encrypted when saved into a project store. Each project store creates a random
project seed wrapped by the Stage 2 Python profile root and derives versioned report/
metadata value keys; root rotation rewraps the seed without changing stored data.
Unavailable secure key storage blocks project-store persistence with no plaintext
fallback. An explicit one-time plaintext export is a separate user action with a
destination/contents warning and local audit record. Tests deny all network access,
scan logs/reports/errors for fixture originals, inspect temp cleanup after injected
crashes, verify no gateway/telemetry writes, inspect project-store ciphertext,
exercise decrypt/rewrap/delete and unavailable-key failure, and enforce explicit
output paths.
Remote synthesis is outside first-release scope rather than an unmodeled upload path.

## Security non-goals and limitations

- No detector guarantees discovery of all sensitive data.
- Pseudonymization is not anonymization under every legal regime.
- Protected structure, writing style, rare combinations, and prompt semantics may
  still identify a person or organization.
- Synthetic output is not differentially private unless a future operator states
  and tests a concrete privacy mechanism and budget.
- Only PNG, JPEG, and WebP image protection is in first-release scope. PDF, SVG,
  layered design files, DICOM, video, and arbitrary image containers remain
  unsupported and must block rather than inherit a raster-image guarantee.
- A reverse proxy cannot keep originals from itself; users needing that property
  must use the client-local SDK.
- Gateway capsule acknowledgement proves possession/opening, not durable client
  storage. The official SDK orders acknowledgement after commit, while a custom or
  compromised client can lie and lose its own restoration state.

## Stage ownership

All promised features are assigned in `PLAN.md`. Architecture or scope changes
must update that file before code, record the reason, and undergo another
zero-context refutational pass.

The detailed boundary inventory is in `threat-boundaries.md`; the feature-to-stage
ownership and acceptance matrix is in `scope-matrix.md`.
