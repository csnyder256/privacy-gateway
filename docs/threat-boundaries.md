# Stage 0 threat-boundary model

This is an architectural threat inventory, not a claim that controls are already implemented.

## Assets

- Original sensitive values and source payloads.
- Reversible mappings, surrogate generations/reservations, client restoration
  capsules, and one-time side-effect restoration capabilities.
- Client-local roots and purpose-derived capsule, mapping-match/generation,
  audit-metadata/integrity, value-encryption, policy-value/commitment, capability,
  and project-store subkeys.
- Tenant value-encryption, integrity, mapping, and policy keys plus encrypted policy
  secrets and stable secret commitments.
- Operator/KMS wrapping keys, per-anchor-segment encryption keys and destruction
  receipts, anchor-root signing keys, and offline break-glass keys.
- Direct-provider credentials and gateway upstream credentials/header policy.
- Policy versions and detector configuration.
- Detection/audit records, which remain sensitive even without raw values.
- Protected downstream prompts and responses.

## Boundary diagram

```text
┌──────────────── Client trust boundary ────────────────┐
│ source → local detector/policy → local audit DB       │
│                 │                mapping + capsule key │
│                 └── policy-transformed payload ──┬─┼───│──── direct TLS ──┐
└──────────────────────────────────────────────────│─│───┘                  │
                                                   │ │ TLS                  │
┌──────────── Gateway/operator trust boundary ───────▼───┐
│ authentication → tenant policy → transform/proxy       │
│       │                │              │                │
│       │        encrypted vault        └── egress ACL ──│──┐
│       │                │                               │  │
│       └── metadata audit DB ← KMS/secret manager       │  │
└────────────────────────────────────────────────────────┘  │ TLS
                                                            │
┌──────────── Untrusted downstream provider ────────────────▼┐◀─────────────┘
│ receives transformed content; returns text/tool/stream data│
└────────────────────────────────────────────────────────────┘
```

In client-local mode, detected values assigned a protecting action do not cross the
first boundary. Values explicitly configured as `keep`, values outside policy, and
missed sensitive data can cross it. In local gateway and managed modes, source
plaintext crosses by design, so the gateway is explicitly trusted with plaintext
in memory even when persistence is encrypted.

## Boundary inventory

| Boundary/entry point | Primary threats | Required controls | Residual risk/tests |
| --- | --- | --- | --- |
| Client input → detector | missed PII, parser/Unicode ambiguity, cross-runtime offset drift, DoS | well-formed UTF-8, original-byte locators, pinned Unicode 15.1 origin-mapped match view, size/depth limits, required detector health, checksums, explicit blocked state | semantic/novel PII can escape; golden Python/TypeScript byte-offset vectors, leak corpus, and fuzzing |
| Detector → policy merge | overlap evasion, low-confidence bypass | deterministic precedence, confidence policy, scope/deny rules, explainable decisions | model disagreement; golden overlap fixtures |
| Policy → mapping | collision, cross-tenant reuse, unstable output | tenant/session HMAC scope, two-way uniqueness, bounded retry then block | inference from surrogate surface; collision property tests |
| Client local store | browser extension compromise, XSS, key theft | IndexedDB isolation guidance, non-extractable WebCrypto keys where available, CSP, short expiry | a compromised client can read originals; browser threat docs |
| Client ↔ gateway | interception, replay, tenant confusion, false durable-store acknowledgement | TLS, authenticated tenant + request/nonce binding in client-local mode; tenant + gateway-session binding in vault modes; idempotency and body limits; official SDK acknowledges only after atomic local re-seal | endpoint compromise; acknowledgement proves capsule possession/opening, not trusted storage attestation, so a custom client can lie and lose its own restore state; integration replay and dishonest-client tests |
| Client → downstream (gateway bypass) | provider credential leakage, redirects/SSRF, response/handle confusion, unsafe egress | application-owned credentials never enter capsules/audit; configured provider allowlist; TLS; no redirects; request/transform-handle pairing in the local adapter; header allowlist; body/backpressure limits | provider retains or infers transformed content; direct-adapter credential/redirect/handle tests |
| Gateway memory | process dump, logs, exceptions | never log values, bounded lifetime, zero-value error payloads, process isolation | Python/JS cannot guarantee memory zeroization |
| Gateway ↔ vault | plaintext fallback, policy/audit exposure, nonce reuse, ciphertext substitution, key reuse, RLS bypass | versioned AEAD envelope, unique nonce per key, row/field/tenant/purpose/expiry AAD, KMS-wrapped tenant keys, separated policy/audit/blind-index subkeys, encrypted policy and audit metadata, composite tenant FKs, RLS + tenant predicates, fail closed | privileged operator/database compromise; forced nonce/substitution/storage-copy tests |
| Key and capability stores | root/wrapping/segment/client-key theft, purpose confusion, failed destruction, capability replay | checked purpose FKs, non-extractable/OS-keystore client roots, isolated KMS/wrapping and anchor roots, per-segment keys+destruction receipts, audited rotations/rewraps, 256-bit hashed one-use capabilities with exact bindings and transactional consume/dispatch state | endpoint/KMS compromise can expose live scopes; old backups remain exposed after compromise; crash/duplicate/revocation tests |
| Privileged operation authorization | cross-tenant object use, over-broad operator, forged issuer, revoked credential, break-glass abuse | normative OIDC claims/scopes/roles, tenant+application object checks, pinned Ed25519 capability issuer, active/retired/revoked state, offline two-person break-glass ceremony, anchored audit | identity provider/operator compromise remains; negative role/scope/tenant/revocation tests |
| Clock/time source | backward jump reactivates expired data, forward jump destroys availability, DB/anchor disagreement | authenticated UTC source, 30-second uncertainty bound, persisted high-water, monotonic elapsed time, latched expiry, reversible fail-closed on uncertainty | compromised OS/hardware time is outside local guarantee; injected jump/reboot/source-loss/skew tests |
| Gateway → downstream | SSRF, credential forwarding, redirect exfiltration | configured allowlisted upstreams only, strip hop/secret headers, no redirects, egress ACL | trusted upstream can retain/infer protected data |
| Downstream → restorer | surrogate mutation, injection, stream splitting, valid-handle replay, cross-transform capability reuse, or mapping swaps in a side-effecting sink | authenticated capsule, Stage 1 canonical finite grammar, incremental labeled parser for client-visible text only, pre-issued one-time capabilities bound to tenant/application/session/policy/transform/capsule + exact mapping generation + operation + sink + JSON Pointer, complete side-effect buffering/parse, atomic all-occurrence validation+capability consumption before one dispatch | unsupported mutations remain unresolved; the trusted app delegates one exact side effect when issuing a capability; authorized client-visible replay can reveal only that client's values; replay/swap/duplicate/cross-transform fuzzing |
| Audit/telemetry | raw-value or classification-metadata leakage, over-retention, tampering, DB rollback/truncation | audit-metadata AEAD, keyed blind indexes, storage-copy plaintext scans, keyed source digests, immutable detection rows committed into exact-expiry hash-chain cohorts, independently root-signed monotonic anchor segments, whole-cohort/segment retention purge, crash reconciliation, deadline-latched logical expiry plus bounded physical purge, scoped access control | blind indexes leak equality/frequency to a copied store and authorized metadata remains identifying; deleting both DB+anchor store can erase evidence; forging a consistent false history requires DB+anchor-store+anchor-root compromise; both are explicit non-goals |
| Raster image adapter | OCR misses, wrong bounding boxes, unredacted metadata/layers | PNG/JPEG/WebP decode allowlist, required OCR health, pixel-region redaction, metadata stripping, output re-decode test, unsupported-format block | non-text visual identity and OCR misses remain; PDF/SVG/layered/DICOM/video are unsupported and block |
| Local structured synthesis | raw tabular leakage, plaintext spill, report/example leakage, implicit upload/output, temp remnants | Python-local-only process, network denied, streaming memory bound, Stage-2-profile-root encrypted owner-only spill/project store, explicit output path, aggregate/keyed-digest report defaults, crash cleanup and log/report scans | browser/OS/SQLite forensic-remnant limits apply; explicit plaintext export is user-authorized and warned; remote synthesis unsupported |

The synthesis path is deliberately separate from the gateway path:

```text
local raw tables -> local inference/generators -> encrypted spill/project store
                                              -> explicit user-selected output
                    (network, gateway, and telemetry denied)
```

## Adversaries

- Accidental developer misuse or misconfiguration.
- Malicious/compromised downstream provider.
- Cross-tenant caller attempting object/reference confusion.
- Network attacker where TLS is absent or terminated incorrectly.
- Compromised gateway/database/operator credential.
- Prompt/content author deliberately evading recognition or mutating tokens.
- Browser extension/XSS attacker in client-local mode.

## Required negative tests

- Disable or crash each required recognizer: adapter must not forward plaintext.
- Remove/corrupt encryption keys: reversible persistence must block.
- Force replacement collisions: allocation must retry then block, never overwrite.
- Cross tenant/session IDs: no mapping, audit, restore, or policy data crosses scope.
- Split/mutate every token across stream boundaries: restore or explicitly surface unresolved tokens.
- Replay/swap a valid handle or mapping at unauthorized and separately authorized
  sink paths, and reuse a consumed capability: block before originals are materialized.
- Crash every audit write and whole-anchor-segment purge phase: recover or block without a silent gap.
- Supply URL/header overrides to proxies: no arbitrary upstream or credential forwarding.
- Expire a session before cleanup: every read must reject it immediately.
- Inject originals into exceptions/loggable fields: scan output must remain value-free.
