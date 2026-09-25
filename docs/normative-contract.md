# Normative first-release contract

This document freezes cross-runtime semantics and objective compatibility claims.
The key words MUST, MUST NOT, SHOULD, and MAY are normative. Implementations do not
get to choose looser fixtures after they are written.

`../contracts/compatibility-v1.json` is the machine-readable first-release manifest.
It is normative with this document; CI MUST fail if generated schemas or docs drift
from it.

## Text, offsets, and canonical bytes

- Text on the wire MUST be well-formed Unicode encoded as UTF-8. Lone UTF-16
  surrogates and invalid UTF-8 MUST be rejected before detection.
- Stored text spans are half-open offsets into the original UTF-8 byte sequence:
  `[start_byte, end_byte)`. The original input is never Unicode-normalized in place.
  Python scalar indices, JavaScript UTF-16 indices, OCR spans, and model-native
  indices MUST be translated to these byte offsets before merge or persistence.
- Built-in ASCII/checksum recognizers run on the original text. Matching that needs
  case/Unicode normalization uses the repository's generated Unicode 15.1
  `toNFKC_Casefold` table and carries an origin map from every normalized scalar to
  the covering original byte span. An expansion maps back to the union of its source
  spans. A match without an unambiguous contiguous original span MUST block rather
  than guess. Python and TypeScript MUST consume the same generated table and vectors.
- JSON Pointers use RFC 6901 over a parser that rejects duplicate object keys and
  over-depth/over-size values. Array indices are decimal with no leading zero except
  `0`. Raster boxes are integer `[x0,y0,x1,y1)` pixel coordinates in decoded image
  orientation after EXIF orientation is applied.
- Canonical records use RFC 8785 JSON Canonicalization Scheme, UTF-8, NFC strings,
  integer epoch microseconds, and integer confidence parts-per-million (`0..1000000`).
  Floats, NaN, Infinity, locale-formatted numbers, duplicate keys, and unpaired
  surrogates are forbidden in signed/digested records. Digests are
  `SHA-256(domain || 0x00 || version || 0x00 || canonical_bytes)`; keyed commitments
  use HMAC-SHA-256 with the same framing. Golden byte/digest vectors are immutable
  fixtures shared by Python, TypeScript, SQLite, and PostgreSQL tests.

## AEAD envelopes and key separation

Every encrypted field uses a versioned envelope with `version`, `algorithm`,
`key_id`, `nonce`, `ciphertext`, and `tag`. Version 1 is AES-256-GCM with a fresh
96-bit CSPRNG nonce. A per-key `(key_id, nonce)` uniqueness constraint is enforced;
a collision retries with a new nonce and blocks after the bounded retry limit.
Associated data is canonical RFC 8785 JSON containing envelope version, algorithm,
tenant, session or policy scope, table, row ID, field name, purpose, policy version,
and absolute expiry. Copying ciphertext between any row, field, tenant, purpose, or
expiry MUST fail authentication.

Seeds never directly encrypt or MAC data. Each root-wrapped session, policy-version,
or project seed is exactly 32 random bytes and is the HKDF input keying material for
that scope. `salt = SHA-256(RFC8785({version:1,derivation_owner_type,
derivation_owner_id,tenant_id,application_id,seed_scope_type,seed_scope_id}))`.
Owner type is exactly `client_profile` or `server_tenant`. Seed scope type is exactly
`session`, `policy_version`, `project_store`, or `synthesis_spill`. All owner/scope/tenant/application
IDs are the base64url-no-padding encoding of 16 random bytes. `application_id` is
JSON null only for `policy_version`; it is required otherwise. Scope ID is the exact
ID of the named session, policy version, project store, or ephemeral spill set.
`info = UTF8("privacy-gateway") || 0x00 || uint16_be(1) || 0x00 || UTF8(label)`.
HKDF-Extract and HKDF-Expand are SHA-256; every v1 output below is 32 bytes. IDs are
the exact NFC JSON strings used in the salt object. HKDF-SHA-256 derives these
non-interchangeable keys with versioned ASCII labels:

- `value-encryption`, `mapping-match`, and `mapping-generation`;
- `policy-value-encryption` and `policy-match-commitment`;
- `audit-metadata-encryption` and `audit-integrity`;
- `audit-blind-index`;
- `capsule-encryption`, `capability-store-integrity`, and
  `project-store-encryption`;
- `synthesis-spill-encryption`.

Legal tuples are closed: `session` permits value-encryption, mapping-match,
mapping-generation, audit-metadata-encryption, audit-integrity, audit-blind-index,
capsule-encryption, and capability-store-integrity; `policy_version` permits only
policy-value-encryption, policy-match-commitment, audit-metadata-encryption,
audit-integrity, and audit-blind-index; `project_store` permits only
project-store-encryption; `synthesis_spill` permits only synthesis-spill-encryption.
Any other seed-scope/label tuple rejects before HKDF.

The server tenant registry and each client profile use the same separation model
with different roots. Tests MUST include forced nonce collision/retry/block,
cross-row/field/tenant/purpose/expiry substitution, wrong-version rejection, and
proof that no encryption key is accepted for a commitment or integrity operation.
Application capability-issuer Ed25519 keys are independently generated and are not
HKDF outputs; `capability-store-integrity` authenticates only local capability-store
records.

## Confidential queryable audit

Detection, policy, transform, and telemetry metadata is sensitive. Encrypted modes
persist locators, entity/detector/action names, confidence, policy details, source
digests, and free-form details only inside AEAD ciphertext. Query columns contain
opaque IDs, expiry/state, and tenant-keyed blind indexes for the approved exact
filters (`entity`, `detector`, `action`, `policy_version`); blind-index keys are
separate from encryption and integrity keys. Authorized query services decrypt the
matched rows and compute ranges/counts in memory. Free-text search is unsupported.
The client-local ledger follows the same rule with `audit-metadata-encryption`.
Storage-copy tests scan SQLite, IndexedDB exports, PostgreSQL dumps, WAL/log output,
and API defaults for fixture values and plaintext classifications.

## Principals, credentials, and authorization

Network credentials are short-lived OIDC JWT access tokens validated for issuer,
audience, signature, `tenant_id`, `sub`, `exp`, `nbf`, and unique `jti`. Maximum
Application-scoped operations additionally require `application_id`; an omitted,
empty, or mismatched claim denies. Maximum clock skew is 30 seconds; bearer tokens
in query strings are rejected. Local-only
commands use the OS account/keystore and explicit local profile rather than inventing
a JWT. The first-release roles/scopes are:

| Principal | Required scopes | Permitted operation |
| --- | --- | --- |
| application runtime | `transform`, `restore:text` | create/use its tenant sessions; restore client-visible text |
| capability issuer | `capability:issue` plus an application-owned Ed25519 issuer key | mint exact one-use side-effect grants for its own tenant/application |
| policy administrator | `policy:read`, `policy:write`, optional `policy:secret:reveal` | version policies; separately reveal encrypted literals |
| privacy auditor | `audit:read` | query/decrypt audit metadata; cannot restore values or mutate history |
| purge worker | `retention:purge` with workload identity | run only due/authorized cohort and session deletion state machines |
| compromise migrator | `key:migrate` with isolated workload identity | one-pass migration for keys already marked compromised-migrating |
| break-glass officer | offline hardware-backed break-glass root plus two-person recorded ceremony | authorize anchor-root compromise transition only |

Tenant and application claims are checked on every object reference. Every session
and session child stores a non-null application owner; tenant membership alone is
insufficient. Tokens and issuer keys have active/retired/revoked states and anchored
audit events. Revocation
is checked before every privileged operation. Side-effect capabilities contain a
random 256-bit secret. `secret_hash = SHA-256(UTF8("privacy-gateway-capability-
secret-v1") || 0x00 || secret_bytes)`. The issuer signs with Ed25519 the RFC 8785
grant `{version:1,capability_id,tenant_id,application_id,session_id,
policy_version_id,transform_id,capsule_id,generation_id,operation,sink,pgpath,
expires_at,jti,secret_hash_b64,issuer_key_id}`; signature is raw 64 bytes encoded
base64url-no-padding. IDs are 16 random bytes in base64url-no-padding and the secret
is presented separately in the same encoding. The store verifies signature/key
state/object associations, persists the active grant and only the hash before return,
and compares a presented secret hash in constant time.
After complete payload validation, one transaction compare-and-sets every required
capability from `active` to `consumed_pending_dispatch` and writes one dispatch
intent/idempotency key before any original is materialized. There is no `consumed`
state. A successful idempotent downstream acknowledgement transitions the whole set
to `dispatched`; a definitive local failure before any send transitions it to
`revoked` and requires newly issued capabilities; timeout, process crash after a
send may have begun, or a downstream without a verifiable idempotency contract
transitions/reconciles to `indeterminate` and blocks automatic retry. Recovery may
resume only when the downstream proves the same idempotency key was not executed or
returns its prior result. Stage 1
owns role/scope/object authorization primitives, Stage 2 owns capability issuance/
consumption, and Stage 3 owns OIDC and adapter enforcement.

## Gateway capsule HPKE profile

Gateway-to-client handoff uses RFC 9180 HPKE Base mode (`mode=0x00`) with
`KEM_ID=0x0020` DHKEM(X25519, HKDF-SHA256), `KDF_ID=0x0001` HKDF-SHA256, and
`AEAD_ID=0x0002` AES-256-GCM. X25519 public keys and `enc` use the suite's raw
32-byte encoding. `info` is UTF-8 `privacy-gateway-hpke-v1`, one zero byte, then
SHA-256 of the canonical binding object. AEAD AAD is that RFC 8785 object:
`{version,tenant_id,application_id,session_id,policy_version_id,transform_id,
capsule_id,request_nonce,expires_at}`. `request_nonce` is 32 random bytes; random
IDs/nonces are case-sensitive base64url without padding; expiry is integer epoch
microseconds.

The wire object is canonical JSON
`{version:1,suite:"0020-0001-0002",enc,ciphertext,binding}` with byte fields
base64url-no-padding. Plaintext is canonical JSON
`{version:1,mappings:[...],ack_nonce}`. `ack_nonce` is 32 random bytes encoded
base64url-no-padding. `mappings` is sorted by decoded `generation_id` bytes; every
entry is exactly `{version:1,mapping_id,generation_id,entity,locale,action,
surrogate,canonical_surrogate,original_utf8_b64,expires_at}`. IDs are 16 random
bytes in base64url-no-padding, enum strings come from the compatibility manifest,
surrogate/canonical fields are JSON strings, original is the exact well-formed UTF-8
source bytes in base64url-no-padding, and expiry is integer epoch microseconds no
later than capsule/session expiry. Duplicate generation/canonical-surrogate entries,
unknown fields/enums, unsorted order, or an entry whose canonicalizer does not
reproduce `canonical_surrogate` blocks. Both peers
call the HPKE exporter with context UTF-8 `privacy-gateway-ack-v1` and length 32.
Acknowledgement is canonical JSON `{version:1,capsule_id,request_nonce,proof}`, where
`proof` is base64url-no-padding HMAC-SHA-256 of canonical
`{version,capsule_id,request_nonce,ack_nonce}` under the exported key. This proves
HPKE possession, not durable client storage. Before erasing plaintext handoff and
exporter material, the gateway stores only
`SHA-256(UTF8("privacy-gateway-expected-ack-v1") || 0x00 || proof_bytes)` with
capsule ID/expiry and the original request nonce. The ack handler first constant-time
compares the supplied request nonce to that stored value, then hashes the decoded
32-byte received proof identically for a constant-time comparison; it deletes both
nonce and digest on ack/timeout.
RFC 9180 vectors plus one repository
vector freezing every byte above are shared by Python, TypeScript, and WebCrypto.

## Time and expiry

All deadlines are absolute integer UTC epoch microseconds and expire when
`effective_now >= expires_at`. Expiry is latched: after a record is observed expired,
an immutable tombstone/state transition prevents any later clock movement from
reactivating it.

Gateway and managed modes require a healthy authenticated time source, synchronized
to UTC, with a configured maximum uncertainty of 30 seconds. The repository clock
accepts a canonical JSON time attestation
`{version:1,source_id,key_id,issued_at,valid_until,uncertainty_us,nonce}` plus an
Ed25519 signature from a configured pinned time-authority key. `source_id` and
`key_id` are NFC ASCII `[A-Za-z0-9._-]{1,64}` and select an exact
`time_authority_keys(source_id,key_id,public_key,state)` version. The signature is
raw 64 bytes encoded base64url-no-padding over the RFC 8785 attestation. `nonce` is
32 random request bytes encoded base64url-no-padding. All times are integer epoch
microseconds; `valid_until-issued_at <= 60 seconds`; the
contract also requires `issued_at <= valid_until` and
`0 <= uncertainty_us <= 30000000`. The attestation is rejected as rollback when
`issued_at + uncertainty_us < persisted_high_water`. Replay, unknown/
revoked source key, invalid signature, excessive lifetime, nonce mismatch, or
an uncertainty-bound violation is unhealthy. The source may be backed by NTS or a
managed signed-time service, but this attestation is the only repository interface.
The repository clock snapshots `base_effective_now = max(issued_at + uncertainty_us,
persisted_high_water)` and the process-monotonic counter on receipt, conservatively
using the upper time bound so uncertain time can expire early but never serve a
possibly expired value. Between attestations, `effective_now = base_effective_now +
(monotonic_now - monotonic_at_receipt)` and is valid only while it is no later than
`valid_until + uncertainty_us`; afterward reversible operations block pending a new
attestation. The high-water mark advances transactionally on every reversible read/
write and expiry transition. If time authentication is unavailable, moves backward, or reports
uncertainty above the bound, protection may still perform irreversible redaction but
reads/restoration of reversible material and new reversible writes fail closed.
SQLite uses the application clock under its single-writer lock; PostgreSQL requires
`abs(transaction_timestamp_us - effective_now) <= 30000000` and blocks on greater
disagreement.

Offline client-local runtimes cannot claim externally exact wall-clock enforcement.
They persist a profile high-water mark, combine it with process-monotonic elapsed
time, latch expiry, and block reversible reads/writes when rollback or uncertainty
exceeds 30 seconds until authenticated time is available. A forward jump may expire
data early; that availability tradeoff is explicit. Tests inject deadline equality,
forward/backward jumps, reboot/high-water recovery, source loss, excess skew, and
database/anchor disagreement. “Exact expiry” in this repository means exact deadline
comparison under this clock contract, not resistance to a compromised OS/hardware
clock.

## Frozen policy surface

The first-release entity catalog is:
`EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `US_SSN`, `IP_ADDRESS`, `API_KEY`,
`PERSON`, `ORGANIZATION`, `LOCATION`, `DATE_TIME`, `MONEY`, `URL`, `IBAN_CODE`,
`US_BANK_NUMBER`, `PASSPORT`, `DRIVER_LICENSE`, and `MEDICAL_LICENSE`.

Actions and reversibility are fixed:

| Action | Reversible allowed | Output contract |
| --- | --- | --- |
| `keep` | no | original unchanged, audited as pass-through |
| `redact` | no | constant entity label, no source-derived suffix |
| `label` | no | entity label preserving neither length nor value |
| `tokenize` | required | authenticated tagged surrogate |
| `hash` | no | tenant-keyed digest; raw SHA hashes are forbidden |
| `generalize` | optional | entity-specific bucket; mapping required when reversible |
| `synthetic` | optional | format/checksum-valid value; mapping required when reversible |

Built-in presets are versioned fixtures, not mutable aliases. `Balanced` tokenizes
all entities except API keys (redact), dates/money (generalize), and URLs (keep).
`Strict` redacts API keys, payment/bank/government/license identifiers and tokenizes
the rest. `Healthcare` redacts API keys, CREDIT_CARD, US_SSN, IBAN_CODE,
US_BANK_NUMBER, PASSPORT, DRIVER_LICENSE, and MEDICAL_LICENSE and uses reversible
synthetic PERSON/LOCATION/DATE_TIME. `Finance` redacts API keys and
government identifiers, tokenizes bank/card identifiers, and synthesizes MONEY.
`DevSecOps` redacts API keys, tokenizes email/phone/IP, and keeps PERSON,
ORGANIZATION, LOCATION, DATE_TIME, MONEY, and URL. Unlisted entities use tokenize.
`tokenize` is always reversible. `generalize` and `synthetic` default to irreversible
unless the manifest has an explicit true reversibility override; therefore Balanced
DATE_TIME/MONEY generalization and Finance MONEY synthesis are irreversible, while
the three Healthcare synthetic overrides are reversible.

## Tagged token grammar

The v1 token surface is ASCII
`[[PG1|ENTITY|GENERATION|AUTH]]`. `ENTITY` is a manifest enum. `GENERATION` is the
RFC 4648 Base32 uppercase/no-padding encoding of the 16 random generation-ID bytes
(exactly 26 characters). `AUTH` is Base32 uppercase/no-padding encoding of the first
10 bytes of HMAC-SHA-256 under `mapping-generation` over canonical
`{version:1,tenant_id,application_id,session_id,generation_id_b64,entity}` (exactly
16 characters). Allocation reserves the canonical uppercase exact token.

The tolerant parser accepts ASCII case variation for `PG1`, entity, generation, and
auth, and zero or one ASCII space on either side of each `|` plus zero or one ASCII
space immediately after `[[` and before `]]`. Delimiters remain exact ASCII `[[`,
`|`, `]]`; no newline, Unicode whitespace, extra/missing delimiter, padding, or other
edit is accepted. Parsing case-normalizes to uppercase, decodes lengths, verifies
the entity and authenticator in constant time, then looks up the exact bound
generation. This grammar is also the unknown-SSE-event surrogate scanner.

Deterministic built-in regex/checksum coverage is mandatory for email, E.164/NANP
phone, Luhn cards, US SSN, IPv4/IPv6, the exact API-key regex families in the
machine manifest, absolute ASCII HTTP/HTTPS URL with nonempty host and no userinfo,
IBAN for the manifest's frozen country-length table,
and US routing numbers. PERSON/ORGANIZATION/LOCATION/DATE_TIME/MONEY and license/
passport coverage require a declared healthy Presidio/spaCy/GLiNER model when a
policy marks them required. First-release locale fixtures are `en-US`, `es-ES`,
`de-DE`, and `fr-FR`; locale-sensitive date/money/phone generators cover all four.
ML language support is adapter-manifest-specific and a required missing language
blocks.

Precedence is: malformed/ambiguous input blocks; explicit deny-list match wins;
scope-excluded candidates are removed; exact allow-list match removes a candidate
unless deny-listed; then required detector health/confidence applies; overlaps sort
by deny-list, policy priority, confidence ppm, longest byte span, earliest start,
entity enum, detector ID. Remaining exact ties must produce the same decision.

Tolerant restoration is finite, not edit-distance guessing. Tagged tokens use only
the case/space variants in the exact grammar above. Format-valid synthetics use
entity canonicalizers already used
by allocation under these exact rules:

- Phone accepts only ASCII digits plus leading `+`, ASCII space, `-`, `.`, `(`, `)`;
  punctuation is removed, parentheses must balance, `+` may occur only first, and
  canonical output is `+` plus 8-15 digits. Values without `+` receive the fixed
  policy-locale country code and must match the exact country code/national-digit
  count in the machine manifest.
- Card accepts either 13-19 contiguous digits or groups of four digits plus a final
  group of one-to-four, separated uniformly by one ASCII space or uniformly by one
  hyphen; mixed/leading/trailing/doubled separators reject. It requires Luhn and
  canonicalizes to digits. SSN accepts exactly `AAAGGSSSS` or `AAA-GG-SSSS`/
  `AAA GG SSSS`; area `000`, `666`, and `900..999`, group `00`, and serial `0000`
  reject; canonical output is nine digits.
- IBAN accepts ASCII letters/digits with optional single spaces every four symbols,
  uppercases ASCII, removes spaces, validates country length and MOD-97, and emits
  uppercase compact form. US routing accepts nine contiguous digits or exactly
  `AAA-AAA-AAA`/`AAA AAA AAA`, validates the ABA checksum, and canonicalizes to digits.
- Generated email is ASCII dot-atom. Local labels are nonempty and use alphanumeric
  bytes plus ASCII code points `33,35,36,37,38,39,42,43,45,47,61,63,94,95,96,
  123,124,125,126`; labels are separated by single dots with no leading/trailing/
  consecutive dot and total local length at most 64. The domain has at least two
  LDH labels, each 1-63 characters with no leading/trailing hyphen, and total length
  at most 253. Local part is byte-exact; domain lowercases ASCII. Quoted local parts,
  address literals, non-ASCII, and IDNA tolerance are unsupported.
- Dates accept ISO `YYYY-MM-DD` everywhere, `MM/DD/YYYY` for `en-US`, `DD/MM/YYYY`
  for `es-ES`/`fr-FR`, and `DD.MM.YYYY` for `de-DE`; Gregorian validity is required
  and canonical output is ISO. The configured locale resolves numeric ambiguity.
- Money permits an optional leading ASCII `-` but no `+`, parentheses, exponent, or
  surrounding whitespace. ISO form is exactly uppercase `CCC`, one ASCII space,
  then an ungrouped integer (`0` or nonzero digit followed by digits), `.`, and two
  decimals. Locale-symbol form is `$` immediately before the number for `en-US`, or
  the number then one ASCII space then `€` for `es-ES`, `de-DE`, and `fr-FR`. Its
  integer is `0` or a nonzero one-to-three digit first group followed by zero or more
  exact three-digit groups; thousands/decimal bytes are exactly the manifest values
  and exactly two decimals are required. Sign precedes ISO code/prefix symbol, or
  the number in suffix-symbol locales. Locale fixes symbol→currency; other symbols/
  codes reject. Canonical output is `ISO4217:signed_minor_integer`.

No arbitrary insertion, deletion, Unicode whitespace, mixed separator, or
Levenshtein match is supported. Reservation stores the digest of validated canonical
output plus entity and locale, so every accepted surface form in one equivalence
class shares one reservation without enumerating an unbounded set.

## Frozen adapter surface

Provider paths in the machine manifest use `PGPath-v1`, not plain RFC 6901: leading
slash and RFC 6901 escaping apply, but an entire segment `*` matches exactly one
array element and never an object property; `*` elsewhere is invalid. Traversal is
array-index ascending then object-key UTF-8 byte order. Duplicate JSON keys reject
before path evaluation. Every request/response text PGPath is `string_leaf_only`: a
match transforms only when that exact node is a string; object/array/number/null
type mismatch is skipped so more-specific descendants still evaluate. All matching
paths are expanded first, identical concrete pointers are deduplicated, and each
string leaf is transformed once in concrete-pointer byte order. An ancestor string
cannot have a descendant, eliminating double transform. A blocked-side-effect path
accepts any node and recursively scans its complete subtree without restoring it.

- OpenAI: `/v1/responses` and `/v1/chat/completions`, JSON and SSE streaming, for
  the request/response fields in checked-in OpenAPI fixtures. Transparent mode
  restores only text output; tool/function arguments containing surrogates block.
- Anthropic: `/v1/messages`, JSON and SSE streaming, for checked-in Messages API
  fixtures. Transparent mode restores only text blocks; `tool_use` input containing
  surrogates blocks.
- Generic middleware: Python ASGI and TypeScript Fetch request/response adapters for
  JSON and UTF-8 text only. Multipart, protobuf, compressed opaque bodies, WebSocket,
  and arbitrary binary pass-through are unsupported and block when protection is
  required.
- Webhooks: inbound/outbound `application/json` only. Headers are
  `X-Privacy-Gateway-Timestamp` (unsigned decimal epoch seconds, no leading zero),
  `X-Privacy-Gateway-Delivery` (lowercase canonical UUIDv4),
  `X-Privacy-Gateway-Key-Id` (ASCII `[A-Za-z0-9._-]{1,64}`), and
  `X-Privacy-Gateway-Signature` (`v1=` plus 64 lowercase hex HMAC characters).
  Webhook keys are 32 random bytes. Signature bytes are HMAC-SHA-256 under the named webhook key over
  `timestamp_ascii || "." || delivery_uuid_ascii || "." || raw_body_bytes`.
  The same authenticated `effective_now` contract evaluates
  `abs(effective_now_seconds - timestamp) < 300`; accepted delivery IDs are stored
  per tenant/application/key until absolute `timestamp + 300 seconds` (never merely
  300 seconds from receipt) and duplicates reject through that deadline. Active keys
  sign and verify. A retired key verifies only when `timestamp <= retired_at` and
  `effective_now_seconds <= timestamp + 300`; its public/verification material cannot
  be deleted before that last eligible deadline. Revoked keys reject immediately.
  Policy paths use PGPath-v1. Redirects and caller-supplied destinations are forbidden.
- MCP: stdio and Streamable HTTP tools `protect_text`, `protect_json`,
  `restore_client_text`, `inspect_policy`, and `verify_round_trip`; side-effect
  restoration is not exposed as a generic MCP tool. Every tool declares all four
  MCP tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`,
  `openWorldHint`) as booleans: `protect_text` and `protect_json` write to the
  gateway's own vault (not read-only, not destructive, not idempotent), the other
  three are read-only and idempotent, and none reaches outside the gateway.

SSE uses UTF-8 lines, permits comments, joins consecutive `data:` lines with LF,
and rejects when joined data exceeds 1,048,576 UTF-8 bytes or total stream input
exceeds 16,777,216 UTF-8 bytes; both counts include bytes before restoration and
the defaults are hard v1 compatibility limits. OpenAI Chat Completions accepts only
`data: <JSON>` chunks matching manifest paths and terminates on exact
`data: [DONE]`; an `error` object blocks. OpenAI Responses accepts event names
`response.output_text.delta` (text at `/delta`), `response.completed` (terminal),
`response.failed`, and `error` (both terminal-blocking). Anthropic Messages accepts
`content_block_delta` with text at `/delta/text`, terminal `message_stop`, and
terminal-blocking `error`. Unknown events may pass only when they contain no string
matching the surrogate grammar; otherwise they block. EOF before a terminal event
blocks. Text deltas enter the incremental restorer in event order; JSON/tool fields
are fully buffered under the side-effect rules.

The exact endpoints, transforms, blocked pointers, transports, webhook protocol,
and MCP names are frozen in `contracts/compatibility-v1.json`; dated provider
fixtures are validated against that manifest. “Compatible” means that manifest and
those fixtures pass; it never means every present or future provider endpoint.

## Structured synthesis privacy-risk report

The report declares an attacker model: the evaluator knows selected quasi-identifier
columns and may possess a withheld real holdout set, but does not receive secret
mapping keys. Configuration must name quasi-identifiers, sensitive attributes, and
warning thresholds. In the formulas, `R` is the real training table, `H` is its
schema-compatible withheld real holdout, and `S` is the synthetic table. Primary and
foreign keys are always excluded. `included_columns` is every remaining shared
column for exact-row matches. `evaluation_columns` is an explicit ordered config
list, defaulting to `included_columns`, for row distance/DCR; it MUST contain at
least one column or distance/DCR metrics are `not_evaluable`. Quasi-identifiers and
sensitive attributes must be subsets of included columns and are used only by their
named k/l metrics. Reports contain aggregates, no raw example rows by default:

- exact real-row match rate and unique-real-row match count (target `0`);
- minimum and distribution of k-anonymity equivalence-class sizes over configured
  quasi-identifiers (default warning when `k < 5`);
- per-sensitive-attribute distinct l-diversity (default warning when `l < 2`);
- distance-to-closest-record for continuous/ordinal normalized fields plus categorical
  mismatch, reported for synthetic→training and synthetic→holdout;
- nearest-neighbor distance ratio `DCR(training) / DCR(holdout)` with the fraction
  below `1.0` (default warning above `0.5`);
- primary/foreign-key leakage excluded from row-match metrics but separately checked
  for copied non-key values and referential validity.

Keys are excluded from row-distance and exact-match columns. Exact row-match rate is
`count(s in S with any r in R equal on every included column) / |S|`; unique-real-
row match count counts matched training rows occurring once in `R`. Strings are NFC
byte-exact, booleans/categoricals use equality, dates use UTC epoch-day, and numbers
use decimal arithmetic. Null/null distance is 0 and null/non-null is 1. Each numeric
or date distance is absolute difference divided by the training max-minus-min and
clipped to 1; a zero range is 0 for equal and 1 otherwise. Categorical/string/
boolean distance is 0 equal and 1 unequal. Row distance is the arithmetic mean over
the ordered `evaluation_columns` with equal column weight.

For each synthetic row, DCR is the minimum row distance to the named real set; ties
do not affect it. Nearest-neighbor ratio is `DCR(training)/DCR(holdout)`: `0/0` is
1, positive/0 is positive infinity, and 0/positive is 0. Its fraction-below-1
denominator is synthetic rows with both sets available. k-anonymity groups `S` by
the exact configured quasi-identifier tuple (null is a value) and reports minimum
and histogram. Distinct l-diversity is computed separately for each configured
sensitive attribute: it counts that attribute's distinct values, including null,
inside each quasi-identifier group and reports the minimum per attribute. Non-key value-copy rate
is copied non-key cells divided by all non-key synthetic cells, comparing each cell
to the same-column training multiset.

Empty training or synthetic data, no included non-key columns, missing configured
columns, or absent/empty holdout for holdout metrics produces `not_evaluable` for
the affected metric, never a passing zero. Thresholds
produce warnings or policy-configured CI failure; they are diagnostics, not a claim
of anonymity, differential privacy, or resistance to an unspecified attacker.
Golden hand-computed fixtures and adversarial memorization fixtures are mandatory.
