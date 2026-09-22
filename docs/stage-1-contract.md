# Stage 1 Contract — Portable Text Core

This contract replaces the over-expanded Stage 1 gate in the initial planning ledger for the
first releasable slice. It is intentionally tied to the user's original product request. More
advanced managed-service, image, PostgreSQL, anchor, key-rotation, and streaming work belongs
to later stages and must not be implied by this stage.

Stage 1 may be marked done only after its automated checks pass and a zero-context skeptic
returns `FAILED TO REFUTE` against these artifacts.

## Required behavior

1. The 17 entity types, seven actions, five presets, and preset overrides match
   `contracts/compatibility-v1.json` in Python and TypeScript.
2. A policy can independently configure action, enabled state, reversibility, integer
   confidence ppm, priority, locale, scope, required detectors, mapping retention, audit
   retention, allow terms, and deny terms. Invalid reversible combinations and duplicate
   entity rules reject.
3. A pluggable detector interface supports a deterministic local recognition floor. Email,
   phone, payment card (Luhn), SSN validity rules, IP, API keys, date, money, absolute HTTP(S)
   URL without userinfo, IBAN (country length plus mod-97), and US routing number (ABA checksum)
   are recognized where enabled. Presidio is an optional adapter; unavailable required
   detectors block.
4. Public spans are half-open UTF-8 byte offsets into the original string. Replacement uses
   origin character positions without offset drift. Deny list, priority, confidence, length,
   start, entity, and detector order make overlap resolution deterministic. Allow terms are
   excluded before transformation.
5. Every action has an explicit operator. Tagged tokens follow
   `[[PG1|ENTITY|GENERATION|AUTH]]`; generations are random per mapping and repeated source
   values within one transform reuse one replacement. Reversible actions block unless a
   server master key or a client restore key exists.
6. Detector exceptions and unavailable required detectors return `blocked` with `text=null`.
   Callers are never given the original input as a fallback output.
7. SQLite stores policy/session state, encrypted originals for server-side reversible
   mappings, a keyed match fingerprint, unique replacements, and a queryable row for every
   applied detection containing entity, detector, confidence ppm, action, policy name/version,
   source digest, byte span, mapping reference, and integer timestamps. Original values do not
   appear in detection or audit detail rows.
8. Persistent reversible storage and session metadata fail closed without an explicit
   32-byte key. AES-GCM uses a fresh 96-bit nonce and row-specific AAD. Expiry is enforced on
   read and by explicit purge. Expired mappings cannot restore.
9. Client-held capsule mode works without a server master key and does not persist original
   mapping values. Exact and documented tagged-token case/spacing tolerance restores display
   text; capsule tampering and wrong keys reject.
10. Recursive JSON transformation preserves non-string values and uses one session. A blocked
    leaf blocks the operation rather than returning a partially protected object.
11. `conformance/core-v1.json` is consumed by Python and TypeScript tests. Both runtimes prove
    catalog/preset parity, UTF-8 byte offsets, checksum behavior, keyless blocking, within-call
    bijection, and exact restoration for the common portable floor.
12. The package installs, the CLI loads, and `privacy-gateway verify` proves round-trip,
    tolerant tagged-token restoration, keyless fail-closed behavior, and absence of the sample
    email from protected output.

## Evidence commands

```bash
pytest
ruff check src tests
ruff format --check src tests
npm run check
npm test
npm run build
python -m build
privacy-gateway verify
```

Passing these commands is necessary but not sufficient.

**Status: FAILED TO REFUTE — 2026-09-21.** The same zero-context skeptic reviewed the
candidate, refuted it with concrete findings, rechecked each correction, and returned the
exact final verdict `VERDICT: FAILED TO REFUTE`. The closing evidence was 32 passing Python
tests, eight passing TypeScript tests, clean Ruff/typecheck/build results, a passing CLI probe,
and a successful Python sdist/wheel build.

## Explicit non-claims

Stage 1 does not claim PostgreSQL support, managed multi-tenancy, encrypted audit metadata,
tamper-evident external anchors, production key rotation, images/OCR, stream safety, proxy
correctness, structured synthetic-data generation, deployment health, or third-party security
certification. Those cannot appear as completed features in release documentation until their
own stage gates close.
