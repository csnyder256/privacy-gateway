# Stage 2 Contract — Client and Streaming Restoration

Stage 2 is complete only when the evidence commands pass and one zero-context skeptic returns
`FAILED TO REFUTE`.

## Required behavior

1. Python and TypeScript expose an incremental tagged-token restorer using the Stage 1 reverse
   map. Tokens split at every possible chunk boundary restore exactly once.
2. The restorer never emits a partial recognized Privacy Gateway token. It retains only a
   bounded candidate suffix and does not buffer unrelated response text indefinitely.
3. Exact tokens and the compatibility contract's bounded ASCII case/spacing variants restore.
   Tabs, multiple spaces, malformed tags, and foreign/unmapped valid tags remain unchanged.
4. `finish()` flushes an incomplete or malformed suffix unchanged. Feeding data after finish
   or finishing twice rejects.
5. Python can construct the stream restorer directly from a client-held encrypted capsule;
   tampered capsules and wrong keys reject before any content is processed.
6. Recursive response restoration changes string leaves only. Callers can provide blocked
   JSON-pointer prefixes (such as tool arguments); matching subtrees remain untouched.
7. Shared fixtures and exhaustive split-point tests exercise both runtimes.

## Non-claims

This stage does not authorize executing restored tool arguments, persist one-use capabilities,
implement HPKE handoff, or claim provider-specific SSE proxy correctness. Those belong to the
integration stage.

## Evidence commands

```bash
pytest
ruff check src tests
ruff format --check src tests
npm run check
npm test
npm run build
```

**Status: FAILED TO REFUTE — 2026-09-21.** The zero-context skeptic first refuted
composite-surrogate streaming, JavaScript Unicode case folding, and candidate buffering.
After corrections and direct re-probes, the same reviewer returned
`VERDICT: FAILED TO REFUTE`. Closing evidence: 44 Python tests and 15 TypeScript tests,
with clean lint, formatting, typecheck, and build results.
