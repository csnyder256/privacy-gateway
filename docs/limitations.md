# Limitations and non-guarantees

- Detection is probabilistic outside deterministic regex/checksum recognizers. A clean result is
  not proof that input contains no personal or confidential data.
- Browser onboarding preview implements only a small deterministic demonstration subset. The
  installed runtime is authoritative.
- The built-in regex detector is strongest for the documented English/US and checksum-backed
  formats. Presidio is optional; spaCy/GLiNER and image OCR are extension points, not bundled v0.1
  features.
- The TypeScript core is in-process/browser capable but does not persist a local audit database.
- OpenAI/Anthropic proxies support non-streaming JSON only. Tool/side-effect fields containing a
  restorable surrogate are rejected rather than automatically restored.
- v0.1 ships encrypted single-operator SQLite storage, not PostgreSQL or an authenticated
  multi-tenant managed service.
- Synthetic data preserves declared types, ranges, null rates, categories, relationships, and
  coarse aggregates. It is not differential privacy and can still be unsafe for release without
  reviewing its privacy report and domain-specific risks.
- No deletion API can prove physical erasure from SSD wear leveling, snapshots, logs, or backups.
