# Stage 4 contract: clean-room structured synthetic data

Status: active first-release gate.

This module is an original MIT implementation. It does not import, vendor, or copy
SDV code. General workflow ideas—schema metadata, relationships, constraints, and
quality evaluation—are not an API or implementation dependency.

## Included in v0.1

- CSV, JSON array, and JSONL reading/writing.
- Schema inference for null, boolean, integer, float, date, email, phone,
  categorical, and free-text columns, with diagnostics for mixed types.
- Explicit schema metadata, nullable fields, numeric ranges, categories, primary
  keys, foreign keys, and locale selection.
- Seeded, deterministic generation with unique primary keys and referentially valid
  multi-table foreign keys.
- Quality reports containing schema/type/nullability and aggregate distribution
  comparisons without raw example values.
- Privacy reports containing exact row match rate, non-key cell copy rate,
  quasi-identifier k-anonymity, per-sensitive-column l-diversity, and warnings.
- CLI generation with explicit input/output paths and local-only execution.

## Acceptance

- Golden inference tests, explicit override tests, all three file formats, seeded
  repeatability, PK uniqueness, FK integrity, nullability/range/category/format
  constraints, locale selection, and no-network behavior.
- Hand-checkable quality/privacy report fixtures; empty/degenerate inputs return
  `not_evaluable` instead of passing or dividing by zero.
- Reports and exceptions contain no raw source examples.
- Source/dependency audit confirms no SDV runtime or copied implementation.
- Full Python/TypeScript regression suites and lint/build gates pass.

## Not claimed in v0.1

The generator preserves declared structure and coarse distributions; it is not a
statistical privacy guarantee, differential privacy system, or replacement for
domain review. Image synthesis, learned generative models, encrypted disk spill,
and dataset-scale streaming are roadmap items.
