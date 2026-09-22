# Evaluation corpus

`cases.jsonl` contains invented values only. It exercises common leak, false-positive, overlap,
and round-trip cases without customer data. Add deployment-specific synthetic fixtures for every
enabled locale and custom recognizer. Never copy production prompts into this directory.

The authoritative executable fixtures live in `tests/` and `conformance/core-v1.json`.
