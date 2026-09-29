"""Exact-span local benchmarks. No source values are copied into reports."""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import math
import platform
import statistics
import tempfile
import time
from collections import Counter
from pathlib import Path

from . import __version__
from .detectors import PresidioDetector, RegexDetector
from .engine import PrivacyEngine
from .models import Action, EntityType, Policy, PolicyRule
from .vault import Vault

PACKAGE = Path(__file__).parent


def dataset_bytes(path: Path | None = None) -> bytes:
    source = path or PACKAGE / "benchmark-cases.jsonl"
    if source.stat().st_size > 20_000_000:
        raise ValueError("benchmark corpus exceeds 20 MB")
    return source.read_bytes()


def load_cases(raw: bytes) -> list[dict]:
    cases = []
    try:
        for line in raw.decode("utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("text"), str)
                or not isinstance(row.get("expected"), list)
            ):
                raise TypeError("each case requires text and an expected span list")
            if len(row["text"].encode()) > 200_000:
                raise ValueError("case text exceeds 200 KB")
            text = row["text"].encode()
            labels = []
            for span in row["expected"]:
                entity = EntityType(span["entity"])
                start, end = span["start"], span["end"]
                if (
                    type(start) is not int
                    or type(end) is not int
                    or not 0 <= start < end <= len(text)
                ):
                    raise ValueError("labels require ordered UTF-8 byte offsets")
                text[:start].decode("utf-8")
                text[start:end].decode("utf-8")
                labels.append((entity.value, start, end))
            if len(labels) != len(set(labels)):
                raise ValueError("duplicate labeled spans")
            allow = row.get("allow_terms", [])
            if not isinstance(allow, list) or not all(isinstance(x, str) for x in allow):
                raise ValueError("allow_terms must contain strings")
            cases.append({"text": row["text"], "expected": labels, "allow_terms": allow})
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid labeled JSONL corpus") from exc
    if not cases or len(cases) > 10_000:
        raise ValueError("corpus must contain between 1 and 10000 cases")
    return cases


def select_detectors(mode: str):
    if mode == "regex":
        return [RegexDetector()]
    if mode == "presidio":
        # Explicit selection must never silently turn into regex-only results.
        return [RegexDetector(), PresidioDetector()]
    raise ValueError("detector must be regex or presidio")


def run_benchmark(*, detectors=None, repeats: int = 20, raw: bytes | None = None) -> dict:
    if type(repeats) is not int or not 1 <= repeats <= 1000:
        raise ValueError("repeats must be an integer from 1 to 1000")
    source = dataset_bytes() if raw is None else raw
    cases = load_cases(source)
    configured = list(detectors) if detectors is not None else [RegexDetector()]
    policy = Policy(
        name="benchmark-exact-span-v1",
        rules=[
            PolicyRule(entity=entity, action=Action.REDACT, reversible=False)
            for entity in EntityType
        ],
        mapping_retention_seconds=60,
        audit_retention_seconds=60,
    )
    rows, durations, by_entity = [], [], {}
    with tempfile.TemporaryDirectory(prefix="privacy-benchmark-") as temporary:
        engine = PrivacyEngine(Vault(Path(temporary) / "benchmark.db"), detectors=configured)
        for index, case in enumerate(cases):
            selected = policy.model_copy(update={"allow_terms": case["allow_terms"]})
            expected = set(case["expected"])
            # Warm up once per case. SQLite lifecycle and audits are part of transform timing.
            first = engine.transform(case["text"], policy=selected)
            engine.vault.delete_session(first.session_id)
            actual = {(d.entity.value, d.start, d.end) for d in first.detections}
            state = first.state.value
            for _ in range(repeats):
                started = time.perf_counter_ns()
                result = engine.transform(case["text"], policy=selected)
                elapsed = (time.perf_counter_ns() - started) / 1_000_000
                engine.vault.delete_session(result.session_id)
                measured = {(d.entity.value, d.start, d.end) for d in result.detections}
                if measured != actual or result.state.value != state:
                    raise ValueError("detector outcomes changed across identical repetitions")
                durations.append(elapsed)
            tp, fp, fn = len(actual & expected), len(actual - expected), len(expected - actual)
            rows.append(
                {
                    "case": index + 1,
                    "expected": len(expected),
                    "detected": len(actual),
                    "true_positives": tp,
                    "false_positives": fp,
                    "false_negatives": fn,
                    "state": state,
                }
            )
            for entity in sorted({x[0] for x in expected | actual}):
                count = by_entity.setdefault(entity, Counter())
                count["true_positives"] += len({x for x in actual & expected if x[0] == entity})
                count["false_positives"] += len({x for x in actual - expected if x[0] == entity})
                count["false_negatives"] += len({x for x in expected - actual if x[0] == entity})
    totals = {
        key: sum(row[key] for row in rows)
        for key in ["true_positives", "false_positives", "false_negatives"]
    }
    tp, fp, fn = (totals[k] for k in ["true_positives", "false_positives", "false_negatives"])
    totals.update(
        precision=tp / (tp + fp) if tp + fp else None,
        recall=tp / (tp + fn) if tp + fn else None,
        f1=2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        blocked_cases=sum(r["state"] == "blocked" for r in rows),
    )
    code = b"".join(
        (PACKAGE / name).read_bytes()
        for name in [
            "benchmark.py",
            "detectors.py",
            "engine.py",
            "models.py",
            "vault.py",
            "crypto.py",
        ]
    )
    # Dataset and code digests describe reproducibility. They do not anonymize an input corpus.
    ordered = sorted(durations)
    return {
        "schema": "privacy-gateway.benchmark",
        "version": 1,
        "provenance": {
            "package_version": __version__,
            "dataset_sha256": hashlib.sha256(source).hexdigest(),
            "engine_sha256": hashlib.sha256(code).hexdigest(),
            "detectors": sorted(d.name for d in configured),
            "python": platform.python_version(),
            "platform": platform.system(),
            "policy": "all entities enabled, redact, non-reversible, 500000 ppm, exact-span v1",
            "case_count": len(cases),
            "repeats": repeats,
            "warmup_per_case": 1,
        },
        "accuracy": totals,
        "by_entity": {key: dict(value) for key, value in sorted(by_entity.items())},
        "cases": rows,
        "timing": {
            "median_ms": statistics.median(ordered),
            "p95_ms": ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)],
            "minimum_ms": min(ordered),
            "samples": len(ordered),
            "scope": "transform including session creation, detection, replacement and SQLite audit; excluding warmup, deletion, HTTP, upstream and detector initialization",
        },
        "limitations": [
            "Small invented fixture corpus. This is not an estimate of production PII coverage.",
            "An exact entity and UTF-8 byte span is a match. Partial spans and wrong entities count as false positive plus miss.",
            "Overlaps and allow terms use the real policy engine. Keep/disabled rules and other policy presets are not benchmarked.",
            "Regex does not detect contextual names; misses remain visible. Add deployment-specific synthetic fixtures and recognizers.",
            "Reports omit text, original values, replacements, recovery keys and capsules. Corpus digests can still identify known input data.",
            "Accuracy counts are reproducible for identical corpus/code/detectors. Timing varies with environment and load.",
        ],
    }


def write_report(doc: dict, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    payload = json.dumps(doc, indent=2, sort_keys=True, allow_nan=False) + "\n"
    (output / "benchmark.json").write_text(payload, encoding="utf-8")
    out = io.StringIO(newline="")
    writer = csv.DictWriter(out, fieldnames=list(doc["cases"][0]))
    writer.writeheader()
    writer.writerows(doc["cases"])
    (output / "benchmark.csv").write_text(out.getvalue(), encoding="utf-8")
    escaped = html.escape(payload)
    rows = "".join(
        "<tr>"
        + "".join("<td>" + html.escape(str(value)) + "</td>" for value in row.values())
        + "</tr>"
        for row in doc["cases"]
    )
    headers = "".join(
        "<th>" + html.escape(key.replace("_", " ")) + "</th>" for key in doc["cases"][0]
    )
    text = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Privacy Gateway benchmark</title><style>body{font:15px/1.6 system-ui;max-width:80rem;margin:3rem auto;padding:0 1rem}table{width:100%;border-collapse:collapse}td,th{padding:.6rem;text-align:left;border-bottom:1px solid #ddd}pre{white-space:pre-wrap;overflow-wrap:anywhere}h1{font-size:3rem}</style></head><body><p>PRIVACY GATEWAY / EXACT-SPAN EVIDENCE</p><h1>Measure. Inspect. Reproduce.</h1><p>Small invented corpus. Coverage is specific to these labeled fixtures.</p><input id="filter" type="search" aria-label="Filter cases" placeholder="Filter cases or state"><table><thead><tr>'
        + headers
        + "</tr></thead><tbody>"
        + rows
        + "</tbody></table><details><summary>Accuracy, timing, provenance and limits</summary><pre>"
        + escaped
        + '</pre></details><script>document.getElementById("filter").addEventListener("input",e=>{document.querySelectorAll("tbody tr").forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(e.target.value.toLowerCase()))})</script></body></html>'
    )
    (output / "benchmark.html").write_text(text, encoding="utf-8")
