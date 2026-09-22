from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Literal

ColumnKind = Literal[
    "null", "boolean", "integer", "float", "date", "email", "phone", "category", "text"
]

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9 .()\-]{6,20}$")


@dataclass
class ColumnSchema:
    name: str
    kind: ColumnKind
    nullable: bool = False
    categories: list[str] = field(default_factory=list)
    minimum: float | None = None
    maximum: float | None = None
    primary_key: bool = False
    locale: str = "en-US"
    null_rate: float = 0.0
    category_weights: dict[str, float] = field(default_factory=dict)
    mean: float | None = None
    standard_deviation: float | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "kind": self.kind,
            "nullable": self.nullable,
            "primary_key": self.primary_key,
            "locale": self.locale,
            "null_rate": self.null_rate,
        }
        if self.categories:
            result["categories"] = self.categories
        if self.minimum is not None:
            result["minimum"] = self.minimum
        if self.maximum is not None:
            result["maximum"] = self.maximum
        if self.category_weights:
            result["category_weights"] = self.category_weights
        if self.mean is not None:
            result["mean"] = self.mean
        if self.standard_deviation is not None:
            result["standard_deviation"] = self.standard_deviation
        return result


@dataclass
class ForeignKey:
    column: str
    parent_table: str
    parent_column: str


@dataclass
class TableSchema:
    name: str
    columns: list[ColumnSchema]
    foreign_keys: list[ForeignKey] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    def column(self, name: str) -> ColumnSchema:
        for column in self.columns:
            if column.name == name:
                return column
        raise KeyError(f"unknown column {name!r} in table {self.name!r}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "columns": [column.as_dict() for column in self.columns],
            "foreign_keys": [vars(key) for key in self.foreign_keys],
            "diagnostics": self.diagnostics,
        }


def _scalar_kind(value: Any) -> ColumnKind:
    if value is None or value == "":
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    text = str(value)
    if text.lower() in {"true", "false"}:
        return "boolean"
    if EMAIL_RE.fullmatch(text):
        return "email"
    try:
        date.fromisoformat(text)
        return "date"
    except ValueError:
        pass
    if PHONE_RE.fullmatch(text):
        return "phone"
    try:
        int(text)
        return "integer"
    except ValueError:
        pass
    try:
        float(text)
        return "float"
    except ValueError:
        pass
    return "text"


def infer_schema(rows: list[dict[str, Any]], name: str = "table") -> TableSchema:
    if not rows:
        raise ValueError("cannot infer a schema from zero rows")
    names = list(dict.fromkeys(key for row in rows for key in row))
    columns: list[ColumnSchema] = []
    diagnostics: list[str] = []
    for column_name in names:
        values = [row.get(column_name) for row in rows]
        non_null = [value for value in values if value not in (None, "")]
        kinds = Counter(_scalar_kind(value) for value in non_null)
        mixed = False
        if not non_null:
            kind: ColumnKind = "null"
        elif set(kinds) <= {"integer", "float"}:
            kind = "float" if "float" in kinds else "integer"
        elif len(kinds) == 1:
            kind = next(iter(kinds))
        else:
            kind = "text"
            mixed = True
            diagnostics.append(
                f"{column_name}: mixed scalar types require an explicit override for strict output"
            )
        categories: list[str] = []
        if kind == "text" and not mixed:
            unique = sorted({str(value) for value in non_null})
            if len(unique) <= min(50, max(4, math.ceil(len(non_null) * 0.2))):
                kind = "category"
                categories = unique
        numeric = [float(value) for value in non_null] if kind in {"integer", "float"} else []
        counts = Counter(str(value) for value in non_null) if kind == "category" else Counter()
        mean = sum(numeric) / len(numeric) if numeric else None
        variance = (
            sum((value - mean) ** 2 for value in numeric) / len(numeric)
            if numeric and mean is not None
            else None
        )
        primary_key = column_name.lower() in {"id", f"{name.lower()}_id"} and len(
            {str(value) for value in non_null}
        ) == len(non_null)
        columns.append(
            ColumnSchema(
                name=column_name,
                kind=kind,
                nullable=len(non_null) != len(values),
                categories=categories,
                minimum=min(numeric) if numeric else None,
                maximum=max(numeric) if numeric and not primary_key else None,
                primary_key=primary_key,
                null_rate=(len(values) - len(non_null)) / len(values),
                category_weights={key: count / len(non_null) for key, count in counts.items()}
                if non_null
                else {},
                mean=mean,
                standard_deviation=math.sqrt(variance) if variance is not None else None,
            )
        )
    return TableSchema(name=name, columns=columns, diagnostics=diagnostics)


def schema_from_dict(value: dict[str, Any]) -> TableSchema:
    return TableSchema(
        name=value["name"],
        columns=[ColumnSchema(**column) for column in value["columns"]],
        foreign_keys=[ForeignKey(**key) for key in value.get("foreign_keys", [])],
        diagnostics=list(value.get("diagnostics", [])),
    )


def _rng(seed: str, table: str, column: str, row: int) -> random.Random:
    digest = hashlib.sha256(f"privacy-gateway\0{seed}\0{table}\0{column}\0{row}".encode()).digest()
    return random.Random(int.from_bytes(digest[:16]))


FIRST_NAMES = {
    "en-US": ["Alex", "Jordan", "Morgan", "Riley", "Taylor", "Casey"],
    "es-ES": ["Alex", "Carmen", "Dani", "Lucia", "Mar", "Sofia"],
    "fr-FR": ["Alex", "Camille", "Lou", "Manon", "Noa", "Sacha"],
}


def _generate(column: ColumnSchema, index: int, seed: str, table: str, total: int) -> Any:
    randomizer = _rng(seed, table, column.name, index)
    if column.primary_key:
        if column.kind == "integer":
            low = math.ceil(column.minimum) if column.minimum is not None else 1
            value = low + index
            if column.maximum is not None and value > math.floor(column.maximum):
                raise ValueError(f"integer primary key {column.name!r} exceeds its range")
            return value
        if column.kind == "float":
            low = column.minimum if column.minimum is not None else 1.0
            if column.maximum is not None:
                if total > 1 and column.maximum <= low:
                    raise ValueError(f"float primary key {column.name!r} exceeds its range")
                value = low if total <= 1 else low + (column.maximum - low) * index / (total - 1)
            else:
                value = low + index
            return float(value)
        if column.kind == "email":
            return f"pk{index + 1}@example.test"
        if column.kind == "phone":
            if index >= 10_000_000:
                raise ValueError(f"phone primary key {column.name!r} exhausted its range")
            return f"+1-202-{index + 1:07d}"
        if column.kind == "date":
            return (date(2000, 1, 1) + timedelta(days=index)).isoformat()
        if column.kind == "category":
            if index >= len(column.categories):
                raise ValueError(f"category primary key {column.name!r} exhausted its values")
            return column.categories[index]
        if column.kind == "boolean":
            if index >= 2:
                raise ValueError(f"boolean primary key {column.name!r} supports at most two rows")
            return bool(index)
        if column.kind == "null":
            raise ValueError(f"null column {column.name!r} cannot be a primary key")
        return f"{table}-{index + 1:06d}"
    if column.nullable and randomizer.random() < column.null_rate:
        return None
    if column.kind == "null":
        return None
    if column.kind == "boolean":
        return bool(randomizer.getrandbits(1))
    if column.kind in {"integer", "float"}:
        low = column.minimum if column.minimum is not None else 0
        high = column.maximum if column.maximum is not None else low + 100
        if high < low:
            raise ValueError(f"column {column.name!r} maximum is below minimum")
        if column.kind == "integer":
            integer_low, integer_high = math.ceil(low), math.floor(high)
            if integer_low > integer_high:
                raise ValueError(f"integer column {column.name!r} has no integer inside its range")
            return randomizer.randint(integer_low, integer_high)
        if column.mean is not None and column.standard_deviation is not None:
            value = randomizer.gauss(column.mean, column.standard_deviation)
            value = min(high, max(low, value))
        else:
            value = randomizer.uniform(low, high)
        return round(value, 4)
    if column.kind == "date":
        return (date(2020, 1, 1) + timedelta(days=randomizer.randrange(0, 3653))).isoformat()
    if column.kind == "email":
        return f"person{randomizer.randrange(100_000, 999_999)}@example.test"
    if column.kind == "phone":
        return f"+1-202-555-{randomizer.randrange(0, 10_000):04d}"
    if column.kind == "category":
        if not column.categories:
            raise ValueError(f"category column {column.name!r} has no categories")
        weights = [column.category_weights.get(value, 1.0) for value in column.categories]
        return randomizer.choices(column.categories, weights=weights, k=1)[0]
    names = FIRST_NAMES.get(column.locale, FIRST_NAMES["en-US"])
    return f"{randomizer.choice(names)} {column.name.replace('_', ' ')} {index + 1}"


def synthesize_table(
    schema: TableSchema, rows: int, *, seed: str = "privacy-gateway"
) -> list[dict]:
    if rows < 0:
        raise ValueError("row count cannot be negative")
    return [
        {
            column.name: _generate(column, index, seed, schema.name, rows)
            for column in schema.columns
        }
        for index in range(rows)
    ]


def synthesize_tables(
    schemas: dict[str, TableSchema], row_counts: dict[str, int], *, seed: str = "privacy-gateway"
) -> dict[str, list[dict]]:
    output = {
        name: synthesize_table(schema, row_counts.get(name, 0), seed=seed)
        for name, schema in schemas.items()
    }
    dependencies = {
        name: {
            relation.parent_table
            for relation in schema.foreign_keys
            if relation.parent_table != name
        }
        for name, schema in schemas.items()
    }
    order: list[str] = []
    pending = set(schemas)
    while pending:
        ready = sorted(name for name in pending if dependencies[name] <= set(order))
        if not ready:
            raise ValueError("foreign-key relationship cycle is not supported")
        order.extend(ready)
        pending.difference_update(ready)
    for table_name in order:
        schema = schemas[table_name]
        relation_columns = [relation.column for relation in schema.foreign_keys]
        if len(relation_columns) != len(set(relation_columns)):
            raise ValueError("multiple foreign keys cannot target the same child column")
        for relation in schema.foreign_keys:
            if relation.parent_table not in output:
                raise ValueError(f"unknown parent table {relation.parent_table!r}")
            parent_values = [row[relation.parent_column] for row in output[relation.parent_table]]
            if output[table_name] and not parent_values:
                raise ValueError(f"parent table {relation.parent_table!r} has no generated rows")
            child_column = schema.column(relation.column)
            if any(not _value_matches_column(value, child_column) for value in parent_values):
                raise ValueError("foreign-key parent values do not match the child column type")
            if child_column.primary_key and len(output[table_name]) > len(set(parent_values)):
                raise ValueError(
                    f"primary/foreign key {relation.column!r} needs at least one unique parent per row"
                )
            available = list(dict.fromkeys(parent_values))
            for index, row in enumerate(output[table_name]):
                randomizer = _rng(seed, table_name, relation.column, index)
                if child_column.primary_key:
                    selected = available.pop(randomizer.randrange(len(available)))
                else:
                    selected = randomizer.choice(parent_values)
                row[relation.column] = selected
    for table_name, schema in schemas.items():
        for relation in schema.foreign_keys:
            parent_values = {row[relation.parent_column] for row in output[relation.parent_table]}
            if any(row[relation.column] not in parent_values for row in output[table_name]):
                raise ValueError("generated foreign-key integrity check failed")
    return output


def _value_matches_column(value: Any, column: ColumnSchema) -> bool:
    if value in (None, ""):
        return column.nullable
    actual = _scalar_kind(value)
    if column.kind == "category":
        return str(value) in column.categories
    return actual == column.kind or (column.kind == "float" and actual == "integer")


def read_rows(path: str | Path, file_format: str | None = None) -> list[dict[str, Any]]:
    path = Path(path)
    kind = (file_format or path.suffix.removeprefix(".")).lower()
    if kind == "csv":
        with path.open(newline="", encoding="utf-8") as stream:
            return list(csv.DictReader(stream))
    if kind == "json":
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
            raise ValueError("JSON input must be an array of objects")
        return value
    if kind in {"jsonl", "ndjson"}:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
        if not all(isinstance(row, dict) for row in rows):
            raise ValueError("JSONL input must contain one object per line")
        return rows
    raise ValueError("supported structured formats are CSV, JSON, and JSONL")


def write_rows(
    path: str | Path, rows: list[dict[str, Any]], file_format: str | None = None
) -> None:
    path = Path(path)
    kind = (file_format or path.suffix.removeprefix(".")).lower()
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "csv":
        fields = list(rows[0]) if rows else []
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            if fields:
                writer.writeheader()
                writer.writerows(rows)
        return
    if kind == "json":
        path.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return
    if kind in {"jsonl", "ndjson"}:
        path.write_text(
            "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
            encoding="utf-8",
        )
        return
    raise ValueError("supported structured formats are CSV, JSON, and JSONL")


def quality_report(real: list[dict], synthetic: list[dict], schema: TableSchema) -> dict[str, Any]:
    if not real or not synthetic or not schema.columns:
        return {"status": "not_evaluable", "reason": "both datasets require at least one row"}
    columns = {}
    for column in schema.columns:
        source = [row.get(column.name) for row in real]
        generated = [row.get(column.name) for row in synthetic]
        source_null = sum(value in (None, "") for value in source) / len(source)
        generated_null = sum(value in (None, "") for value in generated) / len(generated)
        details: dict[str, Any] = {
            "kind": column.kind,
            "source_null_rate": round(source_null, 6),
            "synthetic_null_rate": round(generated_null, 6),
            "null_rate_delta": round(abs(source_null - generated_null), 6),
        }

        def valid(value: Any, schema: ColumnSchema = column) -> bool:
            return _value_matches_column(value, schema)

        details["synthetic_type_valid_rate"] = round(
            sum(valid(value) for value in generated) / len(generated), 6
        )
        if column.kind == "category":
            expected = set(column.categories)
            observed = {str(value) for value in generated if value not in (None, "")}
            details["category_coverage"] = (
                round(len(expected & observed) / len(expected), 6) if expected else None
            )
            expected_weights = column.category_weights
            if expected_weights:
                generated_counts = Counter(
                    str(value) for value in generated if value not in (None, "")
                )
                generated_total = sum(generated_counts.values())
                details["category_total_variation"] = (
                    round(
                        sum(
                            abs(
                                expected_weights.get(value, 0.0)
                                - generated_counts.get(value, 0) / generated_total
                            )
                            for value in set(expected_weights) | set(generated_counts)
                        )
                        / 2,
                        6,
                    )
                    if generated_total
                    else None
                )
        if column.kind in {"integer", "float"}:
            source_numeric = [
                float(value)
                for value in source
                if value not in (None, "") and _scalar_kind(value) in {"integer", "float"}
            ]
            generated_numeric = [
                float(value)
                for value in generated
                if value not in (None, "") and _scalar_kind(value) in {"integer", "float"}
            ]
            if source_numeric and generated_numeric:
                source_mean = sum(source_numeric) / len(source_numeric)
                generated_mean = sum(generated_numeric) / len(generated_numeric)
                scale = max(max(source_numeric) - min(source_numeric), 1.0)
                details["normalized_mean_delta"] = round(
                    abs(source_mean - generated_mean) / scale, 6
                )
        columns[column.name] = details
    return {
        "status": "evaluated",
        "source_rows": len(real),
        "synthetic_rows": len(synthetic),
        "columns": columns,
    }


def privacy_report(
    real: list[dict],
    synthetic: list[dict],
    *,
    quasi_identifiers: list[str],
    sensitive_columns: list[str] | None = None,
    key_columns: list[str] | None = None,
) -> dict[str, Any]:
    sensitive_columns = sensitive_columns or []
    key_columns = key_columns or []
    if not real or not synthetic or not quasi_identifiers:
        return {
            "status": "not_evaluable",
            "reason": "non-empty real/synthetic rows and quasi-identifiers are required",
        }
    real_columns = {name for row in real for name in row}
    synthetic_columns = {name for row in synthetic for name in row}
    all_columns = sorted(real_columns & synthetic_columns)
    if not set(quasi_identifiers) <= real_columns & synthetic_columns:
        return {"status": "not_evaluable", "reason": "quasi-identifier column is missing"}
    if not set(sensitive_columns) <= real_columns & synthetic_columns:
        return {"status": "not_evaluable", "reason": "sensitive column is missing"}
    evaluation = [name for name in all_columns if name not in key_columns]
    if not evaluation:
        return {"status": "not_evaluable", "reason": "no non-key evaluation columns"}
    real_rows = {tuple(str(row.get(name)) for name in evaluation) for row in real}
    exact = sum(tuple(str(row.get(name)) for name in evaluation) in real_rows for row in synthetic)
    source_cells = {str(row.get(name)) for row in real for name in evaluation}
    generated_cells = [str(row.get(name)) for row in synthetic for name in evaluation]
    groups = Counter(tuple(str(row.get(name)) for name in quasi_identifiers) for row in synthetic)
    diversity: dict[str, int] = {}
    for sensitive in sensitive_columns:
        buckets: dict[tuple[str, ...], set[str]] = {}
        for row in synthetic:
            key = tuple(str(row.get(name)) for name in quasi_identifiers)
            buckets.setdefault(key, set()).add(str(row.get(sensitive)))
        diversity[sensitive] = min((len(values) for values in buckets.values()), default=0)
    exact_rate = exact / len(synthetic)
    copy_rate = (
        sum(value in source_cells for value in generated_cells) / len(generated_cells)
        if generated_cells
        else 0.0
    )
    k = min(groups.values(), default=0)
    warnings = []
    if exact_rate > 0:
        warnings.append("synthetic rows exactly match source rows on evaluated columns")
    if copy_rate > 0.2:
        warnings.append("more than 20% of evaluated synthetic cells copy a source value")
    if k < 3:
        warnings.append("minimum quasi-identifier group size is below 3")
    if any(value < 2 for value in diversity.values()):
        warnings.append("minimum sensitive-value diversity is below 2")
    return {
        "status": "evaluated",
        "exact_row_match_rate": round(exact_rate, 6),
        "non_key_cell_copy_rate": round(copy_rate, 6),
        "k_anonymity": k,
        "l_diversity": diversity,
        "warnings": warnings,
    }
