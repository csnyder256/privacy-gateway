import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from privacy_gateway.cli import app
from privacy_gateway.synthetic import (
    ColumnSchema,
    ForeignKey,
    TableSchema,
    infer_schema,
    privacy_report,
    quality_report,
    read_rows,
    schema_from_dict,
    synthesize_table,
    synthesize_tables,
    write_rows,
)

SOURCE = [
    {
        "id": 1,
        "email": "ada@example.com",
        "phone": "+1-202-555-0101",
        "score": 2.5,
        "active": True,
        "joined": "2024-01-02",
        "segment": "A",
        "note": "long distinct note one",
    },
    {
        "id": 2,
        "email": "lin@example.com",
        "phone": "+1-202-555-0102",
        "score": 8.5,
        "active": False,
        "joined": "2024-02-03",
        "segment": "B",
        "note": "long distinct note two",
    },
]


def test_inference_and_schema_round_trip():
    schema = infer_schema(SOURCE, "people")
    assert {column.name: column.kind for column in schema.columns} == {
        "id": "integer",
        "email": "email",
        "phone": "phone",
        "score": "float",
        "active": "boolean",
        "joined": "date",
        "segment": "category",
        "note": "category",
    }
    assert schema.column("id").primary_key is True
    restored = schema_from_dict(schema.as_dict())
    assert restored.as_dict() == schema.as_dict()


def test_mixed_types_emit_diagnostic_without_source_values():
    schema = infer_schema([{"field": 1}, {"field": "secret sample"}], "mixed")
    assert schema.column("field").kind == "text"
    serialized = json.dumps(schema.as_dict())
    assert "secret sample" not in serialized
    assert "mixed scalar types" in serialized


def test_seeded_generation_enforces_declared_constraints():
    schema = TableSchema(
        name="people",
        columns=[
            ColumnSchema("id", "integer", primary_key=True),
            ColumnSchema("score", "float", minimum=1.5, maximum=2.5),
            ColumnSchema("segment", "category", categories=["A", "B"]),
            ColumnSchema("email", "email"),
            ColumnSchema("phone", "phone"),
            ColumnSchema("name", "text", locale="fr-FR"),
        ],
    )
    first = synthesize_table(schema, 50, seed="same")
    assert first == synthesize_table(schema, 50, seed="same")
    assert first != synthesize_table(schema, 50, seed="different")
    assert len({row["id"] for row in first}) == 50
    assert all(1.5 <= row["score"] <= 2.5 for row in first)
    assert all(row["segment"] in {"A", "B"} for row in first)
    assert all(row["email"].endswith("@example.test") for row in first)


def test_primary_keys_ignore_nullability_and_preserve_format_or_reject_capacity():
    email = TableSchema(
        "users", [ColumnSchema("email", "email", nullable=True, null_rate=0.99, primary_key=True)]
    )
    generated = synthesize_table(email, 20, seed="pk")
    assert len({row["email"] for row in generated}) == 20
    assert all(row["email"].endswith("@example.test") for row in generated)
    boolean = TableSchema("flags", [ColumnSchema("id", "boolean", primary_key=True)])
    with pytest.raises(ValueError, match="at most two"):
        synthesize_table(boolean, 3)
    impossible_integer = TableSchema(
        "numbers", [ColumnSchema("id", "integer", primary_key=True, minimum=1.2, maximum=1.2)]
    )
    with pytest.raises(ValueError, match="range"):
        synthesize_table(impossible_integer, 1)
    bounded_integer = TableSchema(
        "bounded", [ColumnSchema("n", "integer", minimum=1.2, maximum=2.2)]
    )
    assert {row["n"] for row in synthesize_table(bounded_integer, 10)} == {2}
    bounded_float_pk = TableSchema(
        "floats", [ColumnSchema("id", "float", primary_key=True, minimum=0.0, maximum=1.0)]
    )
    assert len({row["id"] for row in synthesize_table(bounded_float_pk, 3)}) == 3


def test_relationship_generation_preserves_foreign_keys():
    schemas = {
        "accounts": TableSchema("accounts", [ColumnSchema("id", "integer", primary_key=True)]),
        "orders": TableSchema(
            "orders",
            [
                ColumnSchema("id", "integer", primary_key=True),
                ColumnSchema("account_id", "integer"),
            ],
            [ForeignKey("account_id", "accounts", "id")],
        ),
    }
    output = synthesize_tables(schemas, {"accounts": 3, "orders": 20}, seed="relations")
    parents = {row["id"] for row in output["accounts"]}
    assert all(row["account_id"] in parents for row in output["orders"])
    conflicting = {
        "parents": TableSchema("parents", [ColumnSchema("id", "integer", primary_key=True)]),
        "children": TableSchema(
            "children",
            [ColumnSchema("id", "integer", primary_key=True)],
            [ForeignKey("id", "parents", "id")],
        ),
    }
    with pytest.raises(ValueError, match="unique parent"):
        synthesize_tables(conflicting, {"parents": 2, "children": 3})
    mismatched = {
        "parents": TableSchema("parents", [ColumnSchema("id", "text", primary_key=True)]),
        "children": TableSchema(
            "children",
            [ColumnSchema("parent_id", "integer")],
            [ForeignKey("parent_id", "parents", "id")],
        ),
    }
    with pytest.raises(ValueError, match="child column type"):
        synthesize_tables(mismatched, {"parents": 2, "children": 2})


@pytest.mark.parametrize("suffix", ["csv", "json", "jsonl"])
def test_supported_file_formats_round_trip(tmp_path, suffix):
    path = tmp_path / f"rows.{suffix}"
    write_rows(path, SOURCE)
    assert read_rows(path) == (
        [{key: str(value) for key, value in row.items()} for row in SOURCE]
        if suffix == "csv"
        else SOURCE
    )


def test_reports_are_hand_checkable_and_degenerate_safe():
    schema = infer_schema(SOURCE, "people")
    generated = [dict(SOURCE[0]), {**SOURCE[1], "email": "new@example.test"}]
    quality = quality_report(SOURCE, generated, schema)
    assert quality["status"] == "evaluated"
    assert quality["source_rows"] == 2
    report = privacy_report(
        SOURCE,
        generated,
        quasi_identifiers=["segment"],
        sensitive_columns=["active"],
        key_columns=["id"],
    )
    assert report["exact_row_match_rate"] == 0.5
    assert report["k_anonymity"] == 1
    assert report["l_diversity"] == {"active": 1}
    assert privacy_report([], [], quasi_identifiers=[])["status"] == "not_evaluable"
    assert quality_report([], [], schema)["status"] == "not_evaluable"
    assert quality_report([{}], [{}], TableSchema("empty", []))["status"] == "not_evaluable"
    assert (
        privacy_report([{"id": 1}], [{"id": 2}], quasi_identifiers=["id"], key_columns=["id"])[
            "status"
        ]
        == "not_evaluable"
    )


def test_reports_cover_later_columns_types_and_numeric_distributions():
    privacy = privacy_report(
        [{"qid": "A"}, {"qid": "B", "secret": "LEAK"}],
        [{"qid": "X"}, {"qid": "Y", "secret": "LEAK"}],
        quasi_identifiers=["qid"],
    )
    assert privacy["non_key_cell_copy_rate"] > 0
    assert (
        privacy_report([{"x": 1}], [{"x": 2}], quasi_identifiers=["missing"])["status"]
        == "not_evaluable"
    )
    schema = TableSchema("numbers", [ColumnSchema("value", "integer", minimum=0, maximum=100)])
    report = quality_report([{"value": 0}, {"value": 0}], [{"value": 100}, {"value": 100}], schema)
    assert report["columns"]["value"]["normalized_mean_delta"] == 100.0
    wrong = quality_report([{"value": 1}], [{"value": "WRONG"}], schema)
    assert wrong["columns"]["value"]["synthetic_type_valid_rate"] == 0.0
    leaked = quality_report([{"value": "TOP_SECRET_VALUE"}], [{"value": 1}], schema)
    assert leaked["columns"]["value"]["synthetic_type_valid_rate"] == 1.0
    assert "TOP_SECRET_VALUE" not in json.dumps(leaked)
    assert (
        privacy_report(
            [{"qid": "A", "s": "x"}],
            [{"qid": "B"}],
            quasi_identifiers=["qid"],
            sensitive_columns=["s"],
        )["status"]
        == "not_evaluable"
    )


def test_inferred_null_and_category_distribution_is_preserved_coarsely():
    source = [
        {"segment": "A" if index < 99 else "B", "optional": None if index < 99 else "x"}
        for index in range(100)
    ]
    schema = infer_schema(source, "skewed")
    generated = synthesize_table(schema, 2_000, seed="skew")
    a_rate = sum(row["segment"] == "A" for row in generated) / len(generated)
    null_rate = sum(row["optional"] is None for row in generated) / len(generated)
    assert a_rate > 0.95
    assert null_rate > 0.95


def test_csv_textual_booleans_are_inferred(tmp_path):
    path = tmp_path / "booleans.csv"
    path.write_text("active\nTrue\nFalse\n", encoding="utf-8")
    assert infer_schema(read_rows(path)).column("active").kind == "boolean"


def test_cli_requires_explicit_paths_and_writes_aggregate_outputs(tmp_path):
    source = tmp_path / "source.json"
    output = tmp_path / "generated.jsonl"
    schema = tmp_path / "schema.json"
    report = tmp_path / "report.json"
    source.write_text(json.dumps(SOURCE), encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "synthesize",
            str(source),
            str(output),
            "--rows",
            "5",
            "--schema-output",
            str(schema),
            "--report-output",
            str(report),
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert len(read_rows(output)) == 5
    combined = schema.read_text() + report.read_text()
    assert "ada@example.com" not in combined


def test_source_has_no_sdv_dependency_or_import():
    root = Path(__file__).parents[1]
    dependency_files = (root / "pyproject.toml").read_text() + (
        root / "package-lock.json"
    ).read_text()
    source = (root / "src/privacy_gateway/synthetic.py").read_text()
    assert '"sdv' not in dependency_files.lower()
    assert "import sdv" not in source.lower()
