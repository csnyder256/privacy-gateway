from __future__ import annotations

import json
import os
import re
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Annotated

import typer

from .crypto import decode_key, generate_key, key_from_env
from .engine import PrivacyEngine
from .synthetic import (
    infer_schema,
    privacy_report,
    quality_report,
    read_rows,
    synthesize_table,
    write_rows,
)
from .vault import Vault

app = typer.Typer(
    no_args_is_help=True,
    help="Privacy Gateway: protect sensitive data before it leaves your trust boundary.",
)


def _engine(database: str) -> PrivacyEngine:
    return PrivacyEngine(Vault(database, master_key=key_from_env()))


@app.command()
def keygen():
    """Generate a 256-bit master key. Store it in a secret manager, never in source control."""
    typer.echo(generate_key())


@app.command()
def serve(
    host: str = "127.0.0.1",
    port: int = 8787,
    database: str = "./data/privacy-gateway.db",
    reload: bool = False,
):
    """Run the API and onboarding UI."""
    import uvicorn

    os.environ["PRIVACY_GATEWAY_DB"] = database
    uvicorn.run("privacy_gateway.api:app", host=host, port=port, reload=reload)


@app.command()
def anonymize(
    text: Annotated[str, typer.Argument(help="Text to protect, or '-' to read stdin")],
    preset: str = "balanced",
    database: str = "./data/privacy-gateway.db",
    json_output: bool = typer.Option(False, "--json"),
):
    """Detect and transform PII in one text value."""
    value = typer.get_text_stream("stdin").read() if text == "-" else text
    result = _engine(database).transform(value, preset=preset)
    typer.echo(result.model_dump_json(indent=2) if json_output else result.text)


@app.command("purge-expired")
def purge_expired(database: str = "./data/privacy-gateway.db"):
    """Delete expired sessions and their cascading mappings/audit rows."""
    typer.echo(json.dumps({"deleted": _engine(database).vault.purge_expired()}))


@app.command()
def synthesize(
    input_path: Annotated[Path, typer.Argument(help="Source CSV, JSON, or JSONL file")],
    output_path: Annotated[Path, typer.Argument(help="Explicit synthetic output path")],
    rows: Annotated[int, typer.Option(min=0, help="Number of synthetic rows")] = 100,
    seed: Annotated[str, typer.Option(help="Repeatability seed; not a secret")] = "privacy-gateway",
    schema_output: Annotated[
        Path | None, typer.Option(help="Optional inferred schema JSON path")
    ] = None,
    report_output: Annotated[
        Path | None, typer.Option(help="Optional aggregate report JSON path")
    ] = None,
):
    """Create local synthetic structured data without a network dependency."""
    source = read_rows(input_path)
    schema = infer_schema(source, input_path.stem)
    generated = synthesize_table(schema, rows, seed=seed)
    write_rows(output_path, generated)
    if schema_output:
        schema_output.parent.mkdir(parents=True, exist_ok=True)
        schema_output.write_text(
            json.dumps(schema.as_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    if report_output:
        report_output.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "quality": quality_report(source, generated, schema),
            "privacy": privacy_report(
                source,
                generated,
                quasi_identifiers=[
                    column.name for column in schema.columns if not column.primary_key
                ][:3],
                key_columns=[column.name for column in schema.columns if column.primary_key],
            ),
        }
        report_output.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    typer.echo(json.dumps({"rows": len(generated), "output": str(output_path)}))


@app.command()
def verify():
    """Run local fail-closed, round-trip, and altered-token probes."""
    client_key = generate_key()
    source = "Contact zoe@example.com about 4111 1111 1111 1111."
    with TemporaryDirectory(prefix="privacy-gateway-verify-") as directory:
        gateway = PrivacyEngine(Vault(Path(directory) / "verify.db"))
        protected = gateway.transform(source, preset="finance", restore_key=client_key)
        if protected.text is None or protected.capsule is None:
            raise typer.Exit(1)
        restored = PrivacyEngine.restore_capsule(
            protected.text,
            protected.capsule,
            client_key,
            protected.session_id,
        )
        altered = re.sub(
            r"\[\[PG1\|([A-Z_]+)\|([A-Z2-7]{26})\|([A-Z2-7]{16})\]\]",
            lambda match: (
                f"[[ pg1 | {match.group(1).lower()} | {match.group(2).lower()} | "
                f"{match.group(3).lower()} ]]"
            ),
            protected.text,
        )
        tolerant = PrivacyEngine.restore_capsule(
            altered,
            protected.capsule,
            client_key,
            protected.session_id,
        )
        blocked_gateway = PrivacyEngine(
            Vault(Path(directory) / "blocked.db"),
            detectors=gateway.detectors,
        )
        blocked = blocked_gateway.transform(source, preset="finance")
        checks = {
            "round_trip": restored == source,
            "tolerant_tagged_token": tolerant == source,
            "keyless_reversible_blocks": blocked.text is None and blocked.state.value == "blocked",
            "source_not_in_protected_text": "zoe@example.com" not in protected.text,
            "client_key_valid": len(decode_key(client_key)) == 32,
        }
    typer.echo(json.dumps(checks, indent=2, sort_keys=True))
    if not all(checks.values()):
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
