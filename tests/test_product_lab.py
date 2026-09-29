import json

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from privacy_gateway.api import create_app
from privacy_gateway.benchmark import load_cases, run_benchmark, write_report
from privacy_gateway.cli import app as cli
from privacy_gateway.crypto import generate_key
from privacy_gateway.detectors import RegexDetector
from privacy_gateway.engine import PrivacyEngine
from privacy_gateway.models import Action, EntityType, Policy, PolicyRule
from privacy_gateway.vault import Vault


def policy(**change):
    return Policy(name="trace-test", rules=[PolicyRule(entity=EntityType.EMAIL_ADDRESS, **change)])


def test_trace_actual_decisions_and_reversible_roundtrip(tmp_path):
    engine = PrivacyEngine(Vault(tmp_path / "trace.db"), detectors=[RegexDetector()])
    source = "こんにちは demo@example.test; https://example.test/u/inner@example.test"
    chosen = Policy(
        name="overlap",
        rules=[
            PolicyRule(entity=EntityType.EMAIL_ADDRESS),
            PolicyRule(entity=EntityType.URL, action=Action.REDACT),
        ],
    )
    key = generate_key()
    result = engine.transform(source, policy=chosen, restore_key=key, include_policy_trace=True)
    assert result.text is not None and "demo@example.test" not in result.text
    outcomes = [d["outcome"] for d in result.policy_trace["decisions"]]
    assert outcomes.count("applied") == 2
    assert outcomes.count("overlap_suppressed") == 1
    assert result.policy_trace["decisions"][0]["offset_unit"] == "UTF-8 bytes"
    encoded = json.dumps(result.policy_trace)
    assert (
        "demo@example.test" not in encoded and key not in encoded and result.capsule not in encoded
    )
    restored = engine.restore_capsule(result.text, result.capsule, key, result.session_id)
    assert restored.startswith("こんにちは demo@example.test;")
    assert "inner@example.test" not in restored


def test_trace_allow_confidence_scope_disabled_and_blocks(tmp_path):
    engine = PrivacyEngine(Vault(tmp_path / "trace.db"), detectors=[RegexDetector()])
    source = "safe@example.test"
    chosen = policy(action=Action.REDACT)
    chosen.allow_terms = [source]
    result = engine.transform(source, policy=chosen, include_policy_trace=True)
    assert result.text == source
    assert result.policy_trace["decisions"][0]["outcome"] == "allowed_value"
    assert source not in json.dumps(result.policy_trace)
    result = engine.transform(
        source,
        policy=policy(action=Action.REDACT, minimum_confidence_ppm=999999),
        include_policy_trace=True,
    )
    assert result.policy_trace["decisions"][0]["outcome"] == "below_confidence"
    result = engine.transform(
        source, policy=policy(scopes=["json:/email"]), include_policy_trace=True
    )
    assert result.text == source
    assert result.policy_trace["decisions"][0]["outcome"] == "scope_not_claimed"
    for change in [{"enabled": False}, {"action": Action.KEEP}]:
        result = engine.transform(source, policy=policy(**change), include_policy_trace=True)
        assert result.text == source and not result.policy_trace["rules"][0]["scan_enabled"]
    for chosen in [policy(), policy(action=Action.REDACT, required_detectors=["unavailable"])]:
        result = engine.transform(source, policy=chosen, include_policy_trace=True)
        assert result.text is None and result.policy_trace["state"] == "blocked"
        assert result.policy_trace["gate"]
        assert not result.policy_trace["detection_complete"]
    assert engine.transform(source, policy=policy(action=Action.REDACT)).policy_trace is None


def test_benchmark_counts_reproducible_no_source_exports_and_no_overwrite(tmp_path):
    first = run_benchmark(repeats=1)
    second = run_benchmark(repeats=2)
    assert first["accuracy"] == second["accuracy"]
    assert first["accuracy"]["false_negatives"] >= 1
    assert first["by_entity"]["PERSON"]["false_negatives"] == 1
    assert first["provenance"]["dataset_sha256"] == second["provenance"]["dataset_sha256"]
    assert first["timing"]["samples"] == 19 and second["timing"]["samples"] == 38
    assert (
        first["timing"]["minimum_ms"] <= first["timing"]["median_ms"] <= first["timing"]["p95_ms"]
    )
    output = tmp_path / "report"
    write_report(first, output)
    assert {p.name for p in output.iterdir()} == {
        "benchmark.json",
        "benchmark.csv",
        "benchmark.html",
    }
    assert json.loads((output / "benchmark.json").read_text()) == first
    exported = "".join(p.read_text() for p in output.iterdir())
    assert "test.person@example.test" not in exported and "Alex Example" not in exported
    with pytest.raises(FileExistsError):
        write_report(first, output)
    for raw in [
        b"",
        b'{"text":"test","expected":[{"entity":"EMAIL_ADDRESS","start":0,"end":999}]}',
    ]:
        with pytest.raises(ValueError):
            load_cases(raw)
    for repeats in [0, True, 1001]:
        with pytest.raises(ValueError):
            run_benchmark(repeats=repeats)
    result = CliRunner().invoke(
        cli, ["benchmark", "--output", str(tmp_path / "cli"), "--repeats", "1"]
    )
    assert result.exit_code == 0, result.output
    assert CliRunner().invoke(cli, ["benchmark", "--output", str(tmp_path / "cli")]).exit_code != 0


def test_live_lab_routes_use_actual_engine_and_trace(tmp_path, monkeypatch):
    monkeypatch.delenv("PRIVACY_GATEWAY_MASTER_KEY", raising=False)
    app = create_app(str(tmp_path / "api.db"))
    app.state.engine.detectors = [RegexDetector()]
    client = TestClient(app)
    page = client.get("/walkthrough")
    assert page.status_code == 200 and "lab-form" in page.text
    assert "__PRIVACY_GATEWAY_VERSION__" not in page.text
    response = client.post(
        "/v1/transform",
        json={
            "text": "demo@example.test",
            "restore_key": generate_key(),
            "include_policy_trace": True,
        },
    )
    assert response.status_code == 200
    doc = response.json()
    assert doc["policy_trace"]["decisions"][0]["outcome"] == "applied"
    assert client.delete("/v1/sessions/" + doc["session_id"]).status_code == 200
    report = client.post("/v1/benchmark/demo", json={})
    assert report.status_code == 200
    assert report.json()["provenance"]["case_count"] == 19
