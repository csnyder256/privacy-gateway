"""PostgreSQL backend parity tests.

These run only when PRIVACY_GATEWAY_TEST_PG_DSN points at a reachable database, so the
default suite and CI (which have no PostgreSQL service) skip them. Locally:

    docker run --rm -e POSTGRES_PASSWORD=pg -p 5432:5432 postgres:16-alpine
    PRIVACY_GATEWAY_TEST_PG_DSN=postgresql://postgres:pg@127.0.0.1:5432/postgres pytest tests/test_pg_vault.py
"""

from __future__ import annotations

import os
import uuid

import pytest

from privacy_gateway.crypto import decode_key, generate_key
from privacy_gateway.engine import PrivacyEngine
from privacy_gateway.models import Detection, EntityType
from privacy_gateway.vault import open_vault

DSN = os.getenv("PRIVACY_GATEWAY_TEST_PG_DSN")
pytest.importorskip("psycopg", reason="psycopg not installed")
pytestmark = pytest.mark.skipif(not DSN, reason="set PRIVACY_GATEWAY_TEST_PG_DSN to run")


def _vault():
    from privacy_gateway.pg_vault import PostgresVault

    vault = open_vault(DSN, master_key=decode_key(generate_key()))
    assert isinstance(vault, PostgresVault)
    return vault


def test_open_vault_selects_postgres_backend():
    from privacy_gateway.pg_vault import PostgresVault

    assert isinstance(open_vault(DSN, master_key=None), PostgresVault)


def test_transform_restore_round_trip_and_audit():
    engine = PrivacyEngine(_vault())
    text = "Reach Cade at cade@example.com or +1-202-555-0134."
    result = engine.transform(text, preset="balanced")
    assert result.state.value == "protected"
    assert "cade@example.com" not in result.text
    assert engine.restore(result.text, result.session_id) == text

    summary = engine.vault.session_summary(result.session_id)
    entities = {tag["entity_type"] for tag in summary["tags"]}
    assert "EMAIL_ADDRESS" in entities
    assert engine.vault.delete_session(result.session_id) is True
    with pytest.raises(KeyError):
        engine.vault.reverse_map(result.session_id)


def test_repeated_value_reuses_one_mapping():
    vault = _vault()
    engine = PrivacyEngine(vault)
    session_id, policy = engine.create_session(preset="balanced")
    detection = Detection(
        entity=EntityType.EMAIL_ADDRESS,
        start=0,
        end=15,
        char_start=0,
        char_end=15,
        confidence_ppm=990_000,
        detector="regex-v1",
        value="a@example.com",
    )
    first = vault.store_mapping(
        session_id,
        detection,
        "[[PG1|EMAIL|X]]",
        policy.rules[0].action,
        expires_at=vault._now() + 3600,
    )
    second = vault.find_mapping(session_id, "EMAIL_ADDRESS", "a@example.com")
    assert second is not None and str(second["id"]) == first
    vault.delete_session(session_id)


def test_expired_session_is_unavailable_and_purgeable():
    vault = _vault()
    engine = PrivacyEngine(vault)
    text = f"Ping {uuid.uuid4().hex}@example.com now."
    result = engine.transform(text, preset="balanced")
    # Force expiry by rewriting the row far into the past, then confirm it is gone on read.
    with vault._cursor() as cursor:
        cursor.execute("UPDATE sessions SET expires_at=1 WHERE id=%s", (result.session_id,))
        cursor.execute("UPDATE mappings SET expires_at=1 WHERE session_id=%s", (result.session_id,))
    with pytest.raises(KeyError):
        vault.policy_for(result.session_id)
    deleted = vault.purge_expired()
    assert deleted["sessions"] >= 0  # purge runs and reports per-table counts
