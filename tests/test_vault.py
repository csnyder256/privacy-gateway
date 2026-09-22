import sqlite3
import time

import pytest

from privacy_gateway.crypto import decode_key, generate_key
from privacy_gateway.engine import PrivacyEngine
from privacy_gateway.policies import policy_from_preset
from privacy_gateway.vault import Vault


def test_expired_session_is_enforced_and_deleted(tmp_path):
    vault = Vault(tmp_path / "db.sqlite", decode_key(generate_key()))
    session_id = vault.create_session(policy_from_preset("balanced"), ttl_seconds=1)
    with sqlite3.connect(vault.path) as connection:
        connection.execute(
            "UPDATE sessions SET expires_at=? WHERE id=?", (int(time.time()) - 1, session_id)
        )
    with pytest.raises(KeyError, match="expired"):
        vault.policy_for(session_id)
    with sqlite3.connect(vault.path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM sessions WHERE id=?", (session_id,)
            ).fetchone()[0]
            == 0
        )


def test_metadata_fails_closed_without_encryption_key(tmp_path):
    vault = Vault(tmp_path / "db.sqlite")
    with pytest.raises(RuntimeError, match="metadata requires"):
        vault.create_session(policy_from_preset("balanced"), {"customer": "secret"})


def test_purge_expired_returns_per_table_counts(tmp_path):
    vault = Vault(tmp_path / "db.sqlite", decode_key(generate_key()))
    session_id = vault.create_session(policy_from_preset("balanced"))
    with vault.connect() as connection:
        connection.execute("UPDATE sessions SET expires_at=0 WHERE id=?", (session_id,))
    assert vault.purge_expired()["sessions"] == 1


def test_expired_mapping_cannot_restore_and_is_purgeable(tmp_path):
    vault = Vault(tmp_path / "db.sqlite", decode_key(generate_key()))
    gateway = PrivacyEngine(vault)
    source = "alice@example.com"
    result = gateway.transform(source)
    with vault.connect() as connection:
        connection.execute(
            "UPDATE mappings SET expires_at=0 WHERE session_id=?",
            (result.session_id,),
        )
    assert gateway.restore(result.text, result.session_id) == result.text
    assert vault.purge_expired()["mappings"] == 1


def test_persistent_database_and_wal_do_not_contain_original_value(tmp_path):
    database = tmp_path / "db.sqlite"
    vault = Vault(database, decode_key(generate_key()))
    source = "unique-alice-9173@example.com"
    result = PrivacyEngine(vault).transform(source)
    assert result.text != source
    for candidate in (database, database.with_name(f"{database.name}-wal")):
        if candidate.exists():
            assert source.encode() not in candidate.read_bytes()


def test_client_capsule_mode_persists_no_mapping_originals(tmp_path):
    vault = Vault(tmp_path / "db.sqlite")
    result = PrivacyEngine(vault).transform(
        "alice@example.com",
        restore_key=generate_key(),
    )
    assert result.capsule
    with vault.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM mappings").fetchone()[0] == 0
