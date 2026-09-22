"""Optional PostgreSQL vault backend. Install with: pip install 'privacy-gateway[postgres]'.

PostgresVault mirrors the public API and fail-closed semantics of the default SQLite
:class:`~privacy_gateway.vault.Vault` so the engine can use either without changes. Select
it by passing a ``postgres://`` / ``postgresql://`` URL to :func:`privacy_gateway.vault.open_vault`
(or the ``PRIVACY_GATEWAY_DB`` environment variable).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from contextlib import contextmanager
from typing import Any

from .crypto import open_bytes, seal_bytes
from .models import Action, Detection, Policy
from .vault import MappingCollision

# One statement per element: psycopg's extended protocol runs a single command per execute.
PG_SCHEMA: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      policy_json TEXT NOT NULL,
      metadata_encrypted BYTEA,
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS mappings (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
      entity_type TEXT NOT NULL,
      original_hmac TEXT NOT NULL,
      original_encrypted BYTEA NOT NULL,
      replacement TEXT NOT NULL,
      action TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      UNIQUE(session_id, entity_type, original_hmac),
      UNIQUE(session_id, replacement)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS detections (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
      mapping_id TEXT REFERENCES mappings(id) ON DELETE SET NULL,
      entity_type TEXT NOT NULL,
      detector TEXT NOT NULL,
      confidence_ppm INTEGER NOT NULL,
      action TEXT NOT NULL,
      policy_name TEXT NOT NULL,
      policy_version INTEGER NOT NULL,
      source_hash TEXT NOT NULL,
      start_offset INTEGER NOT NULL,
      end_offset INTEGER NOT NULL,
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_events (
      id TEXT PRIMARY KEY,
      session_id TEXT REFERENCES sessions(id) ON DELETE SET NULL,
      event_type TEXT NOT NULL,
      outcome TEXT NOT NULL,
      detail_json TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_mappings_session ON mappings(session_id, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_detections_session ON detections(session_id, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_detections_entity ON detections(entity_type, action, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events(session_id, created_at)",
)


class PostgresVault:
    def __init__(self, dsn: str, master_key: bytes | None = None):
        try:
            import psycopg
            from psycopg import errors
            from psycopg.rows import dict_row
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "PostgreSQL support requires the extra: pip install 'privacy-gateway[postgres]'"
            ) from exc
        self._psycopg = psycopg
        self._dict_row = dict_row
        self._unique_violation = errors.UniqueViolation
        self.dsn = dsn
        self.path = dsn
        self.master_key = master_key
        with self._cursor() as cursor:
            for statement in PG_SCHEMA:
                cursor.execute(statement)

    @contextmanager
    def _cursor(self):
        connection = self._psycopg.connect(self.dsn)
        try:
            with connection, connection.cursor(row_factory=self._dict_row) as cursor:
                yield cursor
        finally:
            connection.close()

    @staticmethod
    def _now() -> int:
        return int(time.time())

    def create_session(
        self,
        policy: Policy,
        metadata: dict[str, Any] | None = None,
        ttl_seconds: int | None = None,
    ) -> str:
        session_id = str(uuid.uuid4())
        now = self._now()
        ttl = ttl_seconds or max(policy.mapping_retention_seconds, policy.audit_retention_seconds)
        metadata_encrypted = None
        if metadata:
            if self.master_key is None:
                raise RuntimeError("session metadata requires PRIVACY_GATEWAY_MASTER_KEY")
            metadata_encrypted = seal_bytes(
                json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode(),
                self.master_key,
                aad=f"session-metadata:{session_id}".encode(),
            )
        with self._cursor() as cursor:
            cursor.execute(
                "INSERT INTO sessions (id, policy_json, metadata_encrypted, created_at, expires_at)"
                " VALUES (%s,%s,%s,%s,%s)",
                (session_id, policy.model_dump_json(), metadata_encrypted, now, now + ttl),
            )
        return session_id

    def _active_session_row(self, session_id: str) -> dict[str, Any]:
        now = self._now()
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT * FROM sessions WHERE id=%s AND expires_at>%s",
                (session_id, now),
            )
            row = cursor.fetchone()
            if row is None:
                cursor.execute(
                    "DELETE FROM sessions WHERE id=%s AND expires_at<=%s", (session_id, now)
                )
        if row is None:
            raise KeyError(f"unknown or expired session: {session_id}")
        return row

    def policy_for(self, session_id: str) -> Policy:
        return Policy.model_validate_json(self._active_session_row(session_id)["policy_json"])

    def _require_key(self) -> bytes:
        if self.master_key is None:
            raise RuntimeError("persistent reversible mappings require PRIVACY_GATEWAY_MASTER_KEY")
        return self.master_key

    def _fingerprint(self, session_id: str, entity: str, original: str) -> str:
        key = self._require_key()
        return hmac.new(
            key, f"mapping-match\0{session_id}\0{entity}\0{original}".encode(), hashlib.sha256
        ).hexdigest()

    def find_mapping(self, session_id: str, entity: str, original: str) -> dict[str, Any] | None:
        fingerprint = self._fingerprint(session_id, entity, original)
        now = self._now()
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT * FROM mappings WHERE session_id=%s AND entity_type=%s "
                "AND original_hmac=%s AND expires_at>%s",
                (session_id, entity, fingerprint, now),
            )
            return cursor.fetchone()

    def store_mapping(
        self,
        session_id: str,
        detection: Detection,
        replacement: str,
        action: Action,
        *,
        expires_at: int,
    ) -> str:
        key = self._require_key()
        mapping_id = str(uuid.uuid4())
        fingerprint = self._fingerprint(session_id, detection.entity.value, detection.value)
        encrypted = seal_bytes(
            detection.value.encode(),
            key,
            aad=f"mapping:{session_id}:{mapping_id}".encode(),
        )
        try:
            with self._cursor() as cursor:
                cursor.execute(
                    "INSERT INTO mappings (id, session_id, entity_type, original_hmac, "
                    "original_encrypted, replacement, action, created_at, expires_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        mapping_id,
                        session_id,
                        detection.entity.value,
                        fingerprint,
                        encrypted,
                        replacement,
                        action.value,
                        self._now(),
                        expires_at,
                    ),
                )
        except self._unique_violation as exc:
            existing = self.find_mapping(session_id, detection.entity.value, detection.value)
            if existing is not None:
                return str(existing["id"])
            raise MappingCollision("replacement collision") from exc
        return mapping_id

    def record_detection(
        self,
        session_id: str,
        mapping_id: str | None,
        detection: Detection,
        action: Action,
        source_hash: str,
        policy: Policy,
    ) -> str:
        detection_id = str(uuid.uuid4())
        now = self._now()
        with self._cursor() as cursor:
            cursor.execute(
                "INSERT INTO detections (id, session_id, mapping_id, entity_type, detector, "
                "confidence_ppm, action, policy_name, policy_version, source_hash, start_offset, "
                "end_offset, created_at, expires_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    detection_id,
                    session_id,
                    mapping_id,
                    detection.entity.value,
                    detection.detector,
                    detection.confidence_ppm,
                    action.value,
                    policy.name,
                    policy.version,
                    source_hash,
                    detection.start,
                    detection.end,
                    now,
                    now + policy.audit_retention_seconds,
                ),
            )
        return detection_id

    def audit(
        self,
        event_type: str,
        outcome: str,
        detail: dict[str, Any],
        session_id: str | None = None,
        retention_seconds: int = 2_592_000,
    ) -> None:
        now = self._now()
        with self._cursor() as cursor:
            cursor.execute(
                "INSERT INTO audit_events (id, session_id, event_type, outcome, detail_json, "
                "created_at, expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (
                    str(uuid.uuid4()),
                    session_id,
                    event_type,
                    outcome,
                    json.dumps(detail, sort_keys=True, separators=(",", ":")),
                    now,
                    now + retention_seconds,
                ),
            )

    def reverse_map(self, session_id: str) -> dict[str, str]:
        key = self._require_key()
        self._active_session_row(session_id)
        now = self._now()
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT id, replacement, original_encrypted FROM mappings "
                "WHERE session_id=%s AND expires_at>%s",
                (session_id, now),
            )
            rows = cursor.fetchall()
        return {
            row["replacement"]: open_bytes(
                bytes(row["original_encrypted"]),
                key,
                aad=f"mapping:{session_id}:{row['id']}".encode(),
            ).decode()
            for row in rows
        }

    def session_summary(self, session_id: str) -> dict[str, Any]:
        self._active_session_row(session_id)
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT entity_type, detector, action, policy_name, policy_version, "
                "COUNT(*) AS count, MIN(confidence_ppm) AS min_confidence_ppm, "
                "MAX(confidence_ppm) AS max_confidence_ppm "
                "FROM detections WHERE session_id=%s AND expires_at>%s "
                "GROUP BY entity_type, detector, action, policy_name, policy_version",
                (session_id, self._now()),
            )
            rows = cursor.fetchall()
        return {"session_id": session_id, "tags": [dict(row) for row in rows]}

    def delete_session(self, session_id: str) -> bool:
        """Delete one session and all cascading mappings and detections."""
        with self._cursor() as cursor:
            cursor.execute("DELETE FROM sessions WHERE id=%s", (session_id,))
            deleted = cursor.rowcount
        return deleted == 1

    def purge_expired(self) -> dict[str, int]:
        now = self._now()
        deleted: dict[str, int] = {}
        with self._cursor() as cursor:
            for table in ("audit_events", "detections", "mappings", "sessions"):
                cursor.execute(f"DELETE FROM {table} WHERE expires_at<=%s", (now,))
                deleted[table] = cursor.rowcount
        return deleted
