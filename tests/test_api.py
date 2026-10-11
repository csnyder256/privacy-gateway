from fastapi.testclient import TestClient

from privacy_gateway import __version__
from privacy_gateway.api import create_app
from privacy_gateway.crypto import generate_key


def test_onboarding_and_health_are_served(tmp_path):
    client = TestClient(create_app(str(tmp_path / "api.db")))
    assert client.get("/v1/health").json()["ok"] is True
    page = client.get("/")
    assert page.status_code == 200
    assert "Build a policy" in page.text
    assert f'<span class="topbar-meta">v{__version__} / MIT</span>' in page.text
    assert client.get("/assets/app.css").status_code == 200


def test_transform_and_client_capsule_restore(tmp_path):
    client = TestClient(create_app(str(tmp_path / "api.db")))
    key = generate_key()
    transformed = client.post(
        "/v1/transform",
        json={"text": "Email a@example.com", "preset": "balanced", "restore_key": key},
    )
    assert transformed.status_code == 200
    body = transformed.json()
    assert body["state"] == "protected"
    assert body["text"] != "Email a@example.com"
    restored = client.post(
        "/v1/restore/capsule",
        json={
            "text": body["text"],
            "session_id": body["session_id"],
            "capsule": body["capsule"],
            "restore_key": key,
        },
    )
    assert restored.json()["text"] == "Email a@example.com"


def test_capsule_restore_with_wrong_key_fails_closed_as_422(tmp_path):
    client = TestClient(create_app(str(tmp_path / "api.db")))
    key = generate_key()
    body = client.post(
        "/v1/transform",
        json={"text": "Email a@example.com", "preset": "balanced", "restore_key": key},
    ).json()
    response = client.post(
        "/v1/restore/capsule",
        json={
            "text": body["text"],
            "session_id": body["session_id"],
            "capsule": body["capsule"],
            "restore_key": generate_key(),
        },
    )
    assert response.status_code == 422
    assert "authentication failed" in response.json()["detail"]


def test_transform_returns_explicit_blocked_state_without_key(tmp_path):
    client = TestClient(create_app(str(tmp_path / "api.db")))
    response = client.post(
        "/v1/transform",
        json={"text": "Email a@example.com", "preset": "balanced"},
    )
    assert response.status_code == 200
    assert response.json()["state"] == "blocked"
    assert response.json()["text"] is None


def test_expired_purge_route_is_not_shadowed_by_session_delete(tmp_path):
    app = create_app(str(tmp_path / "api.db"))
    client = TestClient(app)
    response = client.delete("/v1/sessions/expired")
    assert response.status_code == 200
    assert response.json()["deleted"] == {
        "audit_events": 0,
        "detections": 0,
        "mappings": 0,
        "sessions": 0,
    }


def test_session_create_maps_fail_closed_client_errors_to_422(tmp_path, monkeypatch):
    """A rejected session request is a client error, never an opaque 500.

    ``POST /v1/sessions`` was the one route that let the engine's fail-closed errors
    escape: an unknown preset raises ``ValueError`` and session metadata without
    ``PRIVACY_GATEWAY_MASTER_KEY`` raises ``RuntimeError``. Both reached the caller as
    a 500, while ``/v1/transform`` answers the same class of error with 422 and the
    reason. A client retrying on 5xx and a monitoring rule counting server faults both
    read the failure wrong.
    """
    monkeypatch.delenv("PRIVACY_GATEWAY_MASTER_KEY", raising=False)
    client = TestClient(create_app(str(tmp_path / "api.db")), raise_server_exceptions=False)

    unknown_preset = client.post("/v1/sessions", json={"preset": "bogus"})
    assert unknown_preset.status_code == 422
    assert "Unknown preset" in unknown_preset.json()["detail"]

    metadata_without_key = client.post(
        "/v1/sessions", json={"preset": "balanced", "metadata": {"customer": "secret"}}
    )
    assert metadata_without_key.status_code == 422
    assert "PRIVACY_GATEWAY_MASTER_KEY" in metadata_without_key.json()["detail"]

    # The same route still creates a session when nothing is rejected.
    created = client.post("/v1/sessions", json={"preset": "balanced"})
    assert created.status_code == 200
    assert created.json()["session_id"]
    assert created.json()["policy"]["name"] == "balanced"
