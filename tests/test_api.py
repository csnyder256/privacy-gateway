from fastapi.testclient import TestClient

from privacy_gateway.api import create_app
from privacy_gateway.crypto import generate_key


def test_onboarding_and_health_are_served(tmp_path):
    client = TestClient(create_app(str(tmp_path / "api.db")))
    assert client.get("/v1/health").json()["ok"] is True
    page = client.get("/")
    assert page.status_code == 200
    assert "Build my policy" in page.text
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
