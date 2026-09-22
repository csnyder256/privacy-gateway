from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from privacy_gateway.adapters import (
    AdapterBlocked,
    PrivacyASGIMiddleware,
    WebhookVerifier,
    normalize_provider_path,
    protect_provider_request,
    provider_headers,
    restore_provider_response,
    validate_upstream,
)
from privacy_gateway.api import create_app
from privacy_gateway.client import (
    AsyncPrivacyGatewayClient,
    PrivacyGatewayClient,
    PrivacyGatewayError,
)
from privacy_gateway.crypto import generate_key
from privacy_gateway.engine import PrivacyEngine
from privacy_gateway.models import Action, EntityType, Policy, PolicyRule
from privacy_gateway.vault import Vault


@pytest.fixture
def engine(tmp_path):
    from privacy_gateway.crypto import decode_key

    return PrivacyEngine(Vault(tmp_path / "adapter.db", decode_key(generate_key())))


@pytest.mark.parametrize(
    ("provider", "path", "body", "expected"),
    [
        (
            "openai",
            "/v1/chat/completions",
            {"model": "gpt-test", "messages": [{"role": "user", "content": "a@b.com"}]},
            ("messages", 0, "content"),
        ),
        (
            "openai",
            "/v1/responses",
            {"model": "gpt-test", "input": "a@b.com"},
            ("input",),
        ),
        (
            "anthropic",
            "/v1/messages",
            {"model": "claude-test", "messages": [{"role": "user", "content": "a@b.com"}]},
            ("messages", 0, "content"),
        ),
    ],
)
def test_provider_requests_protect_only_prompt_fields(engine, provider, path, body, expected):
    protected, session_id = protect_provider_request(
        engine, provider, path, body, preset="balanced"
    )
    value = protected
    for key in expected:
        value = value[key]
    assert "a@b.com" not in value
    assert protected["model"] == body["model"]
    assert engine.vault.session_summary(session_id)["tags"][0]["count"] == 1


def test_provider_nested_prompt_surfaces_are_protected(engine):
    openai, _ = protect_provider_request(
        engine,
        "openai",
        "responses",
        {
            "instructions": "Contact boss@example.com",
            "input": [
                {
                    "type": "function_call_output",
                    "call_id": "call_1",
                    "output": "Email worker@example.com",
                }
            ],
        },
        preset="balanced",
    )
    assert "boss@example.com" not in openai["instructions"]
    assert "worker@example.com" not in openai["input"][0]["output"]
    anthropic, _ = protect_provider_request(
        engine,
        "anthropic",
        "messages",
        {
            "system": [{"type": "text", "text": "Contact boss@example.com"}],
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tool_1",
                            "content": "Email worker@example.com",
                        }
                    ],
                }
            ],
        },
        preset="balanced",
    )
    assert "boss@example.com" not in anthropic["system"][0]["text"]
    assert "worker@example.com" not in anthropic["messages"][0]["content"][0]["content"]
    for provider, path, body in (
        (
            "openai",
            "chat/completions",
            {
                "messages": [{"role": "user", "content": "hello"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {"name": "notify", "description": "Notify a@b.com"},
                    }
                ],
            },
        ),
        (
            "openai",
            "responses",
            {
                "input": "hello",
                "tools": [{"type": "function", "name": "notify", "description": "Notify a@b.com"}],
            },
        ),
        (
            "anthropic",
            "messages",
            {
                "messages": [{"role": "user", "content": "hello"}],
                "tools": [{"name": "notify", "description": "Notify a@b.com"}],
            },
        ),
    ):
        protected, _ = protect_provider_request(engine, provider, path, body, preset="balanced")
        assert "a@b.com" not in str(protected["tools"])


@pytest.mark.parametrize(
    ("provider", "path", "body"),
    [
        ("openai", "responses", {"input": [{"garbage": "a@b.com"}]}),
        (
            "openai",
            "chat/completions",
            {"messages": [{"role": "not-a-role", "content": "a@b.com"}]},
        ),
        (
            "anthropic",
            "messages",
            {"messages": [{"role": "not-a-role", "content": "a@b.com"}]},
        ),
        (
            "openai",
            "responses",
            {"input": [{"type": "message", "role": "user", "content": [{"type": "input_text"}]}]},
        ),
        (
            "openai",
            "chat/completions",
            {"messages": [{"role": "user", "content": [{"type": "text", "text": 123}]}]},
        ),
        ("openai", "responses", {"input": "hello", "stream": "true"}),
    ],
)
def test_malformed_provider_shapes_block(engine, provider, path, body):
    with pytest.raises(AdapterBlocked):
        protect_provider_request(engine, provider, path, body, preset="balanced")


def test_response_text_restores_but_tool_arguments_block(engine):
    request, session_id = protect_provider_request(
        engine,
        "openai",
        "chat/completions",
        {"messages": [{"role": "user", "content": "Email a@b.com"}]},
        preset="balanced",
    )
    token = request["messages"][0]["content"].removeprefix("Email ")
    restored = restore_provider_response(
        engine,
        "openai",
        "chat/completions",
        {"choices": [{"message": {"content": f"Use {token}"}}]},
        session_id,
    )
    assert restored["choices"][0]["message"]["content"] == "Use a@b.com"
    with pytest.raises(AdapterBlocked, match="tool"):
        restore_provider_response(
            engine,
            "openai",
            "chat/completions",
            {
                "choices": [
                    {
                        "message": {
                            "content": "safe",
                            "tool_calls": [{"function": {"arguments": token}}],
                        }
                    }
                ]
            },
            session_id,
        )
    refusal = restore_provider_response(
        engine,
        "openai",
        "chat/completions",
        {"choices": [{"message": {"content": None, "refusal": f"Cannot send {token}"}}]},
        session_id,
    )
    assert refusal["choices"][0]["message"]["refusal"] == "Cannot send a@b.com"
    with pytest.raises(AdapterBlocked, match="side-effect"):
        restore_provider_response(
            engine,
            "openai",
            "chat/completions",
            {"choices": [{"message": {"content": "safe", "function_call": {"arguments": token}}}]},
            session_id,
        )
    openai_request, openai_session = protect_provider_request(
        engine,
        "openai",
        "responses",
        {"input": "Email a@b.com"},
        preset="balanced",
    )
    openai_token = openai_request["input"].removeprefix("Email ")
    response = restore_provider_response(
        engine,
        "openai",
        "responses",
        {
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "refusal", "refusal": f"Cannot send {openai_token}"}],
                }
            ]
        },
        openai_session,
    )
    assert response["output"][0]["content"][0]["refusal"] == "Cannot send a@b.com"
    for side_effect in ("mcp_call", "local_shell_call", "apply_patch_call"):
        with pytest.raises(AdapterBlocked, match="side-effect"):
            restore_provider_response(
                engine,
                "openai",
                "responses",
                {"output": [{"type": side_effect, "arguments": openai_token}]},
                openai_session,
            )
    for side_effect in ("mcp_tool_use", "server_tool_use"):
        with pytest.raises(AdapterBlocked, match="side-effect"):
            restore_provider_response(
                engine,
                "anthropic",
                "messages",
                {"content": [{"type": side_effect, "input": token}]},
                session_id,
            )


@pytest.mark.parametrize(
    ("provider", "path", "body"),
    [
        ("openai", "responses", {}),
        ("openai", "responses", {"unexpected": "value"}),
        ("openai", "chat/completions", {}),
        ("openai", "chat/completions", {"choices": [{}]}),
        ("anthropic", "messages", {}),
        ("anthropic", "messages", {"content": [{"type": "unknown"}]}),
    ],
)
def test_unsupported_provider_response_shapes_block(engine, provider, path, body):
    with pytest.raises(AdapterBlocked):
        restore_provider_response(engine, provider, path, body, "missing-shape-session")


def test_adapter_boundaries_block_unsafe_inputs(engine):
    assert normalize_provider_path("openai", "/v1/responses") == "responses"
    for value in ("http://example.com/v1", "ftp://localhost/v1", "https://u:p@example.com"):
        with pytest.raises(AdapterBlocked):
            validate_upstream(value)
    assert validate_upstream("http://127.0.0.1:9000/v1") == "http://127.0.0.1:9000/v1"
    with pytest.raises(AdapterBlocked, match="streaming"):
        protect_provider_request(
            engine,
            "openai",
            "responses",
            {"input": "hello", "stream": True},
            preset="balanced",
        )
    with pytest.raises(AdapterBlocked, match="unsupported"):
        protect_provider_request(engine, "openai", "files", {}, preset="balanced")


def test_provider_request_uses_one_session_and_propagates_block(tmp_path):
    from privacy_gateway.crypto import decode_key

    gateway = PrivacyEngine(Vault(tmp_path / "single.db", decode_key(generate_key())))
    calls = 0
    original = gateway.create_session

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    gateway.create_session = counted
    protect_provider_request(
        gateway,
        "openai",
        "responses",
        {"instructions": "Email first@example.com", "input": "Email second@example.com"},
        preset="balanced",
    )
    assert calls == 1
    keyless = PrivacyEngine(Vault(tmp_path / "blocked.db"))
    with pytest.raises(AdapterBlocked, match="requires"):
        protect_provider_request(
            keyless, "openai", "responses", {"input": "Email a@b.com"}, preset="balanced"
        )


def test_provider_request_can_use_a_precreated_custom_policy_session(engine):
    policy = Policy(
        name="custom",
        rules=[
            PolicyRule(
                entity=EntityType.EMAIL_ADDRESS,
                action=Action.REDACT,
                reversible=False,
                minimum_confidence_ppm=900_000,
            )
        ],
    )
    session_id, _ = engine.create_session(policy=policy)
    protected, returned_session = protect_provider_request(
        engine,
        "openai",
        "responses",
        {"input": "Email a@b.com"},
        preset="balanced",
        session_id=session_id,
    )
    assert returned_session == session_id
    assert protected["input"] == "Email [REDACTED:EMAIL_ADDRESS]"


def test_provider_header_allowlist():
    forwarded = provider_headers(
        {
            "authorization": "Bearer fake",
            "cookie": "private=1",
            "x-privacy-preset": "strict",
            "x-api-key": "fake",
            "content-length": "99",
        }
    )
    assert forwarded == {"authorization": "Bearer fake", "x-api-key": "fake"}


def test_webhook_signatures_expiry_tamper_and_replay():
    verifier = WebhookVerifier(b"test-secret", tolerance_seconds=300)
    body = b'{"ok":true}'
    headers = verifier.sign(
        body, timestamp=1_000, delivery_id="00000000-0000-4000-8000-000000000001"
    )
    verifier.verify(body, headers, now=1_100)
    with pytest.raises(AdapterBlocked, match="replayed"):
        verifier.verify(body, headers, now=1_101)
    tampered = verifier.sign(body, timestamp=2_000)
    with pytest.raises(AdapterBlocked, match="signature"):
        verifier.verify(b'{"ok":false}', tampered, now=2_000)
    expired = verifier.sign(body, timestamp=3_000)
    with pytest.raises(AdapterBlocked, match="timestamp"):
        verifier.verify(body, expired, now=3_301)
    with pytest.raises(AdapterBlocked, match="JSON"):
        verifier.sign(b"not-json")


def test_python_client_round_trip_and_errors(tmp_path):
    app = create_app(str(tmp_path / "client.db"))

    def handler(request: httpx.Request) -> httpx.Response:
        with TestClient(app) as test_client:
            response = test_client.request(
                request.method,
                request.url.raw_path.decode(),
                content=request.content,
                headers=dict(request.headers),
            )
        return httpx.Response(
            response.status_code,
            content=response.content,
            headers=dict(response.headers),
            request=request,
        )

    key = generate_key()
    with PrivacyGatewayClient(transport=httpx.MockTransport(handler)) as client:
        protected = client.transform("Email a@b.com", restore_key=key)
        assert protected.text and protected.capsule
        assert (
            client.restore_capsule(protected.text, protected.capsule, key, protected.session_id)
            == "Email a@b.com"
        )
        assert client.delete_session(protected.session_id) is True
        with pytest.raises(PrivacyGatewayError, match="404"):
            client.summary(protected.session_id)


def test_async_client_surface_and_round_trip(tmp_path):
    import asyncio

    app = create_app(str(tmp_path / "async-client.db"))

    async def exercise():
        transport = httpx.ASGITransport(app=app)
        key = generate_key()
        async with AsyncPrivacyGatewayClient(transport=transport) as client:
            session = await client.create_session(preset="balanced")
            assert await client.delete_session(session["session_id"]) is True
            protected = await client.transform("Email a@b.com", restore_key=key)
            assert protected.text and protected.capsule
            assert (
                await client.restore_capsule(
                    protected.text, protected.capsule, key, protected.session_id
                )
                == "Email a@b.com"
            )
            summary = await client.summary(protected.session_id)
            assert summary["session_id"] == protected.session_id

    asyncio.run(exercise())


def test_asgi_middleware_rewrites_json_text_and_content_length(engine):
    downstream = FastAPI()

    @downstream.post("/echo")
    async def echo(request: Request):
        raw = await request.body()
        return {
            "body": raw.decode(),
            "content_length": request.headers.get("content-length"),
            "actual": len(raw),
        }

    wrapped = PrivacyASGIMiddleware(downstream, engine)
    client = TestClient(wrapped)
    json_response = client.post("/echo", json={"message": "Email a@b.com"}).json()
    assert "a@b.com" not in json_response["body"]
    assert int(json_response["content_length"]) == json_response["actual"]
    text_response = client.post(
        "/echo", content="Email a@b.com", headers={"content-type": "text/plain"}
    ).json()
    assert "a@b.com" not in text_response["body"]
    assert int(text_response["content_length"]) == text_response["actual"]


def test_proxy_endpoint_body_limit_and_non_json(monkeypatch, tmp_path):
    monkeypatch.setenv("PRIVACY_GATEWAY_OPENAI_UPSTREAM", "https://api.example/v1")
    monkeypatch.setenv("PRIVACY_GATEWAY_MAX_BODY_BYTES", "32")
    monkeypatch.setenv("PRIVACY_GATEWAY_MASTER_KEY", generate_key())
    client = TestClient(create_app(str(tmp_path / "proxy.db")))
    oversized = client.post(
        "/proxy/openai/responses",
        content=b"x" * 33,
        headers={"content-type": "application/json"},
    )
    assert oversized.status_code == 413
    malformed = client.post(
        "/proxy/openai/responses",
        content=b"{",
        headers={"content-type": "application/json"},
    )
    assert malformed.status_code == 422


@pytest.mark.parametrize(
    ("status", "content_type", "expected"),
    [(307, "application/json", "redirects"), (200, "text/plain", "non-JSON")],
)
def test_proxy_rejects_upstream_redirects_and_non_json(
    monkeypatch, tmp_path, status, content_type, expected
):
    class FakeAsyncClient:
        def __init__(self, **kwargs):
            assert kwargs["follow_redirects"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def post(self, url, **kwargs):
            request = httpx.Request("POST", url)
            return httpx.Response(
                status,
                content=b"{}" if "json" in content_type else b"plain",
                headers={"content-type": content_type, "location": "https://other.example"},
                request=request,
            )

    monkeypatch.setattr("privacy_gateway.api.httpx.AsyncClient", FakeAsyncClient)
    monkeypatch.setenv("PRIVACY_GATEWAY_OPENAI_UPSTREAM", "https://api.example/v1")
    monkeypatch.setenv("PRIVACY_GATEWAY_MASTER_KEY", generate_key())
    client = TestClient(create_app(str(tmp_path / f"proxy-{status}.db")))
    response = client.post(
        "/proxy/openai/responses",
        json={"model": "gpt-test", "input": "Email a@b.com"},
    )
    assert response.status_code == 502
    assert expected in response.json()["detail"]


def test_mcp_surface_is_exact():
    source = Path("src/privacy_gateway/mcp_server.py").read_text(encoding="utf-8")
    names = {
        "protect_text",
        "restore_text",
        "restore_client_text",
        "inspect_policy",
        "privacy_summary",
    }
    assert {name for name in names if f"def {name}(" in source} == names
    assert source.count("@mcp.tool()") == 5
