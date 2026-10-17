from __future__ import annotations

import json
from typing import Any, Self

import httpx

from .models import Policy, TransformResponse


class PrivacyGatewayError(RuntimeError):
    """Raised when the gateway rejects a request or returns an invalid response."""


def _describe_detail(body: object, fallback: str) -> str:
    """The ``detail`` a JSON gateway error carries, as text, else ``fallback``."""
    if isinstance(body, dict) and "detail" in body:
        detail = body["detail"]
        if isinstance(detail, str):
            return detail
        # FastAPI answers a validation failure with a list of objects, which an
        # f-string would flatten to a Python repr instead of the JSON the caller
        # can read back.
        if detail is not None:
            return json.dumps(detail)
    return fallback


def _raise(response: httpx.Response) -> None:
    """Raise ``PrivacyGatewayError`` for anything that is not a JSON 2xx.

    A gateway failure is not always JSON: Starlette answers an unhandled exception
    with a ``text/plain`` "Internal Server Error", a reverse proxy answers with an
    HTML error page, and a 503 can carry no body at all. The body is therefore read
    once as text and parsed only when it parses, so a failure arrives as a
    structured error carrying its status rather than as an ``AttributeError`` from
    a JSON scalar or array, or as a bare decode error from a 2xx.
    ``packages/client`` reads it the same way.
    """
    raw = response.text
    try:
        body: object = json.loads(raw)
    except ValueError:
        body, parsed = None, False
    else:
        parsed = True

    if not response.is_success:
        raise PrivacyGatewayError(
            f"gateway returned {response.status_code}: "
            f"{_describe_detail(body, raw.strip() or 'request failed')}"
        )
    if not parsed:
        # A 2xx that is not the promised JSON is a contract break, not a parse
        # accident: report it as a structured error rather than a decode error.
        raise PrivacyGatewayError(
            f"gateway returned {response.status_code}: response body was not JSON"
        )


class PrivacyGatewayClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8787",
        *,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ):
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"), timeout=timeout, transport=transport
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def create_session(
        self,
        *,
        preset: str = "balanced",
        policy: Policy | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        response = self._client.post(
            "/v1/sessions",
            json={
                "preset": preset,
                "policy": policy.model_dump(mode="json") if policy else None,
                "metadata": metadata or {},
            },
        )
        _raise(response)
        return response.json()

    def transform(
        self,
        text: str,
        *,
        preset: str = "balanced",
        session_id: str | None = None,
        restore_key: str | None = None,
        scope: str = "text",
    ) -> TransformResponse:
        response = self._client.post(
            "/v1/transform",
            json={
                "text": text,
                "preset": preset,
                "session_id": session_id,
                "restore_key": restore_key,
                "scope": scope,
            },
        )
        _raise(response)
        return TransformResponse.model_validate(response.json())

    def restore(self, text: str, session_id: str) -> str:
        response = self._client.post("/v1/restore", json={"text": text, "session_id": session_id})
        _raise(response)
        return str(response.json()["text"])

    def restore_capsule(self, text: str, capsule: str, restore_key: str, session_id: str) -> str:
        response = self._client.post(
            "/v1/restore/capsule",
            json={
                "text": text,
                "capsule": capsule,
                "restore_key": restore_key,
                "session_id": session_id,
            },
        )
        _raise(response)
        return str(response.json()["text"])

    def summary(self, session_id: str) -> dict[str, Any]:
        response = self._client.get(f"/v1/sessions/{session_id}/summary")
        _raise(response)
        return response.json()

    def delete_session(self, session_id: str) -> bool:
        response = self._client.delete(f"/v1/sessions/{session_id}")
        _raise(response)
        return bool(response.json()["deleted"])


class AsyncPrivacyGatewayClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8787",
        *,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"), timeout=timeout, transport=transport
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def create_session(
        self,
        *,
        preset: str = "balanced",
        policy: Policy | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        response = await self._client.post(
            "/v1/sessions",
            json={
                "preset": preset,
                "policy": policy.model_dump(mode="json") if policy else None,
                "metadata": metadata or {},
            },
        )
        _raise(response)
        return response.json()

    async def transform(
        self,
        text: str,
        *,
        preset: str = "balanced",
        session_id: str | None = None,
        restore_key: str | None = None,
        scope: str = "text",
    ) -> TransformResponse:
        response = await self._client.post(
            "/v1/transform",
            json={
                "text": text,
                "preset": preset,
                "session_id": session_id,
                "restore_key": restore_key,
                "scope": scope,
            },
        )
        _raise(response)
        return TransformResponse.model_validate(response.json())

    async def restore_capsule(
        self, text: str, capsule: str, restore_key: str, session_id: str
    ) -> str:
        response = await self._client.post(
            "/v1/restore/capsule",
            json={
                "text": text,
                "capsule": capsule,
                "restore_key": restore_key,
                "session_id": session_id,
            },
        )
        _raise(response)
        return str(response.json()["text"])

    async def restore(self, text: str, session_id: str) -> str:
        response = await self._client.post(
            "/v1/restore", json={"text": text, "session_id": session_id}
        )
        _raise(response)
        return str(response.json()["text"])

    async def summary(self, session_id: str) -> dict[str, Any]:
        response = await self._client.get(f"/v1/sessions/{session_id}/summary")
        _raise(response)
        return response.json()

    async def delete_session(self, session_id: str) -> bool:
        response = await self._client.delete(f"/v1/sessions/{session_id}")
        _raise(response)
        return bool(response.json()["deleted"])
