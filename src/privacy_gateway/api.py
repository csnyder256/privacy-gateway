from __future__ import annotations

import os
from pathlib import Path

import httpx
from cryptography.exceptions import InvalidTag
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .adapters import (
    AdapterBlocked,
    normalize_provider_path,
    protect_provider_request,
    provider_headers,
    restore_provider_response,
    validate_upstream,
)
from .crypto import key_from_env
from .engine import PrivacyEngine
from .models import (
    CapsuleRestoreRequest,
    RestoreRequest,
    SessionCreateRequest,
    SessionResponse,
    TransformRequest,
    TransformResponse,
)
from .policies import PRESETS
from .vault import open_vault


def create_app(database_path: str | None = None) -> FastAPI:
    data_path = database_path or os.getenv("PRIVACY_GATEWAY_DB", "./data/privacy-gateway.db")
    vault = open_vault(data_path, master_key=key_from_env())
    engine = PrivacyEngine(vault)
    app = FastAPI(
        title="Privacy Gateway",
        version=__version__,
        description="Policy-controlled PII anonymization, tagging, auditing, and reversible restoration.",
    )
    app.state.vault = vault
    app.state.engine = engine

    @app.get("/v1/health")
    def health():
        return {
            "ok": True,
            "version": __version__,
            "persistent_restoration": vault.master_key is not None,
        }

    @app.get("/v1/presets")
    def presets():
        return {name: policy.model_dump(mode="json") for name, policy in PRESETS.items()}

    @app.post("/v1/sessions", response_model=SessionResponse)
    def create_session(request: SessionCreateRequest):
        session_id, policy = engine.create_session(request.policy, request.preset, request.metadata)
        return SessionResponse(session_id=session_id, policy=policy)

    @app.post("/v1/transform", response_model=TransformResponse)
    def transform(request: TransformRequest):
        try:
            return engine.transform(
                request.text,
                session_id=request.session_id,
                policy=request.policy,
                preset=request.preset or "balanced",
                restore_key=request.restore_key,
                metadata=request.context,
                scope=request.scope,
            )
        except (KeyError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/v1/restore")
    def restore(request: RestoreRequest):
        try:
            return {"text": engine.restore(request.text, request.session_id)}
        except (KeyError, RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/v1/restore/capsule")
    def restore_capsule(request: CapsuleRestoreRequest):
        try:
            return {
                "text": PrivacyEngine.restore_capsule(
                    request.text,
                    request.capsule,
                    request.restore_key,
                    request.session_id,
                )
            }
        except InvalidTag as exc:
            raise HTTPException(status_code=422, detail="capsule authentication failed") from exc
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/v1/sessions/{session_id}/summary")
    def summary(session_id: str):
        try:
            vault.policy_for(session_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return vault.session_summary(session_id)

    @app.delete("/v1/sessions/expired")
    def purge_expired():
        return {"deleted": vault.purge_expired()}

    @app.delete("/v1/sessions/{session_id}")
    def delete_session(session_id: str):
        return {"deleted": vault.delete_session(session_id)}

    async def provider_proxy(provider: str, path: str, request: Request):
        upstream = os.getenv(f"PRIVACY_GATEWAY_{provider.upper()}_UPSTREAM")
        if not upstream:
            raise HTTPException(
                status_code=503,
                detail=f"PRIVACY_GATEWAY_{provider.upper()}_UPSTREAM is not configured",
            )
        maximum = int(os.getenv("PRIVACY_GATEWAY_MAX_BODY_BYTES", "1048576"))
        raw = await request.body()
        if len(raw) > maximum:
            raise HTTPException(status_code=413, detail="provider request body exceeds limit")
        try:
            body = await request.json()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="provider body must be valid JSON") from exc
        preset = request.headers.get("x-privacy-preset", "balanced")
        try:
            endpoint = normalize_provider_path(provider, path)
            upstream = validate_upstream(upstream)
            protected, session_id = protect_provider_request(
                engine,
                provider,
                endpoint,
                body,
                preset=preset,
                session_id=request.headers.get("x-privacy-session-id"),
            )
        except (AdapterBlocked, KeyError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        async with httpx.AsyncClient(timeout=120, follow_redirects=False) as client:
            response = await client.post(
                f"{upstream}/{endpoint}",
                json=protected,
                headers=provider_headers(request.headers),
            )
        if 300 <= response.status_code < 400:
            raise HTTPException(status_code=502, detail="provider redirects are not followed")
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                payload = response.json()
                if response.is_success:
                    payload = restore_provider_response(
                        engine, provider, endpoint, payload, session_id
                    )
            except (ValueError, AdapterBlocked, RuntimeError, KeyError) as exc:
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            return JSONResponse(payload, status_code=response.status_code)
        return JSONResponse({"detail": "upstream returned a non-JSON response"}, status_code=502)

    @app.post("/proxy/openai/{path:path}")
    async def openai_proxy(path: str, request: Request):
        return await provider_proxy("openai", path, request)

    @app.post("/proxy/anthropic/{path:path}")
    async def anthropic_proxy(path: str, request: Request):
        return await provider_proxy("anthropic", path, request)

    static_path = Path(__file__).with_name("static")
    app.mount("/assets", StaticFiles(directory=static_path), name="assets")

    @app.get("/", include_in_schema=False)
    def onboarding():
        return FileResponse(static_path / "index.html")

    return app


app = create_app()
