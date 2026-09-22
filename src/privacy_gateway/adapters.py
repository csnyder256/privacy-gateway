from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .engine import TOKEN_RE, PrivacyEngine
from .models import TransformState


class AdapterBlocked(ValueError):
    """A payload cannot safely cross the configured privacy boundary."""


OPENAI_PATHS = {"chat/completions", "responses"}
ANTHROPIC_PATHS = {"messages"}
SAFE_FORWARD_HEADERS = {
    "accept",
    "accept-encoding",
    "anthropic-beta",
    "anthropic-version",
    "authorization",
    "openai-organization",
    "openai-project",
    "user-agent",
    "x-api-key",
}


def normalize_provider_path(provider: str, path: str) -> str:
    normalized = path.strip("/").removeprefix("v1/")
    allowed = OPENAI_PATHS if provider == "openai" else ANTHROPIC_PATHS
    if normalized not in allowed:
        raise AdapterBlocked(f"unsupported {provider} endpoint: {path}")
    return normalized


def validate_upstream(value: str) -> str:
    parsed = urlparse(value)
    loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise AdapterBlocked("provider upstream must use HTTPS (HTTP is loopback-only)")
    if parsed.username or parsed.password or not parsed.hostname or parsed.query or parsed.fragment:
        raise AdapterBlocked("provider upstream URL contains forbidden components")
    return value.rstrip("/")


def provider_headers(headers: Any) -> dict[str, str]:
    return {key: value for key, value in headers.items() if key.lower() in SAFE_FORWARD_HEADERS}


def _transform_text(
    engine: PrivacyEngine, text: str, session_id: str, preset: str, scope: str
) -> str:
    result = engine.transform(text, session_id=session_id, preset=preset, scope=scope)
    if result.state != TransformState.PROTECTED or result.text is None:
        raise AdapterBlocked(result.reason or "privacy transform blocked")
    return result.text


def _walk_content(
    engine: PrivacyEngine,
    value: Any,
    session_id: str,
    preset: str,
    scope: str,
) -> Any:
    if isinstance(value, str):
        return _transform_text(engine, value, session_id, preset, scope)
    if isinstance(value, list):
        result = []
        for index, item in enumerate(value):
            if isinstance(item, dict) and item.get("type") in {
                "text",
                "input_text",
                "output_text",
            }:
                copy = dict(item)
                key = "text"
                if not isinstance(copy.get(key), str):
                    raise AdapterBlocked(f"text content block requires text at {scope}/{index}")
                copy[key] = _transform_text(
                    engine, copy[key], session_id, preset, f"{scope}/{index}/text"
                )
                result.append(copy)
            elif isinstance(item, dict) and item.get("type") == "tool_result":
                copy = dict(item)
                copy["content"] = _walk_content(
                    engine,
                    copy.get("content", ""),
                    session_id,
                    preset,
                    f"{scope}/{index}/content",
                )
                result.append(copy)
            else:
                raise AdapterBlocked(f"unsupported content block at {scope}/{index}")
        return result
    raise AdapterBlocked(f"unsupported prompt content at {scope}")


def _protect_tool_descriptions(
    engine: PrivacyEngine,
    tools: Any,
    session_id: str,
    preset: str,
    scope: str,
) -> list[dict[str, Any]]:
    if not isinstance(tools, list):
        raise AdapterBlocked("provider tools must be an array")
    output = []
    for index, item in enumerate(tools):
        if not isinstance(item, dict):
            raise AdapterBlocked("provider tools must contain objects")
        copy = dict(item)
        target = copy.get("function") if isinstance(copy.get("function"), dict) else copy
        target = dict(target)
        if "description" in target:
            if not isinstance(target["description"], str):
                raise AdapterBlocked("tool description must be text")
            target["description"] = _transform_text(
                engine,
                target["description"],
                session_id,
                preset,
                f"{scope}/{index}/description",
            )
        if "function" in copy:
            copy["function"] = target
        else:
            copy = target
        output.append(copy)
    return output


def protect_provider_request(
    engine: PrivacyEngine,
    provider: str,
    path: str,
    body: Any,
    *,
    preset: str,
    session_id: str | None = None,
) -> tuple[dict[str, Any], str]:
    endpoint = normalize_provider_path(provider, path)
    if not isinstance(body, dict):
        raise AdapterBlocked("provider body must be a JSON object")
    if body.get("stream") not in {None, False}:
        raise AdapterBlocked("streaming provider responses are not supported in v0.1")
    protected = dict(body)
    if session_id is None:
        session_id, _ = engine.create_session(preset=preset)
    else:
        engine.vault.policy_for(session_id)
    touched = False
    if provider == "openai" and endpoint == "chat/completions":
        messages = body.get("messages")
        if not isinstance(messages, list):
            raise AdapterBlocked("OpenAI chat body requires a messages array")
        output = []
        for index, message in enumerate(messages):
            if not isinstance(message, dict):
                raise AdapterBlocked("OpenAI messages must be objects")
            if message.get("role") not in {"system", "developer", "user", "assistant", "tool"}:
                raise AdapterBlocked("unsupported OpenAI message role")
            copy = dict(message)
            if "content" in copy and copy["content"] is not None:
                copy["content"] = _walk_content(
                    engine,
                    copy["content"],
                    session_id,
                    preset,
                    f"openai.messages/{index}/content",
                )
                touched = True
            if isinstance(copy.get("function_call"), dict):
                call = dict(copy["function_call"])
                if not isinstance(call.get("arguments"), str):
                    raise AdapterBlocked("OpenAI function_call.arguments must be a string")
                call["arguments"] = _transform_text(
                    engine,
                    call["arguments"],
                    session_id,
                    preset,
                    f"openai.messages/{index}/function_call/arguments",
                )
                copy["function_call"] = call
                touched = True
            if isinstance(copy.get("tool_calls"), list):
                calls = []
                for call_index, item in enumerate(copy["tool_calls"]):
                    if not isinstance(item, dict) or not isinstance(item.get("function"), dict):
                        raise AdapterBlocked("OpenAI tool_calls must contain function objects")
                    call = dict(item)
                    function = dict(call["function"])
                    if not isinstance(function.get("arguments"), str):
                        raise AdapterBlocked("OpenAI tool arguments must be strings")
                    function["arguments"] = _transform_text(
                        engine,
                        function["arguments"],
                        session_id,
                        preset,
                        f"openai.messages/{index}/tool_calls/{call_index}/arguments",
                    )
                    call["function"] = function
                    calls.append(call)
                copy["tool_calls"] = calls
                touched = True
            output.append(copy)
        protected["messages"] = output
    elif provider == "openai" and endpoint == "responses":
        if "input" not in body:
            raise AdapterBlocked("OpenAI Responses body requires input")
        value = body["input"]
        if isinstance(value, str):
            protected["input"] = _transform_text(
                engine, value, session_id, preset, "openai.responses/input"
            )
        elif isinstance(value, list):
            output = []
            for index, item in enumerate(value):
                if not isinstance(item, dict) or not isinstance(item.get("type"), str):
                    raise AdapterBlocked("OpenAI Responses input items must be objects")
                copy = dict(item)
                item_type = copy["type"]
                if item_type == "message":
                    if copy.get("role") not in {"system", "developer", "user", "assistant"}:
                        raise AdapterBlocked("unsupported OpenAI Responses message role")
                    if "content" not in copy:
                        raise AdapterBlocked("OpenAI Responses messages require content")
                    copy["content"] = _walk_content(
                        engine,
                        copy["content"],
                        session_id,
                        preset,
                        f"openai.responses/input/{index}/content",
                    )
                elif item_type == "function_call_output":
                    output_value = copy.get("output")
                    if isinstance(output_value, str):
                        copy["output"] = _transform_text(
                            engine,
                            output_value,
                            session_id,
                            preset,
                            f"openai.responses/input/{index}/output",
                        )
                    else:
                        raise AdapterBlocked("function_call_output.output must be a string")
                else:
                    raise AdapterBlocked(f"unsupported OpenAI Responses input type: {item_type}")
                output.append(copy)
            protected["input"] = output
        else:
            raise AdapterBlocked("unsupported OpenAI Responses input")
        if "instructions" in body:
            if not isinstance(body["instructions"], str):
                raise AdapterBlocked("OpenAI Responses instructions must be a string")
            protected["instructions"] = _transform_text(
                engine,
                body["instructions"],
                session_id,
                preset,
                "openai.responses/instructions",
            )
        touched = True
    elif provider == "anthropic":
        messages = body.get("messages")
        if not isinstance(messages, list):
            raise AdapterBlocked("Anthropic body requires a messages array")
        output = []
        for index, message in enumerate(messages):
            if not isinstance(message, dict) or "content" not in message:
                raise AdapterBlocked("Anthropic messages require content")
            if message.get("role") not in {"user", "assistant"}:
                raise AdapterBlocked("unsupported Anthropic message role")
            copy = dict(message)
            copy["content"] = _walk_content(
                engine,
                copy["content"],
                session_id,
                preset,
                f"anthropic.messages/{index}/content",
            )
            output.append(copy)
        protected["messages"] = output
        if isinstance(body.get("system"), str):
            protected["system"] = _transform_text(
                engine, body["system"], session_id, preset, "anthropic.system"
            )
        elif isinstance(body.get("system"), list):
            protected["system"] = _walk_content(
                engine, body["system"], session_id, preset, "anthropic.system"
            )
        elif body.get("system") is not None:
            raise AdapterBlocked("Anthropic system must be text or text blocks")
        touched = True
    if not touched:
        raise AdapterBlocked("provider request contained no supported prompt field")
    if "tools" in body:
        protected["tools"] = _protect_tool_descriptions(
            engine, body["tools"], session_id, preset, f"{provider}.tools"
        )
    return protected, session_id


def restore_provider_response(
    engine: PrivacyEngine, provider: str, path: str, body: Any, session_id: str
) -> dict[str, Any]:
    endpoint = normalize_provider_path(provider, path)
    if not isinstance(body, dict):
        raise AdapterBlocked("provider response must be a JSON object")
    restored = json.loads(json.dumps(body))

    def restore_text(value: Any) -> Any:
        return engine.restore(value, session_id) if isinstance(value, str) else value

    def block_side_effect(value: Any) -> None:
        serialized = json.dumps(value, sort_keys=True, separators=(",", ":"))
        if TOKEN_RE.search(serialized):
            raise AdapterBlocked("restorable surrogate found in tool or side-effect arguments")

    if provider == "openai" and endpoint == "chat/completions":
        choices = restored.get("choices")
        if not isinstance(choices, list):
            raise AdapterBlocked("OpenAI Chat response requires a choices array")
        for choice in choices:
            if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
                raise AdapterBlocked("OpenAI Chat choices require message objects")
            message = choice["message"]
            if "content" in message:
                if message["content"] is not None and not isinstance(message["content"], str):
                    raise AdapterBlocked("OpenAI Chat message content must be text or null")
                message["content"] = restore_text(message["content"])
            if "refusal" in message:
                if message["refusal"] is not None and not isinstance(message["refusal"], str):
                    raise AdapterBlocked("OpenAI Chat refusal must be text or null")
                message["refusal"] = restore_text(message["refusal"])
            if not any(
                key in message for key in ("content", "refusal", "tool_calls", "function_call")
            ):
                raise AdapterBlocked("OpenAI Chat message has no supported output field")
            block_side_effect(message.get("tool_calls", []))
            block_side_effect(message.get("function_call", {}))
    elif provider == "openai":
        output = restored.get("output")
        if not isinstance(output, list):
            raise AdapterBlocked("OpenAI Responses response requires an output array")
        side_effect_types = {
            "apply_patch_call",
            "code_interpreter_call",
            "computer_call",
            "custom_tool_call",
            "file_search_call",
            "function_call",
            "image_generation_call",
            "local_shell_call",
            "mcp_call",
            "web_search_call",
        }
        for item in output:
            if not isinstance(item, dict):
                raise AdapterBlocked("OpenAI Responses output items must be objects")
            item_type = item.get("type")
            if item_type in side_effect_types:
                block_side_effect(item)
                continue
            if item_type != "message" or not isinstance(item.get("content"), list):
                raise AdapterBlocked(f"unsupported OpenAI Responses output type: {item_type}")
            for content in item["content"]:
                if isinstance(content, dict) and content.get("type") in {
                    "output_text",
                    "text",
                }:
                    if not isinstance(content.get("text"), str):
                        raise AdapterBlocked("OpenAI response text block requires text")
                    content["text"] = restore_text(content.get("text"))
                elif isinstance(content, dict) and content.get("type") == "refusal":
                    if not isinstance(content.get("refusal"), str):
                        raise AdapterBlocked("OpenAI refusal block requires refusal text")
                    content["refusal"] = restore_text(content.get("refusal"))
                else:
                    raise AdapterBlocked("unsupported OpenAI response content block")
    else:
        content_blocks = restored.get("content")
        if not isinstance(content_blocks, list):
            raise AdapterBlocked("Anthropic response requires a content array")
        for item in content_blocks:
            if not isinstance(item, dict):
                raise AdapterBlocked("Anthropic content blocks must be objects")
            if item.get("type") == "text":
                if not isinstance(item.get("text"), str):
                    raise AdapterBlocked("Anthropic text block requires text")
                item["text"] = restore_text(item.get("text"))
            elif item.get("type") == "thinking":
                if not isinstance(item.get("thinking"), str):
                    raise AdapterBlocked("Anthropic thinking block requires thinking text")
                item["thinking"] = restore_text(item.get("thinking"))
            elif item.get("type") in {"mcp_tool_use", "server_tool_use", "tool_use"}:
                block_side_effect(item)
            else:
                raise AdapterBlocked(f"unsupported Anthropic content type: {item.get('type')}")
    return restored


class PrivacyASGIMiddleware:
    """Protect JSON/text request bodies before an injected ASGI outbound app sees them."""

    def __init__(self, app: Any, engine: PrivacyEngine, preset: str = "balanced"):
        self.app = app
        self.engine = engine
        self.preset = preset

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        chunks = []
        more = True
        while more:
            event = await receive()
            if event.get("type") != "http.request":
                continue
            chunks.append(event.get("body", b""))
            more = event.get("more_body", False)
        raw = b"".join(chunks)
        content_type = dict(scope.get("headers", [])).get(b"content-type", b"").decode()
        session_id, _ = self.engine.create_session(preset=self.preset)
        try:
            if "application/json" in content_type:
                value = json.loads(raw)
                protected, _ = self.engine.transform_json(
                    value, session_id=session_id, preset=self.preset, scope="asgi"
                )
                raw = json.dumps(protected, separators=(",", ":")).encode()
            elif content_type.startswith("text/"):
                raw = _transform_text(
                    self.engine, raw.decode(), session_id, self.preset, "asgi:text"
                ).encode()
            else:
                raise AdapterBlocked("middleware supports only JSON and text bodies")
        except (UnicodeDecodeError, json.JSONDecodeError, AdapterBlocked, ValueError) as exc:
            payload = json.dumps({"detail": str(exc)}).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 422,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send({"type": "http.response.body", "body": payload})
            return
        delivered = False
        updated_scope = dict(scope)
        headers = [
            (key, value)
            for key, value in scope.get("headers", [])
            if key.lower() not in {b"content-length", b"transfer-encoding"}
        ]
        headers.append((b"content-length", str(len(raw)).encode()))
        updated_scope["headers"] = headers

        async def protected_receive() -> dict:
            nonlocal delivered
            if delivered:
                return {"type": "http.request", "body": b"", "more_body": False}
            delivered = True
            return {"type": "http.request", "body": raw, "more_body": False}

        await self.app(updated_scope, protected_receive, send)


@dataclass
class WebhookVerifier:
    secret: bytes
    tolerance_seconds: int = 300
    _seen: dict[str, int] = field(default_factory=dict)

    @staticmethod
    def signed_bytes(timestamp: int, delivery_id: str, body: bytes) -> bytes:
        return str(timestamp).encode() + b"." + delivery_id.encode() + b"." + body

    def sign(self, body: bytes, *, timestamp: int | None = None, delivery_id: str | None = None):
        self._require_json_object(body)
        timestamp = int(time.time()) if timestamp is None else timestamp
        delivery_id = delivery_id or str(uuid.uuid4())
        signature = hmac.new(
            self.secret,
            self.signed_bytes(timestamp, delivery_id, body),
            hashlib.sha256,
        ).hexdigest()
        return {
            "x-privacy-timestamp": str(timestamp),
            "x-privacy-delivery": delivery_id,
            "x-privacy-signature": f"sha256={signature}",
        }

    @staticmethod
    def _require_json_object(body: bytes) -> None:
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AdapterBlocked("webhook body must be valid JSON") from exc
        if not isinstance(value, dict):
            raise AdapterBlocked("webhook body must be a JSON object")

    def verify(self, body: bytes, headers: dict[str, str], *, now: int | None = None) -> None:
        self._require_json_object(body)
        now = int(time.time()) if now is None else now
        try:
            timestamp = int(headers["x-privacy-timestamp"])
            delivery = str(uuid.UUID(headers["x-privacy-delivery"]))
            supplied = headers["x-privacy-signature"]
        except (KeyError, ValueError) as exc:
            raise AdapterBlocked("invalid webhook authentication headers") from exc
        if abs(now - timestamp) > self.tolerance_seconds:
            raise AdapterBlocked("webhook timestamp outside tolerance")
        self._seen = {key: expiry for key, expiry in self._seen.items() if expiry > now}
        if delivery in self._seen:
            raise AdapterBlocked("webhook delivery replayed")
        expected = self.sign(body, timestamp=timestamp, delivery_id=delivery)["x-privacy-signature"]
        if not hmac.compare_digest(supplied, expected):
            raise AdapterBlocked("invalid webhook signature")
        self._seen[delivery] = max(now, timestamp) + self.tolerance_seconds
