"""Optional MCP surface. Install with: pip install 'privacy-gateway[mcp]'.

The tool set is the normative one (docs/normative-contract.md and
contracts/compatibility-v1.json): protect_text, protect_json,
restore_client_text, inspect_policy and verify_round_trip. Restoration from
the gateway's own stored mappings is deliberately not a tool. An MCP client is
usually a model, and a tool that turns surrogates back into originals would
hand it exactly what the gateway exists to keep from it; restoration happens
through restore_client_text with a capsule and key the caller already holds.
"""

from __future__ import annotations

import functools
import os
from typing import Any

from cryptography.exceptions import InvalidTag

from .crypto import key_from_env
from .engine import PrivacyEngine
from .models import Policy
from .vault import open_vault
from .verification import round_trip_checks


def _sdk():
    """Return the MCP SDK's high-level server class and its ToolError.

    mcp 2.x renamed ``FastMCP`` to ``MCPServer`` and moved it; the constructor,
    ``@tool()`` and ``run()`` used here are unchanged, so both lines work.
    """
    try:
        from mcp.server.mcpserver import MCPServer
        from mcp.server.mcpserver.exceptions import ToolError
    except ImportError:
        pass
    else:
        return MCPServer, ToolError
    try:
        from mcp.server.fastmcp import FastMCP
        from mcp.server.fastmcp.exceptions import ToolError
    except ImportError as exc:
        raise SystemExit("Install the MCP extra: pip install 'privacy-gateway[mcp]'") from exc
    return FastMCP, ToolError


def _reported_as(tool_error):
    """Turn expected failures into the SDK's ToolError, as the HTTP API turns them into 422s.

    mcp 2.1+ treats any other exception as a server fault: the client sees only
    "Error executing tool" and the reason (an unknown preset, a tampered
    capsule) is lost.
    """

    def decorate(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except InvalidTag as exc:
                raise tool_error("capsule authentication failed") from exc
            except (KeyError, ValueError, TypeError, RuntimeError) as exc:
                raise tool_error(str(exc)) from exc

        return wrapper

    return decorate


def _selected_policy(session_id: str | None, policy: dict | None) -> Policy | None:
    if session_id and policy is not None:
        raise ValueError("provide session_id or policy, not both")
    return Policy.model_validate(policy) if policy is not None else None


def build_server(engine: PrivacyEngine, sdk=None):
    """Build the MCP server around an engine without starting a transport."""
    server_class, tool_error = sdk or _sdk()
    mcp = server_class("Privacy Gateway")
    reported = _reported_as(tool_error)

    @mcp.tool()
    @reported
    def protect_text(
        text: str,
        preset: str = "balanced",
        session_id: str | None = None,
        policy: dict | None = None,
    ) -> dict:
        """Protect PII before sending text to an external model or tool."""
        return engine.transform(
            text,
            preset=preset,
            session_id=session_id,
            policy=_selected_policy(session_id, policy),
        ).model_dump(mode="json")

    @mcp.tool()
    @reported
    def protect_json(
        value: Any,
        preset: str = "balanced",
        session_id: str | None = None,
        policy: dict | None = None,
    ) -> dict:
        """Protect every string inside a JSON value, such as tool arguments or a record."""
        selected = _selected_policy(session_id, policy)
        if session_id is None:
            session_id, selected = engine.create_session(selected, preset)
        protected, results = engine.transform_json(value, session_id=session_id, policy=selected)
        return {
            "value": protected,
            "session_id": session_id,
            "detections": [
                detection.model_dump(mode="json")
                for result in results
                for detection in result.detections
            ],
        }

    @mcp.tool()
    @reported
    def restore_client_text(text: str, capsule: str, restore_key: str, session_id: str) -> str:
        """Restore a client-held capsule without persisting the original on the gateway."""
        return PrivacyEngine.restore_capsule(text, capsule, restore_key, session_id)

    @mcp.tool()
    @reported
    def inspect_policy(preset: str = "balanced") -> dict:
        """Return the complete policy behind a built-in preset."""
        from .policies import policy_from_preset

        return policy_from_preset(preset).model_dump(mode="json")

    @mcp.tool()
    @reported
    def verify_round_trip() -> dict:
        """Run the round-trip, tolerant-token and fail-closed probes against this gateway."""
        checks = round_trip_checks(engine.detectors)
        return {"passed": all(checks.values()), "checks": checks}

    return mcp


def main():
    # Resolve the SDK before opening the vault, so a missing extra fails
    # without creating a database or connecting to one.
    sdk = _sdk()
    engine = PrivacyEngine(
        open_vault(os.getenv("PRIVACY_GATEWAY_DB", "./data/privacy-gateway.db"), key_from_env())
    )
    build_server(engine, sdk).run()


if __name__ == "__main__":
    main()
