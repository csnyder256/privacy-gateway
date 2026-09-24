"""Optional MCP surface. Install with: pip install 'privacy-gateway[mcp]'."""

from __future__ import annotations

import os

from .crypto import key_from_env
from .engine import PrivacyEngine
from .models import Policy
from .vault import open_vault


def _server_class():
    """Return the MCP SDK's high-level server class.

    mcp 2.x renamed ``FastMCP`` to ``MCPServer`` and moved it; the constructor,
    ``@tool()`` and ``run()`` used here are unchanged, so both lines work.
    """
    try:
        from mcp.server.mcpserver import MCPServer
    except ImportError:
        pass
    else:
        return MCPServer
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise SystemExit("Install the MCP extra: pip install 'privacy-gateway[mcp]'") from exc
    return FastMCP


def build_server(engine: PrivacyEngine):
    """Build the MCP server around an engine without starting a transport."""
    mcp = _server_class()("Privacy Gateway")

    @mcp.tool()
    def protect_text(
        text: str,
        preset: str = "balanced",
        session_id: str | None = None,
        policy: dict | None = None,
    ) -> dict:
        """Protect PII before sending text to an external model or tool."""
        if session_id and policy is not None:
            raise ValueError("provide session_id or policy, not both")
        selected = Policy.model_validate(policy) if policy is not None else None
        return engine.transform(
            text,
            preset=preset,
            session_id=session_id,
            policy=selected,
        ).model_dump(mode="json")

    @mcp.tool()
    def restore_text(text: str, session_id: str) -> str:
        """Restore protected values when server-side encrypted mappings are enabled."""
        return engine.restore(text, session_id)

    @mcp.tool()
    def restore_client_text(text: str, capsule: str, restore_key: str, session_id: str) -> str:
        """Restore a client-held capsule without persisting the original on the gateway."""
        return PrivacyEngine.restore_capsule(text, capsule, restore_key, session_id)

    @mcp.tool()
    def inspect_policy(preset: str = "balanced") -> dict:
        """Return the complete policy behind a built-in preset."""
        from .policies import policy_from_preset

        return policy_from_preset(preset).model_dump(mode="json")

    @mcp.tool()
    def privacy_summary(session_id: str) -> dict:
        """Return type/action counts without exposing original values."""
        return engine.vault.session_summary(session_id)

    return mcp


def main():
    engine = PrivacyEngine(
        open_vault(os.getenv("PRIVACY_GATEWAY_DB", "./data/privacy-gateway.db"), key_from_env())
    )
    build_server(engine).run()


if __name__ == "__main__":
    main()
