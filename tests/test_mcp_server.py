"""Runs against whichever MCP SDK line is installed; skipped when the extra is absent.

CI installs both mcp 1.x and 2.x in turn. Source inspection alone (see
test_mcp_surface_is_exact) cannot catch an SDK rename, and one did happen.
"""

import asyncio

import pytest

pytest.importorskip("mcp")

from privacy_gateway.crypto import decode_key, generate_key
from privacy_gateway.engine import PrivacyEngine
from privacy_gateway.mcp_server import build_server
from privacy_gateway.vault import Vault

TOOLS = {
    "protect_text",
    "restore_text",
    "restore_client_text",
    "inspect_policy",
    "privacy_summary",
}


@pytest.fixture
def server(tmp_path):
    engine = PrivacyEngine(Vault(tmp_path / "mcp.db", decode_key(generate_key())))
    return build_server(engine)


def test_server_registers_every_tool(server):
    tools = asyncio.run(server.list_tools())
    assert {tool.name for tool in tools} == TOOLS


def test_protect_text_tool_masks_pii(server):
    result = asyncio.run(server.call_tool("protect_text", {"text": "mail ada@example.com"}))
    assert "ada@example.com" not in str(result)
