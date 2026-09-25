"""Runs against whichever MCP SDK line is installed; skipped when the extra is absent.

CI installs both mcp 1.x and 2.x in turn. Source inspection alone (see
test_mcp_surface_is_exact) cannot catch an SDK rename, and one did happen.
"""

import asyncio
import json
import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from privacy_gateway.crypto import decode_key, generate_key
from privacy_gateway.engine import PrivacyEngine
from privacy_gateway.mcp_server import build_server
from privacy_gateway.vault import Vault

MANIFEST = json.loads(Path("contracts/compatibility-v1.json").read_text(encoding="utf-8"))
TOOLS = set(MANIFEST["adapters"]["mcp_tools"])
ANNOTATIONS = MANIFEST["adapters"]["mcp_tool_annotations"]
HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


@pytest.fixture
def engine(tmp_path):
    return PrivacyEngine(Vault(tmp_path / "mcp.db", decode_key(generate_key())))


@pytest.fixture
def server(engine):
    return build_server(engine)


def call(server, name, arguments):
    return asyncio.run(server.call_tool(name, arguments))


def payload(result):
    """The tool's JSON result. mcp 1.x returns the content list, 2.x a CallToolResult."""
    content = getattr(result, "content", result)
    if isinstance(content, tuple):
        content = content[0]
    return json.loads(content[0].text)


def test_server_registers_exactly_the_contract_tools(server):
    tools = asyncio.run(server.list_tools())
    assert {tool.name for tool in tools} == TOOLS


def test_protect_text_tool_masks_pii(server):
    assert "ada@example.com" not in str(
        call(server, "protect_text", {"text": "mail ada@example.com"})
    )


def test_protect_json_masks_nested_strings_and_keeps_structure(server):
    value = {"to": "ada@example.com", "cc": ["bob@example.com"], "count": 2, "ok": True}
    result = payload(call(server, "protect_json", {"value": value}))
    assert "ada@example.com" not in json.dumps(result)
    assert "bob@example.com" not in json.dumps(result)
    protected = result["value"]
    assert set(protected) == {"to", "cc", "count", "ok"}
    assert protected["count"] == 2 and protected["ok"] is True
    assert isinstance(protected["cc"], list) and len(protected["cc"]) == 1
    assert result["session_id"] and len(result["detections"]) == 2


def test_verify_round_trip_reports_every_probe_passing(server):
    result = payload(call(server, "verify_round_trip", {}))
    assert result["passed"] is True
    assert {"round_trip", "tolerant_tagged_token", "keyless_reversible_blocks"} <= set(
        result["checks"]
    )
    assert all(result["checks"].values())


def test_client_errors_reach_the_client_with_their_reason(server):
    # mcp 2.1+ hides the message of any exception that is not the SDK's ToolError.
    with pytest.raises(Exception) as caught:
        call(server, "inspect_policy", {"preset": "nope"})
    assert "nope" in str(caught.value)


def test_tampered_capsule_is_reported_not_crashed(server):
    with pytest.raises(Exception) as caught:
        call(
            server,
            "restore_client_text",
            {
                "text": "x",
                "capsule": "not-a-capsule",
                "restore_key": generate_key(),
                "session_id": "s",
            },
        )
    assert "Error executing tool restore_client_text" != str(caught.value).strip()


# Hosts treat an unset hint as the most cautious reading and some directories
# reject a tool that leaves any hint unset, so every tool declares all four, as
# booleans, with the values the manifest fixes.
def test_every_tool_declares_all_four_hints_as_the_contract_fixes(server):
    assert set(ANNOTATIONS) == TOOLS
    for tool in asyncio.run(server.list_tools()):
        declared = tool.annotations.model_dump(by_alias=True) if tool.annotations else {}
        hints = {hint: declared.get(hint) for hint in HINTS}
        assert all(isinstance(value, bool) for value in hints.values()), (tool.name, hints)
        assert hints == ANNOTATIONS[tool.name], tool.name


def vault_rows(engine):
    with sqlite3.connect(engine.vault.path) as db:
        return list(db.iterdump())


# The hints are claims about behaviour; hold the tools to them. A tool marked
# read-only must leave the vault exactly as it was, and one that writes must
# really write (else the check below proves nothing).
def test_read_only_tools_leave_the_vault_untouched_and_the_others_write(engine, server):
    key = generate_key()
    protected = engine.transform("Email ada@example.com", restore_key=key)
    arguments = {
        "restore_client_text": {
            "text": protected.text,
            "capsule": protected.capsule,
            "restore_key": key,
            "session_id": protected.session_id,
        },
        "inspect_policy": {"preset": "balanced"},
        "verify_round_trip": {},
        "protect_text": {"text": "mail bob@example.com"},
        "protect_json": {"value": {"to": "bob@example.com"}},
    }
    assert set(arguments) == TOOLS
    for name, args in arguments.items():
        before = vault_rows(engine)
        for _ in range(2):
            call(server, name, args)
        changed = vault_rows(engine) != before
        assert changed is not ANNOTATIONS[name]["readOnlyHint"], name
