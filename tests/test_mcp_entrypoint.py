"""The MCP entry point must fail cleanly when the optional SDK is missing.

Runs with or without the [mcp] extra installed.
"""

import pytest

from privacy_gateway import mcp_server


def test_missing_sdk_exits_before_opening_the_vault(tmp_path, monkeypatch):
    database = tmp_path / "data" / "privacy-gateway.db"
    monkeypatch.setenv("PRIVACY_GATEWAY_DB", str(database))

    def missing_sdk():
        raise SystemExit("Install the MCP extra: pip install 'privacy-gateway[mcp]'")

    monkeypatch.setattr(mcp_server, "_sdk", missing_sdk)
    with pytest.raises(SystemExit, match="Install the MCP extra"):
        mcp_server.main()
    assert not database.exists()
    assert not database.parent.exists()
