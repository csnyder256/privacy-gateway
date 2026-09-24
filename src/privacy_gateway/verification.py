"""Active round-trip and leakage probes, shared by the CLI and the MCP surface.

Each probe runs against a throwaway vault, so running them never touches a
real session. The report is a flat map of check name to pass/fail.
"""

from __future__ import annotations

import re
from pathlib import Path
from tempfile import TemporaryDirectory

from .crypto import decode_key, generate_key
from .engine import PrivacyEngine
from .vault import Vault

_TAGGED_TOKEN = re.compile(r"\[\[PG1\|([A-Z_]+)\|([A-Z2-7]{26})\|([A-Z2-7]{16})\]\]")


def round_trip_checks(detectors=None) -> dict[str, bool]:
    """Run the fail-closed, round-trip and altered-token probes.

    ``detectors`` defaults to the engine's own; pass a running engine's
    detectors to probe that configuration rather than the defaults.
    """
    client_key = generate_key()
    source = "Contact zoe@example.com about 4111 1111 1111 1111."
    with TemporaryDirectory(prefix="privacy-gateway-verify-") as directory:
        if detectors is None:
            gateway = PrivacyEngine(Vault(Path(directory) / "verify.db"))
        else:
            gateway = PrivacyEngine(Vault(Path(directory) / "verify.db"), detectors=detectors)
        protected = gateway.transform(source, preset="finance", restore_key=client_key)
        if protected.text is None or protected.capsule is None:
            return {"protects_with_capsule": False}
        restored = PrivacyEngine.restore_capsule(
            protected.text,
            protected.capsule,
            client_key,
            protected.session_id,
        )
        altered = _TAGGED_TOKEN.sub(
            lambda match: (
                f"[[ pg1 | {match.group(1).lower()} | {match.group(2).lower()} | "
                f"{match.group(3).lower()} ]]"
            ),
            protected.text,
        )
        tolerant = PrivacyEngine.restore_capsule(
            altered,
            protected.capsule,
            client_key,
            protected.session_id,
        )
        blocked_gateway = PrivacyEngine(
            Vault(Path(directory) / "blocked.db"),
            detectors=gateway.detectors,
        )
        blocked = blocked_gateway.transform(source, preset="finance")
        return {
            "round_trip": restored == source,
            "tolerant_tagged_token": tolerant == source,
            "keyless_reversible_blocks": blocked.text is None and blocked.state.value == "blocked",
            "source_not_in_protected_text": "zoe@example.com" not in protected.text,
            "client_key_valid": len(decode_key(client_key)) == 32,
        }
