"""Minimal agent-harness boundary: protect before model calls, restore display text only."""

from privacy_gateway.crypto import key_from_env
from privacy_gateway.engine import PrivacyEngine
from privacy_gateway.vault import Vault


def safe_model_call(engine: PrivacyEngine, model_call, user_text: str) -> str:
    protected = engine.transform(user_text, preset="balanced")
    if protected.text is None or protected.state.value != "protected":
        raise RuntimeError(protected.reason or "privacy transform blocked")
    response = model_call(protected.text)
    return engine.restore(response, protected.session_id)


master_key = key_from_env()
if master_key is None:
    raise RuntimeError("Set PRIVACY_GATEWAY_MASTER_KEY from your secret manager")
gateway = PrivacyEngine(Vault("./data/privacy.db", master_key=master_key))
