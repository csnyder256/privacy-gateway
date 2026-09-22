from __future__ import annotations

import base64
import json
import os
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encode_key(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).decode().rstrip("=")


def decode_key(value: str) -> bytes:
    raw = value + "=" * (-len(value) % 4)
    key = base64.urlsafe_b64decode(raw)
    if len(key) != 32:
        raise ValueError("keys must decode to exactly 32 bytes")
    return key


def generate_key() -> str:
    return encode_key(secrets.token_bytes(32))


def key_from_env() -> bytes | None:
    value = os.getenv("PRIVACY_GATEWAY_MASTER_KEY")
    return decode_key(value) if value else None


def seal_bytes(data: bytes, key: bytes, *, aad: bytes = b"") -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def open_bytes(data: bytes, key: bytes, *, aad: bytes = b"") -> bytes:
    if len(data) < 29:
        raise ValueError("invalid sealed payload")
    return AESGCM(key).decrypt(data[:12], data[12:], aad)


def seal_json(value: Any, key: bytes, *, aad: str) -> str:
    payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    return encode_key(seal_bytes(payload, key, aad=aad.encode()))


def open_json(value: str, key: bytes, *, aad: str) -> Any:
    raw = value + "=" * (-len(value) % 4)
    payload = open_bytes(base64.urlsafe_b64decode(raw), key, aad=aad.encode())
    return json.loads(payload)
