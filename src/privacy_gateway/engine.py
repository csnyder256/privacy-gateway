from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
from collections.abc import Iterable
from typing import Any

from .crypto import decode_key, open_json, seal_json
from .detectors import DetectionFailure, Detector, default_detectors, resolve_detections
from .models import (
    Action,
    AppliedDetection,
    Detection,
    EntityType,
    Policy,
    TransformResponse,
    TransformState,
)
from .policies import policy_from_preset
from .vault import MappingCollision, Vault

TOKEN_PATTERN = r"\[\[ ?PG1 ?\| ?([A-Z_]+) ?\| ?([A-Z2-7]{26}) ?\| ?([A-Z2-7]{16}) ?\]\]"
TOKEN_RE = re.compile(TOKEN_PATTERN, re.IGNORECASE | re.ASCII)


def _base32(value: bytes) -> str:
    return base64.b32encode(value).decode().rstrip("=")


def _digits(seed: int, length: int) -> str:
    """Return a deterministic decimal stream without relying on process hash state."""
    output = ""
    value = seed
    while len(output) < length:
        output += f"{value:020d}"
        value = int(hashlib.sha256(str(value).encode()).hexdigest()[:16], 16)
    return output[:length]


def _luhn_check_digit(prefix: str) -> str:
    for candidate in "0123456789":
        digits = [int(char) for char in prefix + candidate]
        parity = len(digits) % 2
        total = 0
        for index, digit in enumerate(digits):
            if index % 2 == parity:
                digit = digit * 2 - 9 if digit > 4 else digit * 2
            total += digit
        if total % 10 == 0:
            return candidate
    raise AssertionError("a Luhn check digit must exist")


def _iban(country: str, seed: int) -> str:
    bban_lengths = {"DE": 18, "ES": 20, "FR": 23, "GB": 18}
    if country == "GB":
        bban = f"PGAT{_digits(seed, 14)}"
    else:
        bban = _digits(seed, bban_lengths[country])
    provisional = f"{bban}{country}00"
    numeric = "".join(str(ord(char) - 55) if char.isalpha() else char for char in provisional)
    return f"{country}{98 - int(numeric) % 97:02d}{bban}"


def _routing_number(seed: int) -> str:
    prefix = f"01{_digits(seed, 6)}"
    weights = (3, 7, 1) * 3
    for candidate in "0123456789":
        digits = [int(char) for char in prefix + candidate]
        if sum(weight * digit for weight, digit in zip(weights, digits, strict=True)) % 10 == 0:
            return prefix + candidate
    raise AssertionError("an ABA routing check digit must exist")


class PrivacyEngine:
    def __init__(self, vault: Vault, detectors: Iterable[Detector] | None = None):
        self.vault = vault
        self.detectors = list(detectors) if detectors is not None else default_detectors()

    def create_session(
        self,
        policy: Policy | None = None,
        preset: str = "balanced",
        metadata: dict[str, Any] | None = None,
    ) -> tuple[str, Policy]:
        selected = policy or policy_from_preset(preset)
        return self.vault.create_session(selected, metadata), selected

    @staticmethod
    def _digest(key: bytes | None, entity: str, value: str, length: int = 16) -> str:
        payload = f"{entity}\0{value}".encode()
        raw = (
            hmac.new(key, payload, hashlib.sha256).digest()
            if key
            else hashlib.sha256(payload).digest()
        )
        return raw.hex()[:length]

    @staticmethod
    def _token(entity: EntityType, key: bytes) -> str:
        generation_bytes = secrets.token_bytes(16)
        generation = _base32(generation_bytes)
        auth = _base32(hmac.new(key, generation_bytes, hashlib.sha256).digest()[:10])
        return f"[[PG1|{entity.value}|{generation}|{auth}]]"

    def _synthetic(self, detection: Detection, key: bytes | None) -> str:
        seed = int(self._digest(key, detection.entity.value, detection.value, 16), 16)
        entity = detection.entity
        if entity == EntityType.EMAIL_ADDRESS:
            return f"person{seed % 100000}@example.test"
        if entity == EntityType.PHONE_NUMBER:
            return f"+1-202-555-{seed % 10000:04d}"
        if entity == EntityType.PERSON:
            first = ("Alex", "Jordan", "Morgan", "Riley", "Taylor", "Casey")[seed % 6]
            last = ("Brooks", "Chen", "Diaz", "Patel", "Rivera", "Singh")[(seed // 7) % 6]
            return f"{first} {last}"
        if entity == EntityType.ORGANIZATION:
            return ("Northstar Labs", "Juniper Works", "Atlas Harbor", "Cinder Systems")[seed % 4]
        if entity == EntityType.LOCATION:
            return ("Madison, WI", "Raleigh, NC", "Boise, ID", "Albany, NY")[seed % 4]
        if entity == EntityType.DATE_TIME:
            return f"20{20 + seed % 7:02d}-{1 + (seed // 7) % 12:02d}-{1 + (seed // 97) % 28:02d}"
        if entity == EntityType.MONEY:
            return f"${10 + seed % 9990:,}.00"
        if entity == EntityType.CREDIT_CARD:
            prefix = f"4{_digits(seed, 14)}"
            return prefix + _luhn_check_digit(prefix)
        if entity == EntityType.US_SSN:
            area = 100 + seed % 799
            if area >= 666:
                area += 1
            group = 1 + (seed // 799) % 99
            serial = 1 + (seed // (799 * 99)) % 9999
            return f"{area:03d}-{group:02d}-{serial:04d}"
        if entity == EntityType.IP_ADDRESS:
            if ":" in detection.value:
                return f"2001:db8::{1 + seed % 65534:x}"
            return f"192.0.2.{1 + seed % 254}"
        if entity == EntityType.API_KEY:
            token = _base32(hashlib.sha256(str(seed).encode()).digest())[:24]
            if detection.value.startswith("AKIA"):
                return f"AKIA{token[:16]}"
            if re.match(r"gh[pousr]_", detection.value):
                return f"{detection.value[:4]}{token}"
            return f"sk-pg_{token}"
        if entity == EntityType.URL:
            return f"https://service-{seed % 10000}.example.test/resource/{seed % 100000}"
        if entity == EntityType.IBAN_CODE:
            country = detection.value.replace(" ", "")[:2].upper()
            return _iban(country if country in {"DE", "ES", "FR", "GB"} else "GB", seed)
        if entity == EntityType.US_BANK_NUMBER:
            return _routing_number(seed)
        if entity == EntityType.PASSPORT:
            return f"P{_digits(seed, 8)}"
        if entity == EntityType.DRIVER_LICENSE:
            return f"D{_digits(seed, 8)}"
        if entity == EntityType.MEDICAL_LICENSE:
            return f"M{_digits(seed, 9)}"
        return f"SYNTHETIC_{entity.value}_{self._digest(key, entity.value, detection.value, 10).upper()}"

    @staticmethod
    def _generalize(detection: Detection) -> str:
        if detection.entity == EntityType.DATE_TIME:
            year = re.search(r"(?:19|20)\d{2}", detection.value)
            return f"{year.group()}" if year else "[DATE]"
        if detection.entity == EntityType.MONEY:
            digits = re.sub(r"\D", "", detection.value).lstrip("0") or "0"
            symbol = detection.value[:1] if detection.value[:1] in "$€£" else ""
            return f"{symbol}~10^{max(0, len(digits) - 1)}"
        if detection.entity == EntityType.EMAIL_ADDRESS and "@" in detection.value:
            return f"***@{detection.value.rsplit('@', 1)[1]}"
        return f"[{detection.entity.value}]"

    def _replacement(
        self,
        detection: Detection,
        action: Action,
        key: bytes | None,
    ) -> str:
        if action == Action.REDACT:
            return f"[REDACTED:{detection.entity.value}]"
        if action == Action.LABEL:
            return f"<{detection.entity.value}>"
        if action == Action.TOKENIZE:
            if key is None:
                raise RuntimeError(
                    "tokenization requires a server master key or client restore key"
                )
            return self._token(detection.entity, key)
        if action == Action.HASH:
            return f"sha256:{self._digest(key, detection.entity.value, detection.value, 48)}"
        if action == Action.GENERALIZE:
            return self._generalize(detection)
        if action == Action.SYNTHETIC:
            return self._synthetic(detection, key)
        return detection.value

    def _blocked(
        self,
        *,
        session_id: str,
        policy: Policy,
        reason: str,
        source_hash: str,
    ) -> TransformResponse:
        self.vault.audit(
            "transform",
            "blocked",
            {"reason": reason, "source_hash": source_hash, "policy": policy.name},
            session_id,
            policy.audit_retention_seconds,
        )
        return TransformResponse(
            text=None,
            state=TransformState.BLOCKED,
            session_id=session_id,
            policy_name=policy.name,
            policy_version=policy.version,
            detections=[],
            reason=reason,
        )

    def transform(
        self,
        text: str,
        *,
        session_id: str | None = None,
        policy: Policy | None = None,
        preset: str = "balanced",
        restore_key: str | None = None,
        metadata: dict[str, Any] | None = None,
        scope: str = "text",
    ) -> TransformResponse:
        if session_id:
            selected = policy or self.vault.policy_for(session_id)
        else:
            session_id, selected = self.create_session(policy, preset, metadata)
        client_key = decode_key(restore_key) if restore_key else None
        operation_key = client_key or self.vault.master_key or secrets.token_bytes(32)
        replacement_key = operation_key
        source_hash = self._digest(operation_key, "source", text, 64)

        reversible = [
            rule
            for rule in selected.rules
            if rule.enabled
            and rule.action != Action.KEEP
            and rule.reversible
            and ("*" in rule.scopes or scope in rule.scopes)
        ]
        if reversible and self.vault.master_key is None and client_key is None:
            return self._blocked(
                session_id=session_id,
                policy=selected,
                reason="reversible policy requires a server master key or client restore key",
                source_hash=source_hash,
            )
        try:
            detections = resolve_detections(text, selected, self.detectors, scope=scope)
        except DetectionFailure as exc:
            return self._blocked(
                session_id=session_id,
                policy=selected,
                reason=str(exc),
                source_hash=source_hash,
            )

        reverse: dict[str, str] = {}
        call_mappings: dict[tuple[EntityType, str], tuple[str, str | None]] = {}
        applied: list[AppliedDetection] = []
        pieces: list[str] = []
        cursor = 0
        expires_at = int(time.time()) + selected.mapping_retention_seconds

        for detection in detections:
            rule = selected.rule_for(detection.entity)
            if rule is None or rule.action == Action.KEEP:
                continue
            lookup_key = (detection.entity, detection.value)
            replacement: str
            mapping_id: str | None
            if lookup_key in call_mappings:
                replacement, mapping_id = call_mappings[lookup_key]
            else:
                existing = None
                if rule.reversible and self.vault.master_key is not None and client_key is None:
                    existing = self.vault.find_mapping(
                        session_id, detection.entity.value, detection.value
                    )
                if existing is not None:
                    replacement = str(existing["replacement"])
                    mapping_id = str(existing["id"])
                else:
                    mapping_id = None
                    for _ in range(8):
                        replacement = self._replacement(detection, rule.action, replacement_key)
                        if rule.reversible and rule.action != Action.TOKENIZE:
                            replacement = (
                                f"{replacement} {self._token(detection.entity, replacement_key)}"
                            )
                        if (
                            not rule.reversible
                            or self.vault.master_key is None
                            or client_key is not None
                        ):
                            break
                        try:
                            mapping_id = self.vault.store_mapping(
                                session_id,
                                detection,
                                replacement,
                                rule.action,
                                expires_at=expires_at,
                            )
                            break
                        except MappingCollision:
                            continue
                    else:
                        return self._blocked(
                            session_id=session_id,
                            policy=selected,
                            reason="unable to allocate a unique replacement",
                            source_hash=source_hash,
                        )
                call_mappings[lookup_key] = (replacement, mapping_id)

            pieces.extend((text[cursor : detection.char_start], replacement))
            cursor = detection.char_end
            if rule.reversible:
                reverse[replacement] = detection.value
            detection_id = self.vault.record_detection(
                session_id,
                mapping_id,
                detection,
                rule.action,
                source_hash,
                selected,
            )
            applied.append(
                AppliedDetection(
                    entity=detection.entity,
                    start=detection.start,
                    end=detection.end,
                    confidence_ppm=detection.confidence_ppm,
                    detector=detection.detector,
                    action=rule.action,
                    replacement=replacement,
                    detection_id=detection_id,
                    mapping_id=mapping_id,
                )
            )
        pieces.append(text[cursor:])
        output = "".join(pieces)
        capsule = (
            seal_json(reverse, client_key, aad=f"privacy-gateway:{session_id}")
            if client_key is not None and reverse
            else None
        )
        self.vault.audit(
            "transform",
            "protected",
            {
                "source_hash": source_hash,
                "detections": len(applied),
                "policy": selected.name,
                "policy_version": selected.version,
            },
            session_id,
            selected.audit_retention_seconds,
        )
        return TransformResponse(
            text=output,
            state=TransformState.PROTECTED,
            session_id=session_id,
            policy_name=selected.name,
            policy_version=selected.version,
            detections=applied,
            capsule=capsule,
        )

    @staticmethod
    def _replace_from_map(text: str, reverse: dict[str, str]) -> str:
        if not reverse:
            return text
        exact = re.compile(
            "|".join(re.escape(value) for value in sorted(reverse, key=len, reverse=True))
        )
        restored = exact.sub(lambda match: reverse[match.group()], text)
        for surface, original in reverse.items():
            match = TOKEN_RE.search(surface)
            if match is None or match.end() != len(surface):
                continue
            expected = tuple(group.upper() for group in match.groups())
            composite = re.compile(
                re.escape(surface[: match.start()]) + TOKEN_PATTERN,
                re.IGNORECASE | re.ASCII,
            )

            def tolerant(candidate: re.Match[str], expected=expected, original=original) -> str:
                actual = tuple(group.upper() for group in candidate.groups())
                return original if actual == expected else candidate.group()

            restored = composite.sub(tolerant, restored)
        return restored

    def restore(self, text: str, session_id: str) -> str:
        restored = self._replace_from_map(text, self.vault.reverse_map(session_id))
        policy = self.vault.policy_for(session_id)
        self.vault.audit(
            "restore",
            "restored",
            {"input_hash": self._digest(self.vault.master_key, "restore", text, 64)},
            session_id,
            policy.audit_retention_seconds,
        )
        return restored

    @classmethod
    def restore_capsule(cls, text: str, capsule: str, restore_key: str, session_id: str) -> str:
        reverse = open_json(capsule, decode_key(restore_key), aad=f"privacy-gateway:{session_id}")
        if not isinstance(reverse, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in reverse.items()
        ):
            raise ValueError("invalid restoration capsule")
        return cls._replace_from_map(text, reverse)

    def transform_json(
        self,
        value: Any,
        *,
        session_id: str | None = None,
        policy: Policy | None = None,
        preset: str = "balanced",
        restore_key: str | None = None,
        scope: str = "json",
    ) -> tuple[Any, list[TransformResponse]]:
        if session_id is None:
            session_id, selected = self.create_session(policy, preset)
        else:
            selected = policy or self.vault.policy_for(session_id)
        results: list[TransformResponse] = []

        def walk(node: Any, path: str) -> Any:
            if isinstance(node, dict):
                return {key: walk(item, f"{path}/{key}") for key, item in node.items()}
            if isinstance(node, list):
                return [walk(item, f"{path}/{index}") for index, item in enumerate(node)]
            if isinstance(node, str):
                result = self.transform(
                    node,
                    session_id=session_id,
                    policy=selected,
                    restore_key=restore_key,
                    scope=f"{scope}:{path or '/'}",
                )
                results.append(result)
                if result.state == TransformState.BLOCKED:
                    raise DetectionFailure(result.reason or "JSON transformation blocked")
                return result.text
            return node

        return walk(value, ""), results
