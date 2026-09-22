from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from typing import ClassVar, Protocol
from urllib.parse import urlsplit

from .models import Action, Detection, EntityType, Policy


class DetectionFailure(RuntimeError):
    """A detector required by the active policy was not able to complete."""


def utf8_offset(text: str, char_offset: int) -> int:
    return len(text[:char_offset].encode("utf-8"))


def detection_from_chars(
    text: str,
    *,
    entity: EntityType,
    char_start: int,
    char_end: int,
    confidence_ppm: int,
    detector: str,
) -> Detection:
    return Detection(
        entity=entity,
        start=utf8_offset(text, char_start),
        end=utf8_offset(text, char_end),
        char_start=char_start,
        char_end=char_end,
        confidence_ppm=confidence_ppm,
        detector=detector,
        value=text[char_start:char_end],
    )


class Detector(Protocol):
    name: str

    def detect(self, text: str, entities: set[EntityType]) -> list[Detection]: ...


class RegexDetector:
    name = "regex-v1"
    PATTERNS: ClassVar[dict[EntityType, re.Pattern[str]]] = {
        EntityType.EMAIL_ADDRESS: re.compile(
            r"(?<![\w.!#$%&'*+=?^`{|}~-])[A-Z0-9.!#$%&'*+=?^_`{|}~-]{1,64}"
            r"@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\."
            r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+(?![\w-])",
            re.IGNORECASE,
        ),
        EntityType.PHONE_NUMBER: re.compile(
            r"(?<!\d)(?:\+?\d{1,3}[ .-]?)?(?:\(\d{2,4}\)|\d{2,4})"
            r"[ .-]\d{3,4}[ .-]\d{4}(?!\d)"
        ),
        EntityType.US_SSN: re.compile(
            r"(?<!\d)(?!000|666|9\d\d)\d{3}([- ]?)(?!00)\d{2}\1(?!0000)\d{4}(?!\d)"
        ),
        EntityType.CREDIT_CARD: re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"),
        EntityType.IP_ADDRESS: re.compile(
            r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:.])"
            r"|(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
        ),
        EntityType.API_KEY: re.compile(
            r"(?<![A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{16,200}|"
            r"gh[pousr]_[A-Za-z0-9]{20,255}|AKIA[A-Z0-9]{16})(?![A-Za-z0-9])"
        ),
        EntityType.DATE_TIME: re.compile(
            r"(?<!\d)(?:20\d{2}[-/]\d{1,2}[-/]\d{1,2}|"
            r"\d{1,2}[-/.]\d{1,2}[-/.]20\d{2})(?!\d)"
        ),
        EntityType.MONEY: re.compile(
            r"(?<!\w)(?:[$€£]\s?\d[\d ,.]*\d|[$€£]\s?\d|"
            r"\d[\d ,.]*\d\s?(?:USD|EUR|GBP)|\d\s?(?:USD|EUR|GBP))(?!\w)",
            re.IGNORECASE,
        ),
        EntityType.URL: re.compile(r"(?<!\w)https?://[^\s<>\"']+", re.IGNORECASE),
        EntityType.IBAN_CODE: re.compile(
            r"(?<![A-Z0-9])(?:DE(?: ?[A-Z0-9]){20}|ES(?: ?[A-Z0-9]){22}|"
            r"FR(?: ?[A-Z0-9]){25}|GB(?: ?[A-Z0-9]){20})(?![A-Z0-9])",
            re.IGNORECASE,
        ),
        EntityType.US_BANK_NUMBER: re.compile(r"(?<!\d)\d{3}(?:[ -]?\d{3}){2}(?!\d)"),
    }

    @staticmethod
    def _luhn(value: str) -> bool:
        digits = [int(char) for char in value if char.isdigit()]
        if not 13 <= len(digits) <= 19:
            return False
        parity = len(digits) % 2
        total = 0
        for index, digit in enumerate(digits):
            if index % 2 == parity:
                digit = digit * 2 - 9 if digit > 4 else digit * 2
            total += digit
        return total % 10 == 0

    @staticmethod
    def _iban(value: str) -> bool:
        compact = re.sub(r"\s", "", value).upper()
        expected = {"DE": 22, "ES": 24, "FR": 27, "GB": 22}
        if len(compact) != expected.get(compact[:2], -1):
            return False
        rotated = compact[4:] + compact[:4]
        numeric = "".join(str(ord(char) - 55) if char.isalpha() else char for char in rotated)
        return int(numeric) % 97 == 1

    @staticmethod
    def _routing(value: str) -> bool:
        digits = [int(char) for char in value if char.isdigit()]
        return (
            len(digits) == 9
            and sum(weight * digit for weight, digit in zip((3, 7, 1) * 3, digits, strict=True))
            % 10
            == 0
        )

    @staticmethod
    def _valid_url(value: str) -> bool:
        try:
            parsed = urlsplit(value)
            return (
                value.isascii()
                and parsed.scheme.lower() in {"http", "https"}
                and bool(parsed.hostname)
                and "@" not in parsed.netloc
                and not parsed.username
                and not parsed.password
            )
        except ValueError:
            return False

    @staticmethod
    def _valid_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def detect(self, text: str, entities: set[EntityType]) -> list[Detection]:
        found: list[Detection] = []
        for entity, pattern in self.PATTERNS.items():
            if entity not in entities:
                continue
            for match in pattern.finditer(text):
                value = match.group()
                if entity == EntityType.CREDIT_CARD and not self._luhn(value):
                    continue
                if entity == EntityType.IBAN_CODE and not self._iban(value):
                    continue
                if entity == EntityType.US_BANK_NUMBER and not self._routing(value):
                    continue
                if entity == EntityType.URL and not self._valid_url(value):
                    continue
                if entity == EntityType.IP_ADDRESS and not self._valid_ip(value):
                    continue
                if entity == EntityType.MONEY and len(value.encode("utf-8")) > 128:
                    continue
                found.append(
                    detection_from_chars(
                        text,
                        entity=entity,
                        char_start=match.start(),
                        char_end=match.end(),
                        confidence_ppm=990_000,
                        detector=self.name,
                    )
                )
        return found


class PresidioDetector:
    name = "presidio-v1"
    ENTITY_MAP: ClassVar[dict[str, EntityType]] = {
        "EMAIL_ADDRESS": EntityType.EMAIL_ADDRESS,
        "PHONE_NUMBER": EntityType.PHONE_NUMBER,
        "US_SSN": EntityType.US_SSN,
        "CREDIT_CARD": EntityType.CREDIT_CARD,
        "IP_ADDRESS": EntityType.IP_ADDRESS,
        "PERSON": EntityType.PERSON,
        "ORGANIZATION": EntityType.ORGANIZATION,
        "LOCATION": EntityType.LOCATION,
        "DATE_TIME": EntityType.DATE_TIME,
        "IBAN_CODE": EntityType.IBAN_CODE,
        "US_BANK_NUMBER": EntityType.US_BANK_NUMBER,
        "US_PASSPORT": EntityType.PASSPORT,
        "US_DRIVER_LICENSE": EntityType.DRIVER_LICENSE,
        "MEDICAL_LICENSE": EntityType.MEDICAL_LICENSE,
    }

    def __init__(self) -> None:
        from presidio_analyzer import AnalyzerEngine

        self._analyzer = AnalyzerEngine()

    def detect(self, text: str, entities: set[EntityType]) -> list[Detection]:
        requested = [name for name, entity in self.ENTITY_MAP.items() if entity in entities]
        if not requested:
            return []
        results = self._analyzer.analyze(text=text, language="en", entities=requested)
        return [
            detection_from_chars(
                text,
                entity=self.ENTITY_MAP[result.entity_type],
                char_start=result.start,
                char_end=result.end,
                confidence_ppm=round(float(result.score) * 1_000_000),
                detector=self.name,
            )
            for result in results
        ]


def _scope_matches(rule_scopes: list[str], scope: str) -> bool:
    return "*" in rule_scopes or scope in rule_scopes


def resolve_detections(
    text: str,
    policy: Policy,
    detectors: Iterable[Detector],
    *,
    scope: str = "text",
) -> list[Detection]:
    active_rules = {
        rule.entity: rule
        for rule in policy.rules
        if rule.enabled and rule.action != Action.KEEP and _scope_matches(rule.scopes, scope)
    }
    entities = set(active_rules)
    candidates: list[Detection] = []
    available = {detector.name for detector in detectors}
    required = {name for rule in active_rules.values() for name in rule.required_detectors}
    missing = required - available
    if missing:
        raise DetectionFailure(f"required detectors unavailable: {', '.join(sorted(missing))}")

    for detector in detectors:
        try:
            candidates.extend(detector.detect(text, entities))
        except Exception as exc:
            raise DetectionFailure(f"detector {detector.name} failed") from exc

    for value, entity in policy.deny_terms.items():
        if entity not in active_rules:
            continue
        for match in re.finditer(re.escape(value), text, re.IGNORECASE):
            candidates.append(
                detection_from_chars(
                    text,
                    entity=entity,
                    char_start=match.start(),
                    char_end=match.end(),
                    confidence_ppm=1_000_000,
                    detector="deny-list",
                )
            )

    allow = {term.casefold() for term in policy.allow_terms}
    eligible = [
        item
        for item in candidates
        if item.entity in active_rules
        and item.confidence_ppm >= active_rules[item.entity].minimum_confidence_ppm
        and item.value.casefold() not in allow
    ]
    eligible.sort(
        key=lambda item: (
            item.detector != "deny-list",
            -active_rules[item.entity].priority,
            -item.confidence_ppm,
            -(item.end - item.start),
            item.start,
            item.entity.value,
            item.detector,
        )
    )
    accepted: list[Detection] = []
    for candidate in eligible:
        if any(candidate.start < item.end and item.start < candidate.end for item in accepted):
            continue
        accepted.append(candidate)
    return sorted(accepted, key=lambda item: item.start)


def default_detectors(include_presidio: bool = True) -> list[Detector]:
    detectors: list[Detector] = [RegexDetector()]
    if include_presidio:
        try:
            detectors.append(PresidioDetector())
        except (ImportError, OSError):
            pass
    return detectors
