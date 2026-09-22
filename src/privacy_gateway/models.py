from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class EntityType(StrEnum):
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    PHONE_NUMBER = "PHONE_NUMBER"
    CREDIT_CARD = "CREDIT_CARD"
    US_SSN = "US_SSN"
    IP_ADDRESS = "IP_ADDRESS"
    API_KEY = "API_KEY"
    PERSON = "PERSON"
    ORGANIZATION = "ORGANIZATION"
    LOCATION = "LOCATION"
    DATE_TIME = "DATE_TIME"
    MONEY = "MONEY"
    URL = "URL"
    IBAN_CODE = "IBAN_CODE"
    US_BANK_NUMBER = "US_BANK_NUMBER"
    PASSPORT = "PASSPORT"
    DRIVER_LICENSE = "DRIVER_LICENSE"
    MEDICAL_LICENSE = "MEDICAL_LICENSE"


class Action(StrEnum):
    KEEP = "keep"
    REDACT = "redact"
    LABEL = "label"
    TOKENIZE = "tokenize"
    HASH = "hash"
    GENERALIZE = "generalize"
    SYNTHETIC = "synthetic"


class TransformState(StrEnum):
    PROTECTED = "protected"
    BYPASSED = "bypassed"
    BLOCKED = "blocked"


class PolicyRule(BaseModel):
    entity: EntityType
    action: Action = Action.TOKENIZE
    enabled: bool = True
    reversible: bool | None = None
    minimum_confidence_ppm: int = Field(default=500_000, ge=0, le=1_000_000)
    priority: int = Field(default=0, ge=-1_000_000, le=1_000_000)
    locale: str = "en-US"
    scopes: list[str] = Field(default_factory=lambda: ["*"])
    required_detectors: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_reversibility(self) -> PolicyRule:
        if self.reversible is None:
            self.reversible = self.action == Action.TOKENIZE
        if self.reversible and self.action in {
            Action.KEEP,
            Action.REDACT,
            Action.LABEL,
            Action.HASH,
        }:
            raise ValueError(f"{self.action.value} cannot be reversible")
        return self

    @property
    def minimum_confidence(self) -> float:
        return self.minimum_confidence_ppm / 1_000_000


class Policy(BaseModel):
    name: str = "balanced"
    version: int = Field(default=1, ge=1)
    rules: list[PolicyRule]
    allow_terms: list[str] = Field(default_factory=list)
    deny_terms: dict[str, EntityType] = Field(default_factory=dict)
    fail_closed: Literal[True] = True
    mapping_retention_seconds: int = Field(default=86_400, ge=1)
    audit_retention_seconds: int = Field(default=2_592_000, ge=1)

    @model_validator(mode="after")
    def unique_rules(self) -> Policy:
        entities = [rule.entity for rule in self.rules]
        if len(entities) != len(set(entities)):
            raise ValueError("a policy may contain only one rule per entity")
        return self

    def rule_for(self, entity: EntityType) -> PolicyRule | None:
        return next((rule for rule in self.rules if rule.entity == entity and rule.enabled), None)


class Detection(BaseModel):
    entity: EntityType
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    confidence_ppm: int = Field(ge=0, le=1_000_000)
    detector: str
    value: str = Field(repr=False)
    char_start: int = Field(ge=0, exclude=True)
    char_end: int = Field(ge=0, exclude=True)

    @model_validator(mode="after")
    def ordered_span(self) -> Detection:
        if self.end <= self.start or self.char_end <= self.char_start:
            raise ValueError("detection spans must be non-empty and ordered")
        return self

    @property
    def confidence(self) -> float:
        return self.confidence_ppm / 1_000_000


class AppliedDetection(BaseModel):
    entity: EntityType
    start: int
    end: int
    confidence_ppm: int
    detector: str
    action: Action
    replacement: str
    detection_id: str
    mapping_id: str | None = None


class TransformRequest(BaseModel):
    text: str
    session_id: str | None = None
    policy: Policy | None = None
    preset: str | None = "balanced"
    restore_key: str | None = Field(
        default=None,
        description="Base64url-encoded 32-byte client key used only to seal the restoration capsule.",
    )
    context: dict[str, Any] = Field(default_factory=dict)
    scope: str = "text"


class TransformResponse(BaseModel):
    text: str | None
    state: TransformState
    session_id: str
    policy_name: str
    policy_version: int
    detections: list[AppliedDetection]
    capsule: str | None = None
    reason: str | None = None


class RestoreRequest(BaseModel):
    text: str
    session_id: str


class CapsuleRestoreRequest(BaseModel):
    text: str
    session_id: str
    capsule: str
    restore_key: str


class SessionCreateRequest(BaseModel):
    policy: Policy | None = None
    preset: str = "balanced"
    metadata: dict[str, Any] = Field(default_factory=dict)


class SessionResponse(BaseModel):
    session_id: str
    policy: Policy
