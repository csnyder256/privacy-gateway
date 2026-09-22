from __future__ import annotations

from .models import Action, EntityType, Policy, PolicyRule

REVERSIBILITY_DEFAULTS = {
    Action.KEEP: False,
    Action.REDACT: False,
    Action.LABEL: False,
    Action.TOKENIZE: True,
    Action.HASH: False,
    Action.GENERALIZE: False,
    Action.SYNTHETIC: False,
}

PRESET_OVERRIDES: dict[str, dict[EntityType, Action]] = {
    "balanced": {
        EntityType.API_KEY: Action.REDACT,
        EntityType.DATE_TIME: Action.GENERALIZE,
        EntityType.MONEY: Action.GENERALIZE,
        EntityType.URL: Action.KEEP,
    },
    "strict": {
        EntityType.API_KEY: Action.REDACT,
        EntityType.CREDIT_CARD: Action.REDACT,
        EntityType.US_SSN: Action.REDACT,
        EntityType.IBAN_CODE: Action.REDACT,
        EntityType.US_BANK_NUMBER: Action.REDACT,
        EntityType.PASSPORT: Action.REDACT,
        EntityType.DRIVER_LICENSE: Action.REDACT,
        EntityType.MEDICAL_LICENSE: Action.REDACT,
    },
    "healthcare": {
        EntityType.API_KEY: Action.REDACT,
        EntityType.CREDIT_CARD: Action.REDACT,
        EntityType.US_SSN: Action.REDACT,
        EntityType.IBAN_CODE: Action.REDACT,
        EntityType.US_BANK_NUMBER: Action.REDACT,
        EntityType.PASSPORT: Action.REDACT,
        EntityType.DRIVER_LICENSE: Action.REDACT,
        EntityType.MEDICAL_LICENSE: Action.REDACT,
        EntityType.PERSON: Action.SYNTHETIC,
        EntityType.LOCATION: Action.SYNTHETIC,
        EntityType.DATE_TIME: Action.SYNTHETIC,
    },
    "finance": {
        EntityType.API_KEY: Action.REDACT,
        EntityType.US_SSN: Action.REDACT,
        EntityType.PASSPORT: Action.REDACT,
        EntityType.DRIVER_LICENSE: Action.REDACT,
        EntityType.MEDICAL_LICENSE: Action.REDACT,
        EntityType.CREDIT_CARD: Action.TOKENIZE,
        EntityType.IBAN_CODE: Action.TOKENIZE,
        EntityType.US_BANK_NUMBER: Action.TOKENIZE,
        EntityType.MONEY: Action.SYNTHETIC,
    },
    "devsecops": {
        EntityType.API_KEY: Action.REDACT,
        EntityType.EMAIL_ADDRESS: Action.TOKENIZE,
        EntityType.PHONE_NUMBER: Action.TOKENIZE,
        EntityType.IP_ADDRESS: Action.TOKENIZE,
        EntityType.PERSON: Action.KEEP,
        EntityType.ORGANIZATION: Action.KEEP,
        EntityType.LOCATION: Action.KEEP,
        EntityType.DATE_TIME: Action.KEEP,
        EntityType.MONEY: Action.KEEP,
        EntityType.URL: Action.KEEP,
    },
}


def _rules(name: str) -> list[PolicyRule]:
    overrides = PRESET_OVERRIDES[name]
    rules: list[PolicyRule] = []
    for entity in EntityType:
        action = overrides.get(entity, Action.TOKENIZE)
        reversible = REVERSIBILITY_DEFAULTS[action]
        if name == "healthcare" and entity in {
            EntityType.PERSON,
            EntityType.LOCATION,
            EntityType.DATE_TIME,
        }:
            reversible = True
        rules.append(
            PolicyRule(
                entity=entity,
                action=action,
                reversible=reversible,
                minimum_confidence_ppm=(
                    650_000
                    if entity
                    in {
                        EntityType.PERSON,
                        EntityType.LOCATION,
                        EntityType.ORGANIZATION,
                    }
                    else 500_000
                ),
            )
        )
    return rules


PRESETS: dict[str, Policy] = {
    name: Policy(name=name, rules=_rules(name)) for name in PRESET_OVERRIDES
}


def policy_from_preset(name: str) -> Policy:
    try:
        return PRESETS[name.lower()].model_copy(deep=True)
    except KeyError as exc:
        raise ValueError(f"Unknown preset {name!r}. Choose from: {', '.join(PRESETS)}") from exc
