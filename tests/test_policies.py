import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from privacy_gateway.models import Action, EntityType, Policy, PolicyRule
from privacy_gateway.policies import PRESETS, policy_from_preset


def test_catalog_and_presets_match_compatibility_manifest():
    manifest = json.loads(Path("contracts/compatibility-v1.json").read_text(encoding="utf-8"))
    assert [entity.value for entity in EntityType] == manifest["entities"]
    assert {action.value for action in Action} == set(manifest["actions"])
    for preset_name, overrides in manifest["preset_overrides"].items():
        policy = PRESETS[preset_name]
        assert {rule.entity for rule in policy.rules} == set(EntityType)
        for entity_name, action in overrides.items():
            assert policy.rule_for(EntityType(entity_name)).action.value == action


def test_policy_rejects_duplicate_rules():
    rule = PolicyRule(entity=EntityType.EMAIL_ADDRESS)
    with pytest.raises(ValidationError, match="only one rule"):
        Policy(rules=[rule, rule])


def test_irreversible_action_rejects_reversible_flag():
    with pytest.raises(ValidationError, match="cannot be reversible"):
        PolicyRule(entity=EntityType.US_SSN, action=Action.REDACT, reversible=True)


def test_preset_returns_independent_copy():
    first = policy_from_preset("balanced")
    first.rules[0].priority = 42
    assert policy_from_preset("balanced").rules[0].priority == 0
