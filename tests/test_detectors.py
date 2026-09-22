import json
from pathlib import Path

from privacy_gateway.detectors import RegexDetector, resolve_detections
from privacy_gateway.models import Action, EntityType, Policy, PolicyRule
from privacy_gateway.policies import policy_from_preset


def policy_for(*entities: EntityType) -> Policy:
    return Policy(
        name="test",
        rules=[
            PolicyRule(entity=entity, action=Action.REDACT, reversible=False) for entity in entities
        ],
    )


def test_utf8_byte_offsets_are_not_codepoint_offsets():
    text = "Zoë: zoe@example.com"
    detection = resolve_detections(
        text,
        policy_for(EntityType.EMAIL_ADDRESS),
        [RegexDetector()],
    )[0]
    assert detection.start == len("Zoë: ".encode())
    assert detection.end == len(text.encode())
    assert detection.value == "zoe@example.com"


def test_checksum_recognizers_reject_invalid_values():
    text = "bad 4111 1111 1111 1112 and 123456789, good 4111 1111 1111 1111 and 021000021"
    found = resolve_detections(
        text,
        policy_for(EntityType.CREDIT_CARD, EntityType.US_BANK_NUMBER),
        [RegexDetector()],
    )
    assert {item.value for item in found} == {"4111 1111 1111 1111", "021000021"}


def test_iban_mod97_and_url_userinfo_validation():
    text = (
        "DE89370400440532013000 DE89370400440532013001 https://example.com/a https://me@example.com"
    )
    found = resolve_detections(
        text,
        policy_for(EntityType.IBAN_CODE, EntityType.URL),
        [RegexDetector()],
    )
    assert {item.value for item in found} == {
        "DE89370400440532013000",
        "https://example.com/a",
    }


def test_url_rejects_password_userinfo_and_non_ascii_hosts():
    text = (
        "https://:pass@example.com/path https://@example.com/path "
        "https://:@example.com/path https://例.com/path https://example.com/path"
    )
    found = resolve_detections(
        text,
        policy_for(EntityType.URL),
        [RegexDetector()],
    )
    assert [item.value for item in found] == ["https://example.com/path"]


def test_money_surface_has_a_cross_runtime_resource_bound():
    text = f"$1234 and ${'9' * 300}"
    found = resolve_detections(text, policy_for(EntityType.MONEY), [RegexDetector()])
    assert [item.value for item in found] == ["$1234"]


def test_allow_list_wins_and_deny_list_adds_custom_detection():
    policy = policy_for(EntityType.EMAIL_ADDRESS, EntityType.PERSON)
    policy.allow_terms = ["safe@example.com"]
    policy.deny_terms = {"Project Heron": EntityType.PERSON}
    found = resolve_detections(
        "safe@example.com bad@example.com Project Heron",
        policy,
        [RegexDetector()],
    )
    assert [(item.value, item.detector) for item in found] == [
        ("bad@example.com", "regex-v1"),
        ("Project Heron", "deny-list"),
    ]


def test_shared_cross_runtime_detection_fixtures():
    fixtures = json.loads(Path("conformance/core-v1.json").read_text())
    for fixture in fixtures["detection"]:
        policy = policy_from_preset(fixture["preset"])
        found = resolve_detections(fixture["text"], policy, [RegexDetector()])
        actual = [
            {
                "entity": item.entity.value,
                "start": item.start,
                "end": item.end,
                "value": item.value,
            }
            for item in found
        ]
        assert actual == fixture["expected"], fixture["name"]
