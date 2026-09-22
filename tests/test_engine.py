import json
import re
from pathlib import Path

import pytest

from privacy_gateway.crypto import decode_key, generate_key
from privacy_gateway.detectors import RegexDetector
from privacy_gateway.engine import PrivacyEngine
from privacy_gateway.models import Action, Detection, EntityType, Policy, PolicyRule, TransformState
from privacy_gateway.vault import Vault


class BrokenDetector:
    name = "broken"

    def detect(self, text, entities):
        raise RuntimeError("boom")


@pytest.fixture
def master_key():
    return decode_key(generate_key())


def engine(tmp_path: Path, key: bytes | None, detectors=None) -> PrivacyEngine:
    return PrivacyEngine(Vault(tmp_path / "gateway.db", key), detectors=detectors)


def test_persistent_round_trip_and_queryable_tags(tmp_path, master_key):
    gateway = engine(tmp_path, master_key)
    original = "Zoë emailed zoe@example.com and used 4111 1111 1111 1111."
    result = gateway.transform(original, preset="finance")
    assert result.state == TransformState.PROTECTED
    assert result.text != original
    assert gateway.restore(result.text, result.session_id) == original
    assert result.detections[0].start == len("Zoë emailed ".encode())
    summary = gateway.vault.session_summary(result.session_id)
    assert {tag["entity_type"] for tag in summary["tags"]} == {
        "EMAIL_ADDRESS",
        "CREDIT_CARD",
    }
    assert all(tag["policy_name"] == "finance" for tag in summary["tags"])


def test_client_capsule_round_trip_without_server_key(tmp_path):
    gateway = engine(tmp_path, None)
    restore_key = generate_key()
    original = "Reach me at person@example.com."
    result = gateway.transform(original, preset="balanced", restore_key=restore_key)
    assert result.state == TransformState.PROTECTED
    assert result.capsule
    assert all(item.mapping_id is None for item in result.detections)
    assert (
        PrivacyEngine.restore_capsule(
            result.text,
            result.capsule,
            restore_key,
            result.session_id,
        )
        == original
    )


def test_client_capsule_mode_never_persists_original_even_when_server_has_key(tmp_path, master_key):
    gateway = engine(tmp_path, master_key)
    restore_key = generate_key()
    result = gateway.transform("Reach me at person@example.com.", restore_key=restore_key)
    assert result.state == TransformState.PROTECTED
    assert result.capsule
    assert all(item.mapping_id is None for item in result.detections)
    with gateway.vault.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM mappings").fetchone()[0] == 0


def test_tolerant_token_restore_allows_case_and_delimiter_spacing(tmp_path):
    gateway = engine(tmp_path, None)
    restore_key = generate_key()
    result = gateway.transform("a@example.com", restore_key=restore_key)
    changed = result.text.lower().replace("|", " | ")
    assert (
        PrivacyEngine.restore_capsule(
            changed,
            result.capsule,
            restore_key,
            result.session_id,
        )
        == "a@example.com"
    )


def test_tolerant_token_restore_rejects_tabs_and_multiple_spaces(tmp_path):
    gateway = engine(tmp_path, None)
    restore_key = generate_key()
    result = gateway.transform("a@example.com", restore_key=restore_key)
    tabbed = result.text.replace("|", "\t|\t")
    wide = result.text.replace("|", "  |  ")
    assert (
        PrivacyEngine.restore_capsule(tabbed, result.capsule, restore_key, result.session_id)
        == tabbed
    )
    assert (
        PrivacyEngine.restore_capsule(wide, result.capsule, restore_key, result.session_id) == wide
    )


def test_tolerant_token_restore_rejects_unicode_case_folding(tmp_path):
    gateway = engine(tmp_path, None)
    restore_key = generate_key()
    result = gateway.transform("a@example.com", restore_key=restore_key)
    unicode_case = result.text.replace("I", "ı", 1)
    assert (
        PrivacyEngine.restore_capsule(
            unicode_case,
            result.capsule,
            restore_key,
            result.session_id,
        )
        == unicode_case
    )


def test_reversible_policy_without_any_key_blocks(tmp_path):
    gateway = engine(tmp_path, None)
    result = gateway.transform("a@example.com")
    assert result.state == TransformState.BLOCKED
    assert result.text is None
    assert "requires" in result.reason


def test_detector_failure_blocks_instead_of_forwarding_original(tmp_path, master_key):
    gateway = engine(tmp_path, master_key, detectors=[BrokenDetector()])
    result = gateway.transform("a@example.com")
    assert result.state == TransformState.BLOCKED
    assert result.text is None
    assert result.reason == "detector broken failed"


def test_policy_cannot_disable_fail_closed():
    with pytest.raises(ValueError, match="Input should be True"):
        Policy(name="unsafe", rules=[], fail_closed=False)


def test_required_detector_absence_blocks(tmp_path, master_key):
    policy = Policy(
        name="required",
        rules=[
            PolicyRule(
                entity=EntityType.EMAIL_ADDRESS,
                action=Action.REDACT,
                reversible=False,
                required_detectors=["presidio-v1"],
            )
        ],
    )
    gateway = engine(tmp_path, master_key, detectors=[])
    result = gateway.transform("a@example.com", policy=policy)
    assert result.state == TransformState.BLOCKED
    assert "required detectors unavailable" in result.reason


def test_repeated_value_gets_one_bijective_replacement(tmp_path, master_key):
    gateway = engine(tmp_path, master_key)
    result = gateway.transform("a@example.com then a@example.com")
    replacements = [item.replacement for item in result.detections]
    assert len(set(replacements)) == 1
    assert gateway.restore(result.text, result.session_id) == "a@example.com then a@example.com"


def test_nonreversible_redaction_needs_no_key(tmp_path):
    policy = Policy(
        name="redact",
        rules=[
            PolicyRule(
                entity=EntityType.EMAIL_ADDRESS,
                action=Action.REDACT,
                reversible=False,
            )
        ],
    )
    result = engine(tmp_path, None).transform("a@example.com", policy=policy)
    assert result.state == TransformState.PROTECTED
    assert result.text == "[REDACTED:EMAIL_ADDRESS]"


def test_keyless_hash_uses_an_ephemeral_key_instead_of_raw_sha256(tmp_path):
    policy = Policy(
        name="hash",
        rules=[
            PolicyRule(
                entity=EntityType.EMAIL_ADDRESS,
                action=Action.HASH,
                reversible=False,
            )
        ],
    )
    gateway = engine(tmp_path, None)
    first = gateway.transform("a@example.com", policy=policy).text
    second = gateway.transform("a@example.com", policy=policy).text
    assert first.startswith("sha256:")
    assert second.startswith("sha256:")
    assert first != second


def test_reversible_generalization_is_bijective_when_values_collapse(tmp_path):
    restore_key = generate_key()
    policy = Policy(
        name="dates",
        rules=[
            PolicyRule(
                entity=EntityType.DATE_TIME,
                action=Action.GENERALIZE,
                reversible=True,
            )
        ],
    )
    gateway = engine(tmp_path, None)
    source = "2024-01-01 then 2024-02-02"
    result = gateway.transform(source, policy=policy, restore_key=restore_key)
    assert len({item.replacement for item in result.detections}) == 2
    assert (
        PrivacyEngine.restore_capsule(
            result.text,
            result.capsule,
            restore_key,
            result.session_id,
        )
        == source
    )


def test_shared_cross_runtime_operator_fixtures(tmp_path):
    fixtures = json.loads(Path("conformance/core-v1.json").read_text(encoding="utf-8"))
    gateway = engine(tmp_path, None)
    for fixture in fixtures["operators"]:
        policy = Policy(
            name=fixture["name"],
            rules=[
                PolicyRule(
                    entity=EntityType(fixture["entity"]),
                    action=Action(fixture["action"]),
                    reversible=False,
                )
            ],
        )
        result = gateway.transform(
            fixture["text"],
            policy=policy,
            restore_key=fixture["key"],
        )
        assert result.text == fixture["expected"], fixture["name"]


@pytest.mark.parametrize(
    ("entity", "source"),
    [
        (EntityType.EMAIL_ADDRESS, "source@example.com"),
        (EntityType.PHONE_NUMBER, "+1-212-555-1234"),
        (EntityType.CREDIT_CARD, "4111 1111 1111 1111"),
        (EntityType.US_SSN, "123-45-6789"),
        (EntityType.IP_ADDRESS, "203.0.113.7"),
        (EntityType.API_KEY, "sk-abcdefghijklmnopqrstuvwxyz"),
        (EntityType.DATE_TIME, "2026-09-21"),
        (EntityType.MONEY, "$1,234.00"),
        (EntityType.URL, "https://source.example/path"),
        (EntityType.IBAN_CODE, "GB82 WEST 1234 5698 7654 32"),
        (EntityType.US_BANK_NUMBER, "021000021"),
    ],
)
def test_standardized_synthetic_values_remain_detectably_format_valid(tmp_path, entity, source):
    policy = Policy(
        name="synthetic-format",
        rules=[PolicyRule(entity=entity, action=Action.SYNTHETIC, reversible=False)],
    )
    result = engine(tmp_path, None).transform(source, policy=policy)
    assert result.state == TransformState.PROTECTED
    assert "SYNTHETIC_" not in result.text
    found = RegexDetector().detect(result.text, {entity})
    assert len(found) == 1
    assert found[0].value == result.text


@pytest.mark.parametrize(
    ("entity", "prefix", "digits"),
    [
        (EntityType.PASSPORT, "P", 8),
        (EntityType.DRIVER_LICENSE, "D", 8),
        (EntityType.MEDICAL_LICENSE, "M", 9),
    ],
)
def test_unstandardized_identifier_synthetics_are_typed_and_bounded(
    tmp_path, entity, prefix, digits
):
    gateway = engine(tmp_path, None)
    source = f"{prefix}12345678"
    detection = Detection(
        entity=entity,
        start=0,
        end=len(source),
        char_start=0,
        char_end=len(source),
        confidence_ppm=990_000,
        detector="fixture",
        value=source,
    )
    assert re.fullmatch(rf"{prefix}\d{{{digits}}}", gateway._synthetic(detection, None))
