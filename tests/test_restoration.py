import pytest
from cryptography.exceptions import InvalidTag

from privacy_gateway.crypto import generate_key
from privacy_gateway.engine import PrivacyEngine
from privacy_gateway.models import Action, EntityType
from privacy_gateway.policies import policy_from_preset
from privacy_gateway.restoration import StreamingRestorer, restore_json
from privacy_gateway.vault import Vault


def protected_fixture(tmp_path):
    key = generate_key()
    gateway = PrivacyEngine(Vault(tmp_path / "db.sqlite"))
    source = "prefix alice@example.com suffix"
    result = gateway.transform(source, restore_key=key)
    return source, result, key


def test_every_two_chunk_split_restores_exactly(tmp_path):
    source, result, key = protected_fixture(tmp_path)
    for split in range(len(result.text) + 1):
        stream = StreamingRestorer.from_capsule(result.capsule, key, result.session_id)
        output = (
            stream.feed(result.text[:split]) + stream.feed(result.text[split:]) + stream.finish()
        )
        assert output == source, split


def test_every_single_character_chunk_restores_once(tmp_path):
    source, result, key = protected_fixture(tmp_path)
    stream = StreamingRestorer.from_capsule(result.capsule, key, result.session_id)
    output = "".join(stream.feed(char) for char in result.text) + stream.finish()
    assert output == source


def test_reversible_composite_surrogate_streams_exactly(tmp_path):
    key = generate_key()
    source = "2024-01-01"
    result = PrivacyEngine(Vault(tmp_path / "composite.db")).transform(
        source,
        preset="healthcare",
        restore_key=key,
    )
    assert result.text.startswith("20") and "[[PG1|" in result.text
    stream = StreamingRestorer.from_capsule(result.capsule, key, result.session_id)
    assert "".join(stream.feed(char) for char in result.text) + stream.finish() == source


def test_reversible_composite_accepts_bounded_token_case_variant(tmp_path):
    key = generate_key()
    source = "2024-01-01"
    result = PrivacyEngine(Vault(tmp_path / "composite-case.db")).transform(
        source,
        preset="healthcare",
        restore_key=key,
    )
    changed = result.text.lower().replace("|", " | ")
    stream = StreamingRestorer.from_capsule(result.capsule, key, result.session_id)
    assert "".join(stream.feed(char) for char in changed) + stream.finish() == source


def test_maximum_domain_generalization_streams_exactly(tmp_path):
    domain = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
    source = f"x@{domain}"
    key = generate_key()
    policy = policy_from_preset("balanced")
    rule = policy.rule_for(EntityType.EMAIL_ADDRESS)
    rule.action = Action.GENERALIZE
    rule.reversible = True
    result = PrivacyEngine(Vault(tmp_path / "max-email.db")).transform(
        source,
        policy=policy,
        restore_key=key,
    )
    assert len(result.text) < StreamingRestorer.max_candidate_chars
    stream = StreamingRestorer.from_capsule(result.capsule, key, result.session_id)
    assert "".join(stream.feed(char) for char in result.text) + stream.finish() == source


def test_foreign_and_malformed_tokens_flush_unchanged():
    foreign = "before [[PG1|EMAIL_ADDRESS|AAAAAAAAAAAAAAAAAAAAAAAAAA|AAAAAAAAAAAAAAAA]] after"
    malformed = "tail [[PG1|EMAIL"
    stream = StreamingRestorer({})
    assert stream.feed(foreign + malformed) == f"{foreign}tail "
    assert stream.finish() == "[[PG1|EMAIL"


def test_buffer_is_bounded_for_unclosed_candidate():
    stream = StreamingRestorer({})
    candidate = "[[" + "A" * 1000
    emitted = stream.feed(candidate)
    assert len(emitted) == len(candidate) - stream.max_candidate_chars
    assert len(stream._buffer) <= stream.max_candidate_chars


def test_buffer_is_bounded_for_unclosed_composite_candidate(tmp_path):
    key = generate_key()
    result = PrivacyEngine(Vault(tmp_path / "bounded-composite.db")).transform(
        "2024-01-01",
        preset="healthcare",
        restore_key=key,
    )
    stream = StreamingRestorer.from_capsule(result.capsule, key, result.session_id)
    prefix = result.text.split("[[", 1)[0]
    emitted = stream.feed(f"{prefix}[[{'A' * 1000}")
    assert emitted
    assert len(stream._buffer) <= stream.max_candidate_chars


def test_finish_and_feed_reject_after_finish():
    stream = StreamingRestorer({})
    stream.finish()
    with pytest.raises(RuntimeError, match="already finished"):
        stream.finish()
    with pytest.raises(RuntimeError, match="already finished"):
        stream.feed("x")


def test_capsule_wrong_key_rejects_before_processing(tmp_path):
    _, result, _ = protected_fixture(tmp_path)
    with pytest.raises(InvalidTag):
        StreamingRestorer.from_capsule(result.capsule, generate_key(), result.session_id)


def test_recursive_restore_respects_blocked_pointer(tmp_path):
    source, result, key = protected_fixture(tmp_path)
    reverse_stream = StreamingRestorer.from_capsule(result.capsule, key, result.session_id)
    reverse = reverse_stream._reverse
    value = {
        "display": result.text,
        "tool": {"arguments": result.text},
        "list": [result.text, 7, True, None],
    }
    restored = restore_json(value, reverse, blocked_pointers={"/tool/arguments"})
    assert restored == {
        "display": source,
        "tool": {"arguments": result.text},
        "list": [source, 7, True, None],
    }
