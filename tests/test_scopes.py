"""Regression tests: a rule's scope narrows where it applies, not whether it exists.

A rule scoped to `json:/other` still says "EMAIL_ADDRESS is PII under this
policy". Before this guard, that rule was dropped from the rule set in any scope
it did not select, which silently removed the entity from two consumers at once:

* a required detector's health check vanished, so `required_detectors` was
  skipped and the payload crossed the boundary unchecked (contract rules 3 and
  6, and the `fail_closed` premise of `models.Policy`);
* an allow term could no longer retire a value the user had declared safe.

Both are exercised here, at the engine boundary where callers observe them. The
same-scope case (`scopes=["text"]` in a `text` transform) must keep working
exactly as before, so each test also pins the behavior that already worked.
"""

from pathlib import Path

from privacy_gateway.engine import PrivacyEngine
from privacy_gateway.models import Action, EntityType, Policy, PolicyRule
from privacy_gateway.vault import Vault


def engine(tmp_path: Path, detectors=None) -> PrivacyEngine:
    return PrivacyEngine(Vault(tmp_path / "gateway.db"), detectors=detectors)


def scoped_rule(*, scopes, required_detectors=(), entity=EntityType.EMAIL_ADDRESS):
    return PolicyRule(
        entity=entity,
        action=Action.REDACT,
        reversible=False,
        scopes=list(scopes),
        required_detectors=list(required_detectors),
    )


def test_required_detector_blocks_even_when_the_rule_is_scoped_elsewhere(tmp_path):
    """A scoped-out rule must not lose its required-detector health check.

    `required_detectors` is the policy's own fail-closed declaration, and
    `models.Policy` refuses to run with `fail_closed=False`. Scope narrowing
    decides where the replacement lands, not whether the requirement exists.
    """
    policy = Policy(
        name="required-scoped",
        rules=[scoped_rule(scopes=["json:/other"], required_detectors=["presidio-v1"])],
    )
    result = engine(tmp_path, detectors=[]).transform(
        "Contact a@example.com today.", policy=policy, scope="json:/allowed"
    )
    assert result.state.value == "blocked"
    assert result.text is None
    assert result.reason == "required detectors unavailable: presidio-v1"


def test_required_detector_that_is_available_does_not_block_a_scoped_out_rule(tmp_path):
    """The check reports health, not scope: an available detector keeps working."""

    class Named:
        name = "presidio-v1"

        def detect(self, text, entities):
            return []

    policy = Policy(
        name="required-present",
        rules=[scoped_rule(scopes=["json:/other"], required_detectors=["presidio-v1"])],
    )
    gateway = PrivacyEngine(Vault(tmp_path / "gateway.db"), detectors=[Named()])
    result = gateway.transform("a@example.com", policy=policy, scope="text")
    assert result.state.value == "protected"


def test_required_detector_absent_still_blocks_when_the_rule_selects_the_scope(tmp_path):
    policy = Policy(
        name="required-in-scope",
        rules=[scoped_rule(scopes=["text"], required_detectors=["presidio-v1"])],
    )
    result = engine(tmp_path, detectors=[]).transform("Contact a@example.com today.", policy=policy)
    assert result.state.value == "blocked"
    assert result.reason == "required detectors unavailable: presidio-v1"


def test_rule_scoped_elsewhere_leaves_its_matches_unchanged(tmp_path):
    """Scope narrowing still narrows: the replacement is not applied elsewhere."""
    policy = Policy(name="narrow", rules=[scoped_rule(scopes=["json:/other"])])
    gateway = engine(tmp_path)
    elsewhere = gateway.transform(
        "Contact a@example.com today.", policy=policy, scope="json:/allowed"
    )
    assert elsewhere.state.value == "protected"
    assert elsewhere.text == "Contact a@example.com today."
    assert elsewhere.detections == []
    named = gateway.transform("Contact a@example.com today.", policy=policy, scope="json:/other")
    assert named.text == "Contact [REDACTED:EMAIL_ADDRESS] today."
    assert [item.replacement for item in named.detections] == ["[REDACTED:EMAIL_ADDRESS]"]


def test_rule_scoped_elsewhere_records_no_decision_it_did_not_make(tmp_path):
    """Nothing is written to the audit trail for a rule that did not apply."""
    policy = Policy(name="narrow", rules=[scoped_rule(scopes=["json:/other"])])
    gateway = engine(tmp_path)
    result = gateway.transform("a@example.com", policy=policy, scope="json:/allowed")
    assert gateway.vault.session_summary(result.session_id)["tags"] == []


def test_allow_term_removes_its_value_in_every_scope(tmp_path):
    """An allow term is a statement about the value, so a narrowed rule cannot drop it."""
    policy = Policy(
        name="allow-everywhere",
        rules=[scoped_rule(scopes=["json:/other"])],
        allow_terms=["safe@example.com"],
    )
    gateway = engine(tmp_path)
    payload = {"allowed": "safe@example.com", "other": "maya@example.com"}
    protected, _ = gateway.transform_json(payload, policy=policy, scope="json")
    assert protected == {"allowed": "safe@example.com", "other": "[REDACTED:EMAIL_ADDRESS]"}


def test_allow_term_removes_its_value_when_the_rule_claims_every_scope(tmp_path):
    policy = Policy(
        name="allow-wide",
        rules=[scoped_rule(scopes=["*"])],
        allow_terms=["safe@example.com"],
    )
    protected, _ = engine(tmp_path).transform_json(
        {"allowed": "safe@example.com", "other": "maya@example.com"}, policy=policy, scope="json"
    )
    assert protected == {"allowed": "safe@example.com", "other": "[REDACTED:EMAIL_ADDRESS]"}


def test_scope_still_selects_the_rule_when_the_value_is_also_allowed(tmp_path):
    """Where the value is not allow-listed, scope selection is untouched."""
    policy = Policy(
        name="scoped-allow",
        rules=[scoped_rule(scopes=["json:/other"])],
        allow_terms=["safe@example.com"],
    )
    gateway = engine(tmp_path)
    result = gateway.transform("safe@example.com", policy=policy, scope="json:/allowed")
    assert result.text == "safe@example.com"
    assert result.detections == []
