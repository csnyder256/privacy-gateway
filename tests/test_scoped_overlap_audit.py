"""Scope selection precedes overlap precedence without dropping health checks."""

import pytest
from test_scopes import engine

from privacy_gateway.models import Action, EntityType, Policy, PolicyRule


@pytest.mark.parametrize("deny", [False, True])
def test_in_scope_email_is_not_suppressed_by_out_of_scope_url(tmp_path, deny):
    text = "https://example.com/contact/a@example.com"
    policy = Policy(
        name="scoped-overlap",
        rules=[
            PolicyRule(
                entity=EntityType.EMAIL_ADDRESS,
                action=Action.REDACT,
                reversible=False,
                scopes=["text"],
                priority=10,
            ),
            PolicyRule(
                entity=EntityType.URL,
                action=Action.REDACT,
                reversible=False,
                scopes=["json:/other"],
                priority=100,
            ),
        ],
        deny_terms={text: EntityType.URL} if deny else {},
    )
    result = engine(tmp_path).transform(text, policy=policy)
    assert result.text == "https://example.com/contact/[REDACTED:EMAIL_ADDRESS]"
    assert [d.entity for d in result.detections] == [EntityType.EMAIL_ADDRESS]


def test_same_scope_url_retains_deny_list_priority(tmp_path):
    text = "https://example.com/contact/a@example.com"
    policy = Policy(
        name="same-scope-overlap",
        rules=[
            PolicyRule(
                entity=EntityType.EMAIL_ADDRESS,
                action=Action.REDACT,
                reversible=False,
                scopes=["text"],
                priority=100,
            ),
            PolicyRule(
                entity=EntityType.URL,
                action=Action.REDACT,
                reversible=False,
                scopes=["text"],
                priority=10,
            ),
        ],
        deny_terms={text: EntityType.URL},
    )
    result = engine(tmp_path).transform(text, policy=policy)
    assert result.text == "[REDACTED:URL]"
