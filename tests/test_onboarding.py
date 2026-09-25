from pathlib import Path

from privacy_gateway import __version__
from privacy_gateway.models import Action, EntityType
from privacy_gateway.policies import PRESETS

STATIC = Path("src/privacy_gateway/static")


def test_wizard_manifest_covers_the_product_catalog():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    for preset in PRESETS:
        assert f'data-preset="{preset}"' in html
    for entity in EntityType:
        assert f'"{entity.value}"' in script
    for action in Action:
        assert f'"{action.value}"' in script
    for mode in ("client", "local", "selfhosted", "oneway"):
        assert f'data-mode="{mode}"' in html
    for adapter in (
        "python",
        "typescript",
        "docker",
        "mcp",
        "openai",
        "anthropic",
        "webhook",
        "synthetic",
    ):
        assert f'data-snippet="{adapter}"' in html
        assert f"  {adapter}:" in script


def test_policy_schema_names_and_sample_privacy_are_explicit():
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    for field in (
        "allow_terms",
        "deny_terms",
        "fail_closed",
        "mapping_retention_seconds",
        "audit_retention_seconds",
        "minimum_confidence_ppm",
        "required_detectors",
    ):
        assert field in script
    persisted = script[script.index("localStorage.setItem") : script.index("} catch")]
    assert "sample-input" not in persisted
    assert "source" not in persisted


def test_accessibility_and_pages_assets_are_wired():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    workflow = Path(".github/workflows/pages.yml").read_text(encoding="utf-8")
    assert '<html lang="en">' in html
    assert 'aria-live="polite"' in html
    assert 'id="allow-terms"' in html and 'id="deny-terms"' in html
    assert ":focus-visible" in css
    assert "prefers-reduced-motion" in css
    assert ".entity-row .reversible,.entity-row .confidence{display:none}" not in css
    assert "_site/assets/app.css" in workflow
    assert "_site/assets/app.js" in workflow


def test_topbar_shows_the_package_version():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert f'<span class="topbar-meta">v{__version__} / MIT</span>' in html, (
        "Bump the version in src/privacy_gateway/static/index.html with the package version; "
        "the Pages site republishes from it when the bump lands on main."
    )
