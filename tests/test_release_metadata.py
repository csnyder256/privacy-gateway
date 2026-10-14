"""The release version must agree everywhere the release gate can see it.

``scripts/verify_release.py`` runs in the ``Release metadata`` job on every pull
request and push to ``main``, and again in the ``Release`` workflow before
anything is packaged. It compares ``VERSION`` against the files ``release.json``
names: ``package_json`` entries by their ``version`` field, and
``version_patterns`` entries by regex.

``package_json`` was empty, so the two publishable npm workspace packages
(``@privacy-gateway/core`` and ``@privacy-gateway/client``, both declaring
``publishConfig.access: public``) were never compared, and they sat at 0.3.0
while the release was 0.5.0 -- three minor releases of drift the gate could not
see. Every release through 0.3.0 bumped both manifests in the same commit as
``pyproject.toml`` and ``src/privacy_gateway/__init__.py``, so the omission is
the defect, not a policy of independent versioning.

These tests keep the gate honest: every workspace package must be listed, its
version must equal ``VERSION``, and the gate must still pass exactly as the
workflows invoke it.
"""

from __future__ import annotations

import json
import subprocess
import sys

from conftest import REPO_ROOT, repo_path


def release_version() -> str:
    return repo_path("VERSION").read_text(encoding="utf-8").strip()


def workspace_package_files() -> list[str]:
    """Every workspace ``package.json``, discovered from the root manifest's globs.

    Reading the globs instead of hardcoding paths means a third workspace package
    cannot be added without this test noticing that the gate does not cover it.
    """
    root = json.loads(repo_path("package.json").read_text(encoding="utf-8"))
    files = {
        str(path.relative_to(REPO_ROOT))
        for pattern in root["workspaces"]
        for path in sorted(REPO_ROOT.glob(f"{pattern}/package.json"))
    }
    assert files, "the root package.json declares no workspace packages"
    return sorted(files)


def test_every_workspace_package_version_agrees_with_the_release():
    version = release_version()
    for filename in workspace_package_files():
        manifest = json.loads(repo_path(filename).read_text(encoding="utf-8"))
        assert manifest["version"] == version, filename


def test_the_release_manifest_covers_every_workspace_package():
    """A package missing from ``package_json`` is a package the gate cannot check."""
    listed = set(json.loads(repo_path("release.json").read_text(encoding="utf-8"))["package_json"])
    assert set(workspace_package_files()) <= listed


def test_the_release_gate_passes_as_the_workflows_run_it():
    result = subprocess.run(
        [sys.executable, str(repo_path("scripts/verify_release.py"))],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "agrees on" in result.stdout
