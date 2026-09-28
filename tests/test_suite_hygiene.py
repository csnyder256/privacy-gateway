"""The suite must not depend on the process working directory.

Two separate portability defects are covered:

* The pytest console entry point left the repository root off ``sys.path``, so
  ``tests/test_onboarding.py`` (an import-time ``from scripts.assemble_site import
  assemble``) aborted collection for the whole module with ``ModuleNotFoundError``.
* Tests that read tracked artifacts through relative paths such as
  ``contracts/compatibility-v1.json`` depended on the working directory being the
  repository root.

Both are pinned here: the shared helper resolves repository artifacts from
``tests/conftest.py``'s own location, and collection is exercised from a directory
that is not the repository root.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys

from conftest import REPO_ROOT, repo_path

TRACKED_PREFIXES = ("contracts/", "conformance/", "src/", "scripts/", ".github/")


def _relative_tracked_paths(path):
    """Yield ``(line, path-literal)`` for relative paths to tracked artifacts.

    Only literal string arguments are inspected, so docstrings and comments that
    merely mention a path cannot trip the guard.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Name) and node.func.id == "Path"):
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant):
            continue
        value = node.args[0].value
        if isinstance(value, str) and value.startswith(TRACKED_PREFIXES):
            yield node.lineno, value


def test_repo_path_resolves_from_any_working_directory(tmp_path, monkeypatch):
    expected = REPO_ROOT / "contracts" / "compatibility-v1.json"
    assert repo_path("contracts/compatibility-v1.json") == expected
    monkeypatch.chdir(tmp_path)
    assert repo_path("contracts/compatibility-v1.json") == expected
    assert repo_path("contracts/compatibility-v1.json").is_file()


def test_no_test_reads_a_tracked_artifact_through_the_working_directory():
    offenders = [
        f"{path.name}:{line}: Path({value!r})"
        for path in sorted((REPO_ROOT / "tests").glob("test_*.py"))
        for line, value in _relative_tracked_paths(path)
    ]
    assert offenders == []


def test_suite_collects_when_pytest_runs_from_outside_the_repository(tmp_path):
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            str(REPO_ROOT / "tests"),
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ModuleNotFoundError" not in result.stdout + result.stderr
