"""Test-suite bootstrap.

Tracked artifacts (manifests, conformance fixtures, the onboarding static root, the
Pages workflow) are read from paths relative to the *repository*, never relative to
the process working directory. Two problems are fixed here:

1. Tests read tracked artifacts through the working directory, so invoking the
   suite outside the repository made those paths miss.
2. The pytest console entry point does not necessarily put the repository root
   on ``sys.path``, so ``from scripts.assemble_site import …`` could fail during
   collection even when the root was the working directory.

``REPO_ROOT`` is published for tests to build absolute paths from, and the
repository root is placed on ``sys.path`` so repository-relative imports resolve
from any working directory.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))


def repo_path(*parts: str) -> Path:
    """An absolute path inside the repository, independent of the working directory."""
    return REPO_ROOT.joinpath(*parts)
