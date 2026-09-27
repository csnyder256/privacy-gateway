"""Assemble GitHub Pages from the most recent release tag."""

import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src/privacy_gateway/static"
VERSION_TOKEN = "__PRIVACY_GATEWAY_VERSION__"


def assemble(output: Path, release_tag: str) -> None:
    if re.fullmatch(r"v\d+\.\d+\.\d+", release_tag) is None:
        raise ValueError(f"Expected a release tag, got {release_tag!r}")
    assets = output / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    if html.count(VERSION_TOKEN) != 1:
        raise ValueError("The site must contain exactly one release version token")
    (output / "index.html").write_text(
        html.replace(VERSION_TOKEN, release_tag.removeprefix("v")), encoding="utf-8"
    )
    for name in ("app.css", "app.js", "favicon.svg"):
        shutil.copyfile(STATIC / name, assets / name)


if __name__ == "__main__":
    assemble(Path(sys.argv[1]), sys.argv[2])
