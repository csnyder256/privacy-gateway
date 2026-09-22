"""Fail CI when the public evaluation corpus stops looking deliberately synthetic."""

from __future__ import annotations

import json
import re
from pathlib import Path

EMAIL = re.compile(r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Z0-9.-]+)", re.IGNORECASE)
API_KEY = re.compile(r"(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})")
SSN = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")


def main() -> None:
    path = Path(__file__).resolve().parents[1] / "evaluation" / "cases.jsonl"
    for line_number, line in enumerate(path.read_text().splitlines(), start=1):
        case = json.loads(line)
        if not isinstance(case.get("id"), str) or not isinstance(case.get("text"), str):
            raise SystemExit(f"{path}:{line_number}: fixture requires string id and text")
        text = case["text"]
        for match in EMAIL.finditer(text):
            if not match.group(1).lower().endswith((".test", ".example")):
                raise SystemExit(f"{path}:{line_number}: use an RFC 2606-style email domain")
        for match in API_KEY.finditer(text):
            if "example" not in match.group().lower():
                raise SystemExit(f"{path}:{line_number}: API-key fixture must be visibly fake")
        if SSN.search(text):
            raise SystemExit(f"{path}:{line_number}: do not include a valid-looking SSN fixture")
    print(f"validated {line_number} invented evaluation fixtures")


if __name__ == "__main__":
    main()
