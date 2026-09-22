from __future__ import annotations

from typing import Any

from .crypto import decode_key, open_json
from .engine import TOKEN_RE, PrivacyEngine


class StreamingRestorer:
    """Incrementally restore tagged display text without emitting partial tags."""

    # Covers the largest v1 composite surface while remaining strictly bounded.
    max_candidate_chars = 512

    def __init__(self, reverse: dict[str, str]):
        if not all(
            isinstance(key, str) and isinstance(value, str) for key, value in reverse.items()
        ):
            raise ValueError("reverse map must contain only string keys and values")
        self._reverse = dict(reverse)
        self._composite_prefixes = []
        for surface in reverse:
            match = TOKEN_RE.search(surface)
            if match is not None and match.end() == len(surface) and match.start() > 0:
                self._composite_prefixes.append(surface[: match.start()])
        self._buffer = ""
        self._finished = False

    @classmethod
    def from_capsule(
        cls,
        capsule: str,
        restore_key: str,
        session_id: str,
    ) -> StreamingRestorer:
        reverse = open_json(
            capsule,
            decode_key(restore_key),
            aad=f"privacy-gateway:{session_id}",
        )
        if not isinstance(reverse, dict):
            raise TypeError("invalid restoration capsule")
        return cls(reverse)

    def feed(self, chunk: str) -> str:
        if self._finished:
            raise RuntimeError("stream restorer is already finished")
        self._buffer += chunk
        cut = self._safe_cut()
        ready, self._buffer = self._buffer[:cut], self._buffer[cut:]
        return PrivacyEngine._replace_from_map(ready, self._reverse)

    def _safe_cut(self) -> int:
        cut = len(self._buffer)
        for surface in self._reverse:
            for length in range(1, min(len(surface), len(self._buffer)) + 1):
                if length < len(surface) and self._buffer.endswith(surface[:length]):
                    cut = min(cut, len(self._buffer) - length)
        for prefix in self._composite_prefixes:
            for length in range(1, min(len(prefix), len(self._buffer)) + 1):
                if self._buffer.endswith(prefix[:length]):
                    cut = min(cut, len(self._buffer) - length)
            start = self._buffer.rfind(f"{prefix}[[")
            if start >= 0 and "]]" not in self._buffer[start + len(prefix) + 2 :]:
                cut = min(cut, start)
        last_open = self._buffer.rfind("[[")
        if last_open >= 0 and "]]" not in self._buffer[last_open + 2 :]:
            if len(self._buffer) - last_open <= self.max_candidate_chars:
                cut = min(cut, last_open)
            else:
                cut = min(cut, max(0, len(self._buffer) - self.max_candidate_chars))
        if self._buffer.endswith("["):
            cut = min(cut, len(self._buffer) - 1)
        return max(cut, len(self._buffer) - self.max_candidate_chars)

    def finish(self) -> str:
        if self._finished:
            raise RuntimeError("stream restorer is already finished")
        self._finished = True
        ready, self._buffer = self._buffer, ""
        return PrivacyEngine._replace_from_map(ready, self._reverse)


def restore_json(
    value: Any,
    reverse: dict[str, str],
    *,
    blocked_pointers: set[str] | None = None,
) -> Any:
    blocked = blocked_pointers or set()

    def is_blocked(pointer: str) -> bool:
        return any(pointer == prefix or pointer.startswith(f"{prefix}/") for prefix in blocked)

    def escape(segment: str) -> str:
        return segment.replace("~", "~0").replace("/", "~1")

    def walk(node: Any, pointer: str) -> Any:
        if is_blocked(pointer):
            return node
        if isinstance(node, str):
            return PrivacyEngine._replace_from_map(node, reverse)
        if isinstance(node, list):
            return [walk(item, f"{pointer}/{index}") for index, item in enumerate(node)]
        if isinstance(node, dict):
            return {key: walk(item, f"{pointer}/{escape(str(key))}") for key, item in node.items()}
        return node

    return walk(value, "")
