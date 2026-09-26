"""Strict parser and arithmetic for sunrpc_fuzz debugfs counter snapshots."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

_COUNTER_LINE: Final[re.Pattern[str]] = re.compile(
    r"(?:pool )?([A-Za-z_][A-Za-z0-9_]* [0-9]+(?: [A-Za-z_][A-Za-z0-9_]* [0-9]+)*)\Z"
)


@dataclass(frozen=True, slots=True)
class CounterParseError(ValueError):
    """A debugfs counter line could not be parsed without ambiguity."""

    file: str
    line: int
    text: str

    def __str__(self) -> str:
        return f"{self.file}:{self.line}: malformed counter line: {self.text!r}"


def _parse_file(file: str, text: str) -> dict[str, int]:
    """Parse one stats/state capture, rejecting malformed and duplicate values."""
    counters: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        match = _COUNTER_LINE.fullmatch(line)
        if match is None:
            raise CounterParseError(file, number, line)
        pairs = match.group(1).split(" ")
        for offset in range(0, len(pairs), 2):
            name, raw_value = pairs[offset:offset + 2]
            if name in counters:
                raise CounterParseError(file, number, line)
            counters[name] = int(raw_value)
    return counters


def snapshot_from_texts(texts: dict[str, str]) -> dict[str, dict[str, int]]:
    """Parse named debugfs captures into per-file integer counter maps."""
    return {file: _parse_file(file, text) for file, text in texts.items()}


def delta(pre: dict[str, dict[str, int]], post: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    """Return per-counter increases, rejecting missing counters and regressions."""
    result: dict[str, dict[str, int]] = {}
    for file, before in pre.items():
        after = post[file]
        result[file] = {}
        for name, value in before.items():
            difference = after[name] - value
            if difference < 0:
                raise ValueError(f"counter regressed: {file}:{name}")
            result[file][name] = difference
    return result


def drained(post: dict[str, dict[str, int]], keys: list[str] | tuple[str, ...] | set[str]) -> bool:
    """Return whether each requested counter is zero and unambiguous across files."""
    values = {name: [counters for counters in post.values() if name in counters] for name in set(keys)}
    missing = sorted(name for name, occurrences in values.items() if not occurrences)
    if missing:
        raise KeyError("missing drain counters: " + ", ".join(missing))
    ambiguous = sorted(name for name, occurrences in values.items() if len(occurrences) > 1)
    if ambiguous:
        raise ValueError("ambiguous drain counters across files: " + ", ".join(ambiguous))
    return all(occurrences[0][name] == 0 for name, occurrences in values.items())
