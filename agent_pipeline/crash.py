"""Kernel crash classification of a Stage 1 run's guest log (#81 §3).

A crash is not an infrastructure failure: the collector seals it as a
``crash-report`` artifact next to the observation, and the observation's
``runtime_errors`` no longer carry it.  A run that completed is judged
from its coverage as usual; a run the crash stopped (a panic) is
incomplete for its own reasons and is run again.  Either way the
Controller keeps the crash as a finding on the job.

The primary evidence is the serial console: after a panic the guest no
longer answers SSH, so ``dmesg`` is only a fallback (D9, D10).
"""

from __future__ import annotations

import enum
import re
from typing import Annotated, Literal

from pydantic import Field

from .contracts import Record, Sanitizer

CRASH_REPORT_ID = "crash-report"
CRASH_REPORT_TYPE = "application/vnd.knfsd.crash-report+json"
#: Report lines kept in the record; the full log is sealed beside it.
MAX_LINES = 16
MAX_LINE = 200

_TIMESTAMP = re.compile(r"^\s*\[\s*[0-9]+\.[0-9]+\]\s*")


class CrashKind(str, enum.Enum):
    KASAN = "kasan"
    KCSAN = "kcsan"
    KERNEL_BUG = "kernel_bug"
    BUG = "bug"
    OOPS = "oops"
    PANIC = "panic"
    WARNING = "warning"


#: (kind, pattern), most specific first: a line is the first kind it
#: matches, so ``Kernel panic - not syncing: KASAN: ...`` is the panic.
#: ``BUG: KCSAN:`` is a crash only on a KCSAN harness.
_KINDS = (
    (CrashKind.PANIC, re.compile(r"Kernel panic")),
    (CrashKind.KCSAN, re.compile(r"BUG: KCSAN:")),
    (CrashKind.KASAN, re.compile(r"KASAN:")),
    (CrashKind.KERNEL_BUG, re.compile(r"kernel BUG")),
    (CrashKind.BUG, re.compile(r"BUG:")),
    (CrashKind.OOPS, re.compile(r"Oops:")),
    (CrashKind.WARNING, re.compile(r"WARNING:")),
)

Line = Annotated[str, Field(min_length=1, max_length=MAX_LINE)]


class CrashReport(Record):
    """The crash lines of one run's guest log.  ``title`` is the first of
    them; ``panicked`` says the kernel stopped, so the run could not
    finish."""

    schema_version: Literal["crash-report-v1"] = "crash-report-v1"
    source: Literal["console", "dmesg"]
    sanitizer: Sanitizer
    kind: CrashKind
    title: Line
    lines: Annotated[tuple[Line, ...], Field(min_length=1,
                                             max_length=MAX_LINES)]
    panicked: bool


def _kind(line: str, sanitizer: Sanitizer) -> CrashKind | None:
    for kind, pattern in _KINDS:
        if pattern.search(line):
            if kind is CrashKind.KCSAN and sanitizer is not Sanitizer.KCSAN:
                return None
            return kind
    return None


def crash_lines(text: str, sanitizer: Sanitizer
                ) -> list[tuple[CrashKind, str]]:
    """Every crash line of a log, without its console timestamp."""
    found = []
    for raw in text.splitlines():
        kind = _kind(raw, sanitizer)
        if kind is not None:
            line = _TIMESTAMP.sub("", raw).strip()[:MAX_LINE]
            found.append((kind, line or kind.value))
    return found


def classify(console: str, dmesg: str | None, sanitizer: Sanitizer,
             ) -> CrashReport | None:
    """The run's crash report, from the console, else from ``dmesg``."""
    for source, text in (("console", console), ("dmesg", dmesg)):
        found = crash_lines(text or "", sanitizer)
        if found:
            return CrashReport(
                source=source, sanitizer=sanitizer, kind=found[0][0],
                title=found[0][1],
                lines=tuple(line for _, line in found[:MAX_LINES]),
                panicked=any(k is CrashKind.PANIC for k, _ in found))
    return None
