"""Read-only harness knowledge for Stage 1 agents (#75 step 5).

Everything here comes from artifacts the pinned HCAP revision selects, never
from a working tree:

* syzlang descriptions: the syzkaller patch series is pinned by the
  ``CallAdmissionProfile`` identity (``patch_series_sha256``, the bytes
  ``tools/syzkaller/build.py`` stores: name, NUL, patch, NUL per patch).
  Every ``sys/linux/*.txt`` file the series creates is rebuilt by applying
  its hunks in order; a file the series only changes keeps its added lines.
* harness patches: the message and description hunks of one series patch,
  which is what an HCAP ``source_refs`` entry such as
  ``bundle/patches/syzkaller/0020-*`` names.
* reference programs: the neutral control programs of the pinned
  ``NeutralControlCatalog`` and the seeds of a pinned
  ``NormalFlowSeedManifest``.  Both are admitted harness programs; neither
  carries candidate data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..admission import CallAdmissionProfile, NeutralControlCatalog
from ..artifacts import ArtifactStore
from ..data import load_record
from ..hcap import ArtifactHcapChecker, HcapCatalog

SYZLANG_PATH = re.compile(r"^sys/linux/[A-Za-z0-9_.-]+\.txt$")
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
PATCH_ID = re.compile(r"^\d{4}$")


class KnowledgeUnavailable(ValueError):
    """The pinned HCAP selects no artifact this lookup needs."""


@dataclass(frozen=True)
class SyzlangFile:
    path: str
    lines: tuple[str, ...]
    #: False when the series only changes an upstream file: ``lines`` are
    #: then its added lines, not the whole file.
    complete: bool


@dataclass(frozen=True)
class SeriesPatch:
    name: str
    subject: str
    message: str
    #: (path, hunk text) of each sys/linux description hunk.
    syzlang_hunks: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ReferenceProgram:
    program_id: str
    kind: str
    program_ref: str
    runtime_selection: dict
    required_capability_ids: tuple[str, ...]


def split_series(data: bytes) -> list[tuple[str, str]]:
    """``name NUL patch NUL`` records, in series order."""
    parts = data.split(b"\0")
    if len(parts) % 2 != 1 or parts[-1] != b"":
        raise ValueError("malformed patch series bytes")
    return [(parts[i].decode("utf-8"), parts[i + 1].decode("utf-8"))
            for i in range(0, len(parts) - 1, 2)]


def _file_diffs(patch: str) -> list[tuple[str, bool, list[str]]]:
    """(path, created, diff body lines) for each file of one patch."""
    out: list[tuple[str, bool, list[str]]] = []
    current = None
    for line in patch.split("\n"):
        if line.startswith("diff --git "):
            m = re.match(r"^diff --git a/(\S+) b/(\S+)$", line)
            current = [m.group(2) if m else "", False, []]
            out.append(current)
        elif current is None:
            continue
        elif line.startswith("new file mode"):
            current[1] = True
        elif line.startswith("--- ") or line.startswith("+++ ") or \
                line.startswith("index "):
            continue
        else:
            current[2].append(line)
    return [(p, c, body) for p, c, body in out]


def _hunks(body: list[str]) -> list[tuple[int, int, list[str]]]:
    """(old start, old count, lines) of each hunk.  Hunk lengths come from
    the header, so trailing mail text (``-- `` and a version) is ignored."""
    out = []
    i = 0
    while i < len(body):
        m = HUNK.match(body[i])
        i += 1
        if m is None:
            continue
        old_n = 1 if m.group(2) is None else int(m.group(2))
        new_n = 1 if m.group(4) is None else int(m.group(4))
        lines: list[str] = []
        seen_old = seen_new = 0
        while i < len(body) and (seen_old < old_n or seen_new < new_n):
            line = body[i]
            i += 1
            if line.startswith("\\"):
                continue
            tag = line[:1] or " "
            if tag == "+":
                seen_new += 1
            elif tag == "-":
                seen_old += 1
            elif tag == " ":
                seen_old += 1
                seen_new += 1
            else:
                raise ValueError("malformed hunk")
            lines.append(tag + line[1:])
        if seen_old != old_n or seen_new != new_n:
            raise ValueError("truncated hunk")
        out.append((int(m.group(1)), old_n, lines))
    return out


def _apply(old: list[str], body: list[str]) -> list[str]:
    """Apply one file's hunks to ``old``; raises if they do not fit."""
    new: list[str] = []
    pos = 0                                 # next unconsumed old line
    for start, count, lines in _hunks(body):
        at = start - 1 if count else start   # 0-based first old line
        if at < pos or at > len(old):
            raise ValueError("hunk out of order")
        new.extend(old[pos:at])
        pos = at
        for line in lines:
            tag, text = line[0], line[1:]
            if tag == "+":
                new.append(text)
                continue
            if pos >= len(old) or old[pos] != text:
                raise ValueError("hunk does not apply")
            if tag == " ":
                new.append(text)
            pos += 1
    new.extend(old[pos:])
    return new


def rebuild_syzlang(series: list[tuple[str, str]]) -> dict[str, SyzlangFile]:
    files: dict[str, list[str]] = {}
    complete: dict[str, bool] = {}
    for _name, patch in series:
        for path, created, body in _file_diffs(patch):
            if not SYZLANG_PATH.match(path):
                continue
            if created or complete.get(path):
                try:
                    files[path] = _apply([] if created else files[path], body)
                    complete[path] = True
                    continue
                except ValueError:
                    complete[path] = False
            # An upstream file: keep what the series adds to it.
            complete.setdefault(path, False)
            if not complete[path]:
                try:
                    hunks = _hunks(body)
                except ValueError:
                    hunks = []
                files.setdefault(path, []).extend(
                    line[1:] for _s, _c, lines in hunks for line in lines
                    if line.startswith("+"))
    return {path: SyzlangFile(path, tuple(lines), complete[path])
            for path, lines in sorted(files.items())}


def series_patches(series: list[tuple[str, str]]) -> list[SeriesPatch]:
    out = []
    for name, patch in series:
        header = patch.split("\ndiff --git ", 1)[0]
        subject = ""
        for line in header.split("\n"):
            if line.startswith("Subject:"):
                subject = re.sub(r"^Subject:\s*(\[PATCH[^\]]*\]\s*)?", "",
                                 line)
                break
        message = header.split("\n\n", 1)[1] if "\n\n" in header else ""
        message = re.split(r"\n---(?:\n|$)", "\n" + message, 1)[0].strip()
        hunks = tuple(
            (path, "\n".join(body).strip("\n"))
            for path, _created, body in _file_diffs(patch)
            if SYZLANG_PATH.match(path))
        out.append(SeriesPatch(name, subject, message, hunks))
    return out


class HarnessKnowledge:
    """Knowledge lookups over one artifact store, per HCAP revision."""

    def __init__(self, store: ArtifactStore) -> None:
        self.store = store
        self._checker = ArtifactHcapChecker(store)

    @staticmethod
    def _authority(catalog: HcapCatalog, kind: str) -> str | None:
        refs = {ref.artifact_ref
                for ref in (*catalog.authority_refs,
                            *(ref for cap in catalog.capabilities
                              for ref in cap.authority_refs))
                if ref.kind == kind}
        return refs.pop() if len(refs) == 1 else None

    def _series(self, revision: str) -> list[tuple[str, str]]:
        catalog = self._checker.load_catalog(revision)
        ref = self._authority(catalog, "CallAdmissionProfile")
        if ref is None:
            raise KnowledgeUnavailable(
                "the pinned HCAP selects no CallAdmissionProfile")
        profile = load_record(self.store, ref, CallAdmissionProfile)
        return split_series(self.store.get(
            profile.identity.patch_series_sha256))

    def syzlang(self, revision: str) -> dict[str, SyzlangFile]:
        return rebuild_syzlang(self._series(revision))

    def patches(self, revision: str) -> list[SeriesPatch]:
        return series_patches(self._series(revision))

    def reference_programs(self, revision: str
                           ) -> list[ReferenceProgram]:
        from ..materializer import NormalFlowSeedManifest   # import cycle

        catalog = self._checker.load_catalog(revision)
        out: list[ReferenceProgram] = []
        neutral = self._authority(catalog, "NeutralControlCatalog")
        if neutral is not None:
            entries = load_record(self.store, neutral,
                                  NeutralControlCatalog).entries
            for index, entry in enumerate(entries):
                out.append(ReferenceProgram(
                    program_id=f"neutral:{index}", kind="neutral_control",
                    program_ref=entry.program_ref,
                    runtime_selection=entry.runtime_selection.model_dump(
                        mode="json"),
                    required_capability_ids=tuple(
                        entry.required_capability_ids)))
        seeds = self._authority(catalog, "NormalFlowSeedManifest")
        if seeds is not None:
            for seed in load_record(self.store, seeds,
                                    NormalFlowSeedManifest).seeds:
                out.append(ReferenceProgram(
                    program_id=f"seed:{seed.seed_id}", kind="seed",
                    program_ref=seed.program_ref,
                    runtime_selection=seed.runtime_selections[0].model_dump(
                        mode="json"),
                    required_capability_ids=()))
        return out

    def program_text(self, ref: str, max_bytes: int) -> bytes:
        return self.store.get(ref)[:max_bytes + 1]
