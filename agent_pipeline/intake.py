"""Candidate intake validation (02 §3).

Source identity only: the commit is exact and exists, the path is normalized
and exists at that commit, and the symbol or range resolves to exactly one
place in that file.  Nothing here asks whether a harness exists for the
commit; harness binding does that next (01 §11.2).  An ambiguous target is
refused, never handed to the Agent to guess.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Protocol

from .contracts import (CandidateLocation, CandidateSubmission, LocationKind,
                        Record, VulnerabilityCandidate)

COMMIT = re.compile(r"^[0-9a-f]{40}$")

#: The source Stage 1 analysis can read (03 §5): the NFS server and client,
#: lockd, SUNRPC, exportfs, and the VFS files a `client_vfs_operation` entry
#: passes through.  A root ending in "/" is a directory; any other root is a
#: path prefix.  Candidates outside these roots are refused at intake.
ANALYSIS_ROOTS = (
    "fs/nfsd/",
    "fs/nfs/",
    "fs/nfs_common/",
    "fs/lockd/",
    "fs/exportfs/",
    "net/sunrpc/",
    "include/linux/nfs",
    "include/linux/sunrpc/",
    "include/linux/lockd/",
    "include/linux/exportfs.h",
    "include/uapi/linux/nfs",
    "include/trace/events/sunrpc.h",
    "fs/attr.c",
    "fs/fcntl.c",
    "fs/file_table.c",
    "fs/ioctl.c",
    "fs/locks.c",
    "fs/namei.c",
    "fs/open.c",
    "fs/read_write.c",
    "fs/readdir.c",
    "fs/remap_range.c",
    "fs/splice.c",
    "fs/stat.c",
    "fs/sync.c",
    "fs/xattr.c",
)


def in_analysis_roots(path: str) -> bool:
    """`path` is normalized; a directory root also matches itself."""
    return any(path == root[:-1] or path.startswith(root)
               if root.endswith("/") else path.startswith(root)
               for root in ANALYSIS_ROOTS)
SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class IntakeRejected(Record):
    reason: str
    detail: str = ""


class SourceTree(Protocol):
    def has_commit(self, commit: str) -> bool: ...

    def read_text(self, commit: str, path: str) -> str | None:
        """The file at `commit`, or None when it is not a file there."""


class GitSourceTree:
    """A kernel checkout read through git plumbing only."""

    def __init__(self, repo: Path) -> None:
        self.repo = Path(repo)

    def _git(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(self.repo), *args],
                              capture_output=True, check=False)

    def has_commit(self, commit: str) -> bool:
        return self._git("cat-file", "-e", f"{commit}^{{commit}}"
                         ).returncode == 0

    def read_text(self, commit: str, path: str) -> str | None:
        kind = self._git("cat-file", "-t", f"{commit}:{path}")
        if kind.returncode != 0 or kind.stdout.strip() != b"blob":
            return None
        out = self._git("cat-file", "blob", f"{commit}:{path}")
        if out.returncode != 0:
            return None
        return out.stdout.decode("utf-8", errors="replace")


def normalized(path: str) -> bool:
    if not path or path.startswith("/") or "\\" in path:
        return False
    parts = path.split("/")
    return all(p not in ("", ".", "..") for p in parts) and \
        PurePosixPath(path).as_posix() == path


def validate(sub: CandidateSubmission, tree: SourceTree,
             candidate_id: str) -> VulnerabilityCandidate | IntakeRejected:
    loc = sub.location
    if not COMMIT.match(sub.kernel_commit):
        return IntakeRejected(reason="commit_not_exact",
                              detail=sub.kernel_commit)
    if not tree.has_commit(sub.kernel_commit):
        return IntakeRejected(reason="commit_not_found",
                              detail=sub.kernel_commit)
    if not normalized(loc.path):
        return IntakeRejected(reason="path_not_normalized", detail=loc.path)
    if not in_analysis_roots(loc.path):
        return IntakeRejected(reason="path_outside_analysis_roots",
                              detail=loc.path)
    text = tree.read_text(sub.kernel_commit, loc.path)
    if text is None:
        return IntakeRejected(reason="path_not_found", detail=loc.path)
    if loc.kind is LocationKind.FUNCTION:
        if not loc.symbol or not SYMBOL.match(loc.symbol):
            return IntakeRejected(reason="symbol_missing",
                                  detail=loc.symbol or "")
        found = find_function(text, loc.symbol)
        if not found:
            return IntakeRejected(reason="symbol_not_found",
                                  detail=loc.symbol)
        if len(found) > 1:
            return IntakeRejected(
                reason="symbol_ambiguous",
                detail=", ".join(f"{a}-{b}" for a, b in found))
        start, end = found[0]
        if (loc.start_line, loc.end_line) not in ((None, None),
                                                  (start, end)):
            return IntakeRejected(reason="range_mismatch",
                                  detail=f"{start}-{end}")
    else:
        if loc.symbol is not None:
            return IntakeRejected(reason="symbol_not_allowed",
                                  detail=loc.symbol)
        start, end = loc.start_line, loc.end_line
        if start is None or end is None or start < 1 or end < start:
            return IntakeRejected(reason="range_invalid",
                                  detail=f"{start}-{end}")
        if end > line_count(text):
            return IntakeRejected(reason="range_outside_file",
                                  detail=f"{start}-{end}")
    return VulnerabilityCandidate(
        candidate_id=candidate_id, kernel_commit=sub.kernel_commit,
        location=CandidateLocation(kind=loc.kind, path=loc.path,
                                   symbol=loc.symbol, start_line=start,
                                   end_line=end))


def source_lines(text: str) -> list[str]:
    """Split on "\\n" only, keeping line ends, as search and Git do.

    ``str.splitlines`` also breaks on form feed, vertical tab and other
    separators, which would shift every later line number.
    """
    lines = text.split("\n")
    kept = [line + "\n" for line in lines[:-1]]
    return kept + [lines[-1]] if lines[-1] else kept


def line_count(text: str) -> int:
    return len(source_lines(text))


_ANNOTATION = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*(\([^(){};]*\))?")


def code_only(text: str) -> str:
    """`text` with comments, string and character literals and
    preprocessor lines (with their continuations) blanked to spaces.
    Newlines stay, so offsets and line numbers are those of `text`.  An
    unterminated comment or literal blanks the rest of the file."""
    out = list(text)
    i, n, bol = 0, len(text), True
    while i < n:
        ch = text[i]
        if ch == "\n":
            bol = True
            i += 1
            continue
        if bol and ch in " \t":
            i += 1
            continue
        if bol and ch == "#":
            j = i
            while j < n and not (text[j] == "\n" and text[j - 1] != "\\"):
                j += 1
            end = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            end = n if j < 0 else j + 2
        elif text.startswith("//", i):
            j = text.find("\n", i)
            end = n if j < 0 else j
        elif ch in "\"'":
            j = i + 1
            while j < n and text[j] != ch and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            end = min(j + 1, n)
        else:
            bol = False
            i += 1
            continue
        for k in range(i, end):
            if out[k] != "\n":
                out[k] = " "
        bol = False
        i = end
    return "".join(out)


def find_function(text: str, symbol: str) -> list[tuple[int, int]]:
    """Every definition of `symbol` in kernel C style, as 1-based
    (start_line, end_line).

    Comments, literals and preprocessor lines are blanked first, so text in
    them never matches.  A definition starts at column 0 outside any brace
    with `symbol(` in it, its parameter list is followed (after optional
    annotations such as `__releases(x)`) by `{`, and it ends at the brace
    that closes that one.  A body in which a line starting with `}` comes
    before that brace (braces split by #ifdef) is not found.  A return-type
    line just above the name is included.  Declarations, macros, calls and
    indented text do not match.  Anything this cannot parse is not found,
    which intake reports, rather than guessed.
    """
    code = code_only(text)
    lines = code.split("\n")
    offsets, pos = [], 0
    for ln in lines:
        offsets.append(pos)
        pos += len(ln) + 1
    # Brace depth at the start of each line.
    depth_at, d = [], 0
    for ln in lines:
        depth_at.append(d)
        d += ln.count("{") - ln.count("}")
    name = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(symbol) + r"\s*\(")
    found = []
    for i, ln in enumerate(lines):
        if not ln or ln[0] in " \t{}" or depth_at[i] != 0:
            continue
        m = name.search(ln)
        if not m:
            continue
        at = offsets[i] + m.end() - 1          # the "("
        depth = 0
        while at < len(code):
            ch = code[at]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            elif ch in "{;":
                break
            at += 1
        if depth != 0:
            continue
        at += 1
        while True:
            while at < len(code) and code[at] in " \t\n":
                at += 1
            if code.startswith("{", at):
                break
            a = _ANNOTATION.match(code, at)
            if not a or a.end() == at:
                at = -1
                break
            at = a.end()
        if at < 0:
            continue
        close = _closing_brace(code, at)
        if close is None:
            continue
        open_line = code.count("\n", 0, at)
        end = code.count("\n", 0, close)
        if any(lines[k].startswith("}") for k in range(open_line + 1, end)):
            continue
        start = i
        prev = lines[i - 1] if i > 0 else ""
        if prev and prev[0] not in " \t{}" and "(" not in prev and \
                not prev.rstrip().endswith((";", ",", "{", "}", ")")):
            start = i - 1
        found.append((start + 1, end + 1))
    return found


def _closing_brace(code: str, at: int) -> int | None:
    """Offset of the `}` that closes the `{` at `at`."""
    depth = 0
    for k in range(at, len(code)):
        if code[k] == "{":
            depth += 1
        elif code[k] == "}":
            depth -= 1
            if depth == 0:
                return k
    return None
