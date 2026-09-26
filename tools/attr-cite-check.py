#!/usr/bin/env python3
"""Validate attribution inventory rows and current-kernel source citations."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

ROW_RE = re.compile(r"^\|\s*(B\d{2})\s*\|")
CITE_RE = re.compile(
    r"\[cite:(?P<path>[A-Za-z0-9_./+-]+):(?P<line>[1-9][0-9]*):"
    r"(?P<anchor>[A-Za-z_][A-Za-z0-9_]*):(?P<role>call|assign|name)\]"
)
STATUS: Final = {"attributed", "ownerless", "out-of-fixture"}
SITE_MECHANISMS: Final = {
    "B01": {("net/sunrpc/sched.c", "sunrpc_fuzz_logical_init", "call"), ("net/sunrpc/xprt.c", "fuzz_attributable", "assign")},
    "B02": {("net/sunrpc/svcsock.c", "svc_data_ready", "call"), ("net/sunrpc/svcsock.c", "sunrpc_fuzz_svc_record_received", "call"), ("net/sunrpc/svcsock.c", "rq_kcov_handle", "assign")},
    "B03": {("net/sunrpc/svc.c", "kcov_request_remote_start_checked", "call"), ("net/sunrpc/svc.c", "sunrpc_fuzz_svc_remote_terminal", "call")},
    "B04": {("net/sunrpc/svc_xprt.c", "sunrpc_fuzz_svc_continuation_save", "call"), ("net/sunrpc/svc_xprt.c", "sunrpc_fuzz_svc_continuation_restore", "call"), ("net/sunrpc/fuzz_conn.c", "sunrpc_fuzz_saved_work_grant", "call"), ("net/sunrpc/svc.c", "kcov_request_remote_start_checked", "call")},
    "B05": {("fs/nfsd/nfs4proc.c", "sunrpc_fuzz_svc_continuation_save", "call"), ("fs/nfsd/nfs4proc.c", "sunrpc_fuzz_saved_work_start", "call"), ("fs/nfsd/nfs4proc.c", "sunrpc_fuzz_saved_work_stop", "call")},
    "B06": {("net/sunrpc/svc_xprt.c", "svc_process_bc", "call"), ("net/sunrpc/svc.c", "svc_process_bc", "call"), ("net/sunrpc/svcsock.c", "receive_cb_reply", "call"), ("net/sunrpc/svcsock.c", "sunrpc_fuzz_svc_rqst_reset", "call"), ("net/sunrpc/xprtsock.c", "sunrpc_fuzz_note_record_class", "call")},
    "B07": {("fs/nfsd/nfs4callback.c", "nfsd4_run_cb_work", "call"), ("fs/nfsd/nfs4callback.c", "rpc_call_async", "call")},
    "B08": {("fs/nfsd/nfs4state.c", "nfs4_laundromat", "call"), ("fs/nfsd/nfs4state.c", "queue_delayed_work", "call")},
    "B09": {("fs/nfsd/nfs4recover.c", "nfsd4_cld_grace_start", "call"), ("fs/nfsd/nfs4recover.c", "cld_pipe_upcall", "call")},
    "B10": {("fs/nfsd/filecache.c", "nfsd_file_gc_worker", "call"), ("fs/nfsd/filecache.c", "trace_nfsd_file_gc_removed", "call"), ("fs/nfsd/nfs4state.c", "nfsd4_run_cb", "call"), ("fs/nfsd/nfs4state.c", "nfsd4_state_shrinker_worker", "call")},
    "B11": {("net/sunrpc/fuzz_conn.c", "kcov_request_try_get_child_token", "call"), ("net/sunrpc/fuzz_conn.c", "owner_lane_match", "assign")},
    "B12": {("net/sunrpc/fuzz_conn.c", "sunrpc_fuzz_origin_capture_current", "call"), ("net/sunrpc/fuzz_conn.c", "sunrpc_fuzz_logical_init_auto_finish", "call")},
}


@dataclass(frozen=True, slots=True)
class BoundaryRow:
    row_id: str
    source_line: int
    cells: tuple[str, ...]


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)


def parse_rows(text: str) -> tuple[list[BoundaryRow], list[str]]:
    rows: list[BoundaryRow] = []
    errors: list[str] = []
    seen: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = ROW_RE.match(line)
        if not match:
            continue
        cells = tuple(cell.strip() for cell in line.strip().strip("|").split("|"))
        row_id = match.group(1)
        if row_id in seen:
            errors.append(f"{row_id}: duplicate boundary row at report line {line_number}")
        seen.add(row_id)
        if len(cells) != 9:
            errors.append(
                f"{row_id}: expected 9 columns at report line {line_number}, got {len(cells)}"
            )
            continue
        required = {
            "boundary": cells[1],
            "contexts": cells[2],
            "site": cells[3],
            "fields": cells[4],
            "calls": cells[5],
            "status": cells[6],
            "counters": cells[7],
            "sentinel": cells[8],
        }
        for name, value in required.items():
            if not value or value == "-":
                errors.append(f"{row_id}: empty {name} column")
        if cells[6] not in STATUS:
            errors.append(
                f"{row_id}: invalid status {cells[6]!r}; expected one of {sorted(STATUS)}"
            )
        if not CITE_RE.search(cells[3]):
            errors.append(f"{row_id}: site column has no machine-checkable citation")
        site_mechanisms = {
            (
                citation.group("path"),
                citation.group("anchor"),
                citation.group("role"),
            )
            for citation in CITE_RE.finditer(cells[3])
        }
        expected_mechanisms = SITE_MECHANISMS.get(row_id)
        if expected_mechanisms is None:
            errors.append(f"{row_id}: no site-mechanism policy; add the boundary to checker")
        elif site_mechanisms != expected_mechanisms:
            errors.append(f"{row_id}: site mechanisms {sorted(site_mechanisms)} do not match expected path/anchor/role tuples {sorted(expected_mechanisms)}")
        rows.append(BoundaryRow(row_id, line_number, cells))
    missing_rows = sorted(set(SITE_MECHANISMS) - seen)
    if missing_rows:
        errors.append(f"inventory is missing required rows: {', '.join(missing_rows)}")
    return rows, errors


def safe_source(kernel: Path, relative: str) -> tuple[Path | None, str | None]:
    posix = PurePosixPath(relative)
    if posix.is_absolute() or ".." in posix.parts:
        return None, "citation path must be a relative kernel path without '..'"
    source = kernel.joinpath(*posix.parts)
    try:
        source.relative_to(kernel)
    except ValueError:
        return None, "citation escapes kernel root"
    return source, None


def mechanism_matches(line: str, anchor: str, role: str) -> bool:
    """Return whether an exact source line contains the declared code entity."""
    stripped = line.lstrip()
    if stripped.startswith(("/*", "*", "//")):
        return False
    code = re.sub(r"/\*.*?\*/", "", line)
    code = re.sub(r"//.*$", "", code)
    if role == "call":
        return re.search(rf"\b{re.escape(anchor)}\s*\(", code) is not None
    if role == "assign":
        return re.search(rf"\b{re.escape(anchor)}\b\s*=(?!=)", code) is not None
    if role == "name":
        return re.search(rf"=\s*\"{re.escape(anchor)}\"", code) is not None
    return False


def check_citations(
    text: str, rows: list[BoundaryRow], kernel: Path
) -> tuple[int, list[str]]:
    misses: list[str] = []
    citations = list(CITE_RE.finditer(text))
    malformed_count = text.count("[cite:") - len(citations)
    if malformed_count:
        misses.append(f"document: {malformed_count} malformed citation(s)")

    line_to_row = {row.source_line: row.row_id for row in rows}
    cache: dict[Path, list[str]] = {}
    for citation in citations:
        report_line = text.count("\n", 0, citation.start()) + 1
        row_id = line_to_row.get(report_line, "document")
        relative = citation.group("path")
        requested_line = int(citation.group("line"))
        anchor = citation.group("anchor")
        role = citation.group("role")
        source, path_error = safe_source(kernel, relative)
        label = f"{row_id} {relative}:{requested_line}:{anchor}:{role}"
        if path_error:
            misses.append(f"{label}: {path_error}")
            continue
        assert source is not None
        if not source.is_file():
            misses.append(f"{label}: source file not found")
            continue
        try:
            if source not in cache:
                cache[source] = source.read_text(
                    encoding="utf-8", errors="strict"
                ).splitlines()
            source_lines = cache[source]
        except (OSError, UnicodeError) as exc:
            misses.append(f"{label}: cannot read source: {exc}")
            continue
        if requested_line > len(source_lines):
            misses.append(
                f"{label}: line outside file (file has {len(source_lines)} lines)"
            )
            continue
        if not mechanism_matches(source_lines[requested_line - 1], anchor, role):
            misses.append(
                f"{label}: exact line does not contain the declared {role} mechanism/definition"
            )
    return len(citations), misses


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        fail(f"usage: {Path(argv[0]).name} REPORT KERNEL_ROOT")
        return 2
    report = Path(argv[1])
    kernel = Path(argv[2]).resolve()
    if not report.is_file():
        fail(f"report not found: {report}")
        return 2
    if not kernel.is_dir():
        fail(f"kernel root not found: {kernel}")
        return 2
    try:
        text = report.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        fail(f"cannot read report {report}: {exc}")
        return 2

    rows, row_errors = parse_rows(text)
    citation_count, misses = check_citations(text, rows, kernel)
    for error in (*row_errors, *misses):
        fail(error)
    miss_count = len(row_errors) + len(misses)
    print(
        f"checked {len(rows)} boundary rows and {citation_count} citations: "
        f"{miss_count} misses"
    )
    return 1 if miss_count else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
