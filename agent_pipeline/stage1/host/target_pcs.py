"""Target-PC mapping from the pinned vmlinux.

Remote KCOV records one PC per ``__sanitizer_cov_trace_pc`` call executed,
and ``syz-execprog -coverfile`` writes it as the address of that call
instruction.  So the PCs that can show a target line was reached are the
coverage call sites whose source position is in the target's range:

1. disassemble vmlinux once and keep every ``call __sanitizer_cov_trace_pc``
   address (cached per vmlinux digest);
2. symbolize those addresses with ``addr2line -i``, inline frames included,
   so code inlined into or from the target counts;
3. keep the call sites with a frame in the target file whose line is in
   the intake-resolved ``[start_line, end_line]``.

With ``nokaslr`` the runtime PC is the link address, so no relocation is
applied.  ``check`` reports how many published PCs are call sites, which is
the quick test that the coverage file and this mapping use the same form.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from ...q1 import CandidateTarget, KernelIdentity, TargetPcMapping

METHOD = "kcov-callsite-addr2line-inline.v1"
CALLBACK = "__sanitizer_cov_trace_pc"
_CALL = re.compile(r"^\s*([0-9a-f]+):\s+call\S*\s+[0-9a-f]+ <([^>+]+)>")
_LOCATION = re.compile(r"^(.*):(\d+|\?)(?: \(discriminator \d+\))?$")


@dataclass(frozen=True)
class Frame:
    function: str
    path: str
    line: int | None


def parse_callsites(lines: Iterable[str],
                    callback: str = CALLBACK) -> Iterator[int]:
    """``objdump -d --no-show-raw-insn`` lines -> call-site addresses."""
    for line in lines:
        m = _CALL.match(line)
        if m and m.group(2) == callback:
            yield int(m.group(1), 16)


def iter_addr2line(lines: Iterable[str]) -> Iterator[tuple[int, list[Frame]]]:
    """``addr2line -a -f -i`` output: an address line, then function and
    location pairs, innermost inline frame first."""
    pc: int | None = None
    frames: list[Frame] = []
    function: str | None = None
    for raw in lines:
        line = raw.rstrip("\n")
        if function is None and line.startswith("0x"):
            if pc is not None:
                yield pc, frames
            pc, frames = int(line, 16), []
        elif pc is None:
            raise ValueError(f"unexpected addr2line output: {line[:80]!r}")
        elif function is None:
            function = line
        else:
            m = _LOCATION.match(line)
            if m is None:
                raise ValueError(f"unexpected addr2line location: "
                                 f"{line[:80]!r}")
            frames.append(Frame(function=function, path=m.group(1),
                                line=None if m.group(2) == "?"
                                else int(m.group(2))))
            function = None
    if function is not None:
        raise ValueError("addr2line output ends inside a frame")
    if pc is not None:
        yield pc, frames


def parse_addr2line(text: str) -> dict[int, list[Frame]]:
    return dict(iter_addr2line(text.splitlines()))


def path_matches(frame_path: str, target_path: str) -> bool:
    """addr2line prints build-tree paths; compare repository suffixes."""
    p = frame_path.replace("\\", "/")
    return p == target_path or p.endswith("/" + target_path)


def frame_hits(chain: list[Frame], target: CandidateTarget) -> bool:
    return any(f.line is not None and path_matches(f.path, target.path)
               and target.start_line <= f.line <= target.end_line
               for f in chain)


def select_target_pcs(frames: dict[int, list[Frame]],
                      target: CandidateTarget) -> tuple[int, ...]:
    return tuple(sorted(pc for pc, chain in frames.items()
                        if frame_hits(chain, target)))


def vmlinux_callsites(vmlinux: Path, cache: Path | None,
                      vmlinux_sha256: str,
                      objdump: str = "objdump") -> list[int]:
    if cache is not None:
        cached = cache / f"callsites-{vmlinux_sha256}.json"
        if cached.is_file():
            return json.loads(cached.read_text())
    proc = subprocess.Popen(
        [objdump, "-d", "--no-show-raw-insn", str(vmlinux)],
        stdout=subprocess.PIPE, text=True, bufsize=1 << 20)
    assert proc.stdout is not None
    with proc.stdout:
        sites = sorted(set(parse_callsites(proc.stdout)))
    if proc.wait() != 0:
        raise RuntimeError(f"objdump failed on {vmlinux}")
    if cache is not None:
        cache.mkdir(parents=True, exist_ok=True)
        cached.write_text(json.dumps(sites))
    return sites


def target_callsites(vmlinux: Path, pcs: list[int],
                     target: CandidateTarget,
                     addr2line: str = "addr2line") -> tuple[int, ...]:
    """Symbolize every call site in one addr2line process (DWARF is loaded
    once) and keep the ones in the target, streaming the output."""
    with tempfile.TemporaryFile("w+") as addresses:
        addresses.write("".join(f"{pc:#x}\n" for pc in pcs))
        addresses.seek(0)
        proc = subprocess.Popen(
            [addr2line, "-a", "-f", "-i", "-e", str(vmlinux)],
            stdin=addresses, stdout=subprocess.PIPE, text=True,
            bufsize=1 << 20)
        assert proc.stdout is not None
        with proc.stdout:
            hits = tuple(sorted(pc for pc, chain in
                                iter_addr2line(proc.stdout)
                                if frame_hits(chain, target)))
        if proc.wait() != 0:
            raise RuntimeError(f"addr2line failed on {vmlinux}")
    return hits


def build_mapping(vmlinux: Path, target: CandidateTarget,
                  identity: KernelIdentity, vmlinux_file_sha256: str, *,
                  cache: Path | None = None, objdump: str = "objdump",
                  addr2line: str = "addr2line") -> TargetPcMapping:
    sites = vmlinux_callsites(vmlinux, cache, vmlinux_file_sha256, objdump)
    if not sites:
        raise RuntimeError(f"no {CALLBACK} call sites in {vmlinux}; "
                           "is it a KCOV build?")
    pcs = target_callsites(vmlinux, sites, target, addr2line)
    if not pcs:
        raise RuntimeError(
            f"no coverage call site maps to {target.path}:"
            f"{target.start_line}-{target.end_line}")
    return TargetPcMapping(mapping_method=METHOD, verified=True,
                           target=target, identity=identity, target_pcs=pcs)


def check_pcs(published: Iterable[int], sites: Iterable[int]) -> dict:
    """How the published PCs relate to the coverage call sites.  Call-site
    form should match almost all; return-address form (site + 5 on amd64)
    means the coverage file and the mapping disagree."""
    published = set(published)
    sites = set(sites)
    return {"published": len(published),
            "callsites": len(published & sites),
            "callsite_plus_5": len({pc - 5 for pc in published} & sites)}
