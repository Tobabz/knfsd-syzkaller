#!/usr/bin/env python3
"""Collect NFSD transport PCs separately from request-owned remote KCOV."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Protocol


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
WORKLOAD = HERE / "async-copy-v42-tcp.prog"
MANIFEST = HERE / "manifest.json"
HANDLE = "0x0200000000000001"
STAGES = ("svc_data_ready", "svc_xprt_enqueue", "svc_xprt_dequeue")
GUEST_BINARY = "/opt/frozen-phase9/nfa1-kcov-observer"
GUEST_PREFIX = "/tmp/nfa1-kcov-observe"

for import_root in (ROOT, ROOT / "tools"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

os.environ["KOOV_EXPECTED_CALLS"] = "11"
os.environ["KOOV_CONFLICT_CALL"] = "-1"


class Guest(Protocol):
    def put(self, stage: str, local: Path, remote: str) -> None: ...

    def guest(self, stage: str, command: str) -> subprocess.CompletedProcess[str]: ...


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reach():
    path = ROOT / "tools/run-reach-adapted-window.py"
    spec = importlib.util.spec_from_file_location("nfa1_kcov_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_observer(text: str, meta: str) -> list[int]:
    """Require a stopped, bounded standalone observer, never a managed extra."""
    lines_meta = meta.splitlines()
    if any(not re.fullmatch(r"[a-z]+=[^\n]+", line) for line in lines_meta):
        raise ValueError("malformed observer metadata")
    fields = dict(line.split("=", 1) for line in lines_meta)
    if (len(lines_meta) != 5 or
            set(fields) != {"handle", "capacity", "count", "saturated", "status"}):
        raise ValueError("invalid observer metadata")
    if fields["handle"] != HANDLE or fields["status"] != "stopped":
        raise ValueError("wrong observer handle or incomplete stop")
    capacity, count = int(fields["capacity"]), int(fields["count"])
    if not 0 < capacity or not 0 <= count <= capacity:
        raise ValueError("invalid observer capacity/count")
    if fields["saturated"] not in {"0", "1"} or (count == capacity) != (fields["saturated"] == "1"):
        raise ValueError("invalid observer saturation")
    lines = text.splitlines()
    if len(lines) != count or any(not re.fullmatch(r"0x[0-9a-f]+", line)
                                  or int(line, 16) < 5 for line in lines):
        raise ValueError("truncated or malformed observer PCs")
    return [int(line, 16) - 5 for line in lines]


def _symbolize(vmlinux: Path, pcs: list[int]) -> list[list[str]]:
    unique = sorted(set(pcs))
    if not unique:
        return []
    result = subprocess.run(
        ["llvm-symbolizer", "--inlining", f"--obj={vmlinux}"],
        input="".join(f"0x{pc:x}\n" for pc in unique),
        capture_output=True, text=True, check=True,
    )
    records = [record.splitlines() for record in result.stdout.strip().split("\n\n")]
    if len(records) != len(unique):
        raise ValueError("symbolizer returned the wrong number of PCs")
    return records


def stage_presence(vmlinux: Path, observer_pcs: list[int],
                   managed_pcs: list[int]) -> dict[str, bool]:
    """Symbolize both channels, but never combine their coverage buffers."""
    found = dict.fromkeys((*STAGES, "svc_process"), False)
    for frames in _symbolize(vmlinux, observer_pcs):
        for function, location in zip(frames[::2], frames[1::2]):
            for stage in STAGES:
                if (function == stage or function.startswith(stage + ".")) and (
                    f"/net/sunrpc/{'svcsock.c' if stage == 'svc_data_ready' else 'svc_xprt.c'}:"
                    in location
                ):
                    found[stage] = True
    for frames in _symbolize(vmlinux, managed_pcs):
        for function, location in zip(frames[::2], frames[1::2]):
            if function == "svc_process" and "/net/sunrpc/svc.c:" in location:
                found["svc_process"] = True
    return found


def _managed_pcs(coverage: Path) -> list[int]:
    pcs: list[int] = []
    for path in sorted(coverage.glob("cover_prog*.extra")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not re.fullmatch(r"0x[0-9a-f]+", line):
                raise ValueError(f"malformed managed PC in {path}")
            pcs.append(int(line, 16))
    return pcs


def coverage_complete(mode: str, stages: dict[str, bool],
                      saturated: bool, managed_count: int) -> bool:
    """A full buffer cannot establish which transport stages were absent."""
    return (not saturated and all(stages[stage] for stage in STAGES)
            and (stages["svc_process"] if mode == "on" else managed_count == 0))


class ObservationPlan:
    """Own the guest observer from fixture setup until managed drains finish."""

    def __init__(self, reach, output: Path, binary: Path, vmlinux: Path) -> None:
        self.reach = reach
        self.output = output
        self.binary = binary
        self.vmlinux = vmlinux
        self.counts = {"off": 0, "on": 0}
        self.active = False

    def before_workload(self, vm: Guest, mode: str) -> None:
        self.counts[mode] += 1
        vm.put("observer-copy", self.binary, "/tmp/nfa1-kcov-observer")
        vm.guest("observer-install",
                 "install -m 0755 /tmp/nfa1-kcov-observer " + GUEST_BINARY)
        self.active = True
        vm.guest("observer-start", f"{GUEST_BINARY} start {GUEST_PREFIX}")

    def during_workload(self, vm: Guest, mode: str) -> None:
        del vm, mode

    def after_workload(self, vm: Guest, mode: str) -> None:
        vm.guest("observer-stop", f"{GUEST_BINARY} stop {GUEST_PREFIX}")
        self.active = False
        trial = self.output / f"remote_{mode}" / f"trial_{self.counts[mode]:02d}"
        raw = trial / "nfa1-observer.pcs"
        meta = trial / "nfa1-observer.meta"
        self.reach.pull(vm, "observer-pcs", GUEST_PREFIX + ".pcs", raw)
        self.reach.pull(vm, "observer-meta", GUEST_PREFIX + ".meta", meta)
        metadata = meta.read_text(encoding="utf-8")
        pcs = parse_observer(raw.read_text(encoding="utf-8"), metadata)
        managed = _managed_pcs(trial / "coverage")
        presence = stage_presence(self.vmlinux, pcs, managed)
        saturated = "saturated=1" in metadata.splitlines()
        verdict = {
            "schema": 1, "handle": HANDLE, "scope": "guest-wide, not request-attributed",
            "observer_binary_sha256": _sha256(self.binary),
            "vmlinux_sha256": _sha256(self.vmlinux),
            "observer_pc_records": len(pcs), "managed_pc_records": len(managed),
            "observer_saturated": saturated,
            "stages": presence,
            "assert": coverage_complete(mode, presence, saturated, len(managed)),
        }
        self.reach.write_json(trial / "nfa1-kcov-verdict.json", verdict)
        if not verdict["assert"]:
            raise ValueError("NF-A1 KCOV stages missing, observer saturated, or managed OFF has PCs: "
                             + ", ".join(stage for stage, present in presence.items()
                                         if not present))

    def cleanup(self, vm: Guest, mode: str) -> None:
        del mode
        if self.active:
            vm.guest("observer-cleanup-stop",
                     f"if test -S {GUEST_PREFIX}.sock; then "
                     f"{GUEST_BINARY} stop {GUEST_PREFIX}; fi")
            self.active = False
        vm.guest("observer-cleanup-check", f"test ! -S {GUEST_PREFIX}.sock")


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(add_help=False)
    cli.add_argument("--observer-binary", type=Path)
    own, remaining = cli.parse_known_args(argv)
    reach = _reach()
    args = reach.parse_args(remaining)
    expected = next(program["sha256"] for program in
                    json.loads(MANIFEST.read_text(encoding="utf-8"))["programs"]
                    if program["path"] == WORKLOAD.name)
    if args.workload != WORKLOAD or _sha256(args.workload) != expected:
        raise ValueError("workload differs from the corpus COPY input")
    if (own.observer_binary is None or not own.observer_binary.is_file()
            or not os.access(own.observer_binary, os.X_OK)):
        raise ValueError("observer binary missing or not executable")
    if args.kernel.resolve().parents[3] != args.vmlinux.resolve().parent:
        raise ValueError("kernel and vmlinux are not from the same build root")
    if args.preflight:
        print(f"NF-A1 KCOV READY: {args.output}")
        return 0
    plan = ObservationPlan(reach, args.output, own.observer_binary, args.vmlinux)
    reach.main(remaining, attr_plan=plan)
    print(f"NF-A1 KCOV PASS: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
