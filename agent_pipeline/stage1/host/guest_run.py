"""One program in a fresh guest, the way ``collect`` boots it, without the
service: the runs of a Harness Generation validation (07 §5.2) and of a
promotion probe campaign (07 §5.3)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ...artifacts import ArtifactStore
from ...data import load_record
from ...hcap import RuntimeSelection
from ...materializer import ExecutionHarnessDescriptor
from .collector import CollectorConfig, crash_report, guest_cmdline, run_lane
from .kcov import LaneRun
from .pins import HostFilePin
from .vm import QemuGuest, VmConfig

#: The lane facts a run reports.
FACTS = ("boot_ok", "fixture_ok", "lane_ok", "runner_completed",
         "collection_started", "collection_completed", "extra_present")
#: The facts a booted run needs before its result is the program's.
CLEAN = ("fixture_ok", "lane_ok", "runner_completed", "collection_completed")


@dataclass
class GuestRun:
    lane: LaneRun
    crash: dict | None
    console: Path

    @property
    def facts(self) -> dict[str, bool]:
        return {k: getattr(self.lane, k) for k in FACTS}

    @property
    def clean(self) -> bool:
        return all(getattr(self.lane, k) for k in CLEAN)


def run_program(program: Path, selection: RuntimeSelection,
                descriptor: ExecutionHarnessDescriptor,
                collector: CollectorConfig, files: dict[str, Path], out: Path,
                *, guest_factory: Callable = QemuGuest,
                sleep: Callable[[float], None] = time.sleep) -> GuestRun:
    """Boot ``descriptor``'s files, run ``program`` under ``selection`` and
    collect into ``out``.  Raises ``CollectorError`` when the selection has
    no command line."""
    out.mkdir(parents=True)
    builds = {a.name: a.artifact_ref for a in descriptor.build_artifacts}
    lane = load_record(ArtifactStore(collector.artifact_root),
                       builds["lane-script"], HostFilePin)
    cmdline = guest_cmdline(descriptor, selection, lane.sha256)
    console = out / "console.log"
    guest = guest_factory(VmConfig(
        qemu=collector.qemu, bzimage=files["bzimage"],
        image=files["vm-image"], lane_dir=files["lane-script"].parent,
        ssh_key=collector.ssh_key, cmdline=cmdline, console_log=console,
        memory_mb=collector.memory_mb, cpus=collector.cpus,
        boot_timeout_s=collector.boot_timeout_s, accel=collector.accel))
    result: dict = {}
    try:
        lane_run = run_lane(guest, files, program, selection, lane.sha256,
                            collector, out, result, sleep,
                            exec_slowdown=collector.exec_slowdown)
    finally:
        guest.stop()
    crash = crash_report(out, console, descriptor)
    return GuestRun(lane=lane_run, console=console,
                    crash=None if crash is None
                    else crash.model_dump(mode="json"))
