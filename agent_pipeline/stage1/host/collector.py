"""The VM lane collector: the host command behind ``CommandExecutionEngine``.

``python -m agent_pipeline.stage1.host collect --config collector.json
{input} {output}`` boots one guest from the pinned kernel and image, runs
the harness program once on lane 0 with remote KCOV, and writes the
capture the engine seals (see ``../README.md``, host command contract).

Failures are split the same way the Controller splits them:

* the host cannot run the lease at all (a pinned file differs, the
  descriptor lacks ``nokaslr``, QEMU is missing): exit nonzero, which the
  engine records as ``capture_failed``, a runtime failure;
* the guest ran but something failed (no boot, fixture or lane not ready,
  executor error, guest oops): the capture is written with those facts
  false or listed as runtime errors, and the Judge returns INCONCLUSIVE.
"""

from __future__ import annotations

import json
import math
import shlex
import subprocess
import tarfile
import tempfile
import time
import uuid
from pathlib import Path
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field

from ...artifacts import ArtifactStore
from ...data import canonical_json, load_record
from ...hcap import RuntimeSelection
from ...materializer import ExecutionHarnessDescriptor, ReachabilityHarness
from ...q1 import ExecutionCorrelation, KernelIdentity
from ...sealed_q1 import COVERAGE_TYPE, OBSERVATION_ID, OBSERVATION_TYPE
from .kcov import (STATE_COMMAND, STATS_COMMAND, LaneRun, capture_records,
                   fatal_dmesg, lane_state_ok, parse_cover_pcs, parse_stats,
                   unsettled_generations)
from .pins import HostFilePin, PinCache, verify_file
from .vm import GUEST_COMMAND_TIMEOUT_S, Guest, QemuGuest, VmConfig

#: Descriptor build-artifact names the collector boots from.
RUN_FILES = ("bzimage", "vm-image", "lane-script", "syz-executor",
             "syz-execprog")
GUEST_DIR = "/tmp/stage1"
#: ``syz-execprog -gate``: it creates ``GATE.ready`` after the machine check
#: and runs the program once ``GATE.go`` exists (syzkaller patch 0022).
GATE = f"{GUEST_DIR}/gate"
EXEC_LOG = f"{GUEST_DIR}/exec.log"
EXEC_RC = f"{GUEST_DIR}/exec.rc"
POLL_S = 1.0
FIXTURE_POLL_S = 3.0
#: execprog runs one proc, which the executor binds to lane 0.
LANE = 0
LOG_LIMIT = 4 * 1024 * 1024
EXECPROG_EXIT_GRACE_S = 60
EVIDENCE_COMMAND_TIMEOUT_S = 120
RESULT_TYPE = "application/vnd.knfsd.collector-result+json"
LOG_TYPE = "text/plain"


class CollectorError(RuntimeError):
    """The host cannot run this lease; the engine records capture_failed."""


class CollectorConfig(BaseModel):
    """Host paths and timings, written by ``generate`` next to stage1.json."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("stage1-collector.v1",
                                pattern=r"^stage1-collector\.v1$")
    artifact_root: Path
    #: Descriptor build-artifact name -> host file pinned under that name.
    files: dict[str, Path]
    ssh_key: Path
    qemu: str = "qemu-system-x86_64"
    memory_mb: int = Field(4096, ge=512)
    cpus: int = Field(4, ge=1)
    boot_timeout_s: float = Field(300, gt=0)
    fixture_timeout_s: float = Field(180, gt=0)
    grace_s: float = Field(11, ge=0)
    drain_s: float = Field(10, ge=0)
    exec_timeout_s: float = Field(600, gt=0)
    vmlinux_artifact_name: str = "kernel"
    instrumentation_artifact_name: str = "instrumentation"
    pin_cache: Path | None = None

    @classmethod
    def load(cls, path: Path) -> CollectorConfig:
        return cls.model_validate_json(Path(path).read_bytes())


def verify_pins(config: CollectorConfig,
                descriptor: ExecutionHarnessDescriptor) -> dict[str, Path]:
    """Every pinned descriptor artifact with a configured host file must
    match it byte for byte; the files the boot needs must all exist."""
    store = ArtifactStore(config.artifact_root)
    cache = PinCache(config.pin_cache)
    builds = {a.name: a.artifact_ref for a in descriptor.build_artifacts}
    missing = [n for n in (*RUN_FILES, config.vmlinux_artifact_name)
               if n not in builds or n not in config.files]
    if missing:
        raise CollectorError(f"descriptor or collector config lacks: "
                             f"{', '.join(missing)}")
    for name, path in config.files.items():
        if name not in builds:
            raise CollectorError(f"{name} is not a descriptor build artifact")
        pin = load_record(store, builds[name], HostFilePin)
        if pin.name != name:
            raise CollectorError(f"pin for {name} names {pin.name}")
        verify_file(pin, path, cache)
    return dict(config.files)


def guest_cmdline(descriptor: ExecutionHarnessDescriptor,
                  selection: RuntimeSelection, lane_sha256: str) -> str:
    """The approved command line plus the fixture selection.  The fixture
    parameters come from the harness runtime selection, which the
    Materializer already checked against the descriptor."""
    base = descriptor.guest_kernel_command_line.split()
    if "nokaslr" not in base:
        raise CollectorError("descriptor command line lacks nokaslr; this "
                             "collector publishes unrelocated PCs")
    if any(t.startswith("koov.") for t in base):
        raise CollectorError("descriptor command line must not set koov.*")
    extra = ([f"koov.nfs_version={selection.nfs_version}"]
             if selection.fixture_mode == "single"
             else ["koov.nfs_fixture=broad-knfsd"])
    extra.append(f"koov.nfs_trace={1 if selection.trace_mode == 'on' else 0}")
    extra.append(f"koov.lane_sha256={lane_sha256}")
    return " ".join([*base, *extra])


def _checked(guest: Guest, command: str,
             timeout: float = GUEST_COMMAND_TIMEOUT_S) -> str:
    rc, out = guest.run(command, timeout=timeout)
    if rc != 0:
        raise RuntimeError(f"guest rc={rc}: {command}: {out[-500:]}")
    return out


def _fixture_ready(guest: Guest, selection: RuntimeSelection,
                   lane_sha256: str, timeout_s: float,
                   result: dict) -> bool:
    deadline = time.monotonic() + timeout_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            result["fixture_service"] = "timeout"
            return False
        try:
            rc, active = guest.run(
                "systemctl is-active frozen-phase9-fixture.service",
                timeout=min(GUEST_COMMAND_TIMEOUT_S, remaining))
        except subprocess.TimeoutExpired:
            result["fixture_service"] = "timeout"
            return False
        if active.strip() == "active":
            break
        if active.strip() == "failed":
            result["fixture_service"] = active.strip()
            return False
        time.sleep(min(FIXTURE_POLL_S, max(
            0, deadline - time.monotonic())))
    status = json.loads(_checked(
        guest, "/run/frozen-phase9/lane.sh status /tmp/frozen-phase9.manager"))
    result["fixture_status"] = status
    sha = _checked(guest, "sha256sum /run/frozen-phase9/lane.sh").split()[0]
    if sha != lane_sha256:
        return False
    if int(status.get("lane_count", 0)) <= LANE:
        return False
    if selection.fixture_mode == "single" and \
            str(status.get("nfs_version")) != selection.nfs_version:
        return False
    return int(status.get("nfs_trace", 0)) == \
        (1 if selection.trace_mode == "on" else 0)


def _lane_state(guest: Guest) -> str:
    rc, out = guest.run(
        f"ip netns exec f9l{LANE}s nsenter -t 1 -m -- "
        "cat /sys/kernel/debug/sunrpc_fuzz/lane_state")
    return out.strip() if rc == 0 else ""


def execprog_timeout(timeout_s: float, slowdown: int = 1) -> int:
    """Return the shared whole-second guest and host watchdog."""
    if not math.isfinite(timeout_s) or timeout_s <= 0:
        raise ValueError("execprog timeout must be finite and positive")
    if not 1 <= slowdown <= 1000:
        raise ValueError("execprog slowdown must be in [1, 1000]")
    # GNU timeout accepts fractions, but rounding once keeps the guest process
    # watchdog and every host-side wait on exactly the same deadline.
    return math.ceil(timeout_s * slowdown)


def execprog_argv(timeout_s: float, slowdown: int = 1) -> str:
    """Start execprog in the background.  It stops at the gate after the
    machine check; ``EXEC_RC`` holds its exit status once it is done."""
    watchdog_s = execprog_timeout(timeout_s, slowdown)
    argv = [f"{GUEST_DIR}/syz-execprog",
            f"-executor={GUEST_DIR}/syz-executor", "-os=linux",
            "-arch=amd64", "-vmarch=amd64", "-sandbox=none", "-procs=1",
            "-repeat=1", "-threaded=false", "-cover=true",
            "-coverfile=/tmp/cov/cover", "-remote-cover=true",
            "-disable=all", "-debug", "-vv=1", f"-slowdown={slowdown}",
            f"-gate={GATE}", f"{GUEST_DIR}/program.syz"]
    body = (f"timeout --kill-after={EXECPROG_EXIT_GRACE_S} "
            f"{watchdog_s} {shlex.join(argv)} > {EXEC_LOG} 2>&1; "
            f"echo $? > {EXEC_RC}")
    return (f"rm -rf /tmp/cov {GATE}.ready {GATE}.go {EXEC_RC}; "
            f"mkdir -p /tmp/cov; setsid nohup sh -c {shlex.quote(body)} "
            "< /dev/null > /dev/null 2>&1 &")


def _wait_execprog(guest: Guest, want_ready: bool, deadline: float,
                   sleep: Callable[[float], None]) -> str:
    """Wait against one deadline shared by both sides of the gate."""
    probe = (f"if [ -e {EXEC_RC} ]; then echo exited; "
             + (f"elif [ -e {GATE}.ready ]; then echo ready; " if want_ready
                else "") + "fi")
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "timeout"
        try:
            _, out = guest.run(
                probe, timeout=min(GUEST_COMMAND_TIMEOUT_S, remaining))
        except subprocess.TimeoutExpired:
            return "timeout"
        if out.strip() in ("ready", "exited"):
            return out.strip()
        sleep(min(POLL_S, max(0, deadline - time.monotonic())))


def _deadline_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("execprog watchdog expired")
    return min(GUEST_COMMAND_TIMEOUT_S, remaining)


def run_lane(guest: Guest, files: dict[str, Path], program: Path,
             selection: RuntimeSelection, lane_sha256: str,
             config: CollectorConfig, out: Path,
             result: dict, sleep: Callable[[float], None] = time.sleep,
             exec_slowdown: int = 1,
             ) -> LaneRun:
    """Boot, check the fixture and lane, run the program, collect.  Each
    fact is set only after its step succeeded; an exception stops the run
    and is kept as a runtime error."""
    run = LaneRun()
    try:
        guest.start()
        run.boot_ok = True
        _checked(guest, "mountpoint -q /sys/kernel/debug || "
                        "mount -t debugfs none /sys/kernel/debug")
        if not _fixture_ready(guest, selection, lane_sha256,
                              config.fixture_timeout_s, result):
            run.runtime_errors.append("fixture_not_ready")
            return run
        run.fixture_ok = True
        state = _lane_state(guest)
        result["lane_state_before"] = state
        if not lane_state_ok(state):
            run.runtime_errors.append("lane_not_ready")
            return run
        run.lane_ok = True
        _checked(guest, f"mkdir -p {GUEST_DIR}")
        guest.put(files["syz-executor"], f"{GUEST_DIR}/syz-executor")
        guest.put(files["syz-execprog"], f"{GUEST_DIR}/syz-execprog")
        guest.put(program, f"{GUEST_DIR}/program.syz")
        _checked(guest, f"chmod 0755 {GUEST_DIR}/syz-executor "
                        f"{GUEST_DIR}/syz-execprog")
        sleep(config.grace_s)
        timeout_s = execprog_timeout(config.exec_timeout_s, exec_slowdown)
        _checked(guest, execprog_argv(config.exec_timeout_s, exec_slowdown))
        exec_deadline = (time.monotonic() + timeout_s
                         + EXECPROG_EXIT_GRACE_S)
        gate = _wait_execprog(guest, True, exec_deadline, sleep)
        result["execprog_gate"] = gate
        if gate == "ready":
            # execprog has finished the machine check and waits: the
            # window opens here, so only the program's generation is in it.
            state = _checked(guest, STATE_COMMAND,
                             timeout=_deadline_timeout(exec_deadline))
            result["generations_before"] = state
            busy = unsettled_generations(state)
            raw_before = _checked(guest, STATS_COMMAND,
                                  timeout=_deadline_timeout(exec_deadline))
            result["stats_before"] = raw_before
            if busy:
                run.runtime_errors.append(
                    f"generation_unsettled_at_window_start:{busy[0][:200]}")
            else:
                run.stats_before = parse_stats(raw_before)
                run.collection_started = bool(run.stats_before)
            _checked(guest, f"touch {GATE}.go",
                     timeout=_deadline_timeout(exec_deadline))
            done = _wait_execprog(guest, False, exec_deadline, sleep)
        else:
            done = gate
        rc_text = _checked(guest, f"cat {EXEC_RC} 2>/dev/null || true").strip()
        result["execprog"] = f"{done}:rc={rc_text}"
        run.runner_completed = gate == "ready" and done == "exited" \
            and rc_text == "0"
        if not run.runner_completed:
            stage = "before_gate" if gate != "ready" else "after_gate"
            run.runtime_errors.append(
                f"execprog_failed_{stage}:{done}:rc={rc_text}")
        _, log = guest.run(
            f"cat {EXEC_LOG}", timeout=EVIDENCE_COMMAND_TIMEOUT_S)
        _write_log(out / "executor.log", log)
        sleep(config.drain_s)
        raw_after = _checked(guest, STATS_COMMAND)
        result["stats_after"] = raw_after
        run.stats_after = parse_stats(raw_after)
        state = _lane_state(guest)
        result["lane_state_after"] = state
        if not lane_state_ok(state):
            run.runtime_errors.append("lane_unhealthy_after_program")
        _, dmesg = guest.run(
            "dmesg", timeout=EVIDENCE_COMMAND_TIMEOUT_S)
        _write_log(out / "dmesg.log", dmesg)
        for line in fatal_dmesg(dmesg)[:16]:
            run.runtime_errors.append(f"guest: {line.strip()[:200]}")
        _collect_cover(guest, run, result)
    except Exception as exc:     # the guest side failed; keep the facts
        run.runtime_errors.append(f"{type(exc).__name__}: {str(exc)[:300]}")
    return run


def _collect_cover(guest: Guest, run: LaneRun, result: dict) -> None:
    _checked(guest, "tar -C /tmp/cov -cf /tmp/cov.tar .",
             timeout=EVIDENCE_COMMAND_TIMEOUT_S)
    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / "cov.tar"
        guest.get("/tmp/cov.tar", local)
        with tarfile.open(local) as tf:
            members = {Path(m.name).name: m for m in tf.getmembers()
                       if m.isfile()}
            result["cover_files"] = sorted(members)
            meta = [n for n in members if n.endswith(".meta")]
            extra = [n for n in members if n.endswith(".extra")]
            if len(meta) > 1 or len(extra) > 1:
                raise RuntimeError("more than one program's coverage")
            run.collection_completed = bool(meta)
            if extra:
                run.extra_present = True
                data = tf.extractfile(members[extra[0]]).read()
                run.pcs = parse_cover_pcs(data.decode("ascii"))
            if meta:
                result["cover_meta"] = tf.extractfile(
                    members[meta[0]]).read().decode("ascii", "replace")


def _write_log(path: Path, text: str) -> None:
    data = text.encode("utf-8", "replace")
    if len(data) > LOG_LIMIT:
        data = b"[truncated]\n" + data[-LOG_LIMIT:]
    path.write_bytes(data)


def _tail(path: Path) -> bytes:
    if not path.is_file():
        return b""
    data = path.read_bytes()
    return data if len(data) <= LOG_LIMIT else \
        b"[truncated]\n" + data[-LOG_LIMIT:]


def collect(config: CollectorConfig, inp: Path, out: Path, *,
            guest_factory: Callable[[VmConfig], Guest] = QemuGuest,
            sleep: Callable[[float], None] = time.sleep) -> dict:
    execution = json.loads((inp / "execution.json").read_text())
    harness = ReachabilityHarness.model_validate_json(
        (inp / "harness.json").read_bytes())
    descriptor = ExecutionHarnessDescriptor.model_validate_json(
        (inp / "descriptor.json").read_bytes())
    if harness.execution_harness_id != execution["execution_harness_id"]:
        raise CollectorError("harness and execution disagree")
    files = verify_pins(config, descriptor)
    store = ArtifactStore(config.artifact_root)
    builds = {a.name: a.artifact_ref for a in descriptor.build_artifacts}
    lane_pin = load_record(store, builds["lane-script"], HostFilePin)
    selection = harness.runtime_selection
    cmdline = guest_cmdline(descriptor, selection, lane_pin.sha256)
    identity = KernelIdentity(
        execution_harness_id=execution["execution_harness_id"],
        kernel_commit=descriptor.kernel_commit,
        instrumentation_sha256=builds[config.instrumentation_artifact_name],
        vmlinux_sha256=builds[config.vmlinux_artifact_name],
        kaslr_enabled=False, kaslr_offset=0)
    vm_instance_id = (f"{execution['task_id']}.g{execution['lease_generation']}"
                      f".{uuid.uuid4().hex[:8]}")
    correlation = ExecutionCorrelation(
        job_id=execution["job_id"], task_id=execution["task_id"],
        execution_harness_id=execution["execution_harness_id"],
        vm_instance_id=vm_instance_id, lane=LANE, generation_id=1)
    console = out / "console.log"
    guest = guest_factory(VmConfig(
        qemu=config.qemu, bzimage=files["bzimage"], image=files["vm-image"],
        lane_dir=files["lane-script"].parent, ssh_key=config.ssh_key,
        cmdline=cmdline, console_log=console, memory_mb=config.memory_mb,
        cpus=config.cpus, boot_timeout_s=config.boot_timeout_s))
    result: dict = {"schema_version": "stage1-collector-result.v1",
                    "vm_instance_id": vm_instance_id, "cmdline": cmdline,
                    "runtime_selection": selection.model_dump(mode="json")}
    started = time.time_ns()
    try:
        run = run_lane(guest, files, inp / "program.syz", selection,
                       lane_pin.sha256, config, out, result, sleep)
    finally:
        guest.stop()
    result["elapsed_ns"] = time.time_ns() - started
    result["facts"] = {k: getattr(run, k) for k in (
        "boot_ok", "fixture_ok", "lane_ok", "runner_completed",
        "collection_started", "collection_completed", "extra_present")}
    result["published_pc_count"] = len(run.pcs)
    result["runtime_errors"] = run.runtime_errors
    observation, coverage = capture_records(
        run, candidate_id=harness.candidate_id, identity=identity,
        correlation=correlation, trace_mode=selection.trace_mode)
    (out / "reachability.json").write_bytes(observation)
    (out / "coverage.json").write_bytes(coverage)
    (out / "collector-result.json").write_bytes(canonical_json(result))
    (out / "console.log").write_bytes(_tail(console))
    artifacts = [
        {"identity": OBSERVATION_ID, "type": OBSERVATION_TYPE,
         "path": "reachability.json"},
        {"identity": "coverage", "type": COVERAGE_TYPE,
         "path": "coverage.json"},
        {"identity": "collector-result", "type": RESULT_TYPE,
         "path": "collector-result.json"},
        {"identity": "console-log", "type": LOG_TYPE, "path": "console.log"}]
    for name in ("executor.log", "dmesg.log"):
        if (out / name).is_file():
            artifacts.append({"identity": name.removesuffix(".log") + "-log",
                              "type": LOG_TYPE, "path": name})
    (out / "capture.json").write_text(json.dumps({
        "vm_instance_id": vm_instance_id, "lane": LANE,
        "generation_id": correlation.generation_id,
        "artifacts": artifacts}, indent=1))
    return result
