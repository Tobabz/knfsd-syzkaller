"""Real KVM host command for Stage 2 gate, campaign and replay steps.

The engine supplies immutable inputs and seals only atomically renamed segment
directories.  This module owns the mutable host side: target-mode lane
templates, journal sockets, QEMU/syz-manager processes and evidence capture.
Guest output never supplies VM identity, collection completeness or Q2 host
facts.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shlex
import shutil
import signal
import struct
import subprocess
import tempfile
import time
import uuid
import zlib
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..admission import CallAdmissionProfile
from ..artifacts import ArtifactStore
from ..contracts import Sanitizer
from ..controller.store import Store
from ..data import canonical_json, load_record, parse_json
from ..evidence import ExecutionCorrelation as EvidenceCorrelation
from ..hcap import HcapCatalog, layout_refusals
from ..journal_sink import (CHANNEL_CLOSE_TIMEOUT_S, SEGMENT_SUFFIX,
                            ChannelIdentity, ChannelServer, HostJournal)
from ..materializer import (ExecutionHarnessDescriptor, ReachabilityHarness,
                            descriptor_id)
from ..q1 import ExecutionCorrelation, KernelIdentity
from ..q2 import Q2CollectionWindow
from ..qemu_accel import Accel, accel_of
from ..replay_runner import (PlanError, parse_crash_context,
                             parse_execprog_barriers)
from ..sealed_q1 import COVERAGE_TYPE, OBSERVATION_ID, OBSERVATION_TYPE, PublishedCoverage
from ..sealed_q2 import (CONSOLE_LOG_TYPE, MANAGER_REPORT_TYPE, Q2_EVIDENCE_ID,
                         Q2_EVIDENCE_TYPE, SealedArtifactRef, SealedQ2Evidence)
from ..stage1.host.collector import (EVIDENCE_COMMAND_TIMEOUT_S,
                                     EXECPROG_EXIT_GRACE_S, POLL_S,
                                     CollectorConfig, GUEST_DIR, _checked,
                                     _collect_cover, _deadline_timeout,
                                     _fixture_ready, _wait_execprog,
                                     execprog_argv, execprog_timeout, run_lane,
                                     verify_pins)
from ..stage1.host.kcov import LaneRun, capture_records
from ..stage1.host.pins import HostFilePin, PinCache, verify_file
from ..stage1.host.vm import (GUEST_COMMAND_TIMEOUT_S,
                              GUEST_TRANSFER_TIMEOUT_S, VM_STOP_TIMEOUT_S,
                              Guest, QemuGuest, VmConfig)
from .evidence import (CRASH_LOG_ID, CRASH_LOG_TYPE, EXECPROG_TYPE,
                       GENERATION_COVERAGE_PREFIX, GENERATION_COVERAGE_TYPE,
                       GENERATION_EXECUTION_PREFIX, GENERATION_EXECUTION_TYPE,
                       GenerationExecution,
                       JOURNAL_TYPE, NEUTRAL_COVERAGE_ID,
                       NEUTRAL_COVERAGE_TYPE, NEUTRAL_EXECPROG_ID,
                       REPLAY_EXECPROG_ID, SCENARIO_EXECPROG_ID,
                       journal_identity)
from kcsan_pipeline import ProgramPolicyPipeline


class Stage2StepError(RuntimeError):
    """The trusted host could not produce one complete Stage 2 segment."""


class _EvidenceSealDeadline(Stage2StepError):
    """The host exhausted the reserved evidence-finalization window."""


@dataclass
class _EvidenceSealState:
    deadline: float
    published: bool = False
    cleanup_allowed: bool = False


class _Execution(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    job_id: str
    task_id: str
    step: Literal["gate", "campaign", "replay"]
    harness_ref: str
    execution_harness_id: str
    lease_generation: int
    compiled_ref: str
    rule_set_id: str
    gate_repetitions: int | None
    campaign_id: str | None
    crash_bundle_ref: str | None
    state_dir: str | None = None


class NfsProxyExecution(BaseModel):
    """Patch series' one-file-per-program syz-manager spool record."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["knfsd-nfs-proxy-execution.v2"]
    vm: int = Field(ge=0)
    lane: int = Field(ge=0, le=63)
    execution_id: int
    campaign: bool
    program_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    generation: int = Field(ge=0, le=2**64 - 1)
    program_digest: str = Field(pattern=r"^(?:[0-9a-f]{64})?$")
    activation: str
    activation_status: int = Field(ge=0, le=2**32 - 1)
    deactivation: str
    deactivation_status: int = Field(ge=0, le=2**32 - 1)
    executed: bool
    lease_cleared: bool
    hanged: bool
    error: str = Field(max_length=4096)
    pcs: tuple[Annotated[int, Field(ge=1, le=2**64 - 1)], ...] = Field(
        max_length=1 << 20)


CampaignMode = Literal["fuzz", "proxy_only"]
CAMPAIGN_MODES = ("fuzz", "proxy_only")


@dataclass(frozen=True)
class StepOptions:
    #: The manager config; None when ``variant_managers`` picks one.
    manager: Path | None
    collector: Path
    campaign_executions: int = 96
    campaign_timeout_s: float = 1800
    manager_stop_timeout_s: float = 45
    #: None takes the collector's ``exec_slowdown`` (TCG hosts scale it).
    exec_slowdown: int | None = None
    #: (sanitizer, manager config) pairs of a host with several variants
    #: (#81 D10): a lease runs the manager of its descriptor's sanitizer.
    variant_managers: tuple[tuple[Sanitizer, Path], ...] = ()
    #: ``fuzz``: syz-manager mutates programs and the Proxy applies the rule
    #: set (01 §8).  ``proxy_only``: the manager replays the approved
    #: program unchanged and only the Proxy mutates, so every execution
    #: belongs to one program.
    campaign_mode: CampaignMode = "fuzz"

    def __post_init__(self) -> None:
        if self.campaign_mode not in CAMPAIGN_MODES:
            raise ValueError(
                f"campaign_mode must be one of {sorted(CAMPAIGN_MODES)}")
        if (self.manager is None) == (not self.variant_managers):
            raise ValueError("give one manager or variant managers")
        sanitizers = [sanitizer for sanitizer, _ in self.variant_managers]
        if len(set(sanitizers)) != len(sanitizers):
            raise ValueError("a sanitizer has two variant managers")
        if not 1 <= self.campaign_executions <= 96:
            raise ValueError("campaign_executions must be in [1, 96]")
        if (not all(math.isfinite(value) for value in (
                self.campaign_timeout_s, self.manager_stop_timeout_s))
                or self.campaign_timeout_s <= 0
                or self.manager_stop_timeout_s <= 0):
            raise ValueError("campaign timeouts must be finite and positive")
        if self.exec_slowdown is not None and \
                not 1 <= self.exec_slowdown <= 1000:
            raise ValueError("exec_slowdown must be in [1, 1000]")


MAX_JOURNAL_CHANNELS = 64
MANAGER_SIGNAL_TIMEOUT_S = 10
ARTIFACT_SEAL_RESERVE_S = 300
# One alarm covers the worst-case sequential channel joins and every
# subsequent read, fsync and atomic publication operation.
EVIDENCE_SEAL_RESERVE_S = (
    MAX_JOURNAL_CHANNELS * CHANNEL_CLOSE_TIMEOUT_S
    + ARTIFACT_SEAL_RESERVE_S
)


@dataclass(frozen=True)
class Stage2TimeoutBudget:
    """Worst-case bounded wall time for each Stage 2 lease type."""

    gate_repetition_s: float
    gate_s: float
    replay_s: float
    campaign_s: float

    @property
    def required_s(self) -> float:
        return max(self.gate_s, self.replay_s, self.campaign_s)


def stage2_timeout_budget(
    collector: CollectorConfig, *, exec_slowdown: int,
    gate_repetitions: int, campaign_timeout_s: float,
    manager_stop_timeout_s: float,
) -> Stage2TimeoutBudget:
    """Mirror every explicit timeout on the gate, replay and campaign paths."""
    if type(gate_repetitions) is not int or gate_repetitions < 1:
        raise ValueError("gate repetitions must be a positive integer")
    values = {
        "boot": collector.boot_timeout_s,
        "fixture": collector.fixture_timeout_s,
        "grace": collector.grace_s,
        "drain": collector.drain_s,
        "campaign": campaign_timeout_s,
        "manager stop": manager_stop_timeout_s,
    }
    if any(not math.isfinite(value) or value < 0
           for value in values.values()):
        raise ValueError("Stage 2 timeout inputs must be finite and non-negative")
    if campaign_timeout_s <= 0 or manager_stop_timeout_s <= 0:
        raise ValueError("campaign timeouts must be positive")

    direct = execprog_timeout(collector.exec_timeout_s, exec_slowdown)
    # Gate polling and the guest's GNU timeout share this one process window.
    direct_gate = direct + EXECPROG_EXIT_GRACE_S + POLL_S
    vm_close = 2 * VM_STOP_TIMEOUT_S
    # Channel shutdown is part of the single evidence reserve.  Keeping a
    # separate allowance here would let close/fsync run before the hard seal
    # deadline starts.
    segment_close = vm_close + EVIDENCE_SEAL_RESERVE_S

    # Scenario: 10 ordinary SSH commands, three evidence commands, three
    # uploads and one coverage download. Commands issued while execprog is
    # running are capped by direct_gate and therefore are not counted twice.
    scenario = (
        collector.boot_timeout_s + collector.fixture_timeout_s
        + collector.grace_s + collector.drain_s + direct_gate
        + 10 * GUEST_COMMAND_TIMEOUT_S
        + 3 * EVIDENCE_COMMAND_TIMEOUT_S
        + 4 * GUEST_TRANSFER_TIMEOUT_S
    )
    # Neutral: launch/result SSH, log/tar evidence, one upload/download.
    neutral = (
        collector.drain_s + direct_gate
        + 2 * GUEST_COMMAND_TIMEOUT_S
        + 2 * EVIDENCE_COMMAND_TIMEOUT_S
        + 2 * GUEST_TRANSFER_TIMEOUT_S
    )
    gate_repetition = scenario + neutral + segment_close

    # Replay has mount/status/hash/mkdir/chmod SSH and three uploads.
    replay = (
        collector.boot_timeout_s + collector.fixture_timeout_s + direct
        + 5 * GUEST_COMMAND_TIMEOUT_S
        + 3 * GUEST_TRANSFER_TIMEOUT_S + segment_close
    )
    # A failure in the first manager stop can enter finally and retry cleanup.
    manager_close = 2 * (manager_stop_timeout_s
                         + 2 * MANAGER_SIGNAL_TIMEOUT_S)
    campaign = (campaign_timeout_s + manager_close
                + EVIDENCE_SEAL_RESERVE_S)
    budget = Stage2TimeoutBudget(
        gate_repetition_s=gate_repetition,
        gate_s=gate_repetition * gate_repetitions,
        replay_s=replay, campaign_s=campaign)
    if not all(math.isfinite(value) for value in (
            budget.gate_s, budget.replay_s, budget.campaign_s)):
        raise ValueError("Stage 2 timeout budget is too large")
    return budget


def _deadline_value(deadline: float | _EvidenceSealState) -> float:
    return (deadline.deadline
            if isinstance(deadline, _EvidenceSealState) else deadline)


def _check_evidence_deadline(deadline: float | _EvidenceSealState) -> None:
    """Never publish evidence after consuming its supervisor reserve."""
    value = _deadline_value(deadline)
    if not math.isfinite(value) or time.monotonic() >= value:
        raise _EvidenceSealDeadline("evidence sealing deadline expired")


@contextmanager
def _evidence_seal_window(output: Path, index: int, *,
                          reserve_s: float = EVIDENCE_SEAL_RESERVE_S):
    """Bound channel close and sealing without revoking a publication."""
    if not math.isfinite(reserve_s) or reserve_s <= 0:
        raise ValueError("evidence sealing reserve must be finite and positive")
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    if previous_timer[0] > 0 or previous_timer[1] > 0:
        raise Stage2StepError("evidence sealing requires an unused host alarm")
    if signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK, set()):
        raise Stage2StepError(
            "evidence sealing requires an unblocked host alarm")

    segments = output / "segments"
    temporary = segments / f".{index:06d}.tmp"
    final = segments / f"{index:06d}"

    def expired(unused_signum, unused_frame) -> None:
        raise _EvidenceSealDeadline("evidence sealing deadline expired")

    try:
        previous_handler = signal.signal(signal.SIGALRM, expired)
    except ValueError as exc:
        raise Stage2StepError(
            "evidence sealing must run on the host main thread") from exc
    state = _EvidenceSealState(time.monotonic() + reserve_s)
    try:
        signal.setitimer(signal.ITIMER_REAL, reserve_s)
        try:
            if temporary.exists() or final.exists():
                raise Stage2StepError("evidence segment path already exists")
            state.cleanup_allowed = True
            yield state
            if not state.published:
                _check_evidence_deadline(state)
        except BaseException:
            # A timed-out filesystem operation must not be followed by an
            # unbounded recursive cleanup after the alarm has fired.  Before
            # the deadline, cleanup remains protected by the same timer; after
            # it, an uncommitted dot-directory may be left for lease cleanup.
            # Never remove the final name: rename may have committed just
            # before Python dispatched the deadline exception.
            if (state.cleanup_allowed and not state.published
                    and time.monotonic() < state.deadline):
                try:
                    shutil.rmtree(temporary, ignore_errors=True)
                except _EvidenceSealDeadline:
                    raise
                except BaseException:
                    pass
            raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


@dataclass(frozen=True)
class _Artifact:
    identity: str
    type: str
    data: bytes


@dataclass(frozen=True)
class _Inputs:
    root: Path
    execution: _Execution
    harness: ReachabilityHarness
    descriptor: ExecutionHarnessDescriptor
    collector: CollectorConfig
    manager: dict[str, Any]
    files: dict[str, Path]
    rules: bytes
    lane_sha256: str
    cmdline: str
    lanes: int

    def correlation(self, vm: str, lane: int, generation: int) -> ExecutionCorrelation:
        return ExecutionCorrelation(
            job_id=self.execution.job_id, task_id=self.execution.task_id,
            execution_harness_id=self.execution.execution_harness_id,
            vm_instance_id=vm, lane=lane, generation_id=max(1, generation))


# KCSAN reports are non-fatal signals, not proof that the guest VM stopped.
# Keep them in campaign report detection, but out of the fatal-console test.
_CRASH = re.compile(
    rb"BUG:(?![ \t]+KCSAN:)|KASAN:|kernel BUG|Kernel panic|Oops:|general protection fault")
_KCSAN_REPORT = re.compile(rb"BUG:[ \t]+KCSAN:")


def _campaign_report_state(reports: list[Path], crash_log: Path | None,
                           console: bytes) -> tuple[bool, bool]:
    """Return (report_seen, guest_crashed) without conflating the two.

    syz-manager saves non-fatal sanitizer reports under ``crashes/`` too.
    Only a fatal signature in the host-captured console establishes the
    guest-crashed termination; a report or crash-log artifact alone does not.
    """
    guest_crashed = bool(_CRASH.search(console))
    report_seen = bool(reports or crash_log is not None or guest_crashed or
                       _KCSAN_REPORT.search(console))
    return report_seen, guest_crashed


def _object(path: Path) -> dict[str, Any]:
    value = parse_json(path.read_bytes())
    if not isinstance(value, dict):
        raise Stage2StepError(f"{path.name} is not a JSON object")
    return value


def _journal_lane_count(vm: dict[str, Any], procs: int, *,
                        accel: Accel = "kvm") -> int:
    qemu_args = vm.get("qemu_args")
    if not isinstance(qemu_args, str):
        raise Stage2StepError("manager VM has no QEMU arguments")
    if accel_of(qemu_args) != accel:
        raise Stage2StepError(
            f"manager VM does not run under the collector's {accel}")
    names = [
        part.removeprefix("name=nfsp-journal-")
        for token in qemu_args.split()
        for part in token.split(",")
        if part.startswith("name=nfsp-journal-")
    ]
    if not names or any(not name.isdecimal() for name in names):
        raise Stage2StepError("manager VM has malformed journal channels")
    lanes = [int(name, 10) for name in names]
    if len(lanes) != len(set(lanes)) or max(lanes) >= 64:
        raise Stage2StepError("manager VM has duplicate or out-of-range journal channels")
    expected = set(range(max(lanes) + 1))
    if set(lanes) != expected:
        raise Stage2StepError("manager VM journal channels are not contiguous")
    if not set(range(procs)).issubset(expected):
        raise Stage2StepError("manager VM lacks journal channels for active procs")
    return len(expected)


def _required_path(value: dict[str, Any], key: str, *, label: str) -> Path:
    raw = value.get(key)
    if not isinstance(raw, str) or not raw:
        raise Stage2StepError(f"{label} lacks {key}")
    return Path(raw)


_SYZKALLER_FILES = ("syz-manager", "syz-execprog", "syz-executor")


def _staged_manager(manager: dict[str, Any], collector: CollectorConfig,
                    files: dict[str, Path]) -> dict[str, Any]:
    """A staged harness (07 §5.2) boots the files its validation staged
    under the collector's ``staged_files``; ``verify_pins`` chose them.
    Point the manager at those files, so ``_manager_assets`` sees the
    harness's pins.  syz-manager finds its binaries under one ``syzkaller``
    directory: a staged one gets a directory of links to the pinned files,
    named by them, beside the staged files."""
    root = collector.staged_files
    if root is None:
        return manager
    staged = {name: path for name, path in files.items()
              if path.is_relative_to(root)}
    if not staged:
        return manager
    manager = json.loads(json.dumps(manager))
    vm = manager.get("vm")
    if not isinstance(vm, dict):
        raise Stage2StepError("manager must configure one qemu VM")
    for name, path in staged.items():
        if name == "bzimage":
            vm["kernel"] = str(path)
        elif name == "vm-image":
            manager["image"] = str(path)
        elif name in ("kernel", "lane-script"):
            wanted = "vmlinux" if name == "kernel" else "lane.sh"
            if path.name != wanted:
                raise Stage2StepError(
                    f"staged {name} is not named {wanted}")
            manager["kernel_obj" if name == "kernel"
                    else "workdir_template"] = str(path.parent)
    if staged.keys() & set(_SYZKALLER_FILES):
        if any(name not in files for name in _SYZKALLER_FILES):
            raise Stage2StepError("collector lacks the syzkaller binaries")
        target = manager.get("target")
        if not isinstance(target, str) or target.count("/") != 1:
            raise Stage2StepError(f"unsupported manager target: {target}")
        manager["syzkaller"] = str(_syzkaller_links(
            root, target.replace("/", "_"),
            {name: files[name] for name in _SYZKALLER_FILES}))
    return manager


def _syzkaller_links(root: Path, target_dir: str,
                     binaries: dict[str, Path]) -> Path:
    layout = {"syz-manager": Path("bin/syz-manager"),
              "syz-execprog": Path("bin") / target_dir / "syz-execprog",
              "syz-executor": Path("bin") / target_dir / "syz-executor"}
    key = hashlib.sha256("\n".join(
        f"{layout[name]}={binaries[name].resolve()}"
        for name in sorted(binaries)).encode()).hexdigest()
    final = root / f"syzkaller-{key[:32]}"
    if final.is_dir():
        return final
    tmp = Path(tempfile.mkdtemp(prefix=final.name + ".", dir=root))
    for name, rel in layout.items():
        (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp / rel).symlink_to(binaries[name].resolve())
    try:
        tmp.rename(final)
    except OSError:
        # Another step made the same directory first.
        shutil.rmtree(tmp, ignore_errors=True)
        if not final.is_dir():
            raise
    return final


def _manager_assets(manager: dict[str, Any], vm: dict[str, Any],
                    collector: CollectorConfig,
                    descriptor: ExecutionHarnessDescriptor,
                    builds: dict[str, str]) -> HostFilePin:
    """Verify the files syz-manager will actually use against the harness."""
    target = descriptor.syzkaller_identity.target
    if manager.get("target") != target:
        raise Stage2StepError(f"manager target differs from {target}")
    parts = target.split("/")
    if len(parts) != 2 or not all(parts):
        raise Stage2StepError(f"unsupported manager target: {target}")
    os_name, arch = parts
    syzkaller = _required_path(manager, "syzkaller", label="manager")
    kernel_obj = _required_path(manager, "kernel_obj", label="manager")
    template = _required_path(manager, "workdir_template", label="manager")
    target_bin = syzkaller / "bin" / f"{os_name}_{arch}"
    actual = {
        "bzimage": _required_path(vm, "kernel", label="manager VM"),
        "kernel": kernel_obj / "vmlinux",
        "lane-script": template / "lane.sh",
        "vm-image": _required_path(manager, "image", label="manager"),
        "syz-execprog": target_bin / "syz-execprog",
        "syz-executor": target_bin / "syz-executor",
        "syz-manager": syzkaller / "bin" / "syz-manager",
    }
    missing = [name for name in actual if name not in builds]
    if missing:
        raise Stage2StepError(
            "descriptor lacks manager artifacts: " + ", ".join(missing))
    store = ArtifactStore(collector.artifact_root)
    cache = PinCache(collector.pin_cache)
    pins: dict[str, HostFilePin] = {}
    for name, path in actual.items():
        pin = load_record(store, builds[name], HostFilePin)
        if pin.name != name:
            raise Stage2StepError(f"manager pin for {name} names {pin.name}")
        verify_file(pin, path, cache)
        pins[name] = pin
    if not os.access(actual["syz-manager"], os.X_OK):
        raise Stage2StepError("pinned syz-manager is not executable")

    ssh_key = _required_path(manager, "sshkey", label="manager")
    try:
        same_key = ssh_key.resolve(strict=True) == \
            collector.ssh_key.resolve(strict=True)
    except OSError as exc:
        raise Stage2StepError("manager or collector SSH key is absent") from exc
    if not same_key:
        raise Stage2StepError("manager SSH key differs from collector SSH key")
    manager_qemu = vm.get("qemu", collector.qemu)
    if not isinstance(manager_qemu, str) or not manager_qemu:
        raise Stage2StepError("manager VM has no QEMU executable")
    collector_qemu = shutil.which(collector.qemu)
    actual_qemu = shutil.which(manager_qemu)
    if collector_qemu is None or actual_qemu is None:
        raise Stage2StepError("manager or collector QEMU is not executable")
    if Path(collector_qemu).resolve() != Path(actual_qemu).resolve():
        raise Stage2StepError("manager QEMU differs from collector QEMU")
    return pins["lane-script"]


def _manager_cmdline(vm: dict[str, Any], descriptor: ExecutionHarnessDescriptor,
                     harness: ReachabilityHarness, lane_sha256: str) -> str:
    raw = vm.get("cmdline")
    if not isinstance(raw, str) or not raw:
        raise Stage2StepError("manager VM has no kernel command line")
    base: list[str] = []
    dynamic: dict[str, str] = {}
    for token in raw.split():
        key, separator, value = token.partition("=")
        if not key.startswith("koov."):
            base.append(token)
            continue
        if not separator or key in dynamic:
            raise Stage2StepError("manager VM has malformed fixture arguments")
        dynamic[key] = value
    if tuple(base) != tuple(descriptor.guest_kernel_command_line.split()):
        raise Stage2StepError("manager VM base command line differs from harness")
    selection = harness.runtime_selection
    expected_fixture = ({"koov.nfs_version": selection.nfs_version}
                        if selection.fixture_mode == "single" else
                        {"koov.nfs_fixture": selection.fixture_mode})
    required = {**expected_fixture, "koov.nfs_target": "1",
                "koov.lane_sha256": lane_sha256}
    for key, value in required.items():
        if dynamic.get(key) != value:
            raise Stage2StepError(f"manager VM has unapproved {key}")
    allowed = set(required) | {"koov.nfs_trace"}
    if set(dynamic) - allowed:
        raise Stage2StepError("manager VM has unapproved fixture arguments")
    trace = dynamic.get("koov.nfs_trace")
    expected_trace = "1" if selection.trace_mode == "on" else "0"
    if trace is not None and trace != expected_trace:
        raise Stage2StepError("manager VM trace mode differs from harness")
    return raw


def _authority_record(root: Path, name: str, expected_ref: str, model):
    path = root / name
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise Stage2StepError(f"cannot read {name}") from exc
    if hashlib.sha256(raw).hexdigest() != expected_ref:
        raise Stage2StepError(f"{name} differs from harness authority")
    try:
        parse_json(raw)
        value = model.model_validate_json(raw)
    except (TypeError, ValueError) as exc:
        raise Stage2StepError(f"{name} is not a valid authority record") from exc
    if canonical_json(value) != raw:
        raise Stage2StepError(f"{name} is not canonical")
    return value


def _validate_runtime_authority(
        root: Path, harness: ReachabilityHarness,
        descriptor: ExecutionHarnessDescriptor, manager: dict[str, Any],
) -> None:
    """Bind the manager's actual layout to the harness authorities."""
    catalog = _authority_record(
        root, "hcap.json", harness.hcap_revision, HcapCatalog)
    profile = _authority_record(
        root, "admission.json", harness.call_admission_profile_ref,
        CallAdmissionProfile)
    profile_refs = {
        ref.artifact_ref
        for ref in (*catalog.authority_refs,
                    *(ref for capability in catalog.capabilities
                      for ref in capability.authority_refs))
        if ref.kind == "CallAdmissionProfile"
    }
    if profile_refs != {harness.call_admission_profile_ref}:
        raise Stage2StepError(
            "HCAP does not select the harness call admission authority")
    if profile.identity != descriptor.syzkaller_identity:
        raise Stage2StepError(
            "call admission authority differs from the harness build")
    procs = manager.get("procs")
    if type(procs) is not int or not 1 <= procs <= 64:
        raise Stage2StepError(
            "Stage 2 KVM step requires manager procs in [1, 64]")
    calls = manager.get("enable_syscalls")
    if calls is not None and (not isinstance(calls, list) or not all(
            isinstance(call, str) for call in calls)):
        raise Stage2StepError(
            "manager enable_syscalls must be a list of calls")
    enabled = calls if calls is not None else [entry.call for entry in profile.entries]
    refusals = layout_refusals(
        catalog, profile.entries, enabled_calls=enabled,
        runtime_features=("remote_cover",), procs=procs)
    if refusals:
        raise Stage2StepError(
            f"manager at {procs} proc(s) exceeds a validated layout: "
            f"{refusals[0]}")


def program_calls(program: bytes) -> list[str]:
    """The calls a syz program names, in order of first use: the manager
    enables exactly these, so the campaign stays lane I/O."""
    calls: list[str] = []
    for line in program.decode().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        call = line.split("(", 1)[0].split("=")[-1].strip()
        if call not in calls:
            calls.append(call)
    return calls


def _check_program_calls(program: bytes, manager: dict) -> None:
    """Every call of the candidate program is enabled (#99): syz-manager
    drops a disabled call from a seed without a word, and the campaign
    would fuzz the program without it."""
    calls = manager.get("enable_syscalls")
    if calls is None:
        return              # syz-manager enables every call
    disabled = [call for call in program_calls(program) if call not in calls]
    if disabled:
        raise Stage2StepError(
            "manager enable_syscalls leaves out candidate program calls: "
            + ", ".join(disabled))


def _seedless_syzkaller(source: Path, work: Path) -> Path:
    """Expose the pinned manager binaries without built-in test seeds."""
    source = source.absolute()
    bin_dir = source / "bin"
    if not bin_dir.is_dir():
        raise Stage2StepError(
            f"manager syzkaller tree has no bin directory: {source}")
    view = work / "syzkaller-seedless"
    (view / "sys" / "linux" / "test").mkdir(parents=True)
    (view / "bin").symlink_to(bin_dir, target_is_directory=True)
    return view


def _manager_command(binary: Path, config: Path,
                     mode: CampaignMode = "fuzz") -> list[str]:
    """``proxy_only`` runs only corpus records, without syzkaller program
    mutation."""
    command = [str(binary), "-config", str(config)]
    if mode == "proxy_only":
        command += ["-mode", "corpus-run"]
    return [*command, "-debug"]


def _foreign_campaign_execution(
        records: list[NfsProxyExecution], program_sha256: str
        ) -> NfsProxyExecution | None:
    """Return the first campaign execution that is not the approved seed."""
    return next((record for record in records
                 if record.campaign
                 and record.program_sha256 != program_sha256), None)


def _manager_path(options: StepOptions,
                  descriptor: ExecutionHarnessDescriptor) -> Path:
    if options.manager is not None:
        return options.manager
    path = dict(options.variant_managers).get(descriptor.sanitizer)
    if path is None:
        raise Stage2StepError(f"no variant manager for the "
                              f"{descriptor.sanitizer.value} harness")
    return path


def _load_inputs(options: StepOptions, root: Path) -> _Inputs:
    execution = _Execution.model_validate_json((root / "execution.json").read_bytes())
    harness = ReachabilityHarness.model_validate_json((root / "harness.json").read_bytes())
    descriptor = ExecutionHarnessDescriptor.model_validate_json(
        (root / "descriptor.json").read_bytes())
    if harness.execution_harness_id != execution.execution_harness_id:
        raise Stage2StepError("harness and execution identity disagree")
    if descriptor_id(descriptor) != execution.execution_harness_id:
        raise Stage2StepError("descriptor and execution identity disagree")
    collector = CollectorConfig.load(options.collector)
    files = verify_pins(collector, descriptor)
    manager = _staged_manager(_object(_manager_path(options, descriptor)),
                              collector, files)
    vm = manager.get("vm")
    if manager.get("type") != "qemu" or not isinstance(vm, dict):
        raise Stage2StepError("manager must configure one qemu VM")
    count = vm.get("count", 1)
    if type(count) is not int or count != 1:
        raise Stage2StepError("target-mode campaign requires vm.count 1")
    procs = manager.get("procs")
    if type(procs) is not int or not 1 <= procs <= 64:
        raise Stage2StepError("Stage 2 KVM step requires manager procs in [1, 64]")
    _validate_runtime_authority(root, harness, descriptor, manager)
    _check_program_calls((root / "program.syz").read_bytes(), manager)
    lanes = _journal_lane_count(vm, procs, accel=collector.accel)
    builds = {item.name: item.artifact_ref for item in descriptor.build_artifacts}
    lane_pin = _manager_assets(manager, vm, collector, descriptor, builds)
    cmdline = _manager_cmdline(vm, descriptor, harness, lane_pin.sha256)
    experimental = manager.get("experimental")
    if not isinstance(experimental, dict) or \
            experimental.get("remote_cover") is not True:
        raise Stage2StepError("manager must enable experimental.remote_cover")
    if manager.get("snapshot", False) is not False:
        raise Stage2StepError("manager program snapshot mode must be disabled")
    rules = (root / "rules.nfsprul1").read_bytes()
    if hashlib.sha256(rules).hexdigest() != execution.rule_set_id:
        raise Stage2StepError("rules.nfsprul1 differs from execution authority")
    return _Inputs(root, execution, harness, descriptor, collector, manager,
                   files, rules, lane_pin.sha256, cmdline, lanes)


def _vm_id(execution: _Execution, label: str) -> str:
    task = re.sub(r"[^A-Za-z0-9_.-]", "-", execution.task_id)[:80] or "task"
    return f"{task}.g{execution.lease_generation}.{label}.{uuid.uuid4().hex[:12]}"


def _lane_template(source: Path, target: Path, rules: bytes,
                   prefixes: tuple[str, ...]) -> Path:
    shutil.copytree(source, target)
    target_dir = target / "target"
    target_dir.mkdir(exist_ok=True)
    for lane, prefix in enumerate(prefixes):
        rule_path = target_dir / f"lane{lane}.nfsprul1"
        session_path = target_dir / f"lane{lane}.session"
        for path in (rule_path, session_path):
            if path.exists():
                path.chmod(0o600)
        rule_path.write_bytes(rules)
        session_path.write_text(prefix + "\n")
        rule_path.chmod(0o444)
        session_path.chmod(0o444)
    return target


class _JournalChannels:
    def __init__(self, root: Path, name: str, vm: str, lanes: int,
                 rules: bytes, prefixes: tuple[str, ...]) -> None:
        self.root, self.name, self.vm = root, name, vm
        self.socket_dir = Path(tempfile.mkdtemp(prefix="knfsd-s2-journal-"))
        self.servers: list[ChannelServer] = []
        self.sockets: list[Path] = []
        try:
            self.journal = HostJournal(root, name, fsync=True)
        except BaseException:
            shutil.rmtree(self.socket_dir, ignore_errors=True)
            raise
        try:
            for lane in range(lanes):
                channel = f"nfsp-journal-{lane}"
                self.journal.install_session_series(
                    vm_instance_id=vm, channel_id=channel,
                    prefix=prefixes[lane], lane_id=lane, rule_set=rules)
                socket = self.socket_dir / f"lane{lane}.sock"
                self.servers.append(ChannelServer(
                    socket, self.journal, ChannelIdentity(vm, channel)))
                self.sockets.append(socket)
        except BaseException:
            self.close()
            raise

    def qemu_args(self, *, controller: bool) -> tuple[str, ...]:
        args: list[str] = []
        if controller:
            args += ["-device", "virtio-serial-pci,id=nfspser"]
        for lane, socket in enumerate(self.sockets):
            args += [
                "-chardev", f"socket,id=nfspj{lane},path={socket},server=off",
                "-device", (f"virtserialport,bus=nfspser.0,chardev=nfspj{lane},"
                            f"name=nfsp-journal-{lane}"),
            ]
        return tuple(args)

    def paths(self) -> list[Path]:
        return sorted(self.root.glob(f"{self.name}.[0-9][0-9][0-9][0-9]{SEGMENT_SUFFIX}"))

    def close(self) -> None:
        stopped = True
        for server in reversed(self.servers):
            stopped = server.close() and stopped
        if not stopped:
            raise Stage2StepError(
                "journal channel did not stop before evidence sealing")
        self.servers.clear()
        self.journal.close()
        shutil.rmtree(self.socket_dir, ignore_errors=True)


@contextmanager
def _closed_evidence_channels(output: Path, index: int,
                              channels: _JournalChannels, *,
                              reserve_s: float = EVIDENCE_SEAL_RESERVE_S):
    """Close journal writers inside the same reserve used for sealing."""
    with _evidence_seal_window(
            output, index, reserve_s=reserve_s) as deadline:
        channels.close()
        _check_evidence_deadline(deadline)
        yield deadline


def _journal_artifacts(channels: _JournalChannels, *,
                       deadline: float | _EvidenceSealState) -> list[_Artifact]:
    _check_evidence_deadline(deadline)
    paths = channels.paths()
    if not paths:
        raise Stage2StepError("target-mode VM produced no host journal segment")
    artifacts = []
    for path in paths:
        _check_evidence_deadline(deadline)
        data = path.read_bytes()
        _check_evidence_deadline(deadline)
        artifacts.append(_Artifact(
            journal_identity(path.name), JOURNAL_TYPE, data))
    return artifacts


def _seal_segment(output: Path, index: int, *, vm: str, lane: int,
                  generation: int, host: dict[str, Any],
                  artifacts: list[_Artifact],
                  deadline: float | _EvidenceSealState) -> Path:
    _check_evidence_deadline(deadline)
    if not artifacts or len(artifacts) > 255:
        raise Stage2StepError("segment artifact count must be in [1, 255]")
    identities = [artifact.identity for artifact in artifacts]
    if len(identities) != len(set(identities)):
        raise Stage2StepError("segment has duplicate artifact identities")
    segments = output / "segments"
    segments.mkdir(parents=True, exist_ok=True)
    temporary = segments / f".{index:06d}.tmp"
    final = segments / f"{index:06d}"
    if temporary.exists() or final.exists():
        raise Stage2StepError("evidence segment path already exists")
    temporary.mkdir()
    entries = []
    for number, artifact in enumerate(artifacts):
        _check_evidence_deadline(deadline)
        name = f"artifact-{number:03d}.bin"
        path = temporary / name
        with path.open("xb") as stream:
            stream.write(artifact.data)
            stream.flush()
            os.fsync(stream.fileno())
        _check_evidence_deadline(deadline)
        entries.append({"identity": artifact.identity,
                        "type": artifact.type, "path": name})
    capture = {"vm_instance_id": vm, "lane": lane,
               "generation_id": max(1, generation), "host": host,
               "artifacts": entries}
    with (temporary / "capture.json").open("x") as stream:
        json.dump(capture, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    _check_evidence_deadline(deadline)
    # Keep the alarm interruptible across rename.  If rename commits just as
    # the deadline fires, the exception propagates but the final name remains
    # valid for the engine to harvest.
    os.rename(temporary, final)
    if isinstance(deadline, _EvidenceSealState):
        deadline.published = True
    return final


def _barrier_generation(output: str, fallback: int = 1) -> int:
    try:
        barriers = parse_execprog_barriers(output)
    except PlanError:
        # The raw log is still evidence.  The judge turns malformed barrier
        # output into an inconclusive verdict rather than an infrastructure
        # retry, while capture.json still needs a bounded correlation value.
        return fallback
    return barriers[0].kcov_generation if barriers else fallback


def _neutral_run(guest: Guest, source: Path, config: CollectorConfig, *,
                 exec_slowdown: int = 1) -> tuple[LaneRun, str]:
    run = LaneRun(boot_ok=True, fixture_ok=True, lane_ok=True)
    guest.put(source, f"{GUEST_DIR}/program.syz")
    timeout_s = execprog_timeout(config.exec_timeout_s, exec_slowdown)
    _checked(guest, execprog_argv(config.exec_timeout_s, exec_slowdown))
    exec_deadline = (time.monotonic() + timeout_s
                     + EXECPROG_EXIT_GRACE_S)
    gate = _wait_execprog(guest, True, exec_deadline, time.sleep)
    if gate == "ready":
        run.collection_started = True
        _checked(guest, f"touch {GUEST_DIR}/gate.go",
                 timeout=_deadline_timeout(exec_deadline))
        done = _wait_execprog(guest, False, exec_deadline, time.sleep)
    else:
        done = gate
    rc_text = _checked(guest, f"cat {GUEST_DIR}/exec.rc 2>/dev/null || true").strip()
    run.runner_completed = gate == "ready" and done == "exited" and rc_text == "0"
    if not run.runner_completed:
        run.runtime_errors.append(f"neutral_execprog_failed:{done}:rc={rc_text}")
    _, output = guest.run(f"cat {GUEST_DIR}/exec.log",
                          timeout=EVIDENCE_COMMAND_TIMEOUT_S)
    time.sleep(config.drain_s)
    _collect_cover(guest, run, {})
    return run, output


def _direct_guest(inputs: _Inputs, lane_dir: Path, console: Path,
                  extra_args: tuple[str, ...]) -> QemuGuest:
    c = inputs.collector
    return QemuGuest(VmConfig(
        qemu=c.qemu, bzimage=inputs.files["bzimage"],
        image=inputs.files["vm-image"], lane_dir=lane_dir,
        ssh_key=c.ssh_key, cmdline=inputs.cmdline, console_log=console,
        memory_mb=c.memory_mb, cpus=c.cpus, boot_timeout_s=c.boot_timeout_s,
        accel=c.accel, extra_args=extra_args))


def _gate(inputs: _Inputs, output: Path, options: StepOptions) -> None:
    repetitions = inputs.execution.gate_repetitions
    if repetitions is None or repetitions < 1:
        raise Stage2StepError("gate execution lacks gate_repetitions")
    builds = {item.name: item.artifact_ref for item in inputs.descriptor.build_artifacts}
    identity = KernelIdentity(
        execution_harness_id=inputs.execution.execution_harness_id,
        kernel_commit=inputs.descriptor.kernel_commit,
        instrumentation_sha256=builds[inputs.collector.instrumentation_artifact_name],
        vmlinux_sha256=builds[inputs.collector.vmlinux_artifact_name],
        kaslr_enabled=False, kaslr_offset=0)
    source_template = Path(str(inputs.manager["workdir_template"]))
    work_root = output / "work"
    work_root.mkdir()
    for repetition in range(repetitions):
        work = work_root / f"gate-{repetition:06d}"
        work.mkdir()
        vm = _vm_id(inputs.execution, f"gate{repetition}")
        prefixes = tuple(f"g{repetition}l{lane}-{uuid.uuid4().hex}"
                         for lane in range(inputs.lanes))
        lane_dir = _lane_template(source_template, work / "lane", inputs.rules,
                                  prefixes)
        channels = _JournalChannels(work / "journal", f"gate{repetition}", vm,
                                    inputs.lanes, inputs.rules, prefixes)
        guest = _direct_guest(inputs, lane_dir, work / "console.log",
                              channels.qemu_args(controller=True))
        result: dict[str, Any] = {}
        try:
            try:
                scenario = run_lane(
                    guest, inputs.files, inputs.root / "program.syz",
                    inputs.harness.runtime_selection, inputs.lane_sha256,
                    inputs.collector, work, result,
                    exec_slowdown=options.exec_slowdown)
                scenario_output = (work / "executor.log").read_text(
                    errors="replace")
                neutral, neutral_output = _neutral_run(
                    guest, inputs.root / "neutral.syz", inputs.collector,
                    exec_slowdown=options.exec_slowdown)
            finally:
                guest.stop()
        except BaseException:
            with _closed_evidence_channels(output, repetition, channels):
                pass
            raise
        with _closed_evidence_channels(
                output, repetition, channels) as seal_deadline:
            scenario_generation = _barrier_generation(scenario_output)
            neutral_generation = _barrier_generation(
                neutral_output, scenario_generation + 1)
            correlation = inputs.correlation(vm, 0, scenario_generation)
            observation, coverage = capture_records(
                scenario, candidate_id=inputs.harness.candidate_id,
                identity=identity, correlation=correlation,
                trace_mode=inputs.harness.runtime_selection.trace_mode)
            neutral_coverage = canonical_json(PublishedCoverage(
                correlation=inputs.correlation(vm, 0, neutral_generation),
                pcs=tuple(sorted(neutral.pcs))))
            artifacts = [
                _Artifact(OBSERVATION_ID, OBSERVATION_TYPE, observation),
                _Artifact("coverage", COVERAGE_TYPE, coverage),
                _Artifact(NEUTRAL_COVERAGE_ID, NEUTRAL_COVERAGE_TYPE,
                          neutral_coverage),
                _Artifact(SCENARIO_EXECPROG_ID, EXECPROG_TYPE,
                          scenario_output.encode("utf-8", "replace")),
                _Artifact(NEUTRAL_EXECPROG_ID, EXECPROG_TYPE,
                          neutral_output.encode("utf-8", "replace")),
                *_journal_artifacts(channels, deadline=seal_deadline),
            ]
            _seal_segment(
                output, repetition, vm=vm, lane=0,
                generation=scenario_generation,
                host={"journal_name": channels.name}, artifacts=artifacts,
                deadline=seal_deadline)


def _fixture(guest: Guest, inputs: _Inputs, result: dict[str, Any]) -> bool:
    _checked(guest, "mountpoint -q /sys/kernel/debug || "
                    "mount -t debugfs none /sys/kernel/debug")
    return _fixture_ready(
        guest, inputs.harness.runtime_selection, inputs.lane_sha256,
        inputs.collector.fixture_timeout_s, result)


def _replay(inputs: _Inputs, output: Path, options: StepOptions) -> None:
    replay = inputs.root / "replay"
    rules = (replay / "rules.bin").read_bytes()
    work = output / "work"
    work.mkdir()
    vm = _vm_id(inputs.execution, "replay")
    prefixes = tuple(f"rl{lane}-{uuid.uuid4().hex}"
                     for lane in range(inputs.lanes))
    source_template = Path(str(inputs.manager["workdir_template"]))
    lane_dir = _lane_template(source_template, work / "lane", rules, prefixes)
    channels = _JournalChannels(work / "journal", "replay", vm, inputs.lanes,
                                rules, prefixes)
    console = work / "console.log"
    guest = _direct_guest(inputs, lane_dir, console,
                          channels.qemu_args(controller=True))
    output_text = ""
    fixture_failed = False
    returncode = -1
    try:
        try:
            guest.start()
            if not _fixture(guest, inputs, {}):
                fixture_failed = True
            else:
                _checked(guest, f"mkdir -p {GUEST_DIR}")
                guest.put(inputs.files["syz-executor"],
                          f"{GUEST_DIR}/syz-executor")
                guest.put(inputs.files["syz-execprog"],
                          f"{GUEST_DIR}/syz-execprog")
                guest.put(replay / "programs.log",
                          f"{GUEST_DIR}/programs.log")
                _checked(guest, f"chmod 0755 {GUEST_DIR}/syz-executor "
                                f"{GUEST_DIR}/syz-execprog")
                argv = [
                    f"{GUEST_DIR}/syz-execprog",
                    f"-executor={GUEST_DIR}/syz-executor", "-os=linux",
                    "-arch=amd64", "-vmarch=amd64", "-sandbox=none",
                    "-procs=1", "-repeat=1", "-threaded=false",
                    "-cover=true", "-remote-cover=true", "-disable=all",
                    "-debug", "-vv=1", f"-slowdown={options.exec_slowdown}",
                    f"{GUEST_DIR}/programs.log",
                ]
                returncode, output_text = guest.run(
                    shlex.join(argv), timeout=execprog_timeout(
                        inputs.collector.exec_timeout_s,
                        options.exec_slowdown))
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            output_text += f"\nhost replay error: {type(exc).__name__}: {exc}\n"
        finally:
            guest.stop()
    except BaseException:
        with _closed_evidence_channels(output, 0, channels):
            pass
        raise
    with _closed_evidence_channels(output, 0, channels) as seal_deadline:
        console_bytes = console.read_bytes() if console.is_file() else b""
        _check_evidence_deadline(seal_deadline)
        if _CRASH.search(console_bytes):
            replay_end = "guest_crash"
        elif fixture_failed:
            replay_end = "unknown"
        elif returncode == 0:
            replay_end = "clean"
        else:
            replay_end = "unknown"
        artifacts = [
            _Artifact(REPLAY_EXECPROG_ID, EXECPROG_TYPE,
                      output_text.encode("utf-8", "replace")),
            *_journal_artifacts(channels, deadline=seal_deadline),
        ]
        generation = _barrier_generation(output_text)
        _seal_segment(
            output, 0, vm=vm, lane=0, generation=generation,
            host={"journal_name": channels.name, "replay_end": replay_end,
                  "fixture_failed": fixture_failed}, artifacts=artifacts,
            deadline=seal_deadline)


def _corpus(path: Path, program: bytes) -> None:
    """Write the deterministic one-record syzkaller DB v2 / corpus v5."""
    key = hashlib.sha1(program).hexdigest().encode("ascii")
    compressor = zlib.compressobj(level=9, wbits=-15)
    compressed = compressor.compress(program) + compressor.flush()
    raw = (struct.pack("<IIQ", 0xBADDB, 2, 5)
           + struct.pack("<II", 0xFEE1BAD, len(key)) + key
           + struct.pack("<QI", 0, len(compressed)) + compressed)
    path.write_bytes(raw)


def _manager_qemu_args(value: str, channels: _JournalChannels) -> str:
    tokens = value.split()
    kept: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        following = tokens[index + 1] if index + 1 < len(tokens) else ""
        if token == "-chardev" and "id=nfspj" in following:
            index += 2
            continue
        if token == "-device" and "name=nfsp-journal-" in following:
            index += 2
            continue
        kept.append(token)
        index += 1
    if not any("virtio-serial-pci" in token and "id=nfspser" in token
               for token in kept):
        kept += ["-device", "virtio-serial-pci,id=nfspser"]
    kept.extend(channels.qemu_args(controller=False))
    if any(any(char.isspace() for char in token) for token in kept):
        raise Stage2StepError("QEMU arguments contain whitespace")
    return " ".join(kept)


def _spool(path: Path) -> list[NfsProxyExecution]:
    records = []
    for item in sorted(path.glob("[0-9][0-9]*.json")):
        records.append(NfsProxyExecution.model_validate_json(item.read_bytes()))
    return records


def _correlated(record: NfsProxyExecution) -> bool:
    """Whether one result has an executed target-mode generation."""
    return bool(record.generation and record.program_digest
                and record.activation == "Acked" and record.executed)


def _campaign_records(records: list[NfsProxyExecution]) -> tuple[
        list[NfsProxyExecution], list[NfsProxyExecution]]:
    """Return manager-classified campaign results and correlated executions."""
    campaign = [record for record in records if record.campaign]
    return campaign, [record for record in campaign if _correlated(record)]


def _crash_attribution(
        *, report_seen: bool, crash_log: str | None, vm: str, procs: int,
        campaign: list[NfsProxyExecution],
        correlated: list[NfsProxyExecution],
        foreign: NfsProxyExecution | None
        ) -> tuple[str, tuple[str, ...]]:
    """Grade crash attribution without changing the sanitizer oracle."""
    if not report_seen:
        return "none", ()
    if crash_log is not None:
        try:
            window = parse_crash_context(
                crash_log, vm_instance_id=vm, bound=64)
            current = window.entries[-1]
            matches = [record for record in correlated
                       if record.execution_id == current.exec_id
                       and record.lane == current.lane_id
                       and current.barrier is not None
                       and record.generation
                       == current.barrier.kcov_generation
                       and record.program_digest
                       == current.barrier.program_digest]
            if len(matches) == 1:
                return "exact", ()
        except PlanError:
            pass
    warnings = ["exact_generation_unavailable"]
    if foreign is not None:
        warnings.append(f"foreign_program_execution:{foreign.execution_id}")
    uncorrelated = len(campaign) - len(correlated)
    if uncorrelated:
        warnings.append(f"uncorrelated_program_results:{uncorrelated}")
    if procs == 1 and foreign is None:
        return "campaign", tuple(warnings)
    if procs > 1:
        warnings.append(f"multiple_active_lanes:{procs}")
    return "ambiguous", tuple(warnings)


def _crash_files(workdir: Path) -> tuple[list[Path], Path | None]:
    root = workdir / "crashes"
    reports = sorted(root.glob("*/report*")) if root.is_dir() else []
    logs = sorted(root.glob("*/log*")) if root.is_dir() else []
    return reports, (logs[0] if logs else None)


def _stop_manager(process: subprocess.Popen, timeout_s: float) -> bool:
    """Return true only when the manager drained after SIGINT."""
    if process.poll() is not None:
        return True
    try:
        os.killpg(process.pid, signal.SIGINT)
    except ProcessLookupError:
        process.wait(timeout=MANAGER_SIGNAL_TIMEOUT_S)
        return True
    try:
        process.wait(timeout=timeout_s)
        return True
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            process.wait(timeout=MANAGER_SIGNAL_TIMEOUT_S)
            return True
        try:
            process.wait(timeout=MANAGER_SIGNAL_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=MANAGER_SIGNAL_TIMEOUT_S)
        return False


def _campaign_manager(inputs: _Inputs) -> dict[str, Any]:
    manager = json.loads(json.dumps(inputs.manager))
    kcsan = inputs.descriptor.sanitizer is Sanitizer.KCSAN
    if not kcsan and ("kcsan_policy_file" in manager or
                      "kcsan_policy" in manager):
        raise Stage2StepError("non-KCSAN campaign selects a KCSAN policy")
    if not kcsan:
        return manager
    state_dir = inputs.execution.state_dir
    if state_dir is None:
        raise Stage2StepError("KCSAN campaign lacks Controller state")

    state = Path(state_dir)
    database = state / "controller.sqlite"
    if not database.is_file():
        raise Stage2StepError(f"Controller job store is absent: {database}")
    store = Store(database)
    try:
        job = store.job(inputs.execution.job_id)
        if job.candidate is None or job.candidate.candidate_id != inputs.harness.candidate_id:
            raise Stage2StepError("campaign job and harness select different candidates")
        if job.candidate.kernel_commit != inputs.descriptor.kernel_commit:
            raise Stage2StepError("campaign candidate and kernel commit differ")
        if store.policy(job.job_policy_id).sanitizer is not inputs.descriptor.sanitizer:
            raise Stage2StepError("campaign job and harness sanitizer differ")
        return ProgramPolicyPipeline(
            store, state / "kcsan-policies").manager_config(job.job_id, manager)
    finally:
        store.close()


def _campaign(inputs: _Inputs, output: Path, options: StepOptions) -> None:
    manager = _campaign_manager(inputs)
    work = output / "work"
    work.mkdir()
    workdir, spool = work / "manager-workdir", work / "executions"
    workdir.mkdir()
    spool.mkdir()
    program = (inputs.root / "program.syz").read_bytes()
    program_sha256 = hashlib.sha256(program).hexdigest()
    proxy_only = options.campaign_mode == "proxy_only"
    if proxy_only:
        # Only the Proxy mutates this campaign.  Keep syzkaller on the
        # approved program so both mutation layers cannot mix in one
        # generation.  The manager runs a narrower config than the one
        # preflight checked: the program's own calls only.
        manager["syzkaller"] = str(_seedless_syzkaller(
            Path(str(manager["syzkaller"])), work))
        manager["reproduce"] = False
        manager["enable_syscalls"] = program_calls(program)
    _corpus(workdir / "corpus.db", program)
    vm = _vm_id(inputs.execution, "campaign")
    prefixes = tuple(f"cl{lane}-{uuid.uuid4().hex}"
                     for lane in range(inputs.lanes))
    source_template = Path(str(inputs.manager["workdir_template"]))
    lane_dir = _lane_template(source_template, work / "lane", inputs.rules,
                              prefixes)
    channels = _JournalChannels(work / "journal", "campaign", vm,
                                inputs.lanes, inputs.rules, prefixes)
    manager["workdir"] = str(workdir)
    manager["workdir_template"] = str(lane_dir)
    manager["http"] = ""
    manager.setdefault("experimental", {})["nfs_proxy_evidence"] = str(spool)
    manager["vm"]["qemu_args"] = _manager_qemu_args(
        str(manager["vm"].get("qemu_args", "")), channels)
    config = work / "manager.json"
    config.write_text(json.dumps(manager, indent=2, sort_keys=True) + "\n")
    manager_binary = Path(str(manager["syzkaller"])) / "bin" / "syz-manager"
    manager_log = work / "manager-debug.log"
    start_ns = time.time_ns()
    process: subprocess.Popen | None = None
    complete = False
    unexpected_exit = False
    try:
        try:
            with manager_log.open("wb") as log:
                process = subprocess.Popen(
                    _manager_command(manager_binary, config, options.campaign_mode),
                    stdin=subprocess.DEVNULL, stdout=log,
                    stderr=subprocess.STDOUT, start_new_session=True)
                deadline = time.monotonic() + options.campaign_timeout_s
                while True:
                    records = _spool(spool)
                    _, campaign_records = _campaign_records(records)
                    reports, crash_log = _crash_files(workdir)
                    if (proxy_only and _foreign_campaign_execution(
                            records, program_sha256) is not None or
                            len(campaign_records) >= options.campaign_executions or
                            reports or crash_log is not None):
                        break
                    if process.poll() is not None:
                        unexpected_exit = True
                        break
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.05)
                complete = _stop_manager(
                    process, options.manager_stop_timeout_s)
        finally:
            if process is not None and process.poll() is None:
                _stop_manager(process, options.manager_stop_timeout_s)
    except BaseException:
        with _closed_evidence_channels(output, 0, channels):
            pass
        raise
    with _closed_evidence_channels(output, 0, channels) as seal_deadline:
        end_ns = time.time_ns()
        records = _spool(spool)
        _check_evidence_deadline(seal_deadline)
        if not records:
            raise Stage2StepError("syz-manager produced no program evidence")
        reports, crash_log = _crash_files(workdir)
        console = manager_log.read_bytes()
        _check_evidence_deadline(seal_deadline)
        if b"failed to store NFS proxy evidence" in console:
            raise Stage2StepError("syz-manager reported an evidence spool failure")
        report_seen, guest_crashed = _campaign_report_state(
            reports, crash_log, console)
        campaign_span, correlated = _campaign_records(records)
        if any(record.vm != 0 or record.lane >= inputs.lanes for record in records):
            raise Stage2StepError("syz-manager evidence has an invalid VM or lane")
        execution_ids = [record.execution_id for record in records]
        if len(execution_ids) != len(set(execution_ids)):
            raise Stage2StepError("syz-manager evidence reuses an execution ID")
        if not correlated and not report_seen:
            raise Stage2StepError(
                "syz-manager produced no generation-attributed campaign execution")
        seen: set[tuple[int, int]] = set()
        coverage_artifacts: list[_Artifact] = []
        execution_artifacts: list[_Artifact] = []
        for record in correlated:
            _check_evidence_deadline(seal_deadline)
            key = (record.lane, record.generation)
            if key in seen:
                raise Stage2StepError(
                    "campaign VM restarted and reused a lane generation")
            seen.add(key)
            coverage = PublishedCoverage(
                correlation=inputs.correlation(vm, record.lane, record.generation),
                pcs=record.pcs)
            coverage_artifacts.append(_Artifact(
                f"{GENERATION_COVERAGE_PREFIX}{record.lane}.{record.generation}",
                GENERATION_COVERAGE_TYPE, canonical_json(coverage)))
            execution = GenerationExecution(
                correlation=inputs.correlation(
                    vm, record.lane, record.generation),
                execution_id=record.execution_id,
                program_sha256=record.program_sha256,
                program_digest=record.program_digest,
                activation=record.activation,
                activation_status=record.activation_status,
                deactivation=record.deactivation,
                deactivation_status=record.deactivation_status,
                executed=record.executed, lease_cleared=record.lease_cleared)
            execution_artifacts.append(_Artifact(
                f"{GENERATION_EXECUTION_PREFIX}{record.lane}.{record.generation}",
                GENERATION_EXECUTION_TYPE, canonical_json(execution)))
        report_artifacts: list[_Artifact] = []
        report_refs: list[SealedArtifactRef] = []
        for number, path in enumerate(reports):
            _check_evidence_deadline(seal_deadline)
            data = path.read_bytes()
            _check_evidence_deadline(seal_deadline)
            identity = f"manager-report-{number:04d}"
            report_artifacts.append(_Artifact(identity, MANAGER_REPORT_TYPE, data))
            report_refs.append(SealedArtifactRef(
                identity=identity, sha256=hashlib.sha256(data).hexdigest()))
        console_identity = "console"
        correlation = (inputs.correlation(vm, correlated[0].lane,
                                          correlated[0].generation)
                       if correlated else inputs.correlation(vm, 0, 1))
        window = Q2CollectionWindow(
            start_marker=f"host-ns:{start_ns}", end_marker=f"host-ns:{end_ns}")
        internal = []
        if unexpected_exit and not guest_crashed:
            returncode = process.returncode if process is not None else None
            internal.append(f"manager_exited_unexpectedly:{returncode}")
        if _KCSAN_REPORT.search(console) and not reports:
            internal.append("kcsan_console_report_missing_from_manager_reports")
        foreign = _foreign_campaign_execution(records, program_sha256)
        attribution_quality, attribution_warnings = _crash_attribution(
            report_seen=report_seen,
            crash_log=(crash_log.read_text(errors="replace")
                       if crash_log is not None else None),
            vm=vm, procs=int(manager["procs"]), campaign=campaign_span,
            correlated=correlated, foreign=foreign)
        completeness = "complete" if complete else "truncated"
        termination = "guest_crashed" if guest_crashed else (
            "lost" if unexpected_exit else
            ("runner_stopped" if complete else "lost"))
        q2_correlation = EvidenceCorrelation.model_validate(
            correlation.model_dump(mode="python"))
        q2 = SealedQ2Evidence(
            execution_harness_id=inputs.execution.execution_harness_id,
            correlation=q2_correlation,
            console_log_identity=console_identity,
            console_log_ref=hashlib.sha256(console).hexdigest(),
            console_log_completeness=completeness,
            manager_crash_reports=tuple(report_refs),
            vm_termination=termination, collection_window=window,
            internal_errors=tuple(internal),
            attribution_quality=attribution_quality,
            attribution_warnings=attribution_warnings)
        artifacts = [
            _Artifact(Q2_EVIDENCE_ID, Q2_EVIDENCE_TYPE, canonical_json(q2)),
            _Artifact(console_identity, CONSOLE_LOG_TYPE, console),
            *report_artifacts,
            *coverage_artifacts,
            *execution_artifacts,
        ]
        if crash_log is not None:
            _check_evidence_deadline(seal_deadline)
            artifacts.append(_Artifact(CRASH_LOG_ID, CRASH_LOG_TYPE,
                                       crash_log.read_bytes()))
            _check_evidence_deadline(seal_deadline)
        artifacts.extend(_journal_artifacts(
            channels, deadline=seal_deadline))
        _seal_segment(
            output, 0, vm=vm, lane=correlation.lane,
            generation=correlation.generation_id,
            host={
                "journal_name": channels.name,
                "executions": len(correlated),
                "console_log_identity": console_identity,
                "console_log_completeness": completeness,
                "manager_crash_report_identities": [item.identity
                                                      for item in report_refs],
                "vm_termination": termination,
                "collection_window": window.model_dump(mode="json"),
            }, artifacts=artifacts, deadline=seal_deadline)


def run_step(options: StepOptions, input_dir: Path, output_dir: Path) -> None:
    inputs = _load_inputs(options, Path(input_dir))
    if options.exec_slowdown is None:
        options = replace(options,
                          exec_slowdown=inputs.collector.exec_slowdown)
    output = Path(output_dir)
    if not output.is_dir() or not (output / "segments").is_dir():
        raise Stage2StepError("engine did not prepare output/segments")
    if any((output / "segments").iterdir()):
        raise Stage2StepError("output/segments is not empty")
    if inputs.execution.step == "gate":
        _gate(inputs, output, options)
    elif inputs.execution.step == "campaign":
        _campaign(inputs, output, options)
    else:
        _replay(inputs, output, options)


__all__ = ["NfsProxyExecution", "Stage2StepError", "StepOptions", "run_step"]
