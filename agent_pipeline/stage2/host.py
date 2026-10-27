"""Readiness checks and the real host entry point for Stage 2 VMs (KVM or TCG).

The Stage 2 engine deliberately treats its host command as trusted
configuration.  Preflight checks that configuration and its immutable
authority without booting a guest or writing pipeline state.  The ``step``
subcommand is the configured host command and does run QEMU/syz-manager.

Run the read-only check with::

    python -m agent_pipeline.stage2.host preflight
        --stage1 stage1.json --manager manager.json
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Callable, Literal

from pydantic import Field

from ..artifacts import ArtifactStore
from ..contracts import CampaignMode, JobPolicy, Record
from ..data import load_record, parse_json
from ..admission import CallAdmissionProfile
from ..hcap import ArtifactHcapChecker, HcapCatalog, layout_refusals
from ..m1 import M1JudgeProfile
from ..materializer import (ExecutionHarnessApproval,
                            ExecutionHarnessDescriptor, descriptor_id)
from ..q2 import Q2JudgeProfile
from ..qemu_accel import (KVM_API_VERSION, KVM_GET_API_VERSION,  # noqa: F401
                          AccelError, accel_of, check_kvm)
from ..registry import HarnessCatalog
from ..runner.process_supervisor import ProcessLimits
from ..semantic_promotion import (BuildRegistry,
                                  PromotedSemanticCapabilityRegistry,
                                  check_runtime, promoted_registry,
                                  read_build_registry)
from ..semantic_replay import ReplayJudgeProfile
from ..stage1.config import Stage1Config
from ..stage1.host.collector import CollectorConfig, verify_pins
from ..stage1.host.pins import HostFilePin, file_sha256, verify_file
from .kvm import stage2_timeout_budget


class PreflightCheck(Record):
    name: str = Field(min_length=1, max_length=128)
    status: Literal["pass", "warning", "error"]
    detail: str = Field(min_length=1, max_length=1024)


class PreflightReport(Record):
    schema_version: Literal["stage2-kvm-preflight.v1"] = \
        "stage2-kvm-preflight.v1"
    ready: bool
    checks: tuple[PreflightCheck, ...]


class PreflightError(RuntimeError):
    """One readiness invariant is not met."""


@dataclass(frozen=True)
class _ApprovedHarness:
    harness_id: str
    command_line: tuple[str, ...]
    pins: tuple[tuple[str, HostFilePin], ...]
    #: The koov fixture arguments of the descriptor's allowed runtime
    #: selections, as (selection argument, koov.nfs_trace value) pairs.
    fixtures: frozenset[tuple[str, str]] = frozenset()
    #: Each bound HCAP revision with its call admission profile; a manager
    #: must stay inside their capabilities' validated layouts (#99).
    authorities: tuple[tuple[HcapCatalog, CallAdmissionProfile], ...] = ()

    def pin(self, name: str) -> HostFilePin:
        try:
            return dict(self.pins)[name]
        except KeyError as exc:
            raise PreflightError(
                f"approved harness {self.harness_id[:12]} lacks {name}") from exc


class _Checks:
    def __init__(self) -> None:
        self.items: list[PreflightCheck] = []

    def add(self, name: str, status: Literal["pass", "warning", "error"],
            detail: str) -> None:
        self.items.append(PreflightCheck(
            name=name, status=status, detail=detail[:1024]))

    def attempt(self, name: str, operation: Callable[[], str]) -> bool:
        try:
            detail = operation()
        except (OSError, ValueError, TypeError, RuntimeError,
                subprocess.SubprocessError) as exc:
            self.add(name, "error", f"{type(exc).__name__}: {exc}")
            return False
        self.add(name, "pass", detail)
        return True


def _executable(path: Path | str, *, which: Callable[[str], str | None]
                ) -> Path:
    value = str(path)
    found = Path(value) if Path(value).is_absolute() else None
    if found is None:
        resolved = which(value)
        if resolved is None:
            raise PreflightError(f"executable is not on PATH: {value}")
        found = Path(resolved)
    if not found.is_file() or not os.access(found, os.X_OK):
        raise PreflightError(f"not an executable file: {found}")
    return found


def _check_kvm(
    path: Path, *,
    opener: Callable[[Path, int], int] = os.open,
    ioctl: Callable[[int, int], int] = fcntl.ioctl,
    closer: Callable[[int], None] = os.close,
) -> str:
    try:
        return check_kvm(path, opener=opener, ioctl=ioctl, closer=closer)
    except AccelError as exc:
        raise PreflightError(str(exc)) from exc


def _check_accel(collector: CollectorConfig, kvm_path: Path) -> str:
    """KVM must work when the collector runs under it; TCG needs nothing."""
    if collector.accel == "kvm":
        return _check_kvm(kvm_path)
    return (f"collector runs under TCG (exec slowdown "
            f"{collector.exec_slowdown}); KVM is not used")


def _check_command(config, *, which: Callable[[str], str | None]) -> str:
    binary = _executable(config.argv[0], which=which)
    if not config.cwd.is_dir():
        raise PreflightError(f"command cwd is not a directory: {config.cwd}")
    if not os.access(config.cwd, os.X_OK):
        raise PreflightError(f"command cwd is not searchable: {config.cwd}")
    joined = "\0".join(config.argv)
    missing = [value for value in ("{input}", "{output}")
               if value not in joined]
    if missing:
        raise PreflightError("command argv lacks " + ", ".join(missing))
    return f"command={binary} cwd={config.cwd}"


def _command_option(argv: tuple[str, ...], name: str, default: str) -> str:
    """Read one trusted step option without executing the command parser."""
    values: list[str] = []
    for index, argument in enumerate(argv):
        if argument == name:
            if index + 1 >= len(argv):
                raise PreflightError(f"Stage 2 command {name} lacks a value")
            values.append(argv[index + 1])
        elif argument.startswith(name + "="):
            values.append(argument.removeprefix(name + "="))
    if len(values) > 1:
        raise PreflightError(f"Stage 2 command repeats {name}")
    return values[0] if values else default


def _check_stage2_timeout(config, collector: CollectorConfig,
                          policies: tuple[JobPolicy, ...]) -> str:
    """Ensure the outer supervisor cannot preempt an inner step watchdog."""
    try:
        slowdown = int(_command_option(config.argv, "--exec-slowdown",
                                       str(collector.exec_slowdown)))
        campaign = float(_command_option(
            config.argv, "--campaign-timeout", "1800"))
        manager_stop = float(_command_option(
            config.argv, "--manager-stop-timeout", "45"))
    except ValueError as exc:
        raise PreflightError(
            "Stage 2 command has a non-numeric timeout option"
        ) from exc
    if not 1 <= slowdown <= 1000:
        raise PreflightError("Stage 2 command exec slowdown must be in [1, 1000]")
    repetitions = max(policy.gate_repetitions for policy in policies)
    try:
        budget = stage2_timeout_budget(
            collector, exec_slowdown=slowdown,
            gate_repetitions=repetitions, campaign_timeout_s=campaign,
            manager_stop_timeout_s=manager_stop)
    except (OverflowError, ValueError) as exc:
        raise PreflightError(str(exc)) from exc
    supervisor_reserve = ProcessLimits().stop_reserve_s
    required = budget.required_s + supervisor_reserve
    if config.timeout_s < required:
        raise PreflightError(
            f"Stage 2 supervisor timeout {config.timeout_s:g}s is below the "
            f"configured lease budget {budget.required_s:g}s plus "
            f"supervisor stop reserve {supervisor_reserve:g}s "
            f"(gate={budget.gate_s:g}s, replay={budget.replay_s:g}s, "
            f"campaign={budget.campaign_s:g}s, slowdown={slowdown}, "
            f"gate_repetitions={repetitions})")
    return (f"supervisor timeout {config.timeout_s:g}s covers lease budget "
            f"{budget.required_s:g}s plus stop reserve "
            f"{supervisor_reserve:g}s (gate={budget.gate_s:g}s, "
            f"replay={budget.replay_s:g}s, campaign={budget.campaign_s:g}s, "
            f"slowdown={slowdown}, "
            f"gate_repetitions={repetitions})")


def _check_profiles(store: ArtifactStore, config) -> str:
    load_record(store, config.m1_profile_ref, M1JudgeProfile)
    load_record(store, config.q2_profile_ref, Q2JudgeProfile)
    load_record(store, config.replay_profile_ref, ReplayJudgeProfile)
    return "M1, Q2 and replay profiles are canonical and present"


def _verify_pins_read_only(collector: CollectorConfig, descriptor) -> None:
    # PinCache writes on a miss.  Preflight must leave the collector's
    # persistent cache and all pipeline state untouched.
    verify_pins(collector.model_copy(update={"pin_cache": None}), descriptor)


_MANAGER_PIN_NAMES = ("bzimage", "kernel", "lane-script", "vm-image",
                      "syz-execprog", "syz-executor", "syz-manager")


def _approved_harness(
    store: ArtifactStore, harness_id: str,
    descriptor: ExecutionHarnessDescriptor,
) -> _ApprovedHarness:
    builds = {item.name: item.artifact_ref
              for item in descriptor.build_artifacts}
    pins: list[tuple[str, HostFilePin]] = []
    for name in _MANAGER_PIN_NAMES:
        ref = builds.get(name)
        if ref is None:
            raise PreflightError(
                f"approved harness {harness_id[:12]} lacks {name}")
        pin = load_record(store, ref, HostFilePin)
        if pin.name != name:
            raise PreflightError(f"pin for {name} names {pin.name}")
        pins.append((name, pin))
    return _ApprovedHarness(
        harness_id=harness_id,
        command_line=tuple(descriptor.guest_kernel_command_line.split()),
        pins=tuple(pins),
        fixtures=_stage2_fixtures(descriptor.allowed_runtime_selections))


def _stage2_fixtures(selections) -> frozenset[tuple[str, str]]:
    """The koov arguments that boot each selection Stage 2 may run, as
    stage1/host/collector.py guest_cmdline writes them."""
    return frozenset(
        (f"koov.nfs_version={s.nfs_version}" if s.fixture_mode == "single"
         else f"koov.nfs_fixture={s.fixture_mode}",
         "1" if s.trace_mode == "on" else "0")
        for s in selections if s.fixture_mode not in _STAGE1_ONLY_FIXTURES)


def _check_harnesses(
    store: ArtifactStore, config: Stage1Config, collector: CollectorConfig,
) -> tuple[tuple[PromotedSemanticCapabilityRegistry, ...],
           tuple[_ApprovedHarness, ...]]:
    approvals = [load_record(store, ref, ExecutionHarnessApproval)
                 for ref in config.execution_harness_approvals]
    by_descriptor = {descriptor_id(item.descriptor): item
                     for item in approvals}
    if len(by_descriptor) != len(approvals):
        raise PreflightError("duplicate execution harness approval")
    catalog = load_record(store, config.harness_catalog_ref, HarnessCatalog)
    if not catalog.registrations:
        raise PreflightError("harness catalog has no registrations")
    checker = ArtifactHcapChecker(store)
    promoted: list[PromotedSemanticCapabilityRegistry] = []
    harnesses: list[_ApprovedHarness] = []
    checked_descriptors: set[str] = set()
    authorities: dict[str, list[tuple[HcapCatalog, CallAdmissionProfile]]] = {}
    for registration in catalog.registrations:
        binding = registration.binding
        approval = by_descriptor.get(binding.execution_harness_id)
        if approval is None:
            raise PreflightError(
                f"{binding.execution_harness_id[:12]} has no configured approval")
        descriptor = approval.descriptor
        if (descriptor.kernel_commit != binding.kernel_commit
                or descriptor.sanitizer != binding.sanitizer):
            raise PreflightError("harness binding differs from its descriptor")
        if binding.hcap_revision not in approval.approved_hcap_revisions:
            raise PreflightError("harness binding uses an unapproved HCAP")
        hcap = checker.load_catalog(binding.hcap_revision)
        registry = promoted_registry(store, hcap)
        if registry is None:
            raise PreflightError(
                f"HCAP {binding.hcap_revision[:12]} has no promoted semantic subset")
        promoted.append(registry)
        profiles = [ref.artifact_ref for ref in (
            *hcap.authority_refs,
            *(ref for cap in hcap.capabilities for ref in cap.authority_refs))
            if ref.kind == "CallAdmissionProfile"]
        if len(set(profiles)) != 1:
            raise PreflightError(
                f"HCAP {binding.hcap_revision[:12]} pins no single call "
                "admission profile")
        authorities.setdefault(binding.execution_harness_id, []).append(
            (hcap, load_record(store, profiles[0], CallAdmissionProfile)))
        if binding.execution_harness_id not in checked_descriptors:
            _verify_pins_read_only(collector, descriptor)
            harnesses.append(_approved_harness(
                store, binding.execution_harness_id, descriptor))
            checked_descriptors.add(binding.execution_harness_id)
        tokens = descriptor.guest_kernel_command_line.split()
        if "nokaslr" not in tokens or "nfs.localio_enabled=N" not in tokens:
            raise PreflightError(
                "Stage 2 harness requires nokaslr and nfs.localio_enabled=N")
    return tuple(promoted), tuple(
        replace(harness, authorities=tuple(authorities[harness.harness_id]))
        for harness in harnesses)


def _check_layout(value: dict, procs: int,
                  harnesses: tuple[_ApprovedHarness, ...]) -> None:
    """The manager's procs and calls stay inside the validated layouts of
    every bound HCAP's capabilities (#99)."""
    calls = value.get("enable_syscalls")
    if calls is not None and (not isinstance(calls, list) or not all(
            isinstance(call, str) for call in calls)):
        raise PreflightError("manager enable_syscalls must be a list of calls")
    for harness in harnesses:
        for hcap, profile in harness.authorities:
            # Without enable_syscalls syz-manager enables every call.
            enabled = (calls if calls is not None
                       else [entry.call for entry in profile.entries])
            refusals = layout_refusals(
                hcap, profile.entries, enabled_calls=enabled,
                runtime_features=("remote_cover",), procs=procs)
            if refusals:
                raise PreflightError(
                    f"manager at {procs} proc(s) exceeds a validated "
                    f"layout: {refusals[0]}")


def _check_runtime(
    path: Path, promoted: tuple[PromotedSemanticCapabilityRegistry, ...],
    *, reader: Callable[[Path], BuildRegistry],
) -> BuildRegistry:
    build = reader(path)
    mismatched = [item.proxy_sha256[:12] for item in promoted
                  if not check_runtime(item, build)]
    if mismatched:
        raise PreflightError(
            "runtime is not the promoted Proxy build for: "
            + ", ".join(mismatched))
    return build


def _check_kernel_repo(config: Stage1Config) -> str:
    if not config.kernel_repo.is_dir():
        raise PreflightError(f"kernel repository is absent: {config.kernel_repo}")
    run = subprocess.run(
        ["git", "-C", str(config.kernel_repo), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=30)
    if run.returncode != 0:
        raise PreflightError("kernel repository has no readable HEAD")
    head = run.stdout.strip()
    if not config.artifact_root.is_dir():
        raise PreflightError(f"artifact root is absent: {config.artifact_root}")
    store = ArtifactStore(config.artifact_root)
    catalog = load_record(store, config.harness_catalog_ref, HarnessCatalog)
    commits = {item.binding.kernel_commit for item in catalog.registrations}
    if head not in commits:
        raise PreflightError(
            f"kernel HEAD {head[:12]} is not registered in the harness catalog")
    return f"kernel HEAD {head[:12]} is registered"


_POLICY_DEFAULTS = (1, 1000, 10000, 100, 100000)


def _policy_values(policy: JobPolicy) -> tuple[int, ...]:
    return (policy.gate_repetitions,
            policy.campaign_not_applied_generations,
            policy.campaign_no_signal_generations,
            policy.campaign_inconclusive_generations,
            policy.fuzz_budget_executions)


def _check_policies(policies: tuple[JobPolicy, ...], checks: _Checks) -> None:
    enabled = [p.policy_id for p in policies
               if p.campaign_mode is CampaignMode.MUTATE]
    if enabled:
        checks.add("stage2_policy", "pass",
                   "automatic Stage 2 enabled for: " + ", ".join(enabled))
    else:
        checks.add("stage2_policy", "warning",
                   "no policy has campaign_mode mutate; use operator start_stage2")
    defaults = [p.policy_id for p in policies
                if _policy_values(p) == _POLICY_DEFAULTS]
    if defaults:
        checks.add("campaign_policy", "warning",
                   "placeholder Stage 2 thresholds remain for: "
                   + ", ".join(defaults))
    else:
        checks.add("campaign_policy", "pass",
                   "Stage 2 thresholds differ from repository placeholders")


def _required_path(value: dict, name: str, *, parent: str = "manager") -> Path:
    raw = value.get(name)
    if not isinstance(raw, str) or not raw:
        raise PreflightError(f"{parent} config lacks {name}")
    return Path(raw)


def _bind_manager_command(path: Path, command) -> None:
    expected = path.resolve(strict=True)
    cwd = Path(command.cwd)
    for argument in command.argv[1:]:
        if "{" in argument or "}" in argument:
            continue
        candidate = Path(argument)
        if not candidate.is_absolute():
            candidate = cwd / candidate
        try:
            if candidate.resolve(strict=True) == expected:
                return
        except OSError:
            continue
    raise PreflightError(
        "manager config must be an explicit Stage 2 command argument")


# A manager boots one fixture of an approved runtime selection (#81 D17):
# koov.nfs_version for a single fixture, koov.nfs_fixture otherwise, with
# that selection's koov.nfs_trace.  nlm-knfsd is a Stage 1 reachability
# fixture (HCAP-13); a Stage 2 manager command line selecting it is refused.
_STAGE1_ONLY_FIXTURES = frozenset({"nlm-knfsd"})
_SELECTION_KEYS = ("koov.nfs_fixture", "koov.nfs_version")


def _check_approved_command_line(
    actual: list[str], harnesses: tuple[_ApprovedHarness, ...],
) -> None:
    base: list[str] = []
    dynamic: dict[str, str] = {}
    for token in actual:
        key, separator, value = token.partition("=")
        if not key.startswith("koov."):
            base.append(token)
            continue
        if key == "koov.lane_sha256":
            allowed = bool(separator and len(value) == 64
                           and all(c in "0123456789abcdef" for c in value))
        elif key == "koov.nfs_target":
            allowed = token == "koov.nfs_target=1"
        elif key == "koov.nfs_trace":
            allowed = value in ("0", "1") and separator == "="
        else:
            allowed = key in _SELECTION_KEYS and separator == "="
        if not allowed or key in dynamic:
            raise PreflightError(
                f"manager VM cmdline has unapproved dynamic argument {token}")
        dynamic[key] = value
    selection = [f"{key}={dynamic[key]}" for key in _SELECTION_KEYS
                 if key in dynamic]
    if len(selection) != 1:
        raise PreflightError(
            "manager VM cmdline must select one approved NFS fixture")
    for required in ("koov.lane_sha256", "koov.nfs_target"):
        if required not in dynamic:
            raise PreflightError(
                f"manager VM cmdline lacks approved {required}")
    trace = dynamic.get("koov.nfs_trace")
    for harness in harnesses:
        if tuple(base) != harness.command_line:
            raise PreflightError(
                "manager VM base cmdline differs from the approved command line")
        if not any(fixture == selection[0] and trace in (None, mode)
                   for fixture, mode in harness.fixtures):
            raise PreflightError(
                f"manager VM fixture {selection[0]} (koov.nfs_trace={trace}) "
                "is no Stage 2 runtime selection of approved harness "
                f"{harness.harness_id[:12]}")


def _manager_harnesses(
    value: dict, vm: dict, harnesses: tuple[_ApprovedHarness, ...],
) -> tuple[_ApprovedHarness, ...]:
    """The approved harnesses whose kernel the manager boots.  Sanitizer
    variants (#81 D10) share every other file, so one manager runs one
    variant."""
    if not harnesses:
        raise PreflightError("no approved harness is available")
    kernel = _required_path(value, "kernel_obj") / "vmlinux"
    bzimage = _required_path(vm, "kernel", parent="manager VM")
    try:
        actual = {"kernel": (file_sha256(kernel), kernel.stat().st_size),
                  "bzimage": (file_sha256(bzimage), bzimage.stat().st_size)}
    except OSError as exc:
        raise PreflightError(f"manager kernel is unreadable: {exc}") from exc
    matched = tuple(
        harness for harness in harnesses
        if all((harness.pin(name).sha256, harness.pin(name).size) == ident
               for name, ident in actual.items()))
    if not matched:
        raise PreflightError(
            "manager kernel and bzImage are no approved harness's")
    return matched


def _check_manager_assets(
    value: dict, vm: dict, collector: CollectorConfig,
    harnesses: tuple[_ApprovedHarness, ...],
    *, expected_target: str, which: Callable[[str], str | None],
) -> None:
    kernel_obj = _required_path(value, "kernel_obj")
    syzkaller = _required_path(value, "syzkaller")
    if value.get("target") != expected_target:
        raise PreflightError(
            f"manager target must be the approved {expected_target}")
    os_name, separator, arch = expected_target.partition("/")
    if not separator or not os_name or not arch:
        raise PreflightError(f"unsupported approved target: {expected_target}")
    target_bin = syzkaller / "bin" / f"{os_name}_{arch}"
    files = {
        "bzimage": _required_path(vm, "kernel", parent="manager VM"),
        "kernel": kernel_obj / "vmlinux",
        "lane-script": _required_path(value, "workdir_template") / "lane.sh",
        "vm-image": _required_path(value, "image"),
        "syz-execprog": target_bin / "syz-execprog",
        "syz-executor": target_bin / "syz-executor",
        "syz-manager": syzkaller / "bin/syz-manager",
    }
    for name, manager_file in files.items():
        pins = [harness.pin(name) for harness in harnesses]
        identities = {(pin.sha256, pin.size) for pin in pins}
        if len(identities) != 1:
            raise PreflightError(
                f"approved harnesses disagree on the {name} identity")
        verify_file(pins[0], manager_file)
    _executable(files["syz-manager"], which=which)

    manager_key = _required_path(value, "sshkey")
    if not manager_key.is_file() or not collector.ssh_key.is_file():
        raise PreflightError("manager and collector SSH keys must be files")
    if manager_key.resolve(strict=True) != collector.ssh_key.resolve(strict=True):
        raise PreflightError("manager SSH key differs from the collector SSH key")

    collector_qemu = _executable(collector.qemu, which=which).resolve(strict=True)
    manager_qemu = _executable(vm.get("qemu", collector.qemu),
                               which=which).resolve(strict=True)
    if manager_qemu != collector_qemu:
        raise PreflightError("manager QEMU differs from the collector QEMU")


def _check_manager(
    path: Path, crash_window_bound: int, *, command,
    collector: CollectorConfig, harnesses: tuple[_ApprovedHarness, ...],
    expected_target: str, which: Callable[[str], str | None],
) -> str:
    raw = path.read_bytes()
    value = parse_json(raw)
    if not isinstance(value, dict):
        raise PreflightError("manager config is not a JSON object")
    if value.get("type") != "qemu":
        raise PreflightError("manager config type must be qemu")
    # The lane target is mounted in the executor's mount namespace at
    # /nfs-lane.  The mgrconfig default is already "none"; a manager that
    # explicitly selects another sandbox must not silently bypass that.
    if value.get("sandbox", "none") != "none":
        raise PreflightError("manager sandbox must be none for the NFS lane")
    if "snapshot" in value and value["snapshot"] is not False:
        raise PreflightError("manager program snapshot mode must be false")
    experimental = value.get("experimental")
    if not isinstance(experimental, dict):
        raise PreflightError("manager config lacks experimental settings")
    if experimental.get("remote_cover") is not True:
        raise PreflightError("experimental.remote_cover must be true")
    window = experimental.get("nfs_proxy_window")
    if type(window) is not int or window < crash_window_bound:
        raise PreflightError(
            f"experimental.nfs_proxy_window must be at least {crash_window_bound}")
    vm = value.get("vm")
    if not isinstance(vm, dict) or vm.get("count", 1) != 1:
        raise PreflightError("target-mode campaign requires vm.count 1")
    procs = value.get("procs")
    if type(procs) is not int or not 1 <= procs <= 64:
        raise PreflightError("target-mode campaign requires procs in [1, 64]")
    harnesses = _manager_harnesses(value, vm, harnesses)
    _check_layout(value, procs, harnesses)
    cmdline = str(vm.get("cmdline", "")).split()
    _check_approved_command_line(cmdline, harnesses)
    template_value = value.get("workdir_template")
    if not isinstance(template_value, str) or not template_value:
        raise PreflightError("manager config lacks workdir_template")
    template = Path(template_value)
    lane_script = template / "lane.sh"
    if not lane_script.is_file():
        raise PreflightError(f"manager lane script is absent: {lane_script}")
    lane_digest = file_sha256(lane_script)
    lane_tokens = [token.removeprefix("koov.lane_sha256=")
                   for token in cmdline
                   if token.startswith("koov.lane_sha256=")]
    if lane_tokens != [lane_digest]:
        raise PreflightError("manager lane script differs from koov.lane_sha256")
    qemu_args = str(vm.get("qemu_args", ""))
    if accel_of(qemu_args) != collector.accel:
        raise PreflightError(
            f"manager QEMU args do not select the collector's {collector.accel}")
    journal_names = {
        part.removeprefix("name=")
        for token in qemu_args.split()
        for part in token.split(",")
        if part.startswith("name=")
    }
    missing = [str(lane) for lane in range(procs)
               if f"nfsp-journal-{lane}" not in journal_names]
    if missing:
        raise PreflightError(
            "manager QEMU args lack journal channels for lanes: "
            + ", ".join(missing))
    _bind_manager_command(path, command)
    _check_manager_assets(value, vm, collector, harnesses,
                          expected_target=expected_target, which=which)
    digest = hashlib.sha256(raw).hexdigest()
    return (f"manager sha256={digest}, window={window}, {procs} proc(s), "
            "approved assets, target mode and journal channels enabled")


def preflight(
    stage1_path: Path, *, collector_path: Path | None = None,
    manager_path: Path | None = None, kvm_path: Path = Path("/dev/kvm"),
    which: Callable[[str], str | None] = shutil.which,
    runtime_reader: Callable[[Path], BuildRegistry] = read_build_registry,
) -> PreflightReport:
    """Check one deployment without running a candidate or changing state."""
    checks = _Checks()
    try:
        config = Stage1Config.load(stage1_path)
    except (OSError, ValueError, TypeError) as exc:
        checks.add("stage1_config", "error", f"{type(exc).__name__}: {exc}")
        return PreflightReport(ready=False, checks=tuple(checks.items))
    checks.add("stage1_config", "pass", f"loaded {stage1_path}")
    stage2 = config.stage2
    if stage2 is None:
        checks.add("stage2_config", "error", "Stage1Config.stage2 is unset")
        return PreflightReport(ready=False, checks=tuple(checks.items))
    checks.add("stage2_config", "pass", "Stage 2 backend is configured")

    collector_file = collector_path or Path(config.state_dir) / "collector.json"
    try:
        collector = CollectorConfig.load(collector_file)
    except (OSError, ValueError, TypeError) as exc:
        checks.add("collector_config", "error", f"{type(exc).__name__}: {exc}")
        return PreflightReport(ready=False, checks=tuple(checks.items))
    checks.add("collector_config", "pass", f"loaded {collector_file}")

    checks.attempt("accel", lambda: _check_accel(collector, kvm_path))
    checks.attempt("stage2_command",
                   lambda: _check_command(stage2, which=which))
    checks.attempt("stage2_timeout",
                   lambda: _check_stage2_timeout(
                       stage2, collector, config.policies))
    checks.attempt("qemu", lambda: f"qemu={_executable(collector.qemu, which=which)}")
    checks.attempt("ssh", lambda: f"ssh={_executable('ssh', which=which)}")
    checks.attempt("scp", lambda: f"scp={_executable('scp', which=which)}")
    checks.attempt("kernel_repo", lambda: _check_kernel_repo(config))

    promoted: tuple[PromotedSemanticCapabilityRegistry, ...] = ()
    harnesses: tuple[_ApprovedHarness, ...] = ()
    try:
        if not config.artifact_root.is_dir():
            raise PreflightError(f"artifact root is absent: {config.artifact_root}")
        if not collector.artifact_root.is_dir():
            raise PreflightError(
                f"collector artifact root is absent: {collector.artifact_root}")
        store = ArtifactStore(config.artifact_root)
        _check_profiles(store, stage2)
        promoted, harnesses = _check_harnesses(store, config, collector)
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        checks.add("authority", "error", f"{type(exc).__name__}: {exc}")
    else:
        checks.add("authority", "pass",
                   f"{len(promoted)} harness binding(s), profiles and pins verified")

    compiler_build: BuildRegistry | None = None
    replay_build: BuildRegistry | None = None
    if config.nfs_proxy is None:
        checks.add("compiler_proxy", "error", "Stage1Config.nfs_proxy is unset")
    elif promoted:
        try:
            _executable(config.nfs_proxy, which=which)
            compiler_build = _check_runtime(config.nfs_proxy, promoted,
                                            reader=runtime_reader)
        except (OSError, ValueError, TypeError, RuntimeError,
                subprocess.SubprocessError) as exc:
            checks.add("compiler_proxy", "error",
                       f"{type(exc).__name__}: {exc}")
        else:
            checks.add("compiler_proxy", "pass",
                       f"promoted build {compiler_build.proxy_sha256[:12]}")
    if promoted:
        try:
            _executable(stage2.replay_proxy, which=which)
            replay_build = _check_runtime(stage2.replay_proxy, promoted,
                                          reader=runtime_reader)
        except (OSError, ValueError, TypeError, RuntimeError,
                subprocess.SubprocessError) as exc:
            checks.add("replay_proxy", "error",
                       f"{type(exc).__name__}: {exc}")
        else:
            checks.add("replay_proxy", "pass",
                       f"promoted build {replay_build.proxy_sha256[:12]}")
    if compiler_build is not None and replay_build is not None:
        if compiler_build != replay_build:
            checks.add("proxy_identity", "error",
                       "compiler and replay Proxy registries differ")
        else:
            checks.add("proxy_identity", "pass",
                       "compiler and replay use the same promoted build")

    if config.slots is not None:
        checks.add("resource_key", "pass",
                   "Stage 1 and Stage 2 share the host's KVM slot pool")
    elif stage2.resource_key == config.engine.resource_key:
        checks.add("resource_key", "pass",
                   "Stage 1 and Stage 2 share one KVM resource fence")
    else:
        checks.add("resource_key", "warning",
                   "Stage 1 and Stage 2 use different resource keys")
    _check_policies(config.policies, checks)
    if manager_path is None:
        checks.add("manager_config", "error",
                   "manager config is required for Stage 2 readiness")
    else:
        checks.attempt("manager_config",
                       lambda: _check_manager(manager_path,
                                              stage2.crash_window_bound,
                                              command=stage2,
                                              collector=collector,
                                              harnesses=harnesses,
                                              expected_target=(
                                                  config.syzkaller_identity.target),
                                              which=which))
    ready = not any(item.status == "error" for item in checks.items)
    return PreflightReport(ready=ready, checks=tuple(checks.items))


def _print(report: PreflightReport) -> None:
    for item in report.checks:
        marker = {"pass": "PASS", "warning": "WARN", "error": "FAIL"}[
            item.status]
        print(f"[{marker}] {item.name}: {item.detail}")
    print("READY" if report.ready else "NOT READY")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agent_pipeline.stage2.host",
        description="Stage 2 KVM readiness checks and host step runner")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("preflight")
    check.add_argument("--stage1", type=Path, required=True)
    check.add_argument("--collector", type=Path)
    check.add_argument("--manager", type=Path, required=True)
    check.add_argument("--kvm", type=Path, default=Path("/dev/kvm"))
    check.add_argument("--json", action="store_true")
    step = sub.add_parser("step")
    step.add_argument("--manager", type=Path, required=True)
    step.add_argument("--collector", type=Path, required=True)
    step.add_argument("--campaign-executions", type=int, default=128)
    step.add_argument("--campaign-timeout", type=float, default=1800)
    step.add_argument("--manager-stop-timeout", type=float, default=45)
    step.add_argument("--exec-slowdown", type=int, default=None,
                      help="syz-execprog slowdown for direct gate/replay VMs "
                           "(default: the collector's)")
    step.add_argument("input", type=Path)
    step.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    if args.command == "step":
        from .kvm import StepOptions, run_step
        run_step(StepOptions(
            manager=args.manager, collector=args.collector,
            campaign_executions=args.campaign_executions,
            campaign_timeout_s=args.campaign_timeout,
            manager_stop_timeout_s=args.manager_stop_timeout,
            exec_slowdown=args.exec_slowdown),
            args.input, args.output)
        return 0
    report = preflight(args.stage1, collector_path=args.collector,
                       manager_path=args.manager, kvm_path=args.kvm)
    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        _print(report)
    return 0 if report.ready else 2


if __name__ == "__main__":
    sys.exit(main())
