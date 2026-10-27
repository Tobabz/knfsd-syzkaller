"""M7 stage 1 of a generated semantic subset (07 §5.2; 03-nfs-proxy/06 §30).

A Harness Generation patch set for a ``mutation_engine`` gap changes the
Proxy.  Its validation pins the subset the patch set declares, with crash
survival pending, in the staged revision's HCAP-10
(``semantic_promotion.pin``).  The patch set supplies data only, under
``stage1-host/generation/<gap id>/``:

``subset.json``
    the ``SemanticSubset`` it implements;
``rules.nfsprul1``
    a rule set inside the subset that exercises every element of it;
``production.syz``
    the program that makes those rules fire.

The host does the rest, the way an operator does it with
``semantic_promotion record`` and ``pin``:

1. the build registry of the patch set's guest Proxy (``--capability
   -registry``), and the subset inside it;
2. production: a fresh guest in target mode with the rule set on lane 0,
   its MutationDelta journal on a host sink, ``production.syz`` run once.
   The guest's ``/usr/sbin/nfs-proxy`` must be the Proxy of step 1.  The
   window ends when the host stops the VM: no crash is made (§30);
3. the replay plan of that window (``replay_runner.execprog_window``), the
   compatibility gate, and the replay in another fresh guest on its own
   journal;
4. ``judge_input`` and ``evaluate`` over both sealed journals, the
   ``GuestValidationRun`` record, and ``pin``.

``SemanticGuest`` is the guest side; ``KvmSemanticGuest`` boots the staged
build as ``collect`` does, with the Stage 2 journal channels.

The host copy of the patch set's Proxy is staged beside the harness files,
under the collector's ``staged_files`` by its digest (``stage_proxy``):
M7 stage 2 reads a natural crash's rule set with it (``stage2/semantic.py``).
"""

from __future__ import annotations

import os
import shlex
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from ...artifacts import ArtifactStore
from ...data import put_record
from ...hcap import HcapCatalog, RuntimeSelection
from ...materializer import ExecutionHarnessDescriptor
from ...replay_runner import (PlanError, check_rule_set, execprog_window,
                              judge_input, parse_execprog_barriers,
                              plan_replay, write_replay_inputs)
from ...semantic_delta import DeltaReadError, SealedJournal
from ...semantic_promotion import (GuestValidationRun,
                                   PromotedSemanticCapabilityRegistry,
                                   PromotionRefused, RegistryError,
                                   SemanticSubset, describe_rule_set,
                                   dynamic_originals, pin, promoted_registry,
                                   read_build_registry, subset_problems,
                                   with_semantic_capability)
from ...semantic_replay import ReplayJudgeProfile, Termination, evaluate
from .collector import (GUEST_DIR, CollectorConfig, _checked, _fixture_ready,
                        crash_report, execprog_timeout, guest_cmdline,
                        run_lane)
from .pins import file_sha256
from .vm import QemuGuest, VmConfig

SUBSET = "subset.json"
RULES = "rules.nfsprul1"
PRODUCTION = "production.syz"
#: Where the guest image keeps the Proxy (``tools/bootstrap-kcov-env.py``).
GUEST_PROXY = "/usr/sbin/nfs-proxy"
PROFILE = ReplayJudgeProfile(name="replay-default", revision="1")
#: The host Proxy's name under ``<staged_files>/<sha256>/``.
STAGED_PROXY = "nfs-proxy"


class SemanticRefused(Exception):
    """The patch set's subset does not pass the staged pin."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason, self.detail = reason, detail


@dataclass(frozen=True)
class SideRun:
    """One side of the window: where its journal is and how it ended."""

    journal_dir: Path
    journal_name: str
    vm_instance_id: str
    execprog_output: str
    termination: Termination
    fixture_failed: bool = False


class SemanticGuest(Protocol):
    def production(self, program: Path, rules: bytes, work: Path) -> SideRun:
        ...

    def replay(self, programs: Path, rules: bytes, work: Path) -> SideRun:
        ...


@dataclass(frozen=True)
class SemanticInputs:
    subset: SemanticSubset
    rules: bytes
    program: Path


def read_inputs(directory: Path) -> SemanticInputs:
    """The patch set's subset, rule set and production program."""
    missing = [n for n in (SUBSET, RULES, PRODUCTION)
               if not (directory / n).is_file()]
    if missing:
        raise SemanticRefused("semantic_input_missing", ", ".join(missing))
    try:
        subset = SemanticSubset.model_validate_json(
            (directory / SUBSET).read_bytes())
    except ValueError as exc:
        raise SemanticRefused("semantic_subset_malformed", str(exc)) from exc
    return SemanticInputs(subset, (directory / RULES).read_bytes(),
                          directory / PRODUCTION)


def staged_pin(store: ArtifactStore, proxy: Path, inputs: SemanticInputs,
               guest: SemanticGuest, work: Path, *, kernel_commit: str,
               base_hcap: HcapCatalog | None = None,
               launcher: tuple[str, ...] = ()
               ) -> tuple[PromotedSemanticCapabilityRegistry, str]:
    """Pin ``inputs.subset`` on ``proxy``'s build: the pinned registry and
    the run it rests on.  The base revision's promoted registry is kept
    when the build is the same; another build starts afresh (§30).  The
    patch set built ``proxy``: it runs under ``launcher``."""
    try:
        build = read_build_registry(proxy, launcher=launcher)
    except (OSError, RegistryError) as exc:
        raise SemanticRefused("proxy_registry_unavailable", str(exc)) from exc
    problems = subset_problems(inputs.subset, build.registry)
    if problems:
        raise SemanticRefused("semantic_subset_not_built", "; ".join(problems))
    work.mkdir(parents=True, exist_ok=True)
    production = guest.production(inputs.program, inputs.rules,
                                  work / "production")
    program = inputs.program.read_text()
    try:
        journal = SealedJournal(production.journal_dir,
                                production.journal_name)
        window = execprog_window(
            production.execprog_output, (program,),
            vm_instance_id=production.vm_instance_id, lane_id=0, bound=1)
        plan = plan_replay(journal, window)
    except (PlanError, DeltaReadError) as exc:
        raise SemanticRefused("semantic_production_unplanned",
                              str(exc)) from exc
    if plan.rule_set != inputs.rules:
        raise SemanticRefused("semantic_rules_not_recorded")
    compat = check_rule_set(proxy, plan.rule_set, work, launcher=launcher)
    paths = write_replay_inputs(plan, work / "replay-inputs")
    replay = guest.replay(paths["programs"], plan.rule_set, work / "replay")
    try:
        replay_journal = SealedJournal(replay.journal_dir, replay.journal_name)
        data = judge_input(
            plan, journal, replay_journal,
            replay_vm_instance_id=replay.vm_instance_id, replay_lane_id=0,
            replay_barriers=parse_execprog_barriers(replay.execprog_output),
            production_termination=production.termination,
            replay_termination=replay.termination, compatibility=compat,
            evidence_verified=True, profile=PROFILE,
            fixture_failed=replay.fixture_failed)
    except (PlanError, DeltaReadError) as exc:
        raise SemanticRefused("semantic_replay_unjudged", str(exc)) from exc
    run = GuestValidationRun(
        subset_id=inputs.subset.subset_id, environment="kvm_guest",
        proxy_sha256=build.proxy_sha256,
        registry_digest=build.registry_digest, kernel_commit=kernel_commit,
        production_vm_instance_id=production.vm_instance_id,
        replay_vm_instance_id=replay.vm_instance_id,
        rule_set=describe_rule_set(proxy, plan.rule_set, work,
                                   launcher=launcher),
        judge_input=data, replay_result=evaluate(data),
        original_values=dynamic_originals(journal, replay_journal, data),
        note="Harness Generation validation (07 §5.2)")
    if run.rule_set.rule_set_id != data.rule_set_id:
        raise SemanticRefused("semantic_rules_not_recorded")
    run_ref = put_record(store, run)
    put_record(store, build)
    previous = promoted_registry(store, base_hcap) \
        if base_hcap is not None else None
    if previous is not None and \
            (previous.proxy_sha256, previous.registry_digest) != \
            (build.proxy_sha256, build.registry_digest):
        previous = None
    try:
        pinned = pin(store, build, inputs.subset, (run_ref,), previous)
    except PromotionRefused as refused:
        raise SemanticRefused("semantic_pin_refused",
                              "\n".join(refused.problems)) from refused
    return pinned, run_ref


def pinned_hcap(store: ArtifactStore, hcap: HcapCatalog,
                pinned: PromotedSemanticCapabilityRegistry) -> HcapCatalog:
    """The staged revision with the pinned registry in its HCAP-10."""
    return with_semantic_capability(hcap, put_record(store, pinned), pinned)


def staged_proxy(root: Path, proxy_sha256: str) -> Path:
    """Where ``stage_proxy`` keeps the host Proxy of this digest."""
    return root / proxy_sha256 / STAGED_PROXY


def stage_proxy(root: Path, proxy: Path) -> Path:
    """Copy the patch set's host Proxy under ``root`` by its digest, read
    only, unless it is there already."""
    digest = file_sha256(proxy)
    dest = staged_proxy(root, digest)
    if dest.is_file():
        if file_sha256(dest) != digest:
            raise SemanticRefused("staged_proxy_differs", str(dest))
        return dest
    tmp = dest.parent.with_name(f"{dest.parent.name}.{os.getpid()}")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    shutil.copyfile(proxy, tmp / STAGED_PROXY)
    (tmp / STAGED_PROXY).chmod(0o555)
    try:
        tmp.rename(dest.parent)
    except OSError:
        shutil.rmtree(tmp, ignore_errors=True)
        if not dest.is_file():
            raise
    return dest


# ---------------------------------------------------------------- KVM


class KvmSemanticGuest:
    """Both sides on the staged build, each in a fresh guest in target mode
    with its MutationDelta journal on a host sink."""

    def __init__(self, descriptor: ExecutionHarnessDescriptor,
                 collector: CollectorConfig, files: dict[str, Path],
                 selection: RuntimeSelection, lane_sha256: str,
                 proxy_sha256: str, *,
                 guest_factory: Callable[[VmConfig], object] = QemuGuest,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.descriptor, self.collector, self.files = \
            descriptor, collector, files
        self.selection, self.lane_sha256 = selection, lane_sha256
        self.proxy_sha256 = proxy_sha256
        self.guest_factory, self.sleep = guest_factory, sleep
        self.cmdline = guest_cmdline(descriptor, selection, lane_sha256) + \
            " koov.nfs_target=1"

    def _guest(self, work: Path, rules: bytes, label: str):
        # The Stage 2 step's lane template and journal channels.
        from ...stage2.kvm import _JournalChannels, _lane_template
        vm = f"generation.{label}.{uuid.uuid4().hex[:12]}"
        prefix = f"{label[0]}l0-{uuid.uuid4().hex}"
        lane = _lane_template(self.files["lane-script"].parent, work / "lane",
                              rules, (prefix,))
        channels = _JournalChannels(work / "journal", label, vm, 1, rules,
                                    (prefix,))
        c = self.collector
        guest = self.guest_factory(VmConfig(
            qemu=c.qemu, bzimage=self.files["bzimage"],
            image=self.files["vm-image"], lane_dir=lane, ssh_key=c.ssh_key,
            cmdline=self.cmdline, console_log=work / "console.log",
            memory_mb=c.memory_mb, cpus=c.cpus,
            boot_timeout_s=c.boot_timeout_s, accel=c.accel,
            extra_args=channels.qemu_args(controller=True)))
        return vm, channels, guest

    def _same_proxy(self, guest) -> None:
        out = _checked(guest, f"sha256sum {GUEST_PROXY}")
        if out.split()[:1] != [self.proxy_sha256]:
            raise SemanticRefused(
                "guest_proxy_differs",
                f"{GUEST_PROXY} is not the patch set's Proxy: {out[:200]}")

    def production(self, program: Path, rules: bytes, work: Path) -> SideRun:
        work.mkdir(parents=True)
        vm, channels, guest = self._guest(work, rules, "production")
        try:
            try:
                lane = run_lane(guest, self.files, program, self.selection,
                                self.lane_sha256, self.collector, work, {},
                                self.sleep,
                                exec_slowdown=self.collector.exec_slowdown)
                if not lane.boot_ok:
                    raise SemanticRefused("vm_boot_failed",
                                          "; ".join(lane.runtime_errors))
                self._same_proxy(guest)
            finally:
                guest.stop()
        finally:
            channels.close()
        if crash_report(work, work / "console.log", self.descriptor):
            # A crash here is the patch set's: the production must run
            # clean, as the smoke programs of other gaps do.
            raise SemanticRefused("semantic_production_crashed")
        if not (lane.fixture_ok and lane.lane_ok and lane.runner_completed):
            raise SemanticRefused("semantic_production_failed",
                                  "; ".join(lane.runtime_errors))
        log = work / "executor.log"
        return SideRun(work / "journal", channels.name, vm,
                       log.read_text(errors="replace") if log.is_file()
                       else "", Termination.VM_TEARDOWN)

    def replay(self, programs: Path, rules: bytes, work: Path) -> SideRun:
        work.mkdir(parents=True)
        vm, channels, guest = self._guest(work, rules, "replay")
        c = self.collector
        output, fixture_failed = "", False
        try:
            try:
                guest.start()
                _checked(guest, "mountpoint -q /sys/kernel/debug || "
                                "mount -t debugfs none /sys/kernel/debug")
                if not _fixture_ready(guest, self.selection,
                                      self.lane_sha256, c.fixture_timeout_s,
                                      {}):
                    fixture_failed = True
                else:
                    self._same_proxy(guest)
                    _checked(guest, f"mkdir -p {GUEST_DIR}")
                    for name in ("syz-executor", "syz-execprog"):
                        guest.put(self.files[name], f"{GUEST_DIR}/{name}")
                    guest.put(programs, f"{GUEST_DIR}/programs.log")
                    _checked(guest, f"chmod 0755 {GUEST_DIR}/syz-executor "
                                    f"{GUEST_DIR}/syz-execprog")
                    _, output = guest.run(shlex.join([
                        f"{GUEST_DIR}/syz-execprog",
                        f"-executor={GUEST_DIR}/syz-executor", "-os=linux",
                        "-arch=amd64", "-vmarch=amd64", "-sandbox=none",
                        "-procs=1", "-repeat=1", "-threaded=false",
                        "-cover=true", "-remote-cover=true", "-disable=all",
                        "-debug", "-vv=1", f"-slowdown={c.exec_slowdown}",
                        f"{GUEST_DIR}/programs.log"]),
                        timeout=execprog_timeout(c.exec_timeout_s,
                                                 c.exec_slowdown))
            finally:
                guest.stop()
        finally:
            channels.close()
        (work / "execprog.log").write_text(output)
        ended = Termination.GUEST_CRASH if crash_report(
            work, work / "console.log", self.descriptor) else \
            Termination.VM_TEARDOWN
        return SideRun(work / "journal", channels.name, vm, output, ended,
                       fixture_failed)


__all__ = ["KvmSemanticGuest", "SemanticGuest", "SemanticInputs",
           "SemanticRefused", "SideRun", "pinned_hcap", "read_inputs",
           "staged_pin"]
