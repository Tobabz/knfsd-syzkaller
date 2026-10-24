"""The Stage 2 Runner engine: one trusted host command per gate, campaign or
replay lease, sealing each finished segment while the command runs.

The command is host configuration, like the Stage 1 command; nothing in it
comes from a candidate, the Agent or a rule set.  For each lease the engine
writes the inputs into a fresh directory, runs the command under
``ProcessSupervisor`` and hands every segment the command finishes to the
backend, in order, as soon as it is complete.  A campaign's segments thus
reach the Controller while the campaign still runs (09 §4, §8).

Command contract (``{input}`` and ``{output}`` in argv are replaced):

``input/``
    ``execution.json``  job_id, task_id, step, harness_ref,
                        execution_harness_id, lease_generation, compiled_ref,
                        rule_set_id, gate_repetitions, campaign_id,
                        crash_bundle_ref (null when the step has none)
    ``harness.json``, ``descriptor.json``, ``program.syz``, ``neutral.syz``
                        as for Stage 1
    ``rules.nfsprul1``  the compiled rule set to install, byte for byte
    ``compiled.json``   its ``CompiledMutationRuleSet`` record
    ``replay/``         replay only: ``rules.bin`` (the bytes the crash's
                        journal recorded), ``programs.log`` (the
                        CrashContextWindow in order) and ``plan.json``

``output/segments/NNNNNN/`` (one directory per segment, numbered from 0)
    ``capture.json``    ``{"vm_instance_id", "lane", "generation_id",
                        "host": {...}, "artifacts": [...]}``; ``host`` is
                        the step's report in ``evidence`` (``GateHostFacts``,
                        ``CampaignHostFacts``, ``ReplayHostFacts``)

A segment counts once its directory exists under its final name: write it
as ``segments/.NNNNNN.tmp`` and rename it.  A gate must finish
``gate_repetitions`` segments (no more), a replay one, a campaign at least one;
fewer ends the lease ``capture_failed`` (a runtime failure, never a
verdict), keeping the segments already sealed.

For a replay the engine plans before anything runs: it reads the crash
bundle's journal and crash log, takes the CrashContextWindow
(``crash_window_bound`` programs of the crashing lane), joins it to the
recorded MutationDeltas and asks the replay Proxy (``--check-rules``)
whether it can run the recorded rule set (03-nfs-proxy/05 §25-§27, §39).
When no plan is possible, nothing runs and one segment records why, so
the replay is still judged (REPLAY_INVALID) instead of retried.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

from pydantic import BaseModel, ConfigDict, Field

from ..artifacts import ArtifactStore
from ..data import canonical_json, load_record, parse_json
from ..evidence import ArtifactInput, EvidenceLimits, EvidenceStore
from ..materializer import ExecutionHarnessDescriptor, ReachabilityHarness
from ..replay_runner import (PlanError, check_rule_set, parse_crash_context,
                             plan_replay, write_replay_inputs)
from ..rule_compiler import CompiledMutationRuleSet
from ..runner.evidence_backend import (ExecutionCapture, HostExecutionFacts,
                                       RunnerEvidenceReceiptStore)
from ..runner.models import WorkLease
from ..runner.process_supervisor import HostCommand, ProcessLimits, ProcessSupervisor
from ..runner.slots import SlotPool, resource
from ..runner.worker import LeaseControl
from ..semantic_delta import DeltaReadError
from ..stage1.engine import (INPUT, MAX_CAPTURE_INDEX_BYTES, OUTPUT,
                             CaptureError, _CaptureEntry, _read_regular, _write)
from .evidence import (CRASH_LOG_ID, CRASH_LOG_TYPE, HOST_FACTS_ID,
                       HOST_FACTS_TYPE, JOURNAL_TYPE, PRODUCTION_END,
                       CampaignHostFacts, Compatibility, GateHostFacts,
                       ReplayHostFacts, Stage2HostFacts, is_journal_segment,
                       unpack_journal)

SEGMENTS = "segments"
MAX_SEGMENTS = 100_000
_REPORTS = {"gate": GateHostFacts, "campaign": CampaignHostFacts,
            "replay": ReplayHostFacts}


class _SegmentIndex(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    vm_instance_id: str
    lane: int
    generation_id: int
    host: dict
    artifacts: tuple[_CaptureEntry, ...] = Field(min_length=1, max_length=255)


@dataclass(frozen=True)
class Stage2EngineConfig:
    argv: tuple[str, ...]
    cwd: Path
    work_root: Path
    resource_key: str
    collector_id: str
    #: The Proxy binary that will replay, for the ``--check-rules`` gate.
    replay_proxy: Path
    #: CrashContextWindow bound (01 §8.1): at most the syzkaller ring
    #: (``experimental.nfs_proxy_window``, 6 by default, 64 at most).
    crash_window_bound: int = 4
    env: Mapping[str, str] = field(default_factory=lambda: {"LANG": "C.UTF-8"})
    limits: ProcessLimits = ProcessLimits()
    #: How often a running command's finished segments are taken.
    poll_interval_s: float = 1.0


class _SegmentControl:
    """The lease control the supervisor polls.  Each poll first seals the
    segments the command finished; a segment the backend refuses stops
    the command, as a cancel would."""

    def __init__(self, inner: LeaseControl, harvest: Callable[[], None],
                 interval_s: float) -> None:
        self._inner = inner
        self._harvest = harvest
        self._interval_s = interval_s
        self._next = 0.0
        self.error: BaseException | None = None

    @property
    def lease(self) -> WorkLease:
        return self._inner.lease

    def renew(self) -> WorkLease:
        return self._inner.renew()

    def stop_requested(self) -> bool:
        if self.error is None and time.monotonic() >= self._next:
            self._next = time.monotonic() + self._interval_s
            try:
                self._harvest()
            except BaseException as exc:      # stop the command, re-raise after
                self.error = exc
        return self.error is not None or self._inner.stop_requested()


class Stage2CommandEngine:
    """``StreamingExecutionEngine`` for the Stage 2 steps."""

    def __init__(self, config: Stage2EngineConfig, artifacts: ArtifactStore,
                 supervisor: ProcessSupervisor, *,
                 receipts: RunnerEvidenceReceiptStore,
                 evidence: EvidenceStore | None = None,
                 limits: EvidenceLimits = EvidenceLimits(),
                 check_rules: Callable[[Path, bytes, Path], object] = check_rule_set,
                 slots: SlotPool | None = None) -> None:
        if not 1 <= config.crash_window_bound <= 64:
            raise ValueError("crash_window_bound must be 1..64")
        #: The host's KVM slots, shared with Stage 1 (#81 R4); None runs on
        #: ``config.resource_key``.
        self.slots = slots
        self.config = config
        self.artifacts = artifacts
        self.supervisor = supervisor
        self.receipts = receipts
        self.evidence = evidence or EvidenceStore(artifacts)
        self.limits = limits
        self.check_rules = check_rules

    # ------------------------------------------------------------ inputs

    def _prepare(self, lease: WorkLease) -> tuple[Path, Path, Stage2HostFacts | None]:
        b, t = lease.binding, lease.task_input
        if t.step is None or t.compiled_ref is None:
            raise CaptureError("not a Stage 2 step")
        run = self.config.work_root / f"{b.task_id}.g{lease.generation}"
        inp, out = run / "input", run / "output"
        run.mkdir(parents=True, exist_ok=False)
        inp.mkdir()
        out.mkdir()
        (out / SEGMENTS).mkdir()
        harness = load_record(self.artifacts, b.harness_ref, ReachabilityHarness)
        if harness.execution_harness_id != b.execution_harness_id:
            raise CaptureError("harness does not belong to this execution harness")
        descriptor = load_record(self.artifacts, b.execution_harness_id,
                                 ExecutionHarnessDescriptor)
        compiled = load_record(self.artifacts, t.compiled_ref,
                               CompiledMutationRuleSet)
        if compiled.harness_ref != b.harness_ref:
            raise CaptureError("the rule set was compiled for another harness")
        rules = self.artifacts.get(compiled.nfsprul1_ref)
        _write(inp / "execution.json", canonical_json({
            "job_id": b.job_id, "task_id": b.task_id, "step": t.step,
            "harness_ref": b.harness_ref,
            "execution_harness_id": b.execution_harness_id,
            "lease_generation": lease.generation,
            "compiled_ref": t.compiled_ref,
            "rule_set_id": compiled.nfsprul1_ref,
            "gate_repetitions": t.gate_repetitions,
            "campaign_id": t.campaign_id,
            "crash_bundle_ref": t.crash_bundle_ref}))
        _write(inp / "harness.json", canonical_json(harness))
        _write(inp / "descriptor.json", canonical_json(descriptor))
        _write(inp / "program.syz", self.artifacts.get(harness.program_ref))
        _write(inp / "neutral.syz",
               self.artifacts.get(harness.neutral_program_ref))
        _write(inp / "rules.nfsprul1", rules)
        _write(inp / "compiled.json", canonical_json(compiled))
        unplanned = None
        if t.step == "replay":
            unplanned = self._plan_replay(t.crash_bundle_ref, inp / "replay",
                                          run / "plan-work")
        return inp, out, unplanned

    def _plan_replay(self, crash_bundle_ref: str | None, target: Path,
                     work: Path) -> Stage2HostFacts | None:
        """Write the replay inputs; the facts of an unplanned replay
        otherwise.  Host faults (an unreadable crash bundle) raise."""
        if crash_bundle_ref is None:
            raise CaptureError("a replay names its crash bundle")
        receipt = self.receipts.get(crash_bundle_ref)
        bundle = self.evidence.verify(crash_bundle_ref,
                                      expected_correlation=receipt.correlation)
        facts = Stage2HostFacts.model_validate_json(
            bundle.get(HOST_FACTS_ID, expected_type=HOST_FACTS_TYPE))
        if facts.campaign is None:
            raise CaptureError("the crash bundle is not a campaign bundle")
        production_end = PRODUCTION_END[facts.campaign.vm_termination]
        work.mkdir()
        try:
            journal_dir = work / "production"
            journal = unpack_journal(bundle, facts.campaign.journal_name,
                                     journal_dir)
            log = bundle.get(CRASH_LOG_ID, expected_type=CRASH_LOG_TYPE)
            window = parse_crash_context(
                log.decode("utf-8", errors="replace"),
                vm_instance_id=receipt.correlation.vm_instance_id,
                bound=self.config.crash_window_bound)
            plan = plan_replay(journal, window)
        except (KeyError, ValueError, PlanError, DeltaReadError) as exc:
            return Stage2HostFacts(step="replay", plan_error=_short(exc))
        result = self.check_rules(self.config.replay_proxy, plan.rule_set, work)
        compatibility = Compatibility(ok=result.ok, reason=result.reason,
                                      line=result.line[:512])
        write_replay_inputs(plan, target)
        _write(target / "host.json", canonical_json(
            {"production_end": production_end.value,
             "compatibility": compatibility.model_dump(mode="json"),
             "window_bound": self.config.crash_window_bound}))
        return None

    # ------------------------------------------------------------ run

    def run(self, lease: WorkLease, control: LeaseControl,
            emit: Callable[[ExecutionCapture], None]) -> None:
        inp, out, unplanned = self._prepare(lease)
        t = lease.task_input
        if unplanned is not None:
            now = time.time_ns()
            emit(self._capture_of(unplanned, "replay-unplanned", 0, 0,
                                  (), now, now))
            return
        replay_facts = None
        if t.step == "replay":
            replay_facts = parse_json((inp / "replay" / "host.json").read_bytes())
        wanted = {"gate": t.gate_repetitions, "replay": 1}.get(t.step)
        taken = 0
        started = time.time_ns()

        def harvest() -> None:
            nonlocal taken, started
            while True:
                seg = out / SEGMENTS / f"{taken:06d}"
                if not seg.is_dir():
                    return
                if taken >= (MAX_SEGMENTS if wanted is None else wanted):
                    raise CaptureError(f"{t.step} wrote more than "
                                       f"{taken} segments")
                emit(self._read_segment(t.step, seg, started, replay_facts))
                started = time.time_ns()
                taken += 1

        watch = _SegmentControl(control, harvest, self.config.poll_interval_s)
        argv = tuple(arg.replace(INPUT, str(inp)).replace(OUTPUT, str(out))
                     for arg in self.config.argv)
        with resource(self.slots, self.config.resource_key) as key:
            result = self.supervisor.run(
                HostCommand(argv, self.config.cwd, dict(self.config.env)),
                lease, watch, resource_key=key, limits=self.config.limits)
        _write(out.parent / "process.log",
               result.stdout + b"\n--- stderr ---\n" + result.stderr)
        if watch.error is not None:
            raise watch.error
        # Segments finished after the last poll.
        harvest()
        if result.reason != "completed" or result.returncode != 0:
            raise CaptureError(
                f"host command ended {result.reason} rc={result.returncode}")
        if (wanted is not None and taken != wanted) or taken == 0:
            raise CaptureError(f"{t.step} finished {taken} segments")

    def _read_segment(self, step: str, seg: Path, started_ns: int,
                      replay_facts: dict | None) -> ExecutionCapture:
        raw = _read_regular(seg, "capture.json", MAX_CAPTURE_INDEX_BYTES)
        try:
            index = _SegmentIndex.model_validate(parse_json(raw))
            report = _REPORTS[step].model_validate_json(canonical_json(index.host))
        except (ValueError, TypeError) as exc:
            raise CaptureError("malformed segment capture.json") from exc
        if replay_facts is not None:
            facts = Stage2HostFacts.model_validate_json(canonical_json(
                {"step": step, step: report.model_dump(mode="json"),
                 **replay_facts}))
        else:
            facts = Stage2HostFacts.model_validate_json(canonical_json(
                {"step": step, step: report.model_dump(mode="json")}))
        artifacts = []
        total = 0
        for entry in index.artifacts:
            if entry.identity == HOST_FACTS_ID:
                raise CaptureError("stage2-host is the engine's to write")
            if entry.type == JOURNAL_TYPE and not is_journal_segment(
                    entry.identity.removeprefix("journal/"),
                    report.journal_name):
                raise CaptureError(f"not a {report.journal_name} journal "
                                   f"segment: {entry.identity}")
            data = _read_regular(seg, entry.path, self.limits.max_artifact_bytes)
            total += len(data)
            if total > self.limits.max_bundle_bytes:
                raise CaptureError("segment exceeds the bundle limit")
            artifacts.append(ArtifactInput(identity=entry.identity,
                                           type=entry.type, data=data))
        return self._capture_of(facts, index.vm_instance_id, index.lane,
                                index.generation_id, tuple(artifacts),
                                started_ns, time.time_ns())

    def _capture_of(self, facts: Stage2HostFacts, vm: str, lane: int,
                    generation: int, artifacts: tuple[ArtifactInput, ...],
                    started_ns: int, completed_ns: int) -> ExecutionCapture:
        return ExecutionCapture(
            facts=HostExecutionFacts(
                vm_instance_id=vm, lane=lane, generation_id=generation,
                collector_id=self.config.collector_id,
                collection_started_at_ns=started_ns,
                collection_completed_at_ns=max(started_ns, completed_ns)),
            artifacts=(ArtifactInput(identity=HOST_FACTS_ID,
                                     type=HOST_FACTS_TYPE,
                                     data=canonical_json(facts)),)
            + artifacts)


def _short(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:512]
