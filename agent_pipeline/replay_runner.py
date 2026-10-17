"""M6/S1c Runner side of semantic replay (05 §25-§27, §36; 06 §29, §34 S1c).

What the Runner does, in order:

1. **CrashContextWindow.**  `parse_crash_context` reads the "last executing
   test programs" section syz-manager prepends to a crash log.  With
   syzkaller patch 0024 each record there carries its lane and, once the
   program finished, the NFS proxy barrier of its KCOV generation
   (`nfs-proxy: lane=L generation=G program_digest=HEX ...`).  The window is
   the lane's last `bound` programs in execution order; the bound is job
   policy and is recorded in the plan.  A crash log is one VM instance, so
   the window never crosses one.
2. **Plan.**  `plan_replay` joins every entry to its MutationDelta in the
   sealed production journal (`semantic_delta.SealedJournal`, read only) by
   VM, lane, generation and program digest.  The program still running at
   the crash has no barrier yet; its generation is the next one its lane
   opened on the journal.  An entry with no MutationDelta stays in the
   window as missing: the comparison then cannot be equivalent (05 §25).
   Every joined generation must name one recorded rule set; its exact
   NFSPRUL1 bytes are the replay's rule set.  Nothing is recompiled.
3. **Compatibility gate.**  `check_rule_set` runs `nfs-proxy --check-rules`
   on those bytes: the runtime that will replay says itself whether it can
   (schema, runtime version, transforms).  A refusal is REPLAY_INVALID with
   that reason; there is no remap (§39).
4. **Replay execution.**  The Runner installs the recorded rule set as a
   new Proxy session on a *separate* host journal (`install_replay`), starts
   the guest Proxy in target mode with the same bytes, and runs the
   window's programs in order with `syz-execprog -procs=1 -repeat=1`
   (`write_replay_inputs`).  The same Decoder, Transaction Context,
   Resolver and Edit Applier run; mutations are written ahead to the replay
   journal exactly as in production (§36).
5. **Judge input.**  `judge_input` reads the execprog barriers, joins each
   replayed position to its generation in the replay journal, and projects
   both sides for `semantic_replay.evaluate`.  The production journal
   manifest is checked unchanged (05 oracle §13).

The live run (guest executor, knfsd, virtio-serial sink) is the KVM step a
person takes; the host tests drive the same functions against the built
Proxy with a fake client and the real sink.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import subprocess
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from .journal_sink import HostJournal, ruleset_header
from .semantic_delta import DeltaReadError, GenerationDelta, SealedJournal, SessionDelta
from .semantic_replay import (
    InvalidReason, ReplayJudgeInput, ReplayJudgeProfile, ReplayPosition, Termination,
)


MAX_WINDOW = 64
UINT64_MAX = 2**64 - 1


class PlanError(ValueError):
    """No replay can be planned from this evidence."""


class _Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True,
                              revalidate_instances="always")


# ---------------------------------------------------------------- CrashContextWindow (S1c)


class Barrier(_Record):
    """The executor's activation barrier of one program (patch 0023)."""

    kcov_generation: Annotated[int, Field(ge=0, le=UINT64_MAX)]
    program_digest: Annotated[str, Field(pattern=r"^(?:[0-9a-f]{2})*$")]
    activation: str
    activation_status: int
    deactivation: str
    deactivation_status: int
    executed: bool
    lease_cleared: bool


class WindowEntry(_Record):
    window_index: Annotated[int, Field(ge=0, lt=MAX_WINDOW)]
    exec_id: int
    printed_proc: int
    lane_id: Annotated[int, Field(ge=0, le=2**32 - 1)]
    barrier: Barrier | None
    program: str


class CrashContextWindow(_Record):
    schema_version: Literal["crash-context-window-v1"] = "crash-context-window-v1"
    vm_instance_id: Annotated[str, Field(min_length=1, max_length=256)]
    lane_id: int
    bound: Annotated[int, Field(ge=1, le=MAX_WINDOW)]
    entries: Annotated[tuple[WindowEntry, ...], Field(min_length=1, max_length=MAX_WINDOW)]


_HEADER = re.compile(r"^\S+ ago: executing program (\d+) \(id=(-?\d+)\):$")
_CONTEXT = re.compile(r"^nfs-proxy: lane=(\d+)(.*)$")
_BARRIER = re.compile(
    r" generation=(\d+) program_digest=([0-9a-f]*) activation=(\w+)/(\d+)"
    r" deactivation=(\w+)/(\d+) executed=(true|false) lease_cleared=(true|false)$")
_LOG_START = "last executing test programs:"
_LOG_END = "kernel console output (not intermixed with test programs):"


def _barrier(text: str) -> Barrier | None:
    m = _BARRIER.fullmatch(text)
    if m is None:
        return None
    return Barrier(kcov_generation=int(m.group(1)), program_digest=m.group(2),
                   activation=m.group(3), activation_status=int(m.group(4)),
                   deactivation=m.group(5), deactivation_status=int(m.group(6)),
                   executed=m.group(7) == "true", lease_cleared=m.group(8) == "true")


def parse_crash_context(log: str, *, vm_instance_id: str, bound: int,
                        lane_id: int | None = None) -> CrashContextWindow:
    """The lane's last `bound` programs from a syz-manager crash log.

    `lane_id` defaults to the lane of the most recently started program.
    """
    if _LOG_START not in log:
        raise PlanError("crash log has no last executing programs")
    section = log.split(_LOG_START, 1)[1].split(_LOG_END, 1)[0]
    records: list[dict] = []
    for line in section.splitlines():
        header = _HEADER.fullmatch(line)
        if header:
            records.append({"proc": int(header.group(1)), "id": int(header.group(2)),
                            "lane": None, "barrier": None, "program": []})
            continue
        if not records:
            continue
        context = _CONTEXT.fullmatch(line)
        if context and records[-1]["lane"] is None and not records[-1]["program"]:
            records[-1]["lane"] = int(context.group(1))
            if context.group(2):
                barrier = _barrier(context.group(2))
                if barrier is None:
                    raise PlanError(f"malformed nfs-proxy context line: {line!r}")
                records[-1]["barrier"] = barrier
            continue
        records[-1]["program"].append(line)
    if not records:
        raise PlanError("crash log lists no programs")
    for record in records:
        # Without a context line the printed proc was not rewritten.
        if record["lane"] is None:
            record["lane"] = record["proc"]
    # Hanged() appends a second record for a program whose Note() record is
    # still in the ring: same (lane, id), a synthetic proc, and the barrier.
    # It is one execution, so keep one record at the Note() position (the
    # start; the hung record is stamped at hang time) carrying the barrier.
    merged: list[dict] = []
    seen: dict[tuple[int, int], int] = {}
    for record in records:
        key = (record["lane"], record["id"])
        if record["id"] < 0 or key not in seen:
            if record["id"] >= 0:
                seen[key] = len(merged)
            merged.append(record)
            continue
        first = merged[seen[key]]
        if "\n".join(first["program"]).strip("\n") != "\n".join(record["program"]).strip("\n"):
            raise PlanError(f"lane {key[0]} id {key[1]} is listed with different programs")
        if record["barrier"] is not None:
            if first["barrier"] is not None and first["barrier"] != record["barrier"]:
                raise PlanError(f"lane {key[0]} id {key[1]} is listed with different barriers")
            merged[seen[key]] = record
    records = merged
    lane = records[-1]["lane"] if lane_id is None else lane_id
    # Collect() sorts by start time, so log order is execution order.
    selected = [r for r in records if r["lane"] == lane][-bound:]
    if not selected:
        raise PlanError(f"no program of lane {lane} in the crash log")
    return CrashContextWindow(
        vm_instance_id=vm_instance_id, lane_id=lane, bound=bound,
        entries=tuple(WindowEntry(
            window_index=i, exec_id=r["id"], printed_proc=r["proc"], lane_id=r["lane"],
            barrier=r["barrier"], program="\n".join(r["program"]).strip("\n") + "\n")
            for i, r in enumerate(selected)))


# ---------------------------------------------------------------- plan


class PlannedPosition(_Record):
    window_index: int
    program: str
    proxy_session_id: str | None
    kcov_generation: int | None
    program_digest: str | None


class ReplayPlan(_Record):
    schema_version: Literal["semantic-replay-plan-v1"] = "semantic-replay-plan-v1"
    window: CrashContextWindow
    production_journal: str
    production_manifest_sha256: str
    rule_set_id: str
    rule_set_hex: str
    schema_id: str
    semantic_runtime_version: int
    candidate_id: str
    positions: tuple[PlannedPosition, ...]

    @property
    def rule_set(self) -> bytes:
        return bytes.fromhex(self.rule_set_hex)


def _lane_generations(journal: SealedJournal, vm: str,
                      lane: int) -> list[tuple[SessionDelta, GenerationDelta]]:
    """The lane's generations in the order the lane opened them."""
    out = []
    for session in journal.sessions.values():  # install order
        if session.binding.vm_instance_id != vm or session.lane_id != lane:
            continue
        out += sorted(((session, g) for g in session.generations.values()),
                      key=lambda pair: pair[1].open_seq)
    return out


def _following(ordered: list[tuple[SessionDelta, GenerationDelta]],
               joined: list[tuple[SessionDelta, GenerationDelta] | None],
               ) -> list[tuple[SessionDelta, GenerationDelta]] | None:
    """The lane's generations after the last joined one (None: no anchor)."""
    anchor = next((j for j in reversed(joined) if j is not None), None)
    if anchor is None:
        return None
    index = next(i for i, pair in enumerate(ordered)
                 if pair[0] is anchor[0] and pair[1] is anchor[1])
    return ordered[index + 1:]


def plan_replay(journal: SealedJournal, window: CrashContextWindow) -> ReplayPlan:
    vm, lane = window.vm_instance_id, window.lane_id
    ordered = _lane_generations(journal, vm, lane)
    joined: list[tuple[SessionDelta, GenerationDelta] | None] = []
    for entry in window.entries:
        b = entry.barrier
        if b is None:
            joined.append(None)
            continue
        joined.append(journal.find(vm_instance_id=vm, lane_id=lane,
                                   kcov_generation=b.kcov_generation,
                                   program_digest=b.program_digest)
                      if b.executed else None)
    # Programs that had not finished at the crash have no barrier: they are
    # the lane's next generations after the last joined one, in order.  A
    # lane runs one program at a time, so there cannot be more of them than
    # such programs; if there are, nothing is guessed and they stay missing.
    trailing = 0
    for entry in reversed(window.entries):
        if entry.barrier is not None:
            break
        trailing += 1
    following = _following(ordered, joined[:len(joined) - trailing])
    if following is not None and len(following) <= trailing:
        start = len(joined) - trailing
        joined[start:start + len(following)] = following
    sessions = [pair[0] for pair in joined if pair is not None]
    if not sessions:
        raise PlanError("no window entry has a MutationDelta in the production journal")
    rule_sets = {s.rule_set for s in sessions}
    if len(rule_sets) != 1:
        raise PlanError("window entries name different recorded rule sets")
    session = sessions[0]
    return ReplayPlan(
        window=window, production_journal=journal.name,
        production_manifest_sha256=journal.manifest_sha256(),
        rule_set_id=session.binding.rule_set_id, rule_set_hex=session.rule_set.hex(),
        schema_id=session.schema_id, semantic_runtime_version=session.semantic_runtime_version,
        candidate_id=session.candidate_id,
        positions=tuple(PlannedPosition(
            window_index=e.window_index, program=e.program,
            proxy_session_id=pair[0].binding.proxy_session_id if pair else None,
            kcov_generation=pair[1].kcov_generation if pair else None,
            program_digest=pair[1].program_digest if pair else None)
            for e, pair in zip(window.entries, joined)))


# ---------------------------------------------------------------- compatibility gate


@dataclass(frozen=True)
class Compatibility:
    ok: bool
    reason: InvalidReason | None
    line: str


_REFUSAL_REASON = {
    "malformed": InvalidReason.DELTA_CORRUPT,
    "unsupported_version": InvalidReason.RUNTIME_INCOMPATIBLE,
    "unknown_schema": InvalidReason.SCHEMA_UNAVAILABLE,
    "unsupported_capability": InvalidReason.TRANSFORM_UNSUPPORTED,
}


def check_rule_set(proxy: Path, rule_set: bytes, workdir: Path) -> Compatibility:
    """Ask the replay runtime whether it can run the recorded rule set."""
    path = Path(workdir) / "recorded-rules.bin"
    path.write_bytes(rule_set)
    run = subprocess.run([str(proxy), "--check-rules", str(path)],
                         capture_output=True, text=True, timeout=60)
    line = run.stdout.strip()
    digest = hashlib.sha256(rule_set).hexdigest()
    ok = re.fullmatch(r"rules ok rule_set_id=([0-9a-f]{64}) semantic_runtime_version=(\d+)"
                      r" schema_id=(\S+) rules=(\d+)", line)
    if run.returncode == 0 and ok:
        version, schema_id, _ = ruleset_header(rule_set)
        if (ok.group(1), int(ok.group(2)), ok.group(3)) != (digest, version, schema_id):
            # The runtime read something other than the recorded bytes.
            return Compatibility(False, InvalidReason.RULE_SET_INCOMPATIBLE, line)
        return Compatibility(True, None, line)
    refused = re.match(r"rules refused rule_set_id=[0-9a-f]{64} status=([a-z_]+)", line)
    if run.returncode == 3 and refused:
        return Compatibility(False, _REFUSAL_REASON.get(
            refused.group(1), InvalidReason.RULE_SET_INCOMPATIBLE), line)
    return Compatibility(False, InvalidReason.FIXTURE_FAILED,
                         line or run.stderr.strip()[:200])


# ---------------------------------------------------------------- replay execution


def install_replay(journal: HostJournal, plan: ReplayPlan, *, vm_instance_id: str,
                   channel_id: str, session_prefix: str, lane_id: int) -> None:
    """Install the recorded rule set, byte for byte, on the replay journal.

    `journal` must not be the production journal: the replay writes its own
    MutationDelta (§36) and the production one stays read only.
    """
    journal.install_session_series(vm_instance_id=vm_instance_id, channel_id=channel_id,
                                   prefix=session_prefix, lane_id=lane_id,
                                   rule_set=plan.rule_set)


EXECPROG_FLAGS = ("-procs=1", "-repeat=1")


def write_replay_inputs(plan: ReplayPlan, out: Path) -> dict[str, Path]:
    """rules.bin (the recorded bytes) and programs.log in window order.

    programs.log is a syz-manager execution log, which syz-execprog reads
    in order; with EXECPROG_FLAGS one proc runs them one after another in
    one lane, as the window ran in production.
    """
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    rules = out / "rules.bin"
    rules.write_bytes(plan.rule_set)
    programs = out / "programs.log"
    programs.write_text("".join(f"executing program 0 (id={p.window_index}):\n{p.program}\n"
                                for p in plan.positions))
    plan_path = out / "plan.json"
    plan_path.write_text(plan.model_dump_json(indent=1) + "\n")
    return {"rules": rules, "programs": programs, "plan": plan_path}


_EXECPROG_BARRIER = re.compile(r"nfs proxy barrier:(.*)$")


def parse_execprog_barriers(output: str) -> list[Barrier]:
    """The barrier syz-execprog printed for each program, in order."""
    found = []
    for line in output.splitlines():
        m = _EXECPROG_BARRIER.search(line)
        if m:
            barrier = _barrier(m.group(1).rstrip())
            if barrier is None:
                raise PlanError(f"malformed barrier line: {line!r}")
            found.append(barrier)
    return found


# ---------------------------------------------------------------- judge input


def judge_input(plan: ReplayPlan, production: SealedJournal, replay: SealedJournal, *,
                replay_vm_instance_id: str, replay_lane_id: int,
                replay_barriers: list[Barrier], production_termination: Termination,
                replay_termination: Termination, compatibility: Compatibility,
                evidence_verified: bool, profile: ReplayJudgeProfile,
                production_channel_failed: bool = False,
                replay_channel_failed: bool = False,
                fixture_failed: bool = False) -> ReplayJudgeInput:
    """Both sealed sides of every window position, for `semantic_replay.evaluate`."""
    if production.manifest_sha256() != plan.production_manifest_sha256:
        raise PlanError("production journal changed since the plan (05 oracle §13)")
    invalid = []
    if compatibility.reason is not None:
        invalid.append(compatibility.reason)
    if fixture_failed or len(replay_barriers) > len(plan.positions):
        invalid.append(InvalidReason.FIXTURE_FAILED)
    # One barrier per replayed program, in window order.  The program that
    # was running when the replay crashed printed none: like in production,
    # its generation is the next one the replay lane opened.
    replayed: list[tuple[SessionDelta, GenerationDelta] | None] = []
    for b in replay_barriers[:len(plan.positions)]:
        replayed.append(replay.find(vm_instance_id=replay_vm_instance_id,
                                    lane_id=replay_lane_id, kcov_generation=b.kcov_generation,
                                    program_digest=b.program_digest) if b.executed else None)
    rest = len(plan.positions) - len(replayed)
    following = _following(_lane_generations(replay, replay_vm_instance_id, replay_lane_id),
                           replayed) if replayed else _lane_generations(
                               replay, replay_vm_instance_id, replay_lane_id)
    replayed += (following or [])[:rest]
    positions = []
    for planned in plan.positions:
        prod = None
        if planned.proxy_session_id is not None and planned.kcov_generation is not None:
            session = production.sessions[planned.proxy_session_id]
            prod = production.side(session, session.generations[planned.kcov_generation],
                                   termination=production_termination,
                                   channel_failed=production_channel_failed)
        repl = None
        pair = replayed[planned.window_index] if planned.window_index < len(replayed) else None
        if pair is not None:
            repl = replay.side(pair[0], pair[1], termination=replay_termination,
                               channel_failed=replay_channel_failed)
        positions.append(ReplayPosition(window_index=planned.window_index,
                                        production=prod, replay=repl))
    return ReplayJudgeInput(
        candidate_id=plan.candidate_id,
        production_evidence_manifest_sha256=production.manifest_sha256(),
        replay_evidence_manifest_sha256=replay.manifest_sha256(),
        evidence_verified=evidence_verified, schema_id=plan.schema_id,
        semantic_runtime_version=plan.semantic_runtime_version,
        rule_set_id=plan.rule_set_id, profile=profile,
        invalid_reasons=tuple(invalid), positions=tuple(positions))


def invalid_plan_input(*, candidate_id: str, production_manifest_sha256: str,
                       reason: InvalidReason, profile: ReplayJudgeProfile,
                       evidence_verified: bool, rule_set_id: str = "0" * 64,
                       schema_id: str = "unavailable",
                       semantic_runtime_version: int = 0,
                       window_size: int = 1) -> ReplayJudgeInput:
    """A replay that could not run (corrupt delta, refused rule set) is still
    judged: REPLAY_INVALID with the reason, never skipped."""
    return ReplayJudgeInput(
        candidate_id=candidate_id,
        production_evidence_manifest_sha256=production_manifest_sha256,
        replay_evidence_manifest_sha256=production_manifest_sha256,
        evidence_verified=evidence_verified, schema_id=schema_id,
        semantic_runtime_version=semantic_runtime_version, rule_set_id=rule_set_id,
        profile=profile, invalid_reasons=(reason,),
        positions=tuple(ReplayPosition(window_index=i, production=None, replay=None)
                        for i in range(window_size)))


# ---------------------------------------------------------------- operator entry


def main(argv: list[str] | None = None) -> int:
    """Operator entry for the KVM replay step.

    plan:  python -m agent_pipeline.replay_runner plan --journal-dir D --journal-name N
               --vm VM --crash-log LOG --bound B [--lane L] --proxy BIN --out OUT
           writes OUT/rules.bin, OUT/programs.log and OUT/plan.json, and prints
           the compatibility gate's answer.  Exit 3 when the runtime refuses.
    judge: python -m agent_pipeline.replay_runner judge --plan OUT/plan.json
               --journal-dir D --replay-dir R --replay-name N --replay-vm VM
               --replay-lane L --execprog-output F --proxy BIN
               --production-end E --replay-end E
           prints the ReplayResult JSON.
    """
    import argparse
    import sys
    from .semantic_replay import evaluate

    parser = argparse.ArgumentParser(prog="python -m agent_pipeline.replay_runner")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--journal-dir", type=Path, required=True)
    p.add_argument("--journal-name", required=True)
    p.add_argument("--vm", required=True)
    p.add_argument("--crash-log", type=Path, required=True)
    p.add_argument("--bound", type=int, required=True)
    p.add_argument("--lane", type=int)
    p.add_argument("--proxy", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    j = sub.add_parser("judge")
    j.add_argument("--plan", type=Path, required=True)
    j.add_argument("--journal-dir", type=Path, required=True)
    j.add_argument("--replay-dir", type=Path, required=True)
    j.add_argument("--replay-name", required=True)
    j.add_argument("--replay-vm", required=True)
    j.add_argument("--replay-lane", type=int, required=True)
    j.add_argument("--execprog-output", type=Path, required=True)
    j.add_argument("--proxy", type=Path, required=True)
    ends = [t.value for t in Termination]
    j.add_argument("--production-end", choices=ends, required=True)
    j.add_argument("--replay-end", choices=ends, required=True)
    args = parser.parse_args(argv)
    profile = ReplayJudgeProfile(name="replay-default", revision="1")

    if args.command == "plan":
        try:
            journal = SealedJournal(args.journal_dir, args.journal_name)
            window = parse_crash_context(args.crash_log.read_text(errors="replace"),
                                         vm_instance_id=args.vm, bound=args.bound,
                                         lane_id=args.lane)
            plan = plan_replay(journal, window)
        except (DeltaReadError, PlanError) as error:
            print(f"replay plan refused: {error}", file=sys.stderr)
            return 2
        paths = write_replay_inputs(plan, args.out)
        compat = check_rule_set(args.proxy, plan.rule_set, args.out)
        print(f"plan={paths['plan']} programs={len(plan.positions)} "
              f"rule_set_id={plan.rule_set_id} gate={compat.line}")
        return 0 if compat.ok else 3

    plan = ReplayPlan.model_validate_json(args.plan.read_text())
    production = SealedJournal(args.journal_dir, plan.production_journal)
    replay = SealedJournal(args.replay_dir, args.replay_name)
    compat = check_rule_set(args.proxy, plan.rule_set, args.plan.parent)
    inputs = judge_input(
        plan, production, replay, replay_vm_instance_id=args.replay_vm,
        replay_lane_id=args.replay_lane,
        replay_barriers=parse_execprog_barriers(args.execprog_output.read_text()),
        production_termination=Termination(args.production_end),
        replay_termination=Termination(args.replay_end), compatibility=compat,
        # The operator read both journals here, from the paths given.
        evidence_verified=True, profile=profile)
    print(evaluate(inputs).model_dump_json(indent=1))
    return 0


__all__ = [
    "Barrier", "Compatibility", "CrashContextWindow", "EXECPROG_FLAGS", "PlanError",
    "PlannedPosition", "ReplayPlan", "WindowEntry", "check_rule_set", "install_replay",
    "invalid_plan_input", "judge_input", "parse_crash_context", "parse_execprog_barriers",
    "plan_replay", "write_replay_inputs",
]

if __name__ == "__main__":
    raise SystemExit(main())
