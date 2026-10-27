"""#81 §3: a kernel crash in a Stage 1 run is a finding, not an infra
failure.  The run's Q1 verdict routes the job as usual."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_pipeline.contracts import Q1Status, Sanitizer
from agent_pipeline.controller.records import JobState, RepairCause
from agent_pipeline.crash import (CRASH_REPORT_ID, CRASH_REPORT_TYPE,
                                  CrashKind, CrashReport, classify)
from agent_pipeline.data import canonical_json
from agent_pipeline.evidence import ArtifactInput
from agent_pipeline.evidence import ExecutionCorrelation as EC

from . import test_sealed_q1 as sealed

KASAN = ("[   12.345678] ==================================================\n"
         "[   12.345680] BUG: KASAN: slab-use-after-free in nfsd4_bind\n"
         "[   12.345690] Read of size 8 at addr ffff888012345678\n")
WARNING = "[    9.000001] WARNING: CPU: 1 PID: 77 at fs/nfsd/nfs4state.c:12\n"
PANIC = ("[   20.000000] Oops: general protection fault, probably for "
         "non-canonical address\n"
         "[   20.000100] Kernel panic - not syncing: Fatal exception\n")
KCSAN = "[    5.000000] BUG: KCSAN: data-race in nfsd4_bind / nfsd4_destroy\n"


def report(text: str, sanitizer=Sanitizer.KASAN) -> CrashReport:
    found = classify(text, None, sanitizer)
    assert found is not None
    return found


# ------------------------------------------------------------ classifier

@pytest.mark.parametrize(("text", "kind"), [
    (KASAN, CrashKind.KASAN), (WARNING, CrashKind.WARNING),
    (PANIC, CrashKind.OOPS), ("kernel BUG at mm/slub.c:42!\n",
                              CrashKind.KERNEL_BUG),
    ("BUG: unable to handle page fault\n", CrashKind.BUG)])
def test_every_crash_pattern_is_a_crash(text, kind):
    assert report(text).kind is kind


def test_the_report_keeps_the_crash_lines_without_timestamps():
    r = report(WARNING + KASAN)
    assert r.source == "console" and r.kind is CrashKind.WARNING
    assert r.title == "WARNING: CPU: 1 PID: 77 at fs/nfsd/nfs4state.c:12"
    assert r.lines == (r.title,
                       "BUG: KASAN: slab-use-after-free in nfsd4_bind")
    assert not r.panicked
    assert report(PANIC).panicked


def test_kcsan_is_a_crash_only_on_a_kcsan_harness():
    assert classify(KCSAN, None, Sanitizer.KASAN) is None
    assert report(KCSAN, Sanitizer.KCSAN).kind is CrashKind.KCSAN


def test_the_console_is_the_primary_evidence():
    assert classify("Linux version\n", None, Sanitizer.KASAN) is None
    assert classify("Linux version\n", KASAN, Sanitizer.KASAN).source \
        == "dmesg"
    assert classify(WARNING, KASAN, Sanitizer.KASAN).kind \
        is CrashKind.WARNING


def test_the_report_is_bounded():
    r = report(WARNING * 40)
    assert len(r.lines) == 16
    with pytest.raises(ValidationError):
        CrashReport(source="console", sanitizer=Sanitizer.KASAN,
                    kind=CrashKind.BUG, title="x" * 201, lines=("x",),
                    panicked=False)


# ------------------------------------------------------------ Controller

def finish(w, j, task_id, status=Q1Status.REACHED, reason=None, crash=None,
           name=None):
    """Seal `task_id` with a bundle judged `status`, crashing with
    `crash`."""
    job = w.job(j)
    bundle = name or f"bundle-{task_id}"
    w.judge.add(bundle, job.binding.execution_harness_id,
                job.candidate.candidate_id, status, reason)
    if crash is not None:
        w.judge.crashes[bundle] = crash
    w.runner.finish(task_id, bundle=bundle)
    w.c.poll()
    return bundle


def replay(w, j, crash=None):
    """One run of the Stage 1 replay."""
    job = w.job(j)
    assert job.state is JobState.S1_REPLAYING, job.state
    return finish(w, j, job.pending_task.task_id, crash=crash)


def replays(w, j, *crashes):
    for crash in crashes:
        replay(w, j, crash)


#: The same crash at other addresses: a replay that reproduces it.
KASAN_AGAIN = KASAN.replace("12345678", "87654321").replace("12.3", "40.1")


@pytest.mark.parametrize(("status", "state"), [
    (Q1Status.REACHED, JobState.S1_REACHED),
    (Q1Status.NOT_REACHED, JobState.S1_PLANNING)])
def test_a_crash_finding_is_replayed_then_the_verdict_routes(
        world, status, state):
    j = world.to_running()
    task = world.job(j).pending_task.task_id
    world.judge.crashes["b1"] = report(KASAN)
    world.run(j, status, name="b1")
    job = world.job(j)
    assert job.state is JobState.S1_REPLAYING
    assert job.last_verdict.result.status is status
    (finding,) = job.crash_findings
    assert (finding.task_id, finding.bundle_ref) == (task, "b1")
    assert finding.source == "q1" and finding.kind == "kasan"
    assert not finding.panicked and finding.replay == "pending"
    assert finding.q1_status == status.value
    assert finding.q1_verdict_id == job.last_verdict.result.verdict_id
    assert finding.harness_ref == job.harness.harness_ref
    # D14: M runs, one at a time; another address is the same crash.
    replays(world, j, report(KASAN_AGAIN), None, report(WARNING),
            report(KASAN), None)
    job = world.job(j)
    assert job.state is state
    if status is Q1Status.NOT_REACHED:
        assert job.pending_task.repair.cause \
            is RepairCause.Q1_NOT_REACHED
    (finding,) = job.crash_findings
    assert finding.replay == "done" and finding.review == "queued"
    assert (finding.reproduced, finding.replays) == (2, 5)
    assert [r.reproduced for r in finding.replay_runs] == [
        True, False, False, True, False]
    assert finding.replay_runs[2].kind == "warning"
    assert job.s1_replay is None
    assert world.c.replay(j) == job


def test_a_crash_that_never_reproduces_is_still_reviewed(world):
    j = world.to_running()
    world.judge.crashes["b1"] = report(WARNING)
    world.run(j, Q1Status.REACHED, name="b1")
    replays(world, j, *[None] * 5)
    job = world.job(j)
    assert job.state is JobState.S1_REACHED
    f = job.crash_findings[0]
    assert (f.reproduced, f.replays, f.review) == (0, 5, "queued")


def test_a_panic_is_replayed_then_the_run_is_run_again(world):
    j = world.to_running()
    world.judge.crashes["b1"] = report(PANIC)
    world.run(j, Q1Status.INCONCLUSIVE, "infra", name="b1")
    assert world.job(j).state is JobState.S1_REPLAYING
    replays(world, j, *[report(PANIC)] * 5)
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING
    assert job.counters.runtime_retry == 1
    assert job.crash_findings[0].panicked
    assert job.crash_findings[0].reproduced == 5
    # The same panic again is the crash already replayed.
    world.judge.crashes["b2"] = report(PANIC)
    world.run(j, Q1Status.INCONCLUSIVE, "infra", name="b2")
    job = world.job(j)
    assert job.state is JobState.S1_RUNNING
    assert job.counters.runtime_retry == 2
    assert [f.replay for f in job.crash_findings] == ["done", "duplicate"]
    world.run(j, Q1Status.REACHED, name="b3")
    assert world.job(j).state is JobState.S1_REACHED
    assert world.c.replay(j) == world.job(j)


def test_findings_accumulate_across_runs(world):
    j = world.to_running()
    world.judge.crashes["b1"] = report(PANIC)
    world.judge.crashes["b2"] = report(KASAN)
    world.run(j, Q1Status.INCONCLUSIVE, "infra", name="b1")
    replays(world, j, *[None] * 5)
    world.run(j, Q1Status.REACHED, name="b2")
    replays(world, j, *[None] * 5)
    job = world.job(j)
    assert job.state is JobState.S1_REACHED
    assert [(f.bundle_ref, f.kind, f.replay) for f in job.crash_findings] \
        == [("b1", "oops", "done"), ("b2", "kasan", "done")]
    assert world.c.replay(j) == job


def test_a_run_without_a_crash_adds_no_finding(world):
    j = world.to_running()
    world.run(j, Q1Status.REACHED)
    assert world.job(j).crash_findings == ()


def test_an_unsealed_replay_runs_again_within_runtime_retry(world):
    j = world.to_running()
    world.judge.crashes["b1"] = report(KASAN)
    world.run(j, Q1Status.REACHED, name="b1")
    replay(world, j, report(KASAN))
    limit = world.store.policy("p1").runtime_retry_limit
    for n in range(1, limit + 1):
        world.crash_run(j)
        job = world.job(j)
        assert job.state is JobState.S1_REPLAYING
        assert job.counters.runtime_retry == n
    world.crash_run(j)
    job = world.job(j)
    assert job.state is JobState.BLOCKED_OPERATOR
    assert job.state_reason == "runtime_retry_exhausted"
    assert job.s1_replay is not None
    world.c.operator(j, "resume")
    replays(world, j, *[None] * 4)
    job = world.job(j)
    assert job.state is JobState.S1_REACHED
    assert job.crash_findings[0].reproduced == 1
    assert world.c.replay(j) == job


def test_a_replay_bundle_without_provenance_blocks(world):
    j = world.to_running()
    world.judge.crashes["b1"] = report(KASAN)
    world.run(j, Q1Status.REACHED, name="b1")
    p = world.job(j).pending_task
    world.runner.finish(p.task_id, bundle="unknown-bundle")
    world.c.poll()
    job = world.job(j)
    assert (job.state, job.state_reason) == (JobState.BLOCKED_OPERATOR,
                                             "replay_evidence")
    world.c.operator(j, "resume")
    assert world.job(j).state is JobState.S1_REPLAYING


def test_closing_during_a_replay_abandons_it(world):
    j = world.to_running()
    world.judge.crashes["b1"] = report(KASAN)
    world.run(j, Q1Status.REACHED, name="b1")
    p = world.job(j).pending_task
    world.c.operator(j, "close")
    job = world.job(j)
    assert job.state is JobState.CLOSED
    assert job.crash_findings[0].replay == "abandoned"
    assert job.s1_replay is None and world.runner.cancel_calls[p.task_id]
    assert world.c.replay(j) == job


# ------------------------------------------------------------ sealed judge

def _sealed(tmp_path, crash_artifact):
    f = sealed.setup(tmp_path)
    bundle = f.evidence.verify(f.bundle_ref, expected_correlation=EC(
        **f.correlation.model_dump()))
    artifacts = [ArtifactInput(identity=a.descriptor.identity,
                               type=a.descriptor.type, data=a.data)
                 for a in bundle.artifacts]
    sealed.reseal(f, artifacts + [crash_artifact])
    return f


def test_the_sealed_judge_reads_the_crash_and_keeps_the_verdict(tmp_path):
    crash = report(KASAN)
    f = _sealed(tmp_path, ArtifactInput(
        identity=CRASH_REPORT_ID, type=CRASH_REPORT_TYPE,
        data=canonical_json(crash)))
    assert f.judge.crash_report(f.bundle_ref) == crash
    assert sealed.result(f).status is Q1Status.REACHED


def test_an_unreadable_crash_report_is_unjudgeable_evidence(tmp_path):
    f = _sealed(tmp_path, ArtifactInput(
        identity=CRASH_REPORT_ID, type=CRASH_REPORT_TYPE, data=b"{}"))
    assert f.judge.crash_report(f.bundle_ref) is None
    r = sealed.result(f)
    assert (r.status, r.reason) == (Q1Status.INCONCLUSIVE, "evidence")


def test_a_bundle_without_a_crash_report_has_no_crash(tmp_path):
    f = sealed.setup(tmp_path)
    assert f.judge.crash_report(f.bundle_ref) is None


def test_a_panic_line_naming_its_cause_is_the_panic():
    r = report("BUG: KASAN: use-after-free in nfsd4_bind\n"
               "Kernel panic - not syncing: KASAN: panic_on_warn set\n")
    assert r.kind is CrashKind.KASAN and r.panicked
    assert report("Kernel panic - not syncing: KASAN: x\n").kind \
        is CrashKind.PANIC
