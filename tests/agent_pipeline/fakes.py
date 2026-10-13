"""Fakes for the Controller tests (09 검증 오라클: no LLM, no VM).

The HCAP checker, Materializer and Judge are pure functions of their
arguments and of what a test registered before using them, as the real
components must be.  FakeRunner implements the 09 §8 task contract and
counts submits and starts per task_id.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.components import InMemoryIssues, InMemoryRegistry
from agent_pipeline.contracts import (AnalysisOutput, CandidateSubmission,
                                      GapRef, HarnessBinding, HcapCheck,
                                      JobPolicy, JudgeVersions,
                                      LocationKind, LocationRequest,
                                      MaterializeRejected, Materialized,
                                      PlanOutput, Q1Result, Q1Status,
                                      Sanitizer)
from agent_pipeline.controller.machine import Env
from agent_pipeline.controller.records import JobState, TaskKind
from agent_pipeline.controller.service import Controller
from agent_pipeline.controller.store import Store
from agent_pipeline.controller.tasks import RunnerStatus, SubmitRefused


def sha(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


COMMIT = "a" * 40
OTHER_COMMIT = "b" * 40
SOURCE = """\
// SPDX-License-Identifier: GPL-2.0
#include <linux/nfs.h>

static int helper(int x);

static __be32
nfsd4_target(struct svc_rqst *rqstp, int x)
{
\tif (x)
\t\treturn helper(x);
\treturn 0;
}

int helper(int x) __must_hold(&lock)
{
\treturn nfsd4_target(NULL, x);
}

#ifdef CONFIG_A
static void twice(void)
{
}
#else
static void twice(void)
{
}
#endif
"""


class FakeTree:
    def __init__(self, files: dict[str, dict[str, str]]) -> None:
        self.files = files

    def has_commit(self, commit: str) -> bool:
        return commit in self.files

    def read_text(self, commit: str, path: str) -> str | None:
        return self.files.get(commit, {}).get(path)


class FakeHcap:
    def __init__(self) -> None:
        self.violations: dict[tuple[str, str], tuple[str, ...]] = {}
        self.vocabulary: set[str] = {"syzlang.nfs4.op_lock",
                                     "fixture.lease_expiry"}

    def check_plan(self, plan_ref: str, hcap_revision: str) -> HcapCheck:
        return HcapCheck(violations=self.violations.get(
            (plan_ref, hcap_revision), ()))

    def knows_capability(self, hcap_revision: str, cap: str) -> bool:
        return cap in self.vocabulary


class FakeMaterializer:
    def __init__(self) -> None:
        self.refusals: dict[tuple[str, str], MaterializeRejected] = {}

    def materialize(self, plan_ref: str, binding: HarnessBinding):
        r = self.refusals.get((plan_ref, binding.execution_harness_id))
        if r is not None:
            return r
        return Materialized(
            harness_ref=sha("harness", plan_ref,
                            binding.execution_harness_id),
            review_manifest_sha256=sha("manifest", plan_ref,
                                       binding.execution_harness_id),
            execution_harness_id=binding.execution_harness_id)


class FakeJudge:
    """bundle -> verdict, optionally per JudgeProfile."""

    def __init__(self) -> None:
        self.bundles: dict[str, dict] = {}
        self.missing: set[tuple[str, str]] = set()

    def add(self, bundle: str, harness_id: str, candidate_id: str,
            status: Q1Status, reason: str | None = None,
            gap: GapRef | None = None, profile: str | None = None) -> str:
        entry = self.bundles.setdefault(bundle, {
            "harness_id": harness_id, "candidate_id": candidate_id,
            "by_profile": {}})
        entry["by_profile"][profile] = (status, reason, gap)
        return bundle

    def judge(self, bundle_ref, plan_ref, candidate_id,
              versions: JudgeVersions) -> Q1Result:
        e = self.bundles[bundle_ref]
        status, reason, gap = e["by_profile"].get(
            versions.judge_profile_id, e["by_profile"][None])
        return Q1Result(
            verdict_id=f"q1-{bundle_ref}-{versions.judge_profile_id}-"
                       f"{versions.support_boundary_id}",
            candidate_id=e["candidate_id"],
            execution_harness_id=e["harness_id"],
            judge_profile_id=versions.judge_profile_id,
            support_boundary_id=versions.support_boundary_id,
            evidence_manifest_sha256=sha("manifest", bundle_ref),
            status=status, reason=reason, gap_signal=gap)

    def has_required_evidence(self, bundle_ref, versions) -> bool:
        return (bundle_ref, versions.judge_profile_id) not in self.missing


class FakeRunner:
    """09 §8.  A task runs until finish(); cancel() of a task in
    `slow_cancel` does not end it until a later cancel()."""

    def __init__(self) -> None:
        self.tasks: dict[str, dict] = {}
        self.submits: Counter = Counter()
        self.starts: Counter = Counter()
        self.started: list[str] = []
        self.cancelled: set[str] = set()
        self.cancel_calls: Counter = Counter()
        self.slow_cancel: set[str] = set()

    def _status(self, task_id: str) -> RunnerStatus:
        t = self.tasks.get(task_id)
        if t is None:
            if task_id in self.cancelled:
                return RunnerStatus(state="ended_unsealed",
                                    reason="cancelled")
            return RunnerStatus(state="unknown")
        return RunnerStatus(state=t["state"], reason=t["reason"],
                            bundles=tuple(t["bundles"]))

    def submit(self, task_id, task_input) -> RunnerStatus:
        self.submits[task_id] += 1
        if task_id in self.cancelled:
            raise SubmitRefused(task_id)
        t = self.tasks.get(task_id)
        if t is not None:
            if t["input"] != task_input:
                raise SubmitRefused(task_id)
            return self._status(task_id)
        self.tasks[task_id] = {"input": task_input, "state": "running",
                               "reason": None, "bundles": []}
        self.starts[task_id] += 1
        self.started.append(task_id)
        return self._status(task_id)

    def status(self, task_id) -> RunnerStatus:
        return self._status(task_id)

    def cancel(self, task_id) -> RunnerStatus:
        self.cancel_calls[task_id] += 1
        t = self.tasks.get(task_id)
        if t is None:
            self.cancelled.add(task_id)
            return self._status(task_id)
        if task_id in self.slow_cancel:
            self.slow_cancel.discard(task_id)
            return self._status(task_id)
        if t["state"] == "running":
            t["state"], t["reason"] = "ended_unsealed", "cancelled"
        return self._status(task_id)

    def finish(self, task_id: str, bundle: str | None = None,
               reason: str | None = None) -> None:
        t = self.tasks[task_id]
        if bundle is not None:
            t["bundles"].append(bundle)
            t["state"] = "sealed"
        else:
            t["state"], t["reason"] = "ended_unsealed", reason or "crash"


class FakeAgents:
    def __init__(self) -> None:
        self.requests = []

    def start(self, request) -> None:
        self.requests.append(request)


VERSIONS = JudgeVersions(judge_profile_id="jp-1", support_boundary_id="sb-1")


def binding(execution: str = "build-1", hcap: str = "hcap-1",
            commit: str = COMMIT) -> HarnessBinding:
    return HarnessBinding(kernel_commit=commit, sanitizer=Sanitizer.KASAN,
                          execution_harness_id=sha(execution),
                          hcap_revision=hcap)


def policy(policy_id: str = "p1", **kw) -> JobPolicy:
    values = dict(policy_id=policy_id, sanitizer=Sanitizer.KASAN,
                  approval_required=False, stage1_repair_budget=3,
                  agent_retry_limit=2, runtime_retry_limit=2)
    values.update(kw)
    return JobPolicy(**values)


def function_submission(symbol: str = "nfsd4_target",
                        commit: str = COMMIT) -> CandidateSubmission:
    return CandidateSubmission(kernel_commit=commit, location=LocationRequest(
        kind=LocationKind.FUNCTION, path="fs/nfsd/nfs4xdr.c", symbol=symbol))


class World:
    """A Controller over fakes and a store file.  restart() builds a new
    Controller on the same store and fakes, as after a crash."""

    def __init__(self, tmp: Path, bound: bool = True, **policy_kw) -> None:
        self.tmp = Path(tmp)
        self.store = Store(self.tmp / "jobs.sqlite")
        self.store.save_policy(policy(**policy_kw))
        self.hcap = FakeHcap()
        self.materializer = FakeMaterializer()
        self.judge = FakeJudge()
        self.runner = FakeRunner()
        self.agents = FakeAgents()
        self.issues = InMemoryIssues()
        self.registry = InMemoryRegistry()
        if bound:
            self.registry.put(binding())
        self.tree = FakeTree({COMMIT: {"fs/nfsd/nfs4xdr.c": SOURCE},
                              OTHER_COMMIT: {"fs/nfsd/nfs4xdr.c": SOURCE}})
        self.artifacts = ArtifactStore(self.tmp / "artifacts")
        self.ids = 0
        self.expected_failures = 0
        self.controller = self._controller()

    def _new_id(self) -> str:
        self.ids += 1
        return f"{self.ids:04d}"

    def _controller(self) -> Controller:
        env = Env(policy=self.store.policy, hcap=self.hcap,
                  materializer=self.materializer, judge=self.judge)
        return Controller(self.store, env, self.runner, self.agents,
                          self.issues, self.registry, self.tree,
                          self.artifacts, VERSIONS,
                          clock=lambda: "2026-10-13T00:00:00+00:00",
                          new_id=self._new_id)

    def restart(self) -> Controller:
        versions = self.controller.judge_versions
        self.store.close()
        self.store = Store(self.tmp / "jobs.sqlite")
        self.controller = self._controller()
        self.controller.judge_versions = versions
        self.controller.recover()
        return self.controller

    # -------------------------------------------------------- shortcuts

    @property
    def c(self) -> Controller:
        return self.controller

    def job(self, job_id: str):
        return self.store.job(job_id)

    def submit(self, sub: CandidateSubmission | None = None) -> str:
        return self.c.submit(sub or function_submission(), "p1")

    def agent_ok(self, job_id: str, output) -> None:
        p = self.job(job_id).pending_task
        assert p is not None and p.kind is TaskKind.AGENT, p
        self.c.on_agent_result(p.task_id, p.attempt, output, "test:fake")

    def analysis(self, job_id: str, ref: str = "analysis-1") -> None:
        self.agent_ok(job_id, AnalysisOutput(analysis_ref=sha(ref)))

    def plan(self, job_id: str, ref: str = "plan-1") -> None:
        self.agent_ok(job_id, PlanOutput(plan_ref=sha(ref)))

    def to_running(self, job_id: str | None = None) -> str:
        job_id = job_id or self.submit()
        self.analysis(job_id)
        self.plan(job_id)
        assert self.job(job_id).state is JobState.S1_RUNNING
        return job_id

    def run(self, job_id: str, status: Q1Status, reason: str | None = None,
            gap: GapRef | None = None, name: str | None = None) -> str:
        """Finish the pending Runner task with a bundle judged `status`."""
        j = self.job(job_id)
        p = j.pending_task
        assert p is not None and p.kind is TaskKind.RUNNER, p
        bundle = name or f"bundle-{p.task_id}"
        self.judge.add(bundle, j.binding.execution_harness_id,
                       j.candidate.candidate_id, status, reason, gap)
        self.runner.finish(p.task_id, bundle=bundle)
        self.c.poll()
        return bundle

    def crash_run(self, job_id: str, reason: str = "vm_lost") -> None:
        p = self.job(job_id).pending_task
        self.runner.finish(p.task_id, reason=reason)
        self.c.poll()
