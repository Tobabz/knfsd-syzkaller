"""``python -m agent_pipeline.stage1 --config stage1.json COMMAND``.

Commands:

``submit``       register a candidate and start a job
``run``          run the service loop (Agent Tasks, Runner worker, host
                 authority for Q1 and the Stage 2 steps)
``status``       print a job, its pending task, last verdict and Stage 2
                 results (gate runs, campaign tally, triage, replay)
``approve`` / ``deny``  answer an ``s1_approval`` review
``operator``     send an operator action to a job
``add-mapping``  register a verified ``TargetPcMapping`` JSON file
``issues`` / ``resolve-issue``  list harness gap issues; record a status
                 change (resolved, deferred, reopened, wont_fix) for its jobs
``replay``       re-run a job's stored events and compare (09 §8)
``promotions``   list staged harness promotions (07 §5.3)
``approve-promotion`` / ``reject-promotion``  a person's review of one in
                 ``review``; ``retry-promotion`` runs its campaigns again
``export-promotion``  write its evidence files for the host spec's
                 ``capability_evidence``
"""

from __future__ import annotations

import argparse
import json
import sys
from contextlib import ExitStack, closing
from pathlib import Path

from ..agent_tasks.generation import GenerationAgentExecutor, GenerationSandbox
from ..artifacts import ArtifactStore
from ..contracts import CandidateSubmission, LocationKind, LocationRequest
from ..controller.records import TERMINAL, JobState
from ..data import load_record
from ..hcap import ArtifactHcapChecker
from ..intake import GitSourceTree
from ..materializer import (ArtifactHarnessMaterializer, ExecutionHarnessApproval,
                            StaticExecutionHarnessAuthority)
from ..q1 import TargetPcMapping
from ..registry import ArtifactHarnessRegistry
from ..rule_compiler import ArtifactMutationRuleCompiler
from ..runner.process_supervisor import ProcessLimits, ProcessSupervisor
from ..runner.slots import SlotPolicy, SlotPool
from .authority import DescriptorKernelIdentity
from .config import Stage1Config
from .engine import CommandEngineConfig, CommandExecutionEngine
from ..stage2.authority import Stage2Profiles
from ..stage2.engine import Stage2CommandEngine, Stage2EngineConfig
from .service import GenerationParts, Stage1Parts, Stage1Service, Stage2Parts
from .campaigns import (CampaignStore, CommandCampaigner,
                        CommandCampaignerConfig)
from .validation import (CommandValidator, CommandValidatorConfig,
                         DeferredValidator, StagedExecutionHarnessAuthority,
                         ValidationStore)

#: States where the loop has nothing to do until a person acts.
STOP_STATES = TERMINAL | {JobState.S1_REACHED, JobState.S1_APPROVAL,
                          JobState.BLOCKED_OPERATOR,
                          JobState.BLOCKED_HARNESS_GAP, JobState.PARKED,
                          JobState.CRASH_REVIEW}


def open_stage1(config: Stage1Config, stack: ExitStack, *,
                runtime=None, parser=None, generation_runtime=None,
                run_agents: bool = True) -> Stage1Service:
    """Build the production service from host configuration.  Tests may
    inject ``runtime``, ``generation_runtime`` and ``parser``; production
    uses the PydanticAI drivers and the pinned syzkaller bundle.
    ``run_agents=False`` is for one-shot commands: Agent Tasks and
    validations they create are left to ``run``."""
    artifacts = ArtifactStore(config.artifact_root)
    approvals = tuple(load_record(artifacts, ref, ExecutionHarnessApproval)
                      for ref in config.execution_harness_approvals)
    if parser is None:
        from ..syzkaller.adapter import PinnedSyzParser
        parser = stack.enter_context(PinnedSyzParser(
            config.syzkaller_bundle, identity=config.syzkaller_identity))
    if runtime is None and run_agents:
        from ..agent_tasks.pydantic_ai_runtime import (PydanticAIRuntime,
                                                       RuntimeLimits)
        a = config.agent_runtime
        runtime = PydanticAIRuntime(limits=RuntimeLimits(
            max_requests=a.max_requests, max_tool_calls=a.max_tool_calls,
            request_timeout_seconds=a.request_timeout_s,
            run_timeout_seconds=a.run_timeout_s))
    e = config.engine
    state = Path(config.state_dir)
    slots = None
    if config.slots is not None:
        p = config.slots
        slots = SlotPool.for_host(e.resource_key, SlotPolicy(
            vm_cpus=p.vm_cpus, vm_memory_mb=p.vm_memory_mb,
            reserve_cpus=p.reserve_cpus,
            reserve_memory_mb=p.reserve_memory_mb, max_slots=p.max_slots))
    engine_config = CommandEngineConfig(
        argv=e.argv, cwd=e.cwd, work_root=state / "runs",
        resource_key=e.resource_key, collector_id=e.collector_id, env=e.env,
        limits=ProcessLimits(timeout_s=e.timeout_s,
                             max_output_bytes=e.max_output_bytes))

    def engine(store: ArtifactStore) -> CommandExecutionEngine:
        return CommandExecutionEngine(
            engine_config, store, ProcessSupervisor(state / "processes"),
            slots=slots)

    stage2 = None
    if config.stage2 is not None:
        c = config.stage2
        stage2_config = Stage2EngineConfig(
            argv=c.argv, cwd=c.cwd, work_root=state / "stage2-runs",
            resource_key=c.resource_key, collector_id=c.collector_id,
            replay_proxy=c.replay_proxy,
            crash_window_bound=c.crash_window_bound, env=c.env,
            limits=ProcessLimits(timeout_s=c.timeout_s,
                                 max_output_bytes=c.max_output_bytes),
            poll_interval_s=c.poll_interval_s)

        def stage2_engine(store, receipts, evidence) -> Stage2CommandEngine:
            return Stage2CommandEngine(
                stage2_config, store, ProcessSupervisor(state / "processes"),
                receipts=receipts, evidence=evidence, slots=slots)

        stage2 = Stage2Parts(
            engine_factory=stage2_engine,
            profiles=Stage2Profiles(
                m1_profile_ref=c.m1_profile_ref,
                q2_profile_ref=c.q2_profile_ref,
                replay_profile_ref=c.replay_profile_ref,
                crash_window_bound=c.crash_window_bound))

    authority = StaticExecutionHarnessAuthority(approvals)
    generation = None
    if config.generation is not None:
        authority, generation = _generation(
            config, stack, artifacts, authority, slots,
            runtime=generation_runtime, run=run_agents)

    tree = GitSourceTree(config.kernel_repo)
    parts = Stage1Parts(
        state_dir=state, artifacts=artifacts, tree=tree,
        registry=ArtifactHarnessRegistry(artifacts, config.harness_catalog_ref),
        materializer=ArtifactHarnessMaterializer(
            artifacts, authority, parser),
        runtime=runtime, tools=None, engine_factory=engine,
        judge_versions=config.judge_versions,
        identities=DescriptorKernelIdentity(
            config.vmlinux_artifact_name, config.instrumentation_artifact_name),
        policies=config.policies, sealer_id=config.sealer_id,
        worker_id=config.worker_id,
        lease_duration_ns=int(config.lease_duration_s * 1e9),
        agent_workers=config.agent_workers, run_agents=run_agents,
        runner_workers=1 if slots is None else slots.count,
        compiler=None if config.nfs_proxy is None else
        ArtifactMutationRuleCompiler(artifacts, config.nfs_proxy,
                                     state / "compile"),
        stage2=stage2, generation=generation)
    return stack.enter_context(Stage1Service(parts))


def _generation(config: Stage1Config, stack: ExitStack,
                artifacts: ArtifactStore,
                static: StaticExecutionHarnessAuthority, slots, *, runtime,
                run: bool):
    """07 §5: the generation Agent, the validator and the authority that
    adds the staged approvals validation left to the static ones."""
    g = config.generation
    state = Path(config.state_dir)
    state.mkdir(parents=True, exist_ok=True)
    store = stack.enter_context(closing(
        ValidationStore(state / "validations.sqlite")))
    authority = StagedExecutionHarnessAuthority(static, store, artifacts)
    if run:
        v = g.validation
        validator = CommandValidator(CommandValidatorConfig(
            argv=v.argv, cwd=v.cwd, work_root=state / "validation-runs",
            resource_key=v.resource_key, env=v.env, timeout_s=v.timeout_s),
            store, artifacts, state / "validation.lock", slots=slots)
    else:
        validator = DeferredValidator(store)
    campaigner = None
    if g.campaign is not None:
        campaigns = stack.enter_context(closing(
            CampaignStore(state / "campaigns.sqlite")))
        if run:
            c = g.campaign
            campaigner = CommandCampaigner(CommandCampaignerConfig(
                argv=c.argv, cwd=c.cwd, work_root=state / "campaign-runs",
                resource_key=c.resource_key, stage1=c.stage1,
                collector=c.collector, env=c.env, timeout_s=c.timeout_s,
                campaign=c.campaign),
                campaigns, artifacts, state / "campaign.lock", slots=slots)
        else:
            campaigner = DeferredValidator(campaigns)
    if runtime is None and run:
        from ..agent_tasks.pydantic_ai_generation import (
            PydanticAIGenerationRuntime)
        runtime = PydanticAIGenerationRuntime()
    extra = {} if g.allowed_paths is None else \
        {"allowed_paths": g.allowed_paths}
    sandbox = GenerationSandbox(
        repo=g.repo, worktree_root=g.worktree_root, base_ref=g.base_ref,
        launcher=g.launcher, env=g.env, **extra)
    hcap = ArtifactHcapChecker(artifacts)
    executor = GenerationAgentExecutor(
        runtime, artifacts, sandbox, None,
        contract_for=lambda gap, revision: gap_contract(hcap, gap, revision))
    return authority, GenerationParts(executor=executor, validator=validator,
                                      workers=g.workers,
                                      campaigner=campaigner)


def gap_contract(hcap: ArtifactHcapChecker, gap, revision: str | None):
    """The gap key's vocabulary contract in the base HCAP revision."""
    if revision is None:
        return None
    try:
        catalog = hcap.load_catalog(revision)
    except (OSError, ValueError):
        return None
    for item in catalog.gap_contracts:
        if item.missing_capability_id == gap.missing_capability_id:
            return item
    return None


def resubmit(service: Stage1Service, job_id: str, kernel_commit: str) -> str:
    """Submit an earlier job's candidate location again at ``kernel_commit``.

    A candidate binds the kernel commit it was submitted at; when that commit
    cannot be rebuilt, the location is submitted again and the new job goes
    through intake like any submission.  The earlier job is kept as it is.
    """
    old = service.job(job_id)
    return service.controller.submit(CandidateSubmission(
        kernel_commit=kernel_commit, location=old.submission.location),
        old.job_policy_id)


def _job_summary(service: Stage1Service, job_id: str) -> dict:
    job = service.job(job_id)
    out = {"job_id": job.job_id, "state": job.state.value,
           "state_reason": job.state_reason}
    if job.candidate is not None:
        out["candidate_id"] = job.candidate.candidate_id
    if job.pending_task is not None:
        p = job.pending_task
        out["pending_task"] = {"task_id": p.task_id, "kind": p.kind.value,
                               "attempt": p.attempt}
    if job.harness is not None:
        out["review_manifest_sha256"] = job.harness.review_manifest_sha256
    if job.last_verdict is not None:
        v = job.last_verdict
        out["last_verdict"] = {"status": v.result.status.value,
                               "reason": v.result.reason,
                               "bundle_ref": v.bundle_ref}
    if job.gate_runs:
        out["gate_runs"] = [{"bundle_ref": r.bundle_ref,
                             "q1": r.q1.status.value,
                             "rules": {x.rule_id: x.status for x in r.rules},
                             "ambient": list(r.ambient)}
                            for r in job.gate_runs]
    if job.campaign is not None:
        out["campaign"] = {"campaign_id": job.campaign.campaign_id,
                           **job.campaign.tally.model_dump(mode="json")}
    if job.triage:
        out["triage"] = [t.model_dump(mode="json") for t in job.triage]
    if job.fixed is not None:
        k = job.fixed
        out["fixed"] = {
            "campaign_id": k.campaign_id, "sent": k.sent,
            "reached": k.reached, "not_reached": k.not_reached,
            "crashes": k.crashes,
            "consecutive_not_reached": k.consecutive_not_reached,
            "in_flight": [a.task_id for a in k.in_flight]}
    if job.crash_findings:
        out["crash_findings"] = [f.model_dump(mode="json")
                                 for f in job.crash_findings]
    if job.replay is not None:
        out["replay"] = {"crash_bundle_ref": job.replay.crash.bundle_ref,
                         "outcome": None if job.replay.outcome is None else
                         job.replay.outcome.model_dump(mode="json")}
    due = service.controller.promotion_due(job)
    if due is not None:
        # 07 §5.3: decided with this Stage 1 end (approve-promotion).
        out["promotion_due"] = {"promotion_id": due.promotion_id,
                                "state": due.state.value,
                                "reason": due.reason,
                                "evidence_refs": list(due.evidence_refs)}
    failures = service.store.effect_failures(job_id)
    if failures:
        out["last_effect_failure"] = list(failures[-1])
    return out


def _promotion_summary(p) -> dict:
    return {"promotion_id": p.promotion_id, "generation_id": p.generation_id,
            "gap": p.gap.model_dump(mode="json"), "state": p.state.value,
            "reason": p.reason,
            "staged_binding": p.staged_binding.model_dump(mode="json"),
            "capabilities": [c.model_dump(mode="json")
                             for c in p.capabilities],
            "withheld_program_sha256s": list(p.withheld_program_sha256s),
            "review": None if p.review is None
            else p.review.model_dump(mode="json"),
            "issue_resolved": p.issue_resolved}


def export_promotion(service: Stage1Service, promotion_id: str,
                     out: Path) -> dict[str, str]:
    """Each capability's campaign evidence as ``<capability>.evidence.json``
    in ``out``, for the host spec's ``capability_evidence``."""
    p = service.store.promotion(promotion_id)
    out.mkdir(parents=True, exist_ok=True)
    written = {}
    for c in p.capabilities:
        if c.evidence_ref is None:
            continue
        path = out / f"{c.capability_id}.evidence.json"
        path.write_bytes(service.artifacts.get(c.evidence_ref))
        written[c.capability_id] = str(path)
    return written


def _print(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m agent_pipeline.stage1",
                                 description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", type=Path, required=True)
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("submit")
    s.add_argument("--commit", required=True)
    s.add_argument("--path", required=True)
    s.add_argument("--kind", choices=[k.value for k in LocationKind],
                   default=LocationKind.FUNCTION.value)
    s.add_argument("--symbol")
    s.add_argument("--start-line", type=int)
    s.add_argument("--end-line", type=int)
    s.add_argument("--policy", required=True)

    rs = sub.add_parser(
        "resubmit", help="submit an earlier job's candidate location at "
        "another kernel commit, as a new job")
    rs.add_argument("job")
    rs.add_argument("--commit", required=True)

    sd = sub.add_parser(
        "seed", help="start a new job for an earlier job's candidate under "
        "another policy (e.g. a KCSAN one) from that job's plan, skipping "
        "Analysis and Planning")
    sd.add_argument("job")
    sd.add_argument("--policy", required=True)

    r = sub.add_parser("run")
    r.add_argument("--job", help="stop when this job reaches a stop state")
    r.add_argument("--timeout", type=float, help="seconds")
    r.add_argument("--interval", type=float, default=1.0)

    st = sub.add_parser("status")
    st.add_argument("job", nargs="?")

    a = sub.add_parser("approve")
    a.add_argument("job")
    a.add_argument("task")
    a.add_argument("review_manifest_sha256")
    a.add_argument("decision_id")

    d = sub.add_parser("deny")
    d.add_argument("job")
    d.add_argument("task")
    d.add_argument("note")

    o = sub.add_parser("operator")
    o.add_argument("job")
    o.add_argument("action")

    ri = sub.add_parser("resolve-issue",
                        help="record a harness gap issue status change")
    ri.add_argument("issue", help="gap-N, as printed by issues")
    ri.add_argument("status", choices=["resolved", "deferred", "reopened",
                                       "wont_fix"])
    ri.add_argument("--resolution", default="")

    sub.add_parser("issues")

    m = sub.add_parser("add-mapping")
    m.add_argument("file", type=Path)

    rp = sub.add_parser("replay")
    rp.add_argument("job")

    sub.add_parser("promotions")
    for name in ("approve-promotion", "reject-promotion"):
        pr = sub.add_parser(name)
        pr.add_argument("promotion")
        pr.add_argument("decision_id")
        pr.add_argument("--note", default="")
    rtp = sub.add_parser("retry-promotion")
    rtp.add_argument("promotion")
    ep = sub.add_parser("export-promotion")
    ep.add_argument("promotion")
    ep.add_argument("out", type=Path)

    args = ap.parse_args(argv)
    config = Stage1Config.load(args.config)
    with ExitStack() as stack:
        # Only the service loop runs Agent Tasks; a one-shot command that
        # creates one leaves it for run, which stores its result.
        service = open_stage1(config, stack,
                              run_agents=args.command == "run")
        if args.command == "submit":
            job_id = service.controller.submit(CandidateSubmission(
                kernel_commit=args.commit, location=LocationRequest(
                    kind=LocationKind(args.kind), path=args.path,
                    symbol=args.symbol, start_line=args.start_line,
                    end_line=args.end_line)), args.policy)
            _print(_job_summary(service, job_id))
        elif args.command == "resubmit":
            job_id = resubmit(service, args.job, args.commit)
            _print({"resubmitted_from": args.job,
                    **_job_summary(service, job_id)})
        elif args.command == "seed":
            try:
                job_id = service.controller.seed(args.job, args.policy)
            except (KeyError, ValueError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            _print({"seeded_from": args.job,
                    **_job_summary(service, job_id)})
        elif args.command == "run":
            service.recover()
            for err in service.recover_errors:
                print(f"error: {err}", file=sys.stderr)
            service.start_worker()
            seen: dict[str, str] = {}

            def show(report) -> None:
                for p in report.publications:
                    if p.outcome != "published":
                        print(f"host authority {p.outcome} for {p.task_id}: "
                              f"{p.detail}", file=sys.stderr)
                for err in report.errors + service.worker_errors:
                    print(f"error: {err}", file=sys.stderr)
                service.worker_errors.clear()
                for job in service.store.jobs():
                    if seen.get(job.job_id) != job.state.value:
                        seen[job.job_id] = job.state.value
                        _print(_job_summary(service, job.job_id))

            def done() -> bool:
                return args.job is not None and \
                    service.job(args.job).state in STOP_STATES

            ok = service.run(done, interval_s=args.interval,
                             timeout_s=args.timeout, on_step=show)
            if args.job:
                _print(_job_summary(service, args.job))
            return 0 if ok else 2
        elif args.command == "status":
            jobs = [args.job] if args.job else \
                [j.job_id for j in service.store.jobs()]
            _print([_job_summary(service, j) for j in jobs])
        elif args.command == "approve":
            service.controller.approve(args.job, args.task,
                                       args.review_manifest_sha256,
                                       args.decision_id)
            _print(_job_summary(service, args.job))
        elif args.command == "deny":
            service.controller.deny(args.job, args.task, args.note)
            _print(_job_summary(service, args.job))
        elif args.command == "operator":
            service.controller.operator(args.job, args.action)
            _print(_job_summary(service, args.job))
        elif args.command == "promotions":
            _print([_promotion_summary(p)
                    for p in service.store.promotions()])
        elif args.command in ("approve-promotion", "reject-promotion",
                              "retry-promotion"):
            c = service.controller
            try:
                if args.command == "retry-promotion":
                    p = c.retry_promotion(args.promotion)
                else:
                    p = (c.approve_promotion
                         if args.command == "approve-promotion"
                         else c.reject_promotion)(
                        args.promotion, args.decision_id, args.note)
            except (KeyError, ValueError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            _print(_promotion_summary(p))
        elif args.command == "export-promotion":
            _print(export_promotion(service, args.promotion, args.out))
        elif args.command == "add-mapping":
            mapping = TargetPcMapping.model_validate_json(args.file.read_bytes())
            print(service.mappings.add(mapping))
        elif args.command == "resolve-issue":
            # Recorded first, so a running service also applies it; applied
            # here too so the linked jobs show the result at once.
            service.issues.change(args.issue, args.status, args.resolution)
            for err in service.deliver_issue_events():
                print(f"error: {err}", file=sys.stderr)
            _print(service.issues.issues())
        elif args.command == "issues":
            _print(service.issues.issues())
        elif args.command == "replay":
            job = service.controller.replay(args.job)
            _print({"job_id": job.job_id, "replayed_seq": job.seq,
                    "matches": True})
    return 0
