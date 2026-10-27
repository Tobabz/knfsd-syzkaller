"""M7 stage 2 on the host: a natural Stage 2 crash as promotion evidence
(03-nfs-proxy/06 §30; 02-llm-agent/07 §5.3 item 7).

A job on a staged harness whose HCAP-10 pins a subset with crash survival
pending ran a campaign; a guest crash came from it, and Stage 2 replayed
it.  ``ArtifactSemanticRecorder`` is the Controller's ``SemanticRecorder``:
for the promotion's staged revision it does what an operator does with
``semantic_promotion record`` and ``promote``:

1. the pinned registry of the revision (the candidate revision once a
   subset passed), and its pending subsets;
2. the host copy of that build's Proxy, staged by validation under the
   collector's ``staged_files`` (``stage1/host/semantic.py``
   ``stage_proxy``); it runs under the generation launcher;
3. both sealed journals of the replay (``ArtifactStage2Judge
   .replay_sides``), the rule set described by that Proxy and the
   original values;
4. for each pending subset the rule set fits: the ``GuestValidationRun``.
   A crash that left no MutationDelta at the crash cut is
   ``unreproducible`` (the run and an ``UnreproducibleCrash`` are stored);
   otherwise ``promote`` with the pinned registry as ``previous``, and the
   staged revision with the subset passed.

Nothing here decides: a person approves at the end of Stage 2, and the
shared binding is the host's promotion.
"""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from typing import Callable

from ..artifacts import ArtifactStore
from ..controller.promotion import HarnessPromotion, SemanticStatus
from ..controller.records import CrashRef
from ..data import put_record
from ..hcap import ArtifactHcapChecker
from ..replay_runner import PlanError
from ..semantic_delta import DeltaReadError
from ..semantic_promotion import (BuildRegistry, GuestValidationRun,
                                  PromotionRefused, UnreproducibleCrash,
                                  describe_rule_set, dynamic_originals,
                                  promote, promoted_registry, rule_problems,
                                  unreproducible, with_semantic_capability)
from ..semantic_replay import evaluate
from ..stage1.host.pins import file_sha256
from ..stage1.host.semantic import staged_proxy

NOTE = "natural Stage 2 crash (M7 stage 2, 03-nfs-proxy/06 §30)"
_UNREADABLE = (ValueError, KeyError, PlanError, DeltaReadError)


def _status(state: str, reason: str | None = None, **kw) -> SemanticStatus:
    return SemanticStatus(state=state, reason=None if reason is None
                          else reason[:2000], **kw)


class ArtifactSemanticRecorder:
    """``SemanticRecorder`` over the CAS and the Stage 2 judge.  ``judge``
    may be bound after construction (the service builds it later)."""

    def __init__(self, artifacts: ArtifactStore, judge=None, *,
                 staged_files: Path | None, workdir: Path,
                 launcher: tuple[str, ...] = (),
                 describe: Callable = describe_rule_set) -> None:
        self.artifacts = artifacts
        self.judge = judge
        self.staged_files = staged_files
        self.workdir = Path(workdir)
        self.launcher = launcher
        self.describe = describe
        self.hcap = ArtifactHcapChecker(artifacts)

    def record(self, p: HarnessPromotion, crash: CrashRef,
               replay_bundle_ref: str) -> SemanticStatus:
        if crash.binding != p.staged_binding:
            return _status("not_evidence", "crash_on_another_binding")
        revision = p.candidate_hcap_revision or p.staged_binding.hcap_revision
        hcap = self.hcap.load_catalog(revision)
        pinned = promoted_registry(self.artifacts, hcap)
        if pinned is None or not pinned.pending:
            return _status("not_evidence", "no_pending_subset")
        if self.judge is None or self.staged_files is None:
            return _status("unavailable", "no_stage2_judge" if
                           self.judge is None else "no_staged_files")
        proxy = staged_proxy(self.staged_files, pinned.proxy_sha256)
        if not proxy.is_file() or file_sha256(proxy) != pinned.proxy_sha256:
            return _status("unavailable", f"staged_proxy_missing:{proxy}")
        build = BuildRegistry(proxy_sha256=pinned.proxy_sha256,
                              registry_digest=pinned.registry_digest,
                              registry=pinned.registry)
        self.workdir.mkdir(parents=True, exist_ok=True)
        work = self.workdir / uuid.uuid4().hex
        work.mkdir()
        work.chmod(0o755)         # the launcher's Proxy reads the rule set
        try:
            with self.judge.replay_sides(
                    replay_bundle_ref, crash_bundle_ref=crash.bundle_ref,
                    compiled=crash.compiled) as sides:
                described = self.describe(proxy, sides.plan.rule_set, work,
                                          launcher=self.launcher)
                originals = dynamic_originals(sides.production, sides.replay,
                                              sides.judge_input)
        except _UNREADABLE as exc:
            return _status("not_evidence",
                           f"replay_unreadable:{type(exc).__name__}: {exc}")
        finally:
            shutil.rmtree(work, ignore_errors=True)
        data = sides.judge_input
        subsets = {s.subset.subset_id: s.subset for s in pinned.subsets}
        problems = []
        for subset_id in pinned.pending:
            subset = subsets[subset_id]
            outside = [x for rule in described.rules
                       for x in rule_problems(rule, described.schema_id,
                                              subset)]
            if outside:
                # Not this subset's rule set: its crash says nothing of it.
                problems.append(f"{subset_id}: {'; '.join(outside)}")
                continue
            run = GuestValidationRun(
                subset_id=subset_id, environment="kvm_guest",
                proxy_sha256=build.proxy_sha256,
                registry_digest=build.registry_digest,
                kernel_commit=sides.kernel_commit,
                production_vm_instance_id=sides.production_vm_instance_id,
                replay_vm_instance_id=sides.replay_vm_instance_id,
                rule_set=described, judge_input=data,
                replay_result=evaluate(data), original_values=originals,
                note=NOTE)
            run_ref = put_record(self.artifacts, run)
            if unreproducible(run):
                lost = put_record(self.artifacts, UnreproducibleCrash(
                    subset_id=subset_id, proxy_sha256=build.proxy_sha256,
                    registry_digest=build.registry_digest,
                    run_refs=(run_ref,)))
                return _status("unreproducible", "no_delta_at_crash_cut",
                               subset_id=subset_id, run_ref=run_ref,
                               record_ref=lost)
            try:
                promoted = promote(self.artifacts, build, subset, (run_ref,),
                                   pinned)
            except PromotionRefused as refused:
                problems.append(f"{subset_id}: "
                                f"{'; '.join(refused.problems)}")
                continue
            registry_ref = put_record(self.artifacts, promoted)
            candidate = with_semantic_capability(hcap, registry_ref, promoted)
            return _status("evidence", subset_id=subset_id, run_ref=run_ref,
                           record_ref=registry_ref,
                           hcap_revision=put_record(self.artifacts,
                                                    candidate))
        return _status("not_evidence", "\n".join(problems) or None)


__all__ = ["ArtifactSemanticRecorder"]
