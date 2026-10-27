"""M7 stage 2 on the host: the recorder over a replayed natural crash.

The two sides are the M6 host run of `test_semantic_promotion` (the built
Proxy, the real sink, a crash cut), standing in for a Stage 2 campaign
crash and its replay; the Stage 2 judge is replaced by one that opens
them.  It checks the recorder's gate over them, not KVM evidence.
"""

from __future__ import annotations

from contextlib import contextmanager

import pytest

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import (CompiledRuleSet, GapClass, GapRef,
                                      HarnessBinding, Sanitizer)
from agent_pipeline.controller.promotion import HarnessPromotion
from agent_pipeline.controller.records import CrashRef
from agent_pipeline.data import load_record, put_record
from agent_pipeline.hcap import ArtifactHcapChecker
from agent_pipeline.replay_runner import (judge_input, parse_crash_context,
                                          parse_execprog_barriers,
                                          plan_replay, check_rule_set)
from agent_pipeline.semantic_delta import SealedJournal
from agent_pipeline.semantic_promotion import (
    GuestValidationRun, PromotedSemanticCapabilityRegistry,
    UnreproducibleCrash, pin, promoted_registry, with_semantic_capability)
from agent_pipeline.semantic_replay import Termination
from agent_pipeline.stage1.host.semantic import stage_proxy, staged_proxy
from agent_pipeline.stage2.judge import ReplaySides
from agent_pipeline.stage2.semantic import ArtifactSemanticRecorder

from . import test_journal_live as live_mod
from .test_journal_live import LANE, VM
from .test_semantic_promotion import (  # noqa: F401  (fixtures)
    KERNEL, ONE_RULE, OTHER_ORIGINALS, _catalog, _ended, _production, build,
    proxy_binary, run, subset)
from .test_semantic_replay_live import (PROFILE, _barriers, _crash_log,
                                        _replay)

pytestmark = live_mod.pytestmark
COMPILED = CompiledRuleSet(rule_set_ref="b" * 64, compiled_ref="c" * 64,
                           hcap_revision="d" * 64)


@pytest.fixture(scope="module")
def sides(proxy_binary, tmp_path_factory):
    """A crashed production window and its replay on other originals."""
    tmp = tmp_path_factory.mktemp("stage2-crash")
    production = _production(proxy_binary, tmp / "production", ONE_RULE)
    plan = plan_replay(SealedJournal(production, "lane0"),
                       parse_crash_context(_crash_log(1), vm_instance_id=VM,
                                           bound=4))
    compat = check_rule_set(proxy_binary, plan.rule_set, tmp)
    with pytest.MonkeyPatch.context() as mp:
        replay = _replay(proxy_binary, tmp / "replay", plan, OTHER_ORIGINALS,
                         mp)
    sealed = SealedJournal(production, "lane0")
    data = judge_input(
        plan, sealed, replay, replay_vm_instance_id=VM, replay_lane_id=LANE,
        replay_barriers=parse_execprog_barriers(_barriers(11)),
        production_termination=Termination.GUEST_CRASH,
        replay_termination=Termination.GUEST_CRASH, compatibility=compat,
        evidence_verified=True, profile=PROFILE)
    return ReplaySides(plan=plan, production=sealed, replay=replay,
                       judge_input=data, kernel_commit=KERNEL,
                       production_vm_instance_id=VM,
                       replay_vm_instance_id=VM)


class Judge:
    def __init__(self, sides) -> None:
        self.sides = sides
        self.asked: list[tuple[str, str]] = []

    @contextmanager
    def replay_sides(self, bundle_ref, *, crash_bundle_ref, compiled):
        self.asked.append((bundle_ref, crash_bundle_ref))
        assert compiled == COMPILED
        if isinstance(self.sides, Exception):
            raise self.sides
        yield self.sides


def _staged(store, build, run) -> HarnessBinding:
    """The staged revision validation leaves: the subset pinned pending."""
    pinned = pin(store, build, subset(), (put_record(store, _ended(run)),))
    hcap = with_semantic_capability(_catalog(), put_record(store, pinned),
                                    pinned)
    return HarnessBinding(kernel_commit=KERNEL, sanitizer=Sanitizer.KASAN,
                          execution_harness_id="e" * 64,
                          hcap_revision=put_record(store, hcap))


def _promotion(staged) -> HarnessPromotion:
    return HarnessPromotion(
        promotion_id="gen-1.p", generation_id="gen-1",
        gap=GapRef(gap_class=GapClass.MUTATION_ENGINE,
                   missing_capability_id="semantic.nfs4.open_reply"),
        kernel_commit=KERNEL, sanitizer=Sanitizer.KASAN, base_binding=None,
        staged_binding=staged, runtime_retry_limit=1, kind="semantic")


def _crash(staged) -> CrashRef:
    return CrashRef(bundle_ref="crash-1", campaign_id="cmp-1",
                    compiled=COMPILED, binding=staged, harness_ref="h" * 64,
                    execution_harness_id=staged.execution_harness_id,
                    q2_verdict_id="q2", m1_verdict_id="m1")


def _recorder(store, judge, tmp_path, proxy=None):
    root = tmp_path / "staged-files"
    root.mkdir(exist_ok=True)
    if proxy is not None:
        stage_proxy(root, proxy)
    return ArtifactSemanticRecorder(store, judge, staged_files=root,
                                    workdir=tmp_path / "work")


def test_a_replayed_natural_crash_passes_the_pending_subset(
        proxy_binary, build, run, sides, tmp_path):
    store = ArtifactStore(tmp_path / "cas")
    staged = _staged(store, build, run)
    judge = Judge(sides)
    st = _recorder(store, judge, tmp_path, proxy_binary).record(
        _promotion(staged), _crash(staged), "replay-1")
    assert st.state == "evidence", st.reason
    assert judge.asked == [("replay-1", "crash-1")]
    recorded = load_record(store, st.run_ref, GuestValidationRun)
    assert recorded.subset_id == subset().subset_id
    assert recorded.judge_input.positions[-1].production.termination is \
        Termination.GUEST_CRASH
    promoted = load_record(store, st.record_ref,
                           PromotedSemanticCapabilityRegistry)
    assert promoted.pending == ()
    assert st.run_ref in promoted.subsets[0].evidence_refs
    # The candidate revision is the staged one with the subset passed.
    candidate = ArtifactHcapChecker(store).load_catalog(st.hcap_revision)
    assert promoted_registry(store, candidate).pending == ()
    entry = next(c for c in candidate.capabilities if c.id == "HCAP-10")
    assert st.run_ref in entry.evidence_refs
    assert not any("pending" in c for c in entry.constraints)


def test_a_crash_without_its_delta_is_recorded_unreproducible(
        proxy_binary, build, run, sides, tmp_path):
    store = ArtifactStore(tmp_path / "cas")
    staged = _staged(store, build, run)
    positions = list(sides.judge_input.positions)
    last = positions[-1]
    positions[-1] = last.model_copy(update={
        "production": last.production.model_copy(update={"batches": ()})})
    lost = ReplaySides(**{**sides.__dict__, "judge_input":
                          sides.judge_input.model_copy(
                              update={"positions": tuple(positions)})})
    st = _recorder(store, Judge(lost), tmp_path, proxy_binary).record(
        _promotion(staged), _crash(staged), "replay-1")
    assert (st.state, st.subset_id) == ("unreproducible",
                                        subset().subset_id)
    record = load_record(store, st.record_ref, UnreproducibleCrash)
    assert record.run_refs == (st.run_ref,)


def test_a_replay_on_the_production_originals_is_not_evidence(
        proxy_binary, build, run, sides, tmp_path):
    store = ArtifactStore(tmp_path / "cas")
    staged = _staged(store, build, run)
    st = _recorder(store, Judge(ValueError("the replay was not planned")),
                   tmp_path, proxy_binary).record(
        _promotion(staged), _crash(staged), "replay-1")
    assert st.state == "not_evidence"
    assert "replay_unreadable" in st.reason


def test_without_the_staged_proxy_the_recorder_waits(build, run, sides,
                                                     tmp_path):
    store = ArtifactStore(tmp_path / "cas")
    staged = _staged(store, build, run)
    judge = Judge(sides)
    st = _recorder(store, judge, tmp_path).record(
        _promotion(staged), _crash(staged), "replay-1")
    assert (st.state, judge.asked) == ("unavailable", [])
    assert str(staged_proxy(tmp_path / "staged-files",
                            build.proxy_sha256)) in st.reason


def test_a_crash_on_another_binding_is_not_evidence(proxy_binary, build, run,
                                                    sides, tmp_path):
    store = ArtifactStore(tmp_path / "cas")
    staged = _staged(store, build, run)
    other = _crash(staged).model_copy(update={
        "binding": staged.model_copy(update={"hcap_revision": "f" * 64})})
    st = _recorder(store, Judge(sides), tmp_path, proxy_binary).record(
        _promotion(staged), other, "replay-1")
    assert (st.state, st.reason) == ("not_evidence",
                                     "crash_on_another_binding")


def test_the_staged_proxy_is_kept_by_its_digest(proxy_binary, build,
                                                tmp_path):
    root = tmp_path / "staged-files"
    path = stage_proxy(root, proxy_binary)
    assert path == staged_proxy(root, build.proxy_sha256)
    assert stage_proxy(root, proxy_binary) == path
    assert path.stat().st_mode & 0o777 == 0o555
